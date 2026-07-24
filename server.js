'use strict';

const http = require('http');
const net = require('net');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = parseInt(process.env.PORT || '3000', 10);
const TARGET_HOST = process.env.TARGET_HOST || '';
const TARGET_PORT = parseInt(process.env.TARGET_PORT || '22', 10);
const RELAY_TOKEN = process.env.RELAY_TOKEN || '';
const CONNECT_TIMEOUT_MS = parseInt(process.env.CONNECT_TIMEOUT_MS || '10000', 10);
const MAX_CONNECTIONS_PER_IP = parseInt(process.env.MAX_CONNECTIONS_PER_IP || '5', 10);
const MAX_FRAME_BYTES = parseInt(process.env.MAX_FRAME_BYTES || String(16 * 1024 * 1024), 10);
const PING_INTERVAL_MS = parseInt(process.env.PING_INTERVAL_MS || '25000', 10);

const activeByIp = new Map();

function log(event, details = {}) {
  console.log(JSON.stringify({ time: new Date().toISOString(), event, ...details }));
}

function clientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

function isAuthorized(req, parsedUrl) {
  if (!RELAY_TOKEN) return true;
  const headerToken = req.headers['x-relay-token'];
  const queryToken = parsedUrl.searchParams.get('token');
  return headerToken === RELAY_TOKEN || queryToken === RELAY_TOKEN;
}

function reserveConnection(ip) {
  const current = activeByIp.get(ip) || 0;
  if (current >= MAX_CONNECTIONS_PER_IP) return false;
  activeByIp.set(ip, current + 1);
  return true;
}

function releaseConnection(ip) {
  const current = activeByIp.get(ip) || 0;
  if (current <= 1) activeByIp.delete(ip);
  else activeByIp.set(ip, current - 1);
}

function rejectUpgrade(socket, statusCode, message) {
  const body = `${message}\n`;
  socket.write(
    `HTTP/1.1 ${statusCode} ${http.STATUS_CODES[statusCode] || 'Error'}\r\n` +
    'Connection: close\r\n' +
    'Content-Type: text/plain; charset=utf-8\r\n' +
    `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n` +
    body
  );
  socket.destroy();
}

function websocketAccept(key) {
  return crypto
    .createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');
}

function sendWsFrame(socket, opcode, payload = Buffer.alloc(0)) {
  if (!Buffer.isBuffer(payload)) payload = Buffer.from(payload);
  const length = payload.length;
  let header;

  if (length < 126) {
    header = Buffer.allocUnsafe(2);
    header[1] = length;
  } else if (length <= 0xffff) {
    header = Buffer.allocUnsafe(4);
    header[1] = 126;
    header.writeUInt16BE(length, 2);
  } else {
    header = Buffer.allocUnsafe(10);
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(length), 2);
  }

  header[0] = 0x80 | (opcode & 0x0f); // FIN + opcode, server frames are unmasked.
  return socket.write(Buffer.concat([header, payload]));
}

class WebSocketFrameParser {
  constructor(onData, onPing, onPong, onClose, onError) {
    this.buffer = Buffer.alloc(0);
    this.onData = onData;
    this.onPing = onPing;
    this.onPong = onPong;
    this.onClose = onClose;
    this.onError = onError;
  }

  push(chunk) {
    if (!chunk || chunk.length === 0) return;
    this.buffer = this.buffer.length ? Buffer.concat([this.buffer, chunk]) : chunk;

    try {
      while (this.buffer.length >= 2) {
        const first = this.buffer[0];
        const second = this.buffer[1];
        const opcode = first & 0x0f;
        const masked = (second & 0x80) !== 0;
        let payloadLength = second & 0x7f;
        let offset = 2;

        if (!masked) throw new Error('Client WebSocket frames must be masked');

        if (payloadLength === 126) {
          if (this.buffer.length < 4) return;
          payloadLength = this.buffer.readUInt16BE(2);
          offset = 4;
        } else if (payloadLength === 127) {
          if (this.buffer.length < 10) return;
          const longLength = this.buffer.readBigUInt64BE(2);
          if (longLength > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Frame too large');
          payloadLength = Number(longLength);
          offset = 10;
        }

        if (payloadLength > MAX_FRAME_BYTES) throw new Error('Frame exceeds MAX_FRAME_BYTES');
        if (this.buffer.length < offset + 4 + payloadLength) return;

        const mask = this.buffer.subarray(offset, offset + 4);
        offset += 4;
        const payload = Buffer.from(this.buffer.subarray(offset, offset + payloadLength));
        this.buffer = this.buffer.subarray(offset + payloadLength);

        for (let i = 0; i < payload.length; i += 1) {
          payload[i] ^= mask[i & 3];
        }

        if (opcode === 0x0 || opcode === 0x1 || opcode === 0x2) {
          // SSH is a byte stream, so message boundaries and continuation frames do not matter.
          this.onData(payload);
        } else if (opcode === 0x8) {
          this.onClose(payload);
          return;
        } else if (opcode === 0x9) {
          this.onPing(payload);
        } else if (opcode === 0xA) {
          this.onPong(payload);
        } else {
          throw new Error(`Unsupported WebSocket opcode: ${opcode}`);
        }
      }
    } catch (error) {
      this.onError(error);
    }
  }
}

function connectUpstream(onConnect, onFailure) {
  const upstream = net.createConnection({ host: TARGET_HOST, port: TARGET_PORT });
  upstream.setNoDelay(true);
  upstream.setKeepAlive(true, 30000);
  upstream.setTimeout(CONNECT_TIMEOUT_MS, () => {
    upstream.destroy(new Error('Upstream connect timeout'));
  });

  const connectError = (error) => onFailure(error);
  upstream.once('error', connectError);
  upstream.once('connect', () => {
    upstream.removeListener('error', connectError);
    upstream.setTimeout(0);
    onConnect(upstream);
  });
  return upstream;
}

function handleStandardWebSocket(req, socket, head, ip) {
  const key = req.headers['sec-websocket-key'];
  const version = req.headers['sec-websocket-version'];
  if (typeof key !== 'string' || version !== '13') {
    rejectUpgrade(socket, 400, 'A valid RFC 6455 WebSocket handshake is required on /ssh');
    return;
  }

  let released = false;
  const release = () => {
    if (!released) {
      released = true;
      releaseConnection(ip);
    }
  };

  const upstream = connectUpstream(
    (connected) => {
      const accept = websocketAccept(key);
      socket.write(
        'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
      );

      socket.setNoDelay(true);
      socket.setKeepAlive(true, 30000);

      let closed = false;
      let pingTimer;
      const closeBoth = (reason) => {
        if (closed) return;
        closed = true;
        if (pingTimer) clearInterval(pingTimer);
        if (!socket.destroyed) socket.destroy();
        if (!connected.destroyed) connected.destroy();
        release();
        log('ws_closed', { ip, reason });
      };

      const parser = new WebSocketFrameParser(
        (payload) => {
          if (!connected.destroyed && !connected.write(payload)) socket.pause();
        },
        (payload) => sendWsFrame(socket, 0xA, payload),
        () => {},
        (payload) => {
          sendWsFrame(socket, 0x8, payload);
          closeBoth('client_close');
        },
        (error) => {
          log('ws_protocol_error', { ip, error: error.message });
          sendWsFrame(socket, 0x8, Buffer.from([0x03, 0xEA])); // 1002 protocol error
          closeBoth('protocol_error');
        }
      );

      connected.on('data', (chunk) => {
        if (!socket.destroyed && !sendWsFrame(socket, 0x2, chunk)) connected.pause();
      });
      connected.on('drain', () => socket.resume());
      socket.on('drain', () => connected.resume());
      socket.on('data', (chunk) => parser.push(chunk));

      connected.on('end', () => {
        if (!socket.destroyed) sendWsFrame(socket, 0x8);
        closeBoth('upstream_end');
      });
      connected.on('error', (error) => closeBoth(`upstream_error:${error.code || error.message}`));
      socket.on('error', (error) => closeBoth(`client_error:${error.code || error.message}`));
      socket.on('end', () => closeBoth('client_end'));
      socket.on('close', () => closeBoth('client_close'));

      pingTimer = setInterval(() => {
        if (!socket.destroyed) sendWsFrame(socket, 0x9, Buffer.from('keepalive'));
      }, PING_INTERVAL_MS);
      pingTimer.unref();

      if (head && head.length) parser.push(head);
      log('ws_connected', { ip, target: `${TARGET_HOST}:${TARGET_PORT}` });
    },
    (error) => {
      release();
      log('upstream_connect_error', { ip, error: error.message });
      rejectUpgrade(socket, 502, 'Unable to connect to SSH backend');
    }
  );

  socket.once('close', () => {
    if (!upstream.destroyed) upstream.destroy();
    release();
  });
}

function handleRawUpgrade(req, socket, head, ip) {
  // Compatibility mode for clients that use an HTTP 101 response and then send
  // unframed SSH bytes. This is not RFC 6455 and depends on the upstream edge
  // transparently tunnelling upgraded connections.
  let released = false;
  const release = () => {
    if (!released) {
      released = true;
      releaseConnection(ip);
    }
  };

  const upstream = connectUpstream(
    (connected) => {
      const key = req.headers['sec-websocket-key'];
      let response =
        'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n';
      if (typeof key === 'string') response += `Sec-WebSocket-Accept: ${websocketAccept(key)}\r\n`;
      response += '\r\n';
      socket.write(response);

      socket.setNoDelay(true);
      socket.setKeepAlive(true, 30000);
      connected.pipe(socket);
      socket.pipe(connected);
      if (head && head.length) connected.write(head);

      const closeBoth = (reason) => {
        if (!socket.destroyed) socket.destroy();
        if (!connected.destroyed) connected.destroy();
        release();
        log('raw_closed', { ip, reason });
      };

      connected.on('error', (error) => closeBoth(`upstream_error:${error.code || error.message}`));
      socket.on('error', (error) => closeBoth(`client_error:${error.code || error.message}`));
      connected.on('end', () => closeBoth('upstream_end'));
      socket.on('end', () => closeBoth('client_end'));
      socket.on('close', () => closeBoth('client_close'));
      log('raw_connected', { ip, target: `${TARGET_HOST}:${TARGET_PORT}` });
    },
    (error) => {
      release();
      log('upstream_connect_error', { ip, error: error.message });
      rejectUpgrade(socket, 502, 'Unable to connect to SSH backend');
    }
  );

  socket.once('close', () => {
    if (!upstream.destroyed) upstream.destroy();
    release();
  });
}

const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(TARGET_HOST ? 200 : 503, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      ok: Boolean(TARGET_HOST),
      service: 'railway-ssh-ws-relay',
      modes: ['/ssh', '/raw'],
      activeConnections: [...activeByIp.values()].reduce((a, b) => a + b, 0),
    }));
    return;
  }

  res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
  res.end('Railway SSH-over-WebSocket relay is running.\n');
});

server.on('upgrade', (req, socket, head) => {
  const ip = clientIp(req);
  let parsedUrl;

  try {
    parsedUrl = new URL(req.url, 'http://relay.local');
  } catch {
    rejectUpgrade(socket, 400, 'Invalid URL');
    return;
  }

  if (!TARGET_HOST || !Number.isInteger(TARGET_PORT) || TARGET_PORT < 1 || TARGET_PORT > 65535) {
    rejectUpgrade(socket, 503, 'TARGET_HOST or TARGET_PORT is not configured');
    return;
  }
  if (!isAuthorized(req, parsedUrl)) {
    rejectUpgrade(socket, 401, 'Invalid relay token');
    return;
  }
  if (!reserveConnection(ip)) {
    rejectUpgrade(socket, 429, 'Too many active connections');
    return;
  }

  if (parsedUrl.pathname === '/ssh') {
    handleStandardWebSocket(req, socket, head, ip);
  } else if (parsedUrl.pathname === '/raw') {
    handleRawUpgrade(req, socket, head, ip);
  } else {
    releaseConnection(ip);
    rejectUpgrade(socket, 404, 'Unknown relay path');
  }
});

server.on('clientError', (error, socket) => {
  log('client_http_error', { error: error.message });
  if (!socket.destroyed) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
});

server.listen(PORT, '0.0.0.0', () => {
  log('listening', {
    port: PORT,
    targetConfigured: Boolean(TARGET_HOST),
    targetPort: TARGET_PORT,
    tokenRequired: Boolean(RELAY_TOKEN),
  });
});
