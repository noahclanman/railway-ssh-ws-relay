'use strict';

const http = require('http');
const net = require('net');
const crypto = require('crypto');
const { URL } = require('url');

function envInt(name, fallback, min, max) {
  const raw = process.env[name];
  const value = raw == null || raw === '' ? fallback : Number.parseInt(raw, 10);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer from ${min} to ${max}`);
  }
  return value;
}

const CONFIG = Object.freeze({
  listenPort: envInt('PORT', 3000, 1, 65535),
  targetHost: String(process.env.TARGET_HOST || '').trim(),
  targetPort: envInt('TARGET_PORT', 550, 1, 65535),
  relayToken: String(process.env.RELAY_TOKEN || ''),
  connectTimeoutMs: envInt('CONNECT_TIMEOUT_MS', 10000, 1000, 120000),
  idleTimeoutMs: envInt('IDLE_TIMEOUT_MS', 0, 0, 86400000),
  maxConnectionsPerIp: envInt('MAX_CONNECTIONS_PER_IP', 5, 1, 1000),
  maxFrameBytes: envInt('MAX_FRAME_BYTES', 16 * 1024 * 1024, 1024, 64 * 1024 * 1024),
  pingIntervalMs: envInt('PING_INTERVAL_MS', 25000, 5000, 3600000),
});

const RAW_PATHS = new Set(['/ssh']);
const FRAMED_PATHS = new Set(['/ws']);
const activeByIp = new Map();

function log(event, details = {}) {
  process.stdout.write(`${JSON.stringify({ time: new Date().toISOString(), event, ...details })}\n`);
}

function clientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

function reserveConnection(ip) {
  const count = activeByIp.get(ip) || 0;
  if (count >= CONFIG.maxConnectionsPerIp) return false;
  activeByIp.set(ip, count + 1);
  return true;
}

function releaseConnection(ip) {
  const count = activeByIp.get(ip) || 0;
  if (count <= 1) activeByIp.delete(ip);
  else activeByIp.set(ip, count - 1);
}

function isAuthorized(req, url) {
  if (!CONFIG.relayToken) return true;
  return req.headers['x-relay-token'] === CONFIG.relayToken ||
    url.searchParams.get('token') === CONFIG.relayToken;
}

function httpResponse(socket, statusCode, body, extraHeaders = {}) {
  if (socket.destroyed) return;
  const payload = Buffer.from(`${body}\n`, 'utf8');
  const headers = {
    Connection: 'close',
    'Content-Type': 'text/plain; charset=utf-8',
    'Content-Length': String(payload.length),
    ...extraHeaders,
  };
  const lines = [`HTTP/1.1 ${statusCode} ${http.STATUS_CODES[statusCode] || 'Error'}`];
  for (const [name, value] of Object.entries(headers)) lines.push(`${name}: ${value}`);
  socket.end(`${lines.join('\r\n')}\r\n\r\n${payload.toString('utf8')}`);
}

function websocketAccept(key) {
  return crypto
    .createHash('sha1')
    .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
    .digest('base64');
}

function validWebSocketKey(key) {
  if (typeof key !== 'string') return false;
  try {
    return Buffer.from(key, 'base64').length === 16;
  } catch {
    return false;
  }
}

function connectTarget() {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({
      host: CONFIG.targetHost,
      port: CONFIG.targetPort,
    });

    let settled = false;
    const finishReject = (error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(error);
    };

    socket.setNoDelay(true);
    socket.setKeepAlive(true, 30000);
    socket.setTimeout(CONFIG.connectTimeoutMs, () => {
      finishReject(new Error(`target connection timed out after ${CONFIG.connectTimeoutMs}ms`));
    });
    socket.once('error', finishReject);
    socket.once('connect', () => {
      if (settled) return;
      settled = true;
      socket.setTimeout(CONFIG.idleTimeoutMs);
      socket.removeListener('error', finishReject);
      resolve(socket);
    });
  });
}

function writeRawUpgrade(req, socket) {
  const key = req.headers['sec-websocket-key'];
  let response =
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n';

  if (validWebSocketKey(key)) {
    response += `Sec-WebSocket-Accept: ${websocketAccept(key)}\r\n`;
  }
  socket.write(`${response}\r\n`);
}

function bridgeRaw(req, client, head, upstream, ip, path) {
  let closed = false;
  const close = (reason, error) => {
    if (closed) return;
    closed = true;
    if (!client.destroyed) client.destroy();
    if (!upstream.destroyed) upstream.destroy();
    releaseConnection(ip);
    log('connection_closed', {
      reason,
      error: error ? String(error.code || error.message || error) : undefined,
    });
  };

  client.setNoDelay(true);
  client.setKeepAlive(true, 30000);
  if (CONFIG.idleTimeoutMs > 0) client.setTimeout(CONFIG.idleTimeoutMs);

  writeRawUpgrade(req, client);

  // `head` contains bytes received after the HTTP headers in the same packet.
  if (head && head.length > 0) upstream.write(head);

  client.pipe(upstream);
  upstream.pipe(client);

  client.on('timeout', () => close('client_idle_timeout'));
  upstream.on('timeout', () => close('target_idle_timeout'));
  client.on('error', (error) => close('client_error', error));
  upstream.on('error', (error) => close('target_error', error));
  client.on('end', () => close('client_end'));
  upstream.on('end', () => close('target_end'));
  client.on('close', () => close('client_close'));
  upstream.on('close', () => close('target_close'));
  log('connection_opened');
}

function sendFrame(socket, opcode, payload = Buffer.alloc(0)) {
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
  header[0] = 0x80 | (opcode & 0x0f);
  return socket.write(Buffer.concat([header, payload]));
}

class FrameParser {
  constructor(handlers) {
    this.buffer = Buffer.alloc(0);
    this.handlers = handlers;
    this.fragmentOpcode = null;
  }

  push(chunk) {
    if (!chunk || chunk.length === 0) return;
    this.buffer = this.buffer.length ? Buffer.concat([this.buffer, chunk]) : Buffer.from(chunk);

    try {
      while (this.buffer.length >= 2) {
        const first = this.buffer[0];
        const second = this.buffer[1];
        const fin = Boolean(first & 0x80);
        const rsv = first & 0x70;
        const opcode = first & 0x0f;
        const masked = Boolean(second & 0x80);
        let length = second & 0x7f;
        let offset = 2;

        if (rsv !== 0) throw new Error('RSV bits are not supported');
        if (!masked) throw new Error('client frames must be masked');
        if (opcode >= 0x8 && !fin) throw new Error('control frames must not be fragmented');

        if (length === 126) {
          if (this.buffer.length < 4) return;
          length = this.buffer.readUInt16BE(2);
          offset = 4;
        } else if (length === 127) {
          if (this.buffer.length < 10) return;
          const bigLength = this.buffer.readBigUInt64BE(2);
          if (bigLength > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('frame is too large');
          length = Number(bigLength);
          offset = 10;
        }

        if (opcode >= 0x8 && length > 125) throw new Error('control frame payload exceeds 125 bytes');
        if (length > CONFIG.maxFrameBytes) throw new Error('frame exceeds MAX_FRAME_BYTES');
        if (this.buffer.length < offset + 4 + length) return;

        const mask = this.buffer.subarray(offset, offset + 4);
        offset += 4;
        const payload = Buffer.from(this.buffer.subarray(offset, offset + length));
        this.buffer = this.buffer.subarray(offset + length);
        for (let i = 0; i < payload.length; i += 1) payload[i] ^= mask[i & 3];

        if (opcode === 0x0) {
          if (this.fragmentOpcode == null) throw new Error('unexpected continuation frame');
          this.handlers.data(payload);
          if (fin) this.fragmentOpcode = null;
        } else if (opcode === 0x1 || opcode === 0x2) {
          if (this.fragmentOpcode != null) throw new Error('new data frame during fragmented message');
          this.handlers.data(payload);
          if (!fin) this.fragmentOpcode = opcode;
        } else if (opcode === 0x8) {
          this.handlers.close(payload);
          return;
        } else if (opcode === 0x9) {
          this.handlers.ping(payload);
        } else if (opcode === 0xA) {
          this.handlers.pong(payload);
        } else {
          throw new Error(`unsupported opcode ${opcode}`);
        }
      }
    } catch (error) {
      this.handlers.error(error);
    }
  }
}

function bridgeFramed(req, client, head, upstream, ip, path) {
  const key = req.headers['sec-websocket-key'];
  const version = req.headers['sec-websocket-version'];
  if (!validWebSocketKey(key) || version !== '13') {
    upstream.destroy();
    releaseConnection(ip);
    httpResponse(client, 400, 'Bad Request');
    return;
  }

  let closed = false;
  let pingTimer;
  const close = (reason, error) => {
    if (closed) return;
    closed = true;
    if (pingTimer) clearInterval(pingTimer);
    if (!client.destroyed) client.destroy();
    if (!upstream.destroyed) upstream.destroy();
    releaseConnection(ip);
    log('connection_closed', {
      reason,
      error: error ? String(error.code || error.message || error) : undefined,
    });
  };

  client.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${websocketAccept(key)}\r\n\r\n`
  );

  client.setNoDelay(true);
  client.setKeepAlive(true, 30000);
  if (CONFIG.idleTimeoutMs > 0) client.setTimeout(CONFIG.idleTimeoutMs);

  const parser = new FrameParser({
    data(payload) {
      if (!upstream.destroyed && !upstream.write(payload)) client.pause();
    },
    ping(payload) {
      if (!client.destroyed) sendFrame(client, 0xA, payload);
    },
    pong() {},
    close(payload) {
      if (!client.destroyed) sendFrame(client, 0x8, payload);
      close('client_close_frame');
    },
    error(error) {
      if (!client.destroyed) sendFrame(client, 0x8, Buffer.from([0x03, 0xEA]));
      close('protocol_error', error);
    },
  });

  client.on('data', (chunk) => parser.push(chunk));
  client.on('drain', () => upstream.resume());
  upstream.on('drain', () => client.resume());
  upstream.on('data', (chunk) => {
    if (!client.destroyed && !sendFrame(client, 0x2, chunk)) upstream.pause();
  });

  client.on('timeout', () => close('client_idle_timeout'));
  upstream.on('timeout', () => close('target_idle_timeout'));
  client.on('error', (error) => close('client_error', error));
  upstream.on('error', (error) => close('target_error', error));
  client.on('end', () => close('client_end'));
  upstream.on('end', () => {
    if (!client.destroyed) sendFrame(client, 0x8);
    close('target_end');
  });
  client.on('close', () => close('client_close'));
  upstream.on('close', () => close('target_close'));

  pingTimer = setInterval(() => {
    if (!client.destroyed) sendFrame(client, 0x9, Buffer.from('keepalive'));
  }, CONFIG.pingIntervalMs);
  pingTimer.unref();

  if (head && head.length > 0) parser.push(head);
  log('connection_opened');
}

const server = http.createServer((req, res) => {
  let requestUrl;
  try {
    requestUrl = new URL(req.url || '/', 'http://localhost');
  } catch {
    res.writeHead(400, {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
      'content-length': '0',
    });
    res.end();
    return;
  }

  if (requestUrl.pathname === '/health') {
    const configured = Boolean(CONFIG.targetHost);
    const body = JSON.stringify({ ok: configured });
    res.writeHead(configured ? 200 : 503, {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'content-length': String(Buffer.byteLength(body)),
    });
    res.end(body);
    return;
  }

  res.writeHead(404, {
    'content-type': 'text/plain; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': '0',
  });
  res.end();
});

server.on('upgrade', async (req, socket, head) => {
  const ip = clientIp(req);
  let requestUrl;

  try {
    requestUrl = new URL(req.url || '/', 'http://relay.local');
  } catch {
    httpResponse(socket, 400, 'Bad Request');
    return;
  }

  const path = requestUrl.pathname;
  log('upgrade_received');

  if (!CONFIG.targetHost) {
    httpResponse(socket, 503, 'Service Unavailable');
    return;
  }
  if (!RAW_PATHS.has(path) && !FRAMED_PATHS.has(path)) {
    httpResponse(socket, 404, 'Not Found');
    return;
  }
  if (!isAuthorized(req, requestUrl)) {
    httpResponse(socket, 401, 'Unauthorized');
    return;
  }
  if (!reserveConnection(ip)) {
    httpResponse(socket, 429, 'Too Many Requests');
    return;
  }

  let upstream;
  try {
    upstream = await connectTarget();
  } catch (error) {
    releaseConnection(ip);
    log('upstream_error', {
      error: String(error.code || error.message || error),
    });
    httpResponse(socket, 502, 'Bad Gateway');
    return;
  }

  // The client may disconnect while the relay is establishing the target TCP connection.
  if (socket.destroyed) {
    upstream.destroy();
    releaseConnection(ip);
    return;
  }

  if (RAW_PATHS.has(path)) bridgeRaw(req, socket, head, upstream, ip, path);
  else bridgeFramed(req, socket, head, upstream, ip, path);
});

server.on('clientError', (error, socket) => {
  log('client_http_error', { error: error.message });
  httpResponse(socket, 400, 'Bad HTTP request');
});

server.on('error', (error) => {
  log('server_error', { error: error.stack || error.message });
  process.exitCode = 1;
});

server.listen(CONFIG.listenPort, '0.0.0.0', () => {
  log('listening', { port: CONFIG.listenPort });
});

function shutdown(signal) {
  log('shutdown', { signal });
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
