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
  port: envInt('PORT', 3000, 1, 65535),
  targetHost: String(process.env.TARGET_HOST || '').trim(),
  targetPort: envInt('TARGET_PORT', 80, 1, 65535),
  relayToken: String(process.env.RELAY_TOKEN || ''),
  originPath: String(process.env.ORIGIN_PATH || '/').trim() || '/',
  originHost: String(process.env.ORIGIN_HOST_HEADER || process.env.TARGET_HOST || '').trim(),
  xRealHost: String(process.env.ORIGIN_X_REAL_HOST || '127.0.0.1:550').trim(),
  connectTimeoutMs: envInt('CONNECT_TIMEOUT_MS', 10000, 1000, 120000),
  idleTimeoutMs: envInt('IDLE_TIMEOUT_MS', 0, 0, 86400000),
  maxConnectionsPerIp: envInt('MAX_CONNECTIONS_PER_IP', 8, 1, 1000),
  maxHeaderBytes: envInt('MAX_ORIGIN_HEADER_BYTES', 65536, 4096, 1048576),
});

const VERSION = '4.1.0';
const TUNNEL_PATHS = new Set(['/', '/ssh', '/ssh-ws', '/ws']);
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

function reserve(ip) {
  const current = activeByIp.get(ip) || 0;
  if (current >= CONFIG.maxConnectionsPerIp) return false;
  activeByIp.set(ip, current + 1);
  return true;
}

function release(ip) {
  const current = activeByIp.get(ip) || 0;
  if (current <= 1) activeByIp.delete(ip);
  else activeByIp.set(ip, current - 1);
}

function headerContains(value, token) {
  return typeof value === 'string' && value
    .split(',')
    .some((part) => part.trim().toLowerCase() === token);
}

function validWebSocketKey(key) {
  if (typeof key !== 'string') return false;
  try {
    return Buffer.from(key, 'base64').length === 16;
  } catch {
    return false;
  }
}

function websocketAccept(key) {
  return crypto
    .createHash('sha1')
    .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
    .digest('base64');
}

function authorized(req, url) {
  if (!CONFIG.relayToken) return true;
  return url.searchParams.get('token') === CONFIG.relayToken ||
    req.headers['x-relay-token'] === CONFIG.relayToken;
}

function writeHttpError(socket, statusCode, message) {
  if (socket.destroyed) return;
  const body = Buffer.from(`${message}\n`);
  socket.end(
    `HTTP/1.1 ${statusCode} ${http.STATUS_CODES[statusCode] || 'Error'}\r\n` +
    'Connection: close\r\n' +
    'Content-Type: text/plain; charset=utf-8\r\n' +
    `Content-Length: ${body.length}\r\n` +
    'Cache-Control: no-store\r\n' +
    `X-Relay-Version: ${VERSION}\r\n\r\n` +
    body.toString('utf8')
  );
}

function connectTarget() {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: CONFIG.targetHost, port: CONFIG.targetPort });
    let settled = false;

    const fail = (error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(error);
    };

    socket.setNoDelay(true);
    socket.setKeepAlive(true, 30000);
    socket.setTimeout(CONFIG.connectTimeoutMs, () => fail(new Error('connect timeout')));
    socket.once('error', fail);
    socket.once('connect', () => {
      if (settled) return;
      settled = true;
      socket.removeListener('error', fail);
      socket.setTimeout(CONFIG.idleTimeoutMs);
      resolve(socket);
    });
  });
}

function buildOriginHandshake() {
  const path = CONFIG.originPath.startsWith('/') ? CONFIG.originPath : `/${CONFIG.originPath}`;
  const host = CONFIG.originHost || CONFIG.targetHost;
  const lines = [
    `GET ${path} HTTP/1.1`,
    `Host: ${host}`,
    'Upgrade: websocket',
    'Connection: Upgrade',
  ];
  if (CONFIG.xRealHost) lines.push(`X-Real-Host: ${CONFIG.xRealHost}`);
  return Buffer.from(`${lines.join('\r\n')}\r\n\r\n`, 'utf8');
}

function buildClient101(req) {
  const lines = [
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `X-Relay-Version: ${VERSION}`,
    'X-Relay-Mode: pdirect-origin',
  ];

  const key = req.headers['sec-websocket-key'];
  if (validWebSocketKey(key)) {
    lines.push(`Sec-WebSocket-Accept: ${websocketAccept(key)}`);
  }

  return Buffer.from(`${lines.join('\r\n')}\r\n\r\n`, 'utf8');
}

function bridge(client, upstream, ip) {
  let finished = false;

  const close = (reason, error) => {
    if (finished) return;
    finished = true;
    release(ip);
    if (!client.destroyed) client.destroy();
    if (!upstream.destroyed) upstream.destroy();
    log('tunnel_closed', {
      ip,
      reason,
      error: error ? String(error.code || error.message || error) : undefined,
    });
  };

  client.setNoDelay(true);
  client.setKeepAlive(true, 30000);
  if (CONFIG.idleTimeoutMs > 0) client.setTimeout(CONFIG.idleTimeoutMs);

  client.pipe(upstream);
  upstream.pipe(client);

  client.on('timeout', () => close('client_timeout'));
  upstream.on('timeout', () => close('origin_timeout'));
  client.on('error', (error) => close('client_error', error));
  upstream.on('error', (error) => close('origin_error', error));
  client.on('end', () => close('client_end'));
  upstream.on('end', () => close('origin_end'));
  client.on('close', () => close('client_close'));
  upstream.on('close', () => close('origin_close'));
}

async function openTunnel(req, client, head, ip) {
  let upstream;
  try {
    upstream = await connectTarget();
  } catch (error) {
    release(ip);
    log('origin_connect_error', {
      ip,
      target: `${CONFIG.targetHost}:${CONFIG.targetPort}`,
      error: String(error.code || error.message || error),
    });
    writeHttpError(client, 502, `Cannot connect to ${CONFIG.targetHost}:${CONFIG.targetPort}`);
    return;
  }

  if (client.destroyed) {
    upstream.destroy();
    release(ip);
    return;
  }

  upstream.write(buildOriginHandshake());

  let buffer = Buffer.alloc(0);
  let completed = false;

  const fail = (message, error) => {
    if (completed) return;
    completed = true;
    upstream.destroy();
    release(ip);
    log('origin_handshake_failed', {
      ip,
      target: `${CONFIG.targetHost}:${CONFIG.targetPort}`,
      message,
      error: error ? String(error.code || error.message || error) : undefined,
    });
    writeHttpError(client, 502, message);
  };

  const handshakeTimer = setTimeout(
    () => fail('PDirect did not return 101 before timeout'),
    CONFIG.connectTimeoutMs
  );

  const beforeHandshakeError = (error) => fail('PDirect connection failed before 101', error);
  upstream.once('error', beforeHandshakeError);
  upstream.once('end', () => fail('PDirect closed before returning 101'));
  upstream.once('close', () => fail('PDirect closed before returning 101'));

  function onData(chunk) {
    if (completed) return;
    buffer = Buffer.concat([buffer, chunk]);

    if (buffer.length > CONFIG.maxHeaderBytes) {
      fail('PDirect response headers are too large');
      return;
    }

    const headerEnd = buffer.indexOf('\r\n\r\n');
    if (headerEnd < 0) return;

    const headerText = buffer.subarray(0, headerEnd).toString('latin1');
    const statusLine = headerText.split('\r\n')[0] || '';
    const match = /^HTTP\/1\.[01]\s+(\d{3})\b/.exec(statusLine);
    const statusCode = match ? Number(match[1]) : 0;
    const remainder = buffer.subarray(headerEnd + 4);

    if (statusCode !== 101) {
      fail(`PDirect returned ${statusLine || 'an invalid response'} instead of 101`);
      return;
    }

    completed = true;
    clearTimeout(handshakeTimer);
    upstream.removeListener('data', onData);
    upstream.removeListener('error', beforeHandshakeError);
    upstream.removeAllListeners('end');
    upstream.removeAllListeners('close');

    // Generate a clean viewer-side 101. Do not copy PDirect's response because
    // legacy PDirect usually omits Sec-WebSocket-Accept.
    client.write(buildClient101(req));

    // Bytes after PDirect's headers may already contain the SSH banner.
    if (remainder.length) client.write(remainder);

    // Node may already have parsed bytes sent immediately after the viewer's
    // HTTP headers. Forward them only after the origin handshake succeeded.
    if (head && head.length) upstream.write(head);

    log('tunnel_connected', {
      ip,
      target: `${CONFIG.targetHost}:${CONFIG.targetPort}`,
      originPath: CONFIG.originPath,
      xRealHost: CONFIG.xRealHost || null,
      viewerProto: req.headers['x-forwarded-proto'] || 'direct',
      viewerHasKey: validWebSocketKey(req.headers['sec-websocket-key']),
    });

    bridge(client, upstream, ip);
  }

  upstream.on('data', onData);
}

async function checkTarget() {
  let socket;
  try {
    socket = await connectTarget();
  } catch (error) {
    return { ok: false, error: String(error.code || error.message || error) };
  }

  socket.write(buildOriginHandshake());
  return await new Promise((resolve) => {
    let buffer = Buffer.alloc(0);
    const started = Date.now();
    const timer = setTimeout(() => {
      socket.destroy();
      resolve({ ok: false, error: 'PDirect handshake timeout' });
    }, CONFIG.connectTimeoutMs);

    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      const end = buffer.indexOf('\r\n\r\n');
      if (end < 0) return;

      clearTimeout(timer);
      const headerText = buffer.subarray(0, end).toString('latin1');
      const statusLine = headerText.split('\r\n')[0] || '';
      const match = /^HTTP\/1\.[01]\s+(\d{3})\b/.exec(statusLine);
      const statusCode = match ? Number(match[1]) : 0;
      const banner = buffer.subarray(end + 4, end + 260).toString('utf8').replace(/[\r\n]+$/g, '');
      socket.destroy();
      resolve({
        ok: statusCode === 101,
        statusCode,
        statusLine,
        banner: banner || null,
        looksLikeSsh: banner.startsWith('SSH-'),
        elapsedMs: Date.now() - started,
      });
    });

    socket.once('error', (error) => {
      clearTimeout(timer);
      resolve({ ok: false, error: String(error.code || error.message || error) });
    });
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || '/', 'http://relay.local');

  if (url.pathname === '/health') {
    res.writeHead(CONFIG.targetHost ? 200 : 503, {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-relay-version': VERSION,
    });
    res.end(JSON.stringify({
      ok: Boolean(CONFIG.targetHost),
      service: 'railway-ssh-ws-relay',
      version: VERSION,
      target: CONFIG.targetHost ? `${CONFIG.targetHost}:${CONFIG.targetPort}` : null,
      originPath: CONFIG.originPath,
      originHost: CONFIG.originHost || null,
      originXRealHost: CONFIG.xRealHost || null,
      activeConnections: [...activeByIp.values()].reduce((sum, value) => sum + value, 0),
    }));
    return;
  }

  if (url.pathname === '/check-target') {
    if (!authorized(req, url)) {
      res.writeHead(401, { 'content-type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ ok: false, error: 'Invalid relay token' }));
      return;
    }
    const result = CONFIG.targetHost
      ? await checkTarget()
      : { ok: false, error: 'TARGET_HOST is not configured' };
    res.writeHead(result.ok ? 200 : 502, {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
    });
    res.end(JSON.stringify({
      ...result,
      target: CONFIG.targetHost ? `${CONFIG.targetHost}:${CONFIG.targetPort}` : null,
    }));
    return;
  }

  if (TUNNEL_PATHS.has(url.pathname)) {
    res.writeHead(426, {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
      upgrade: 'websocket',
      'x-relay-version': VERSION,
    });
    res.end('WebSocket upgrade required.\n');
    return;
  }

  res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
  res.end('Not found.\n');
});

server.on('upgrade', async (req, socket, head) => {
  let url;
  try {
    url = new URL(req.url || '/', 'http://relay.local');
  } catch {
    writeHttpError(socket, 400, 'Invalid URL');
    return;
  }

  if (req.method !== 'GET') {
    writeHttpError(socket, 400, 'GET is required');
    return;
  }
  if (String(req.headers.upgrade || '').toLowerCase() !== 'websocket') {
    writeHttpError(socket, 400, 'Upgrade: websocket is required');
    return;
  }
  if (!headerContains(req.headers.connection, 'upgrade')) {
    writeHttpError(socket, 400, 'Connection: Upgrade is required');
    return;
  }
  if (!TUNNEL_PATHS.has(url.pathname)) {
    writeHttpError(socket, 404, 'Unknown tunnel path; use /ssh');
    return;
  }
  if (!authorized(req, url)) {
    writeHttpError(socket, 401, 'Invalid relay token');
    return;
  }
  if (!CONFIG.targetHost) {
    writeHttpError(socket, 503, 'TARGET_HOST is not configured');
    return;
  }

  const ip = clientIp(req);
  if (!reserve(ip)) {
    writeHttpError(socket, 429, 'Too many active connections');
    return;
  }

  log('upgrade_received', {
    ip,
    path: url.pathname,
    host: req.headers.host || '',
    viewerProto: req.headers['x-forwarded-proto'] || 'direct',
    viewerHasKey: validWebSocketKey(req.headers['sec-websocket-key']),
    target: `${CONFIG.targetHost}:${CONFIG.targetPort}`,
  });

  await openTunnel(req, socket, head, ip);
});

server.on('clientError', (error, socket) => {
  log('client_http_error', { error: error.message });
  writeHttpError(socket, 400, 'Bad HTTP request');
});

server.on('error', (error) => {
  log('server_error', { error: error.stack || error.message });
  process.exitCode = 1;
});

server.listen(CONFIG.port, '0.0.0.0', () => {
  log('listening', {
    port: CONFIG.port,
    target: CONFIG.targetHost ? `${CONFIG.targetHost}:${CONFIG.targetPort}` : null,
    originPath: CONFIG.originPath,
    tokenRequired: Boolean(CONFIG.relayToken),
  });
});

function shutdown(signal) {
  log('shutdown', { signal });
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
