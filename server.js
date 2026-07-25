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

function envBool(name, fallback) {
  const raw = process.env[name];
  if (raw == null || raw === '') return fallback;
  if (/^(1|true|yes|on)$/i.test(raw)) return true;
  if (/^(0|false|no|off)$/i.test(raw)) return false;
  throw new Error(`${name} must be true or false`);
}

const MODE = String(process.env.ORIGIN_MODE || 'ws').trim().toLowerCase();
if (!['ws', 'ssh'].includes(MODE)) {
  throw new Error('ORIGIN_MODE must be ws or ssh');
}

const CONFIG = Object.freeze({
  port: envInt('PORT', 3000, 1, 65535),
  mode: MODE,
  targetHost: String(process.env.TARGET_HOST || '').trim(),
  targetPort: envInt('TARGET_PORT', MODE === 'ws' ? 80 : 550, 1, 65535),
  relayToken: String(process.env.RELAY_TOKEN || ''),
  connectTimeoutMs: envInt('CONNECT_TIMEOUT_MS', 10000, 1000, 120000),
  idleTimeoutMs: envInt('IDLE_TIMEOUT_MS', 0, 0, 86400000),
  maxConnectionsPerIp: envInt('MAX_CONNECTIONS_PER_IP', 8, 1, 1000),
  originPath: String(process.env.ORIGIN_PATH || '').trim(),
  originHostHeader: String(process.env.ORIGIN_HOST_HEADER || '').trim(),
  originXRealHost: String(process.env.ORIGIN_X_REAL_HOST || '127.0.0.1:550').trim(),
  injectWsHeaders: envBool('INJECT_WS_HEADERS', true),
  maxOriginHeaderBytes: envInt('MAX_ORIGIN_HEADER_BYTES', 65536, 4096, 1048576),
});

const PATHS = new Set(['/', '/ssh', '/ssh-ws', '/ws']);
const activeByIp = new Map();

function log(event, details = {}) {
  process.stdout.write(`${JSON.stringify({ time: new Date().toISOString(), event, ...details })}\n`);
}

function clientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) return forwarded.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

function reserve(ip) {
  const count = activeByIp.get(ip) || 0;
  if (count >= CONFIG.maxConnectionsPerIp) return false;
  activeByIp.set(ip, count + 1);
  return true;
}

function release(ip) {
  const count = activeByIp.get(ip) || 0;
  if (count <= 1) activeByIp.delete(ip);
  else activeByIp.set(ip, count - 1);
}

function isAuthorized(req, url) {
  if (!CONFIG.relayToken) return true;
  return url.searchParams.get('token') === CONFIG.relayToken ||
    req.headers['x-relay-token'] === CONFIG.relayToken;
}

function httpResponse(socket, statusCode, body, extraHeaders = {}) {
  if (socket.destroyed) return;
  const payload = Buffer.from(`${body}\n`, 'utf8');
  const headers = {
    Connection: 'close',
    'Content-Type': 'text/plain; charset=utf-8',
    'Content-Length': String(payload.length),
    'Cache-Control': 'no-store',
    'X-Relay-Version': '4.0.0',
    ...extraHeaders,
  };
  const lines = [`HTTP/1.1 ${statusCode} ${http.STATUS_CODES[statusCode] || 'Error'}`];
  for (const [name, value] of Object.entries(headers)) lines.push(`${name}: ${value}`);
  socket.end(`${lines.join('\r\n')}\r\n\r\n${payload.toString('utf8')}`);
}

function headerHasToken(value, expected) {
  if (typeof value !== 'string') return false;
  return value.split(',').some((part) => part.trim().toLowerCase() === expected);
}

function validWebSocketKey(key) {
  if (typeof key !== 'string') return false;
  try { return Buffer.from(key, 'base64').length === 16; } catch { return false; }
}

function websocketAccept(key) {
  return crypto.createHash('sha1')
    .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
    .digest('base64');
}

function validateUpgrade(req) {
  if (req.method !== 'GET') return 'GET is required';
  if (String(req.headers.upgrade || '').toLowerCase() !== 'websocket') {
    return 'Upgrade: websocket is required';
  }
  if (!headerHasToken(req.headers.connection, 'upgrade')) {
    return 'Connection: Upgrade is required';
  }
  return null;
}

function connectTcp(host, port) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port });
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

function sanitizeOriginPath(reqUrl) {
  if (!CONFIG.originPath) return reqUrl.pathname + reqUrl.search;
  if (!CONFIG.originPath.startsWith('/')) return `/${CONFIG.originPath}`;
  return CONFIG.originPath;
}

function buildOriginRequest(req, reqUrl) {
  const path = sanitizeOriginPath(reqUrl);
  const headers = new Map();

  // Preserve client headers but drop Railway/internal routing metadata and the
  // public relay token before forwarding to the VPS WebSocket service.
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    const name = req.rawHeaders[i];
    const value = req.rawHeaders[i + 1];
    const lower = name.toLowerCase();
    if (lower === 'host' || lower === 'x-relay-token') continue;
    if (lower.startsWith('x-railway-')) continue;
    if (lower === 'x-forwarded-for' || lower === 'x-forwarded-host' || lower === 'x-forwarded-proto') continue;
    headers.set(lower, { name, value });
  }

  const originHost = CONFIG.originHostHeader || CONFIG.targetHost;
  headers.set('host', { name: 'Host', value: originHost });
  headers.set('upgrade', { name: 'Upgrade', value: 'websocket' });
  headers.set('connection', { name: 'Connection', value: 'Upgrade' });

  if (CONFIG.injectWsHeaders) {
    if (!validWebSocketKey(req.headers['sec-websocket-key'])) {
      headers.set('sec-websocket-key', {
        name: 'Sec-WebSocket-Key',
        value: crypto.randomBytes(16).toString('base64'),
      });
    }
    if (req.headers['sec-websocket-version'] !== '13') {
      headers.set('sec-websocket-version', { name: 'Sec-WebSocket-Version', value: '13' });
    }
  }

  if (CONFIG.originXRealHost) {
    headers.set('x-real-host', { name: 'X-Real-Host', value: CONFIG.originXRealHost });
  }

  const lines = [`GET ${path} HTTP/1.1`];
  for (const { name, value } of headers.values()) lines.push(`${name}: ${value}`);
  return Buffer.from(`${lines.join('\r\n')}\r\n\r\n`, 'utf8');
}

function bridgeSockets(client, upstream, ip, metadata) {
  let closed = false;
  const close = (reason, error) => {
    if (closed) return;
    closed = true;
    if (!client.destroyed) client.destroy();
    if (!upstream.destroyed) upstream.destroy();
    release(ip);
    log('tunnel_closed', {
      ...metadata,
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

async function proxyToWebSocketOrigin(req, reqUrl, client, head, ip) {
  let upstream;
  try {
    upstream = await connectTcp(CONFIG.targetHost, CONFIG.targetPort);
  } catch (error) {
    release(ip);
    log('origin_connect_error', {
      ip,
      mode: 'ws',
      target: `${CONFIG.targetHost}:${CONFIG.targetPort}`,
      error: String(error.code || error.message || error),
    });
    httpResponse(client, 502, `Cannot connect to WebSocket origin ${CONFIG.targetHost}:${CONFIG.targetPort}`);
    return;
  }

  if (client.destroyed) {
    upstream.destroy();
    release(ip);
    return;
  }

  const originRequest = buildOriginRequest(req, reqUrl);
  upstream.write(originRequest);
  if (head && head.length) upstream.write(head);

  let responseBuffer = Buffer.alloc(0);
  let completed = false;

  const fail = (status, message) => {
    if (completed) return;
    completed = true;
    upstream.destroy();
    release(ip);
    httpResponse(client, status, message);
  };

  const onErrorBeforeHandshake = (error) => {
    log('origin_handshake_error', {
      ip,
      target: `${CONFIG.targetHost}:${CONFIG.targetPort}`,
      error: String(error.code || error.message || error),
    });
    fail(502, 'WebSocket origin closed before returning 101');
  };

  upstream.once('error', onErrorBeforeHandshake);
  upstream.once('close', () => {
    if (!completed) fail(502, 'WebSocket origin closed before returning 101');
  });

  upstream.on('data', function onHandshakeData(chunk) {
    if (completed) return;
    responseBuffer = Buffer.concat([responseBuffer, chunk]);
    if (responseBuffer.length > CONFIG.maxOriginHeaderBytes) {
      fail(502, 'WebSocket origin response headers are too large');
      return;
    }

    const headerEnd = responseBuffer.indexOf('\r\n\r\n');
    if (headerEnd < 0) return;

    const headerBlock = responseBuffer.subarray(0, headerEnd + 4);
    const remainder = responseBuffer.subarray(headerEnd + 4);
    const statusLine = headerBlock.toString('latin1').split('\r\n', 1)[0];
    const match = /^HTTP\/1\.[01]\s+(\d{3})\b/.exec(statusLine);
    const statusCode = match ? Number(match[1]) : 0;

    completed = true;
    upstream.removeListener('data', onHandshakeData);
    upstream.removeListener('error', onErrorBeforeHandshake);

    // Preserve the origin response exactly. PDirect should return 101.
    client.write(headerBlock);
    if (remainder.length) client.write(remainder);

    if (statusCode !== 101) {
      log('origin_rejected_upgrade', {
        ip,
        statusCode,
        statusLine,
        target: `${CONFIG.targetHost}:${CONFIG.targetPort}`,
      });
      client.end();
      upstream.destroy();
      release(ip);
      return;
    }

    log('tunnel_connected', {
      ip,
      mode: 'ws-origin',
      publicPath: reqUrl.pathname,
      originPath: sanitizeOriginPath(reqUrl),
      target: `${CONFIG.targetHost}:${CONFIG.targetPort}`,
      xRealHost: CONFIG.originXRealHost || null,
    });

    bridgeSockets(client, upstream, ip, {
      mode: 'ws-origin',
      target: `${CONFIG.targetHost}:${CONFIG.targetPort}`,
    });
  });
}

async function proxyDirectToSsh(req, client, head, ip) {
  let upstream;
  try {
    upstream = await connectTcp(CONFIG.targetHost, CONFIG.targetPort);
  } catch (error) {
    release(ip);
    httpResponse(client, 502, `Cannot connect to SSH backend ${CONFIG.targetHost}:${CONFIG.targetPort}`);
    return;
  }

  if (client.destroyed) {
    upstream.destroy();
    release(ip);
    return;
  }

  const key = req.headers['sec-websocket-key'];
  let response =
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    'X-Relay-Version: 4.0.0\r\n' +
    'X-Relay-Mode: direct-ssh\r\n';
  if (validWebSocketKey(key)) response += `Sec-WebSocket-Accept: ${websocketAccept(key)}\r\n`;
  client.write(`${response}\r\n`);
  if (head && head.length) upstream.write(head);

  log('tunnel_connected', {
    ip,
    mode: 'direct-ssh',
    target: `${CONFIG.targetHost}:${CONFIG.targetPort}`,
  });
  bridgeSockets(client, upstream, ip, {
    mode: 'direct-ssh',
    target: `${CONFIG.targetHost}:${CONFIG.targetPort}`,
  });
}

async function checkWsOrigin() {
  const socket = await connectTcp(CONFIG.targetHost, CONFIG.targetPort);
  const key = crypto.randomBytes(16).toString('base64');
  const host = CONFIG.originHostHeader || CONFIG.targetHost;
  const path = CONFIG.originPath || '/';
  const lines = [
    `GET ${path} HTTP/1.1`,
    `Host: ${host}`,
    'Upgrade: websocket',
    'Connection: Upgrade',
    'Sec-WebSocket-Version: 13',
    `Sec-WebSocket-Key: ${key}`,
  ];
  if (CONFIG.originXRealHost) lines.push(`X-Real-Host: ${CONFIG.originXRealHost}`);
  socket.write(`${lines.join('\r\n')}\r\n\r\n`);

  return await new Promise((resolve) => {
    let buffer = Buffer.alloc(0);
    const started = Date.now();
    const timer = setTimeout(() => {
      socket.destroy();
      resolve({ ok: false, error: 'origin handshake timeout' });
    }, Math.min(CONFIG.connectTimeoutMs, 10000));

    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      const end = buffer.indexOf('\r\n\r\n');
      if (end < 0) return;
      clearTimeout(timer);
      const headers = buffer.subarray(0, end).toString('latin1');
      const rest = buffer.subarray(end + 4);
      const statusLine = headers.split('\r\n')[0];
      const statusCode = Number((/^HTTP\/1\.[01]\s+(\d{3})/.exec(statusLine) || [])[1] || 0);
      const banner = rest.subarray(0, 256).toString('utf8').replace(/[\r\n]+$/g, '');
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

async function checkSshOrigin() {
  const socket = await connectTcp(CONFIG.targetHost, CONFIG.targetPort);
  return await new Promise((resolve) => {
    const started = Date.now();
    const timer = setTimeout(() => {
      socket.destroy();
      resolve({ ok: true, reachable: true, banner: null, looksLikeSsh: false, elapsedMs: Date.now() - started });
    }, 3000);
    socket.once('data', (chunk) => {
      clearTimeout(timer);
      const banner = chunk.subarray(0, 256).toString('utf8').replace(/[\r\n]+$/g, '');
      socket.destroy();
      resolve({ ok: true, reachable: true, banner, looksLikeSsh: banner.startsWith('SSH-'), elapsedMs: Date.now() - started });
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
      'x-relay-version': '4.0.0',
    });
    res.end(JSON.stringify({
      ok: Boolean(CONFIG.targetHost),
      service: 'railway-ssh-ws-relay',
      version: '4.0.0',
      mode: CONFIG.mode,
      target: CONFIG.targetHost ? `${CONFIG.targetHost}:${CONFIG.targetPort}` : null,
      originPath: CONFIG.originPath || '(preserve viewer path)',
      originHostHeader: CONFIG.originHostHeader || CONFIG.targetHost || null,
      originXRealHost: CONFIG.originXRealHost || null,
      activeConnections: [...activeByIp.values()].reduce((a, b) => a + b, 0),
    }));
    return;
  }

  if (url.pathname === '/check-target') {
    if (!isAuthorized(req, url)) {
      res.writeHead(401, { 'content-type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ ok: false, error: 'Invalid relay token' }));
      return;
    }
    if (!CONFIG.targetHost) {
      res.writeHead(503, { 'content-type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ ok: false, error: 'TARGET_HOST is not configured' }));
      return;
    }
    let result;
    try {
      result = CONFIG.mode === 'ws' ? await checkWsOrigin() : await checkSshOrigin();
    } catch (error) {
      result = { ok: false, error: String(error.code || error.message || error) };
    }
    res.writeHead(result.ok ? 200 : 502, {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
    });
    res.end(JSON.stringify({
      ...result,
      mode: CONFIG.mode,
      target: `${CONFIG.targetHost}:${CONFIG.targetPort}`,
    }));
    return;
  }

  if (PATHS.has(url.pathname)) {
    res.writeHead(426, {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
      upgrade: 'websocket',
    });
    res.end('WebSocket upgrade required.\n');
    return;
  }

  res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
  res.end('Railway SSH-over-WS relay v4.0\nUse /ssh with a WebSocket upgrade.\n');
});

server.on('upgrade', async (req, socket, head) => {
  let url;
  try { url = new URL(req.url || '/', 'http://relay.local'); }
  catch { httpResponse(socket, 400, 'Invalid URL'); return; }

  const ip = clientIp(req);
  const validationError = validateUpgrade(req);
  if (validationError) {
    httpResponse(socket, 400, validationError);
    return;
  }
  if (!PATHS.has(url.pathname)) {
    httpResponse(socket, 404, 'Unknown tunnel path; use /ssh');
    return;
  }
  if (!isAuthorized(req, url)) {
    httpResponse(socket, 401, 'Invalid relay token');
    return;
  }
  if (!CONFIG.targetHost) {
    httpResponse(socket, 503, 'TARGET_HOST is not configured');
    return;
  }
  if (!reserve(ip)) {
    httpResponse(socket, 429, 'Too many active connections');
    return;
  }

  log('upgrade_received', {
    ip,
    mode: CONFIG.mode,
    path: url.pathname,
    host: req.headers.host || '',
    forwardedProto: req.headers['x-forwarded-proto'] || '',
    hasWebSocketKey: validWebSocketKey(req.headers['sec-websocket-key']),
    target: `${CONFIG.targetHost}:${CONFIG.targetPort}`,
  });

  if (CONFIG.mode === 'ws') await proxyToWebSocketOrigin(req, url, socket, head, ip);
  else await proxyDirectToSsh(req, socket, head, ip);
});

server.on('clientError', (error, socket) => {
  log('client_http_error', { error: error.message });
  httpResponse(socket, 400, 'Bad HTTP request');
});

server.on('error', (error) => {
  log('server_error', { error: error.stack || error.message });
  process.exitCode = 1;
});

server.listen(CONFIG.port, '0.0.0.0', () => {
  log('listening', {
    port: CONFIG.port,
    mode: CONFIG.mode,
    target: CONFIG.targetHost ? `${CONFIG.targetHost}:${CONFIG.targetPort}` : null,
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
