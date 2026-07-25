'use strict';

const net = require('net');
const http = require('http');
const { spawn } = require('child_process');
const path = require('path');

const TIMEOUT = 7000;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });
}

async function startRelay(env) {
  const child = spawn(process.execPath, [path.join(__dirname, 'server.js')], {
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  child.stdout.on('data', (d) => { output += d; });
  child.stderr.on('data', (d) => { output += d; });
  for (let i = 0; i < 100; i += 1) {
    if (child.exitCode != null) throw new Error(`relay exited\n${output}`);
    if (output.includes('"event":"listening"')) return { child, output: () => output };
    await sleep(30);
  }
  child.kill('SIGKILL');
  throw new Error(`relay did not start\n${output}`);
}

function tunnelTest(port, payload, expectedBanner) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port });
    let buffer = Buffer.alloc(0);
    let phase = 0;
    const timer = setTimeout(() => finish(new Error('tunnel test timeout')), TIMEOUT);
    const finish = (error) => {
      clearTimeout(timer);
      socket.destroy();
      error ? reject(error) : resolve();
    };
    socket.once('error', finish);
    socket.once('connect', () => socket.write(payload));
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      try {
        if (phase === 0) {
          const end = buffer.indexOf('\r\n\r\n');
          if (end < 0) return;
          const headers = buffer.subarray(0, end).toString('latin1');
          if (!headers.startsWith('HTTP/1.1 101')) throw new Error(`expected 101, got ${headers}`);
          buffer = buffer.subarray(end + 4);
          phase = 1;
        }
        if (phase === 1 && buffer.includes(Buffer.from(expectedBanner))) {
          buffer = Buffer.alloc(0);
          phase = 2;
          socket.write('SSH-2.0-HTTPInjector_Test\r\n');
          return;
        }
        if (phase === 2 && buffer.includes(Buffer.from('SSH-2.0-HTTPInjector_Test'))) finish();
      } catch (error) { finish(error); }
    });
  });
}

function getJson(port, route) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: '127.0.0.1', port, path: route }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { body += c; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(body) }); }
        catch (error) { reject(error); }
      });
    });
    req.once('error', reject);
    req.setTimeout(TIMEOUT, () => req.destroy(new Error('HTTP timeout')));
  });
}

(async () => {
  // Mock existing PDirect/WebSocket service on VPS port 80.
  let sawInjectedKey = false;
  let sawXRealHost = false;
  const pdirect = net.createServer((socket) => {
    let buffer = Buffer.alloc(0);
    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      const end = buffer.indexOf('\r\n\r\n');
      if (end < 0) return;
      socket.removeListener('data', onData);
      const headers = buffer.subarray(0, end).toString('latin1');
      sawInjectedKey = /Sec-WebSocket-Key:/i.test(headers);
      sawXRealHost = /X-Real-Host:\s*127\.0\.0\.1:550/i.test(headers);
      const rest = buffer.subarray(end + 4);
      socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
      socket.write('SSH-2.0-Dropbear_PDirect_Test\r\n');
      if (rest.length) socket.write(rest);
      socket.on('data', (data) => socket.write(data));
    };
    socket.on('data', onData);
  });
  await new Promise((resolve, reject) => {
    pdirect.once('error', reject);
    pdirect.listen(0, '127.0.0.1', resolve);
  });

  const relayPort = await freePort();
  const relay = await startRelay({
    PORT: String(relayPort),
    ORIGIN_MODE: 'ws',
    TARGET_HOST: '127.0.0.1',
    TARGET_PORT: String(pdirect.address().port),
    RELAY_TOKEN: 'test-secret',
    ORIGIN_X_REAL_HOST: '127.0.0.1:550',
  });

  try {
    const minimal =
      'GET /ssh?token=test-secret HTTP/1.1\r\n' +
      'Host: app.up.railway.app\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n\r\n';
    await tunnelTest(relayPort, minimal, 'SSH-2.0-Dropbear_PDirect_Test');
    if (!sawInjectedKey) throw new Error('relay did not inject RFC WebSocket headers toward PDirect');
    if (!sawXRealHost) throw new Error('relay did not send X-Real-Host');
    console.log('PASS exact minimal HTTP Injector payload -> Railway relay -> PDirect WS origin -> SSH banner');

    const full =
      'GET /ssh?token=test-secret HTTP/1.1\r\n' +
      'Host: app.up.railway.app\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      'Sec-WebSocket-Version: 13\r\n' +
      'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n';
    await tunnelTest(relayPort, full, 'SSH-2.0-Dropbear_PDirect_Test');
    console.log('PASS full RFC handshake -> PDirect WS origin -> bidirectional raw SSH');

    const check = await getJson(relayPort, '/check-target?token=test-secret');
    if (check.status !== 200 || check.body.statusCode !== 101) {
      throw new Error(`check-target failed: ${JSON.stringify(check)}`);
    }
    console.log('PASS /check-target verifies the VPS WebSocket port returns 101');
  } finally {
    relay.child.kill('SIGTERM');
    await new Promise((resolve) => pdirect.close(resolve));
  }

  // Optional direct-to-Dropbear mode.
  const ssh = net.createServer((socket) => {
    socket.write('SSH-2.0-Dropbear_Direct_Test\r\n');
    socket.on('data', (data) => socket.write(data));
  });
  await new Promise((resolve, reject) => {
    ssh.once('error', reject);
    ssh.listen(0, '127.0.0.1', resolve);
  });
  const relayPort2 = await freePort();
  const relay2 = await startRelay({
    PORT: String(relayPort2),
    ORIGIN_MODE: 'ssh',
    TARGET_HOST: '127.0.0.1',
    TARGET_PORT: String(ssh.address().port),
    RELAY_TOKEN: 'test-secret',
  });
  try {
    const full =
      'GET /ssh?token=test-secret HTTP/1.1\r\n' +
      'Host: app.up.railway.app\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      'Sec-WebSocket-Version: 13\r\n' +
      'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n';
    await tunnelTest(relayPort2, full, 'SSH-2.0-Dropbear_Direct_Test');
    console.log('PASS optional direct SSH mode -> Dropbear backend');
  } finally {
    relay2.child.kill('SIGTERM');
    await new Promise((resolve) => ssh.close(resolve));
  }

  console.log('ALL TESTS PASSED');
})().catch((error) => {
  console.error(`FAIL: ${error.stack || error.message}`);
  process.exitCode = 1;
});
