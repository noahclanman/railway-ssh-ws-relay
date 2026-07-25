'use strict';

const net = require('net');
const crypto = require('crypto');
const { spawn } = require('child_process');
const path = require('path');

const TEST_TIMEOUT_MS = 6000;

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

function maskedFrame(payload, opcode = 0x2) {
  const data = Buffer.from(payload);
  const mask = crypto.randomBytes(4);
  let header;
  if (data.length < 126) {
    header = Buffer.alloc(6);
    header[1] = 0x80 | data.length;
    mask.copy(header, 2);
  } else {
    header = Buffer.alloc(8);
    header[1] = 0x80 | 126;
    header.writeUInt16BE(data.length, 2);
    mask.copy(header, 4);
  }
  header[0] = 0x80 | opcode;
  const offset = header.length - 4;
  const out = Buffer.from(data);
  for (let i = 0; i < out.length; i += 1) out[i] ^= mask[i & 3];
  return Buffer.concat([header, out]);
}

function parseServerFrame(buffer) {
  if (buffer.length < 2) return null;
  const opcode = buffer[0] & 0x0f;
  let length = buffer[1] & 0x7f;
  let offset = 2;
  if (length === 126) {
    if (buffer.length < 4) return null;
    length = buffer.readUInt16BE(2);
    offset = 4;
  } else if (length === 127) {
    if (buffer.length < 10) return null;
    length = Number(buffer.readBigUInt64BE(2));
    offset = 10;
  }
  if (buffer.length < offset + length) return null;
  return {
    opcode,
    payload: buffer.subarray(offset, offset + length),
    rest: buffer.subarray(offset + length),
  };
}

function connectAndCollect(port, request, assertion) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port });
    let buffer = Buffer.alloc(0);
    const timeout = setTimeout(() => {
      socket.destroy();
      reject(new Error('test socket timed out'));
    }, TEST_TIMEOUT_MS);

    const done = (error) => {
      clearTimeout(timeout);
      socket.destroy();
      if (error) reject(error);
      else resolve();
    };

    socket.once('error', done);
    socket.once('connect', () => socket.write(request));
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      try {
        assertion({ socket, buffer, setBuffer(value) { buffer = value; }, done });
      } catch (error) {
        done(error);
      }
    });
  });
}

async function testMinimalRawHttpInjector(port) {
  let phase = 'headers';
  await connectAndCollect(
    port,
    'GET /ssh?token=test-secret HTTP/1.1\r\n' +
      'Host: railway.test\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n\r\n',
    ({ socket, buffer, setBuffer, done }) => {
      if (phase === 'headers') {
        const end = buffer.indexOf('\r\n\r\n');
        if (end < 0) return;
        const headers = buffer.subarray(0, end).toString('utf8');
        if (!headers.startsWith('HTTP/1.1 101')) throw new Error(`minimal raw expected 101, got ${headers}`);
        if (!headers.includes('X-Relay-Mode: raw-ssh')) throw new Error('minimal raw mode header missing');
        if (headers.toLowerCase().includes('sec-websocket-accept:')) throw new Error('minimal raw should not invent Sec-WebSocket-Accept');
        setBuffer(buffer.subarray(end + 4));
        phase = 'banner';
      }
      if (phase === 'banner') {
        if (!buffer.includes(Buffer.from('SSH-2.0-Dropbear_Test'))) return;
        phase = 'echo';
        setBuffer(Buffer.alloc(0));
        socket.write('SSH-2.0-HTTPInjector_Minimal\r\n');
        return;
      }
      if (phase === 'echo' && buffer.includes(Buffer.from('SSH-2.0-HTTPInjector_Minimal'))) done();
    }
  );
}

async function testRawHttpInjector(port, forwardedProto = 'http') {
  let phase = 'headers';
  await connectAndCollect(
    port,
    'GET /ssh?token=test-secret HTTP/1.1\r\n' +
      'Host: railway.test\r\n' +
      `X-Forwarded-Proto: ${forwardedProto}\r\n` +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      'Sec-WebSocket-Version: 13\r\n' +
      'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n',
    ({ socket, buffer, setBuffer, done }) => {
      if (phase === 'headers') {
        const end = buffer.indexOf('\r\n\r\n');
        if (end < 0) return;
        const headers = buffer.subarray(0, end).toString('utf8');
        if (!headers.startsWith('HTTP/1.1 101')) throw new Error(`raw expected 101, got ${headers}`);
        if (!headers.includes('X-Relay-Mode: raw-ssh')) throw new Error('raw mode header missing');
        setBuffer(buffer.subarray(end + 4));
        phase = 'banner';
      }
      if (phase === 'banner') {
        const current = phase === 'banner' ? buffer : Buffer.alloc(0);
        if (!current.includes(Buffer.from('SSH-2.0-Dropbear_Test'))) return;
        phase = 'echo';
        setBuffer(Buffer.alloc(0));
        socket.write('SSH-2.0-HTTPInjector_Test\r\n');
        return;
      }
      if (phase === 'echo' && buffer.includes(Buffer.from('SSH-2.0-HTTPInjector_Test'))) done();
    }
  );
}

async function testFramedWebSocket(port) {
  const key = crypto.randomBytes(16).toString('base64');
  let phase = 'headers';
  let frames = Buffer.alloc(0);
  await connectAndCollect(
    port,
    'GET /ws?token=test-secret HTTP/1.1\r\n' +
      'Host: railway.test\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      'Sec-WebSocket-Version: 13\r\n' +
      `Sec-WebSocket-Key: ${key}\r\n\r\n`,
    ({ socket, buffer, setBuffer, done }) => {
      if (phase === 'headers') {
        const end = buffer.indexOf('\r\n\r\n');
        if (end < 0) return;
        const headers = buffer.subarray(0, end).toString('utf8');
        if (!headers.startsWith('HTTP/1.1 101')) throw new Error(`framed expected 101, got ${headers}`);
        if (!headers.includes('X-Relay-Mode: rfc6455')) throw new Error('framed mode header missing');
        frames = buffer.subarray(end + 4);
        setBuffer(Buffer.alloc(0));
        phase = 'banner';
      } else {
        frames = Buffer.concat([frames, buffer]);
        setBuffer(Buffer.alloc(0));
      }

      while (true) {
        const frame = parseServerFrame(frames);
        if (!frame) return;
        frames = frame.rest;
        if (frame.opcode !== 0x2) continue;
        if (phase === 'banner' && frame.payload.includes(Buffer.from('SSH-2.0-Dropbear_Test'))) {
          phase = 'echo';
          socket.write(maskedFrame('SSH-2.0-Framed_Test\r\n'));
        } else if (phase === 'echo' && frame.payload.includes(Buffer.from('SSH-2.0-Framed_Test'))) {
          done();
          return;
        }
      }
    }
  );
}

async function testStatus(port, request, expectedStatus) {
  await connectAndCollect(port, request, ({ buffer, done }) => {
    const end = buffer.indexOf('\r\n\r\n');
    if (end < 0) return;
    const firstLine = buffer.subarray(0, end).toString('utf8').split('\r\n')[0];
    if (!firstLine.startsWith(`HTTP/1.1 ${expectedStatus}`)) {
      throw new Error(`expected status ${expectedStatus}, got ${firstLine}`);
    }
    done();
  });
}

async function startRelay(relayPort, targetPort) {
  const child = spawn(process.execPath, [path.join(__dirname, 'server.js')], {
    env: {
      ...process.env,
      PORT: String(relayPort),
      TARGET_HOST: '127.0.0.1',
      TARGET_PORT: String(targetPort),
      RELAY_TOKEN: 'test-secret',
      CONNECT_TIMEOUT_MS: '1500',
      PING_INTERVAL_MS: '60000',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
  child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });

  for (let i = 0; i < 50; i += 1) {
    if (child.exitCode != null) throw new Error(`relay exited early\n${stdout}\n${stderr}`);
    if (stdout.includes('"event":"listening"')) return { child, output: () => stdout + stderr };
    await delay(50);
  }
  child.kill('SIGKILL');
  throw new Error(`relay did not start\n${stdout}\n${stderr}`);
}

(async () => {
  const backend = net.createServer((socket) => {
    socket.setNoDelay(true);
    socket.write('SSH-2.0-Dropbear_Test\r\n');
    socket.on('data', (chunk) => socket.write(chunk));
  });
  await new Promise((resolve, reject) => {
    backend.once('error', reject);
    backend.listen(0, '127.0.0.1', resolve);
  });

  const targetPort = backend.address().port;
  const relayPort = await freePort();
  const relay = await startRelay(relayPort, targetPort);

  try {
    await testMinimalRawHttpInjector(relayPort);
    console.log('PASS exact minimal HTTP Injector payload: 101, SSH banner, bidirectional raw bytes');

    await testRawHttpInjector(relayPort, 'http');
    console.log('PASS port 80 viewer: valid upgrade returns 101 and relays raw SSH');

    await testRawHttpInjector(relayPort, 'https');
    console.log('PASS port 443 viewer: valid upgrade returns 101 and relays raw SSH');

    await testFramedWebSocket(relayPort);
    console.log('PASS framed /ws: RFC 6455 handshake and bidirectional SSH bytes');

    await testStatus(
      relayPort,
      'GET /ssh?token=test-secret HTTP/1.1\r\nHost: test\r\n\r\n',
      426
    );
    console.log('PASS incomplete port-80 request: 426 from app, never app-level 301');

    await testStatus(
      relayPort,
      'GET /ssh?token=wrong HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n',
      401
    );
    console.log('PASS invalid token: 401');

    await testStatus(
      relayPort,
      'GET /wrong?token=test-secret HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n',
      404
    );
    console.log('PASS invalid path: 404');
  } finally {
    relay.child.kill('SIGTERM');
    await new Promise((resolve) => backend.close(resolve));
  }

  const deadTargetPort = await freePort();
  const relayPort2 = await freePort();
  const relay2 = await startRelay(relayPort2, deadTargetPort);
  try {
    await testStatus(
      relayPort2,
      'GET /ssh?token=test-secret HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n',
      502
    );
    console.log('PASS unreachable SSH backend: 502');
  } finally {
    relay2.child.kill('SIGTERM');
  }

  console.log('ALL TESTS PASSED');
})().catch((error) => {
  console.error(`FAIL: ${error.stack || error.message}`);
  process.exitCode = 1;
});
