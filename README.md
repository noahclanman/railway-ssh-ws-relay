# Railway SSH-over-WebSocket Relay v2.0

This project relays an authorized HTTP Injector SSH tunnel from Railway to a fixed SSH or Dropbear service on your own VPS.

## Correct connection path

```text
HTTP Injector -- TLS/WSS port 443 --> Railway relay -- raw TCP --> VPS_IP:550 Dropbear
```

`TARGET_PORT=550` is correct when Dropbear listens on VPS port 550. Do not point the relay to VPS port 80 when port 80 is PDirect/WebSocket; the Railway service already performs the HTTP upgrade.

## Railway variables

```env
TARGET_HOST=YOUR_VPS_PUBLIC_IP
TARGET_PORT=550
RELAY_TOKEN=YOUR_LONG_RANDOM_SECRET
CONNECT_TIMEOUT_MS=10000
IDLE_TIMEOUT_MS=0
MAX_CONNECTIONS_PER_IP=5
```

Your VPS firewall/security group must allow inbound TCP 550. Test from another machine:

```bash
nc -vz YOUR_VPS_PUBLIC_IP 550
```

A reachable SSH port should also show an SSH banner:

```bash
timeout 5 bash -c 'cat < /dev/null > /dev/tcp/YOUR_VPS_PUBLIC_IP/550'
```

## Deploy

1. Upload this folder to GitHub.
2. Create a Railway project from the repository.
3. Add the variables above.
4. Generate a Railway public domain.
5. Open `https://YOUR_RAILWAY_DOMAIN/health`.

Expected health result includes:

```json
{"ok":true,"version":"2.0.0","target":"YOUR_VPS_PUBLIC_IP:550"}
```

Then verify that Railway can actually reach Dropbear:

```text
https://YOUR_RAILWAY_DOMAIN/check-target?token=YOUR_RELAY_TOKEN
```

A correct response should contain `"reachable":true`, an `SSH-2.0-...` banner, and `"looksLikeSsh":true`. A `502` here means the VPS IP, port, firewall, or Dropbear listener is wrong.

## HTTP Injector configuration

Use Railway on public port 443:

```text
SSH host/server: YOUR_RAILWAY_DOMAIN
SSH port: 443
SSL/TLS: ON
SNI: YOUR_RAILWAY_DOMAIN
SSH username/password: your VPS SSH account
```

Use this custom payload:

```text
GET /ssh?token=YOUR_RELAY_TOKEN HTTP/1.1[crlf]
Host: YOUR_RAILWAY_DOMAIN[crlf]
Upgrade: websocket[crlf]
Connection: Upgrade[crlf]
Sec-WebSocket-Version: 13[crlf]
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==[crlf][crlf]
```

The `/ssh` route intentionally behaves like PDirect: it returns `101 Switching Protocols` and then passes raw SSH bytes to Dropbear.

Expected response:

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
X-Relay-Mode: raw-ssh
```

For a true RFC 6455 WebSocket client, use `/ws?token=...` instead. HTTP Injector custom-payload mode should use `/ssh`.

## Important port behavior

- Public `443`: use this with Railway and enable SSL/TLS in HTTP Injector.
- Public `80`: Railway's edge may redirect HTTP to HTTPS, resulting in `301` before this app receives the request.
- Backend `550`: Railway connects here on your VPS because this is Dropbear/SSH.
- VPS `80`: not used by this relay if it runs PDirect/WebSocket.

The Node app itself never sends a `301` redirect.

## Status codes

- `101`: upgrade succeeded.
- `301`/`308`: Railway or another edge redirected HTTP to HTTPS; use port 443 with SSL enabled.
- `401`: missing or incorrect `RELAY_TOKEN`.
- `404`: wrong path; use `/ssh`.
- `429`: too many simultaneous connections from one IP.
- `502`: Railway cannot reach `TARGET_HOST:TARGET_PORT`.
- `503`: `TARGET_HOST` is missing.

## Local tests

```bash
npm run check
npm test
```

The tests create a mock Dropbear-style backend and verify:

- `/ssh` returns 101 and relays the SSH banner plus raw bidirectional bytes.
- `/ws` performs RFC 6455 framing and relays SSH bytes.
- Invalid token returns 401.
- Invalid path returns 404.
- Unreachable backend returns 502.
