# Railway SSH-over-WS Relay v3.1 — HTTP 80 + HTTPS 443

This Railway-only relay is designed for HTTP Injector using either:

```text
HTTP  :80  (SSL/TLS OFF)
HTTPS :443 (SSL/TLS ON)
```

Both public ports reach the same Railway service and the app listens only on Railway's assigned `$PORT`.

## Traffic path

```text
HTTP Injector :80 or :443
        -> Railway WebSocket upgrade
        -> relay app on $PORT
        -> raw TCP to VPS_IP:550
        -> Dropbear/SSH
```

`TARGET_PORT=550` is correct when Dropbear listens on VPS port 550. Do not use VPS port 80 as the backend if port 80 is already PDirect/WebSocket.

## Why you got 301 on port 80

Railway redirects ordinary plain HTTP GET requests. Port 80 must therefore send a **complete valid WebSocket upgrade**. An incomplete payload can be classified as a normal GET and redirected to HTTPS.

Required headers:

- `GET ... HTTP/1.1`
- `Host` equal to the Railway domain
- `Upgrade: websocket`
- `Connection: Upgrade`
- `Sec-WebSocket-Version: 13`
- a valid 16-byte Base64 `Sec-WebSocket-Key`

## Railway variables

```env
TARGET_HOST=YOUR_VPS_PUBLIC_IP
TARGET_PORT=550
RELAY_TOKEN=YOUR_LONG_RANDOM_SECRET
CONNECT_TIMEOUT_MS=10000
IDLE_TIMEOUT_MS=0
MAX_CONNECTIONS_PER_IP=5
```

Do not set `PORT`; Railway supplies it automatically.

## HTTP Injector — port 80

```text
SSH Server: YOUR-APP.up.railway.app
SSH Port: 80
SSL/TLS: OFF
SNI: blank/off
```

Payload:

```text
GET /ssh?token=YOUR_RELAY_TOKEN HTTP/1.1[crlf]
Host: YOUR-APP.up.railway.app[crlf]
Upgrade: websocket[crlf]
Connection: Upgrade[crlf]
Sec-WebSocket-Version: 13[crlf]
Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==[crlf]
Pragma: no-cache[crlf]
Cache-Control: no-cache[crlf][crlf]
```

## HTTP Injector — port 443

```text
SSH Server: YOUR-APP.up.railway.app
SSH Port: 443
SSL/TLS: ON
SNI: YOUR-APP.up.railway.app
```

Use the same payload above.

## Important payload rules

- The `Host` header must be the Railway domain, not your VPS IP/domain.
- Do not put `http://` or `https://` in the `Host` header.
- Do not use `[lf]`; use `[crlf]` so Railway parses a valid HTTP/1.1 request.
- Do not omit `Sec-WebSocket-Key` or `Sec-WebSocket-Version` on port 80.
- `/ssh` returns `101` and then carries raw SSH bytes for HTTP Injector/PDirect-style tunneling.
- `/ws` is RFC 6455 framed mode for a true WebSocket client.

## Checks

```text
https://YOUR-APP.up.railway.app/health
https://YOUR-APP.up.railway.app/check-target?token=YOUR_RELAY_TOKEN
```

`/check-target` should show a banner beginning with `SSH-2.0-`.

## Local tests

```bash
npm run check
npm test
```

The test suite verifies:

- HTTP-viewer upgrade (`X-Forwarded-Proto: http`) returns `101`.
- HTTPS-viewer upgrade (`X-Forwarded-Proto: https`) returns `101`.
- SSH banner and raw traffic pass in both directions.
- Invalid/incomplete WebSocket handshakes return `400`, not a redirect.
- Wrong token returns `401`.
- Unreachable Dropbear returns `502`.
