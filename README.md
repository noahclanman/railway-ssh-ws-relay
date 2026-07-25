# Railway SSH-over-WebSocket Relay v4.0

This version fixes the backend design for a VPS that already runs PDirect/SSH-over-WebSocket:

```text
HTTP Injector -> Railway -> VPS PDirect port 80 -> Dropbear port 550
```

The default mode is a transparent WebSocket-origin relay. Railway forwards the HTTP upgrade to the VPS WebSocket listener instead of replacing it.

## Railway variables for your existing setup

```env
ORIGIN_MODE=ws
TARGET_HOST=YOUR_VPS_PUBLIC_IP
TARGET_PORT=80
ORIGIN_X_REAL_HOST=127.0.0.1:550
RELAY_TOKEN=YOUR_LONG_SECRET
CONNECT_TIMEOUT_MS=10000
IDLE_TIMEOUT_MS=0
MAX_CONNECTIONS_PER_IP=8
```

Do not manually define `PORT`; Railway supplies it.

If PDirect accepts another path, set:

```env
ORIGIN_PATH=/
```

Leave `ORIGIN_PATH` unset to preserve `/ssh`.

## Exact HTTP Injector payload

Use the standards-complete payload for Railway:

```text
GET /ssh?token=YOUR_LONG_SECRET HTTP/1.1[crlf]
Host: YOUR-APP.up.railway.app[crlf]
Upgrade: websocket[crlf]
Connection: Upgrade[crlf]
Sec-WebSocket-Version: 13[crlf]
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==[crlf][crlf]
```

The app also accepts the minimal four-header payload if it reaches the app, and injects missing RFC headers before forwarding to PDirect. Railway's public edge may still require the complete handshake.

## HTTP Injector settings

### TLS/WSS

```text
Remote proxy / SSH proxy: YOUR-APP.up.railway.app:443
SSL/TLS: ON
SNI: YOUR-APP.up.railway.app
Payload: the payload above
```

### Plain WS attempt

```text
Remote proxy / SSH proxy: YOUR-APP.up.railway.app:80
SSL/TLS: OFF
Payload: the same payload
```

The application accepts both once Railway forwards the upgrade. If port 80 is redirected before the app logs `upgrade_received`, that response is from Railway's edge, not this code.

## Required VPS checks

```bash
ss -lntp | grep ':80 '
curl -i --http1.1 \
  -H 'Upgrade: websocket' \
  -H 'Connection: Upgrade' \
  -H 'Sec-WebSocket-Version: 13' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  http://YOUR_VPS_IP/
```

The VPS response must be `101 Switching Protocols`.

## Railway diagnostics

```text
https://YOUR-APP.up.railway.app/health
https://YOUR-APP.up.railway.app/check-target?token=YOUR_LONG_SECRET
```

For `ORIGIN_MODE=ws`, `/check-target` must report `statusCode: 101`.

Railway logs must show:

```text
"event":"upgrade_received"
"event":"tunnel_connected","mode":"ws-origin"
```

If there is no `upgrade_received`, the request was stopped before reaching the app.

## Optional direct Dropbear mode

Only use this if you deliberately want Railway to replace PDirect:

```env
ORIGIN_MODE=ssh
TARGET_HOST=YOUR_VPS_PUBLIC_IP
TARGET_PORT=550
```
