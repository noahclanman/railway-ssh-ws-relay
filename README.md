# Railway SSH-over-WebSocket Relay

A fixed-target WebSocket-to-TCP relay intended to carry an SSH byte stream from an authorized client to your own VPS SSH/Dropbear listener.

It exposes two upgrade paths:

- `/ssh` — real RFC 6455 WebSocket framing. Use this first.
- `/raw` — compatibility mode for clients that expect `101 Switching Protocols` and then send raw, unframed SSH bytes. This mode is experimental because platform edge proxies may require standards-compliant WebSocket frames.

The backend target is fixed by Railway environment variables. Clients cannot choose arbitrary destinations, so this is not an open proxy.

## Architecture

```text
HTTP Injector
    -> WSS :443
Railway public domain /ssh
    -> outbound TCP
Your VPS Dropbear/sshd port, for example :550
```

You do not need PDirect.py on the VPS when `/ssh` or `/raw` connects directly to Dropbear. Keep the selected Dropbear/SSH port reachable from Railway.

## Railway deployment

1. Upload this folder to a GitHub repository.
2. In Railway, create a project and choose **Deploy from GitHub Repo**.
3. Add these service variables:

```env
TARGET_HOST=your-vps-ip-or-dns
TARGET_PORT=550
RELAY_TOKEN=generate-a-long-random-secret
```

4. In **Settings -> Networking -> Public Networking**, generate a Railway domain or add a custom domain.
5. Open `https://YOUR_DOMAIN/health`. It should return `"ok": true`.

The process must bind to Railway's `PORT`; this project already does that.

## HTTP Injector setup

Use the same SSH username and password that exist on the VPS. The public connection endpoint is the Railway domain on port `443`.

### Mode A: real WebSocket — recommended

Use this when HTTP Injector has a real SSH-over-WebSocket/WebSocket transport option.

- Server/address: `YOUR_RAILWAY_DOMAIN`
- Port: `443`
- TLS/SSL: enabled
- SNI: `YOUR_RAILWAY_DOMAIN`
- WebSocket path: `/ssh?token=YOUR_RELAY_TOKEN`
- Host header: `YOUR_RAILWAY_DOMAIN`

A standards-compliant handshake looks like:

```http
GET /ssh?token=YOUR_RELAY_TOKEN HTTP/1.1
Host: YOUR_RAILWAY_DOMAIN
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: <client-generated-random-key>
```

Let HTTP Injector generate the WebSocket key when possible.

### Mode B: raw 101 compatibility

Use this only when your existing VPS setup works by receiving a `101` response and then sending raw SSH bytes without WebSocket frames.

Example payload:

```text
GET /raw?token=YOUR_RELAY_TOKEN HTTP/1.1[crlf]
Host: YOUR_RAILWAY_DOMAIN[crlf]
Upgrade: websocket[crlf]
Connection: Upgrade[crlf][crlf]
```

If Railway rejects the connection or SSH identification never appears, your client/platform combination requires real WebSocket framing; use `/ssh` instead.

## VPS firewall

Allow the backend SSH/Dropbear port only from trusted sources where practical. Railway outbound IPs may not be static on every plan/setup, so confirm your Railway networking options before using an IP allowlist. At minimum:

- use a strong SSH password or, preferably, an SSH key;
- set a long `RELAY_TOKEN`;
- do not expose an unrestricted target selector;
- keep `MAX_CONNECTIONS_PER_IP` low.

## Important Railway limitation

Railway's HTTP public edge currently applies a maximum request duration to WebSocket connections. A long-running VPN tunnel may therefore be disconnected periodically. HTTP Injector must reconnect, and the SSH session will be re-established. This makes Railway workable for testing or reconnect-capable use, but less stable than a relay on a VPS/CDN path without that hard connection-duration limit.

## Local run

```bash
export TARGET_HOST=127.0.0.1
export TARGET_PORT=22
export RELAY_TOKEN=test-secret
node server.js
```

Health check:

```bash
curl http://127.0.0.1:3000/health
```
