# Private Gateway

A lightweight authenticated TCP gateway for forwarding upgraded HTTP/WebSocket connections to a fixed backend service.

The public HTTP routes expose no configuration details:

- `/` returns `404 Not Found`.
- `/health` returns only `{"ok":true}` when the service is configured.
- Backend host, port, version, routes, and connection counts are not published.

## Features

- Raw upgraded tunnel at `/ssh`
- RFC 6455 framed WebSocket tunnel at `/ws`
- Optional token authentication
- Per-client connection limits
- TCP keepalive and configurable timeouts
- Minimal public health endpoint
- Docker and Railway deployment support
- No runtime dependencies outside Node.js

## Connection flow

```text
Client
  │
  │ HTTP Upgrade or WebSocket
  ▼
Private Gateway
  │
  │ Raw TCP
  ▼
Configured backend service
```

The gateway completes the public upgrade itself and then connects directly to the raw TCP backend.

> **Important:** `TARGET_PORT` must be the port of the raw backend service. For example, when Dropbear listens on port `550`, use `TARGET_PORT=550`. Do not point this build at a second HTTP/WebSocket proxy.

## Requirements

- A GitHub repository containing these files
- A Railway account
- A reachable TCP backend
- Node.js 20 or newer for local use

## Project files

```text
.
├── Dockerfile
├── package.json
├── railway.json
├── server.js
├── self-test.js
├── .env.example
├── .gitignore
└── README.md
```

## Deploy to Railway

### 1. Create the repository

Create a new GitHub repository and upload all project files to its root.

For a private deployment, set the repository visibility to **Private**.

### 2. Create the Railway service

1. Open Railway and create a new project.
2. Select **Deploy from GitHub repo**.
3. Choose the repository.
4. Railway will detect the root `Dockerfile` and build the service.

### 3. Add variables

Open the Railway service, go to **Variables**, and use the raw editor to add:

```env
TARGET_HOST=YOUR_BACKEND_IP_OR_HOSTNAME
TARGET_PORT=550
RELAY_TOKEN=REPLACE_WITH_A_LONG_RANDOM_SECRET
CONNECT_TIMEOUT_MS=10000
IDLE_TIMEOUT_MS=0
MAX_CONNECTIONS_PER_IP=5
MAX_FRAME_BYTES=16777216
PING_INTERVAL_MS=25000
```

Do not manually add `PORT`. Railway supplies it automatically.

### Variable reference

| Variable | Required | Default | Description |
|---|---:|---:|---|
| `TARGET_HOST` | Yes | None | Fixed backend IP address or hostname |
| `TARGET_PORT` | Yes | `550` | Raw TCP backend port |
| `RELAY_TOKEN` | Recommended | Empty | Secret required in the URL or `X-Relay-Token` header |
| `CONNECT_TIMEOUT_MS` | No | `10000` | Backend connection timeout in milliseconds |
| `IDLE_TIMEOUT_MS` | No | `0` | Idle timeout; `0` disables it |
| `MAX_CONNECTIONS_PER_IP` | No | `5` | Maximum simultaneous tunnels from one client IP |
| `MAX_FRAME_BYTES` | No | `16777216` | Maximum accepted RFC 6455 frame size |
| `PING_INTERVAL_MS` | No | `25000` | Keepalive ping interval for `/ws` |

Generate a strong token locally:

```bash
openssl rand -hex 32
```

### 4. Generate a public domain

In the service settings:

1. Open **Networking**.
2. Find **Public Networking**.
3. Select **Generate Domain**.
4. Save the generated hostname, for example:

```text
example.up.railway.app
```

### 5. Verify the deployment

Open:

```text
https://YOUR_DOMAIN/health
```

Expected response:

```json
{"ok":true}
```

The root URL intentionally returns an empty `404` response.

## Client endpoints

### Raw upgraded tunnel

```text
/ssh?token=YOUR_RELAY_TOKEN
```

This route returns `101 Switching Protocols` and then carries a raw bidirectional TCP stream.

Recommended upgrade request:

```http
GET /ssh?token=YOUR_RELAY_TOKEN HTTP/1.1
Host: YOUR_DOMAIN
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==

```

HTTP Injector payload format:

```text
GET /ssh?token=YOUR_RELAY_TOKEN HTTP/1.1[crlf]
Host: YOUR_DOMAIN[crlf]
Upgrade: websocket[crlf]
Connection: Upgrade[crlf]
Sec-WebSocket-Version: 13[crlf]
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==[crlf][crlf]
```

### RFC 6455 WebSocket tunnel

```text
/ws?token=YOUR_RELAY_TOKEN
```

Use this route only with clients that send and receive standard RFC 6455 WebSocket frames.

## HTTP Injector example

### HTTPS / port 443

```text
Remote proxy: YOUR_DOMAIN
Proxy port: 443
SSL/TLS: enabled
SNI: YOUR_DOMAIN
Payload path: /ssh?token=YOUR_RELAY_TOKEN
```

### HTTP / port 80

```text
Remote proxy: YOUR_DOMAIN
Proxy port: 80
SSL/TLS: disabled
SNI: blank
Payload path: /ssh?token=YOUR_RELAY_TOKEN
```

The same upgrade payload can be used for both. If port `80` receives `301` or `308`, the public ingress redirected HTTP to HTTPS before the request reached the application. Use port `443` with TLS in that case.

## Token authentication

A token can be supplied in either location.

### URL query

```text
/ssh?token=YOUR_RELAY_TOKEN
```

### Request header

```http
X-Relay-Token: YOUR_RELAY_TOKEN
```

When `RELAY_TOKEN` is configured, requests without the correct token receive `401 Unauthorized`.

## Local installation

```bash
git clone YOUR_REPOSITORY_URL
cd YOUR_REPOSITORY_FOLDER
npm install
cp .env.example .env
```

Edit `.env`, then export the variables before starting:

```bash
set -a
. ./.env
set +a
npm start
```

The local server listens on port `3000` unless `PORT` is set.

Check it:

```bash
curl -i http://127.0.0.1:3000/health
```

## Run tests

Check JavaScript syntax:

```bash
npm run check
```

Run the included end-to-end tests:

```bash
npm test
```

The tests create a temporary mock backend and verify:

- Raw `/ssh` upgrade
- RFC 6455 `/ws` framing
- Bidirectional data forwarding
- Invalid-token rejection
- Unknown-path rejection
- Unreachable-backend handling

## Docker

Build:

```bash
docker build -t private-gateway .
```

Run:

```bash
docker run --rm \
  -p 3000:3000 \
  -e TARGET_HOST=YOUR_BACKEND_IP \
  -e TARGET_PORT=550 \
  -e RELAY_TOKEN=YOUR_SECRET \
  private-gateway
```

Verify:

```bash
curl -i http://127.0.0.1:3000/health
```

## Updating the deployment

Push changes to the GitHub branch connected to Railway. When automatic deployments are enabled, Railway builds and deploys the new commit.

```bash
git add .
git commit -m "Update gateway"
git push
```

## Status codes

| Code | Meaning |
|---:|---|
| `101` | Tunnel upgrade accepted |
| `400` | Invalid HTTP or WebSocket request |
| `401` | Missing or incorrect token |
| `404` | Unknown normal route or tunnel path |
| `429` | Per-IP connection limit reached |
| `502` | Backend cannot be reached |
| `503` | `TARGET_HOST` is not configured |

## Troubleshooting

### Health endpoint returns `503`

Set `TARGET_HOST` in Railway and deploy the staged variable changes.

### Tunnel returns `401`

Confirm that the token in the request exactly matches `RELAY_TOKEN`.

### Tunnel returns `404`

Use `/ssh` for the raw tunnel or `/ws` for an RFC 6455 client.

### Tunnel returns `502`

The gateway cannot connect to the configured backend. Verify:

```bash
nc -vz YOUR_BACKEND_IP 550
```

Also check:

- The backend service is running.
- The configured port is correct.
- The VPS firewall permits incoming connections.
- The hosting provider security group permits the port.
- The backend is listening on a public interface when required.

On the backend server:

```bash
ss -lntp | grep ':550 '
```

### Client receives `301` or `308`

The request was redirected before the application processed the upgrade. Use HTTPS on port `443` and enable TLS/SNI in the client.

### Connection opens but authentication fails

The gateway only forwards TCP traffic. Authentication is still handled by the backend service, so use a valid backend username, password, or key.

## Security recommendations

- Keep the GitHub repository private.
- Never commit a real `.env` file.
- Use a random token of at least 32 bytes.
- Rotate the token if it is exposed.
- Restrict the backend firewall when practical.
- Do not expose diagnostic routes containing backend addresses or banners.
- Prefer TLS on port `443` for client connections.
- Do not publish screenshots containing environment variables.
- Review Railway logs without sharing tokens or backend addresses.

The gateway hides configuration details from normal HTTP responses, but it does not make a public repository private or prevent network operators from observing unencrypted port-80 traffic.

## License

MIT
