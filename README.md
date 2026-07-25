# Private Gateway

Keep this repository private. Configure the required Railway environment variables and deploy it as a Node.js service.

The public status endpoint is intentionally limited:

```json
{"ok":true}
```

All other ordinary HTTP requests return an empty `404` response. Detailed target diagnostics and identifying response headers are disabled.
