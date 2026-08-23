# Code MCP

A minimal MCP (Model Context Protocol) server over HTTP with Streamable HTTP transport and JSON-RPC 2.0.

Three implementations with identical surface and behavior: Python (`code_mcp.py`), Java (`CodeMCP.java`), TypeScript/Bun (`code-mcp.ts`).

## Features

- **Tools (always available):** read, write, edit, multi_edit, bash, grep, find, ls, job, mcp
- **Tools (conditional):**
  - `preview` — enabled when `cloudflared` is on PATH
  - `remember`, `forget`, `recall` — enabled with `--enable-memory`
  - `get_upload_link` — enabled with `--public` or `--domain` (requires `--token`)

## Usage

```bash
# Python (3.10+, no external deps)
python3 code_mcp.py [flags...]

# Bun
bun code-mcp.ts [flags...]

# Java (JDK 21+, runs directly without compile)
java CodeMCP.java [flags...]
```

All three accept the same flags. See the **Flags** table below.

### Gateway Mode

Connect to a [code-mcp-gateway](https://github.com/Tuanm/code-mcp-gateway) to expose this server to the internet without `cloudflared`:

```bash
python3 code_mcp.py --gateway --port 7777          # bare flag: uses wss://code-mcp.tuanm.workers.dev
bun code-mcp.ts     --gateway wss://gateway.example.workers.dev --port 7777
java CodeMCP.java   --gateway wss://gateway.example.workers.dev --port 7777
```

A bare `--gateway` (no URL) connects to the managed gateway at
`wss://code-mcp.tuanm.workers.dev`.

The gateway authenticates every device at connect time against its device
registry (unknown ids or missing/mismatched tokens are rejected with 401, so
nobody can hijack a registered device). Pass `--id` with the registered device
ID and `--token` with that device's token; the token is presented to the
gateway as `X-Device-Token` on the WebSocket upgrade:

```bash
python3 code_mcp.py --gateway wss://gateway.example.workers.dev --id my-device --token my-secret --port 7777
```

Need a credential that differs from the local server token? Use
`--gateway-token` — it overrides `--token` for the gateway connection only.

All three clients implement the same gateway WebSocket protocol with proactive
liveness detection:

- **App-layer keepalive**: client sends `{"type":"keepalive"}` every ~25 s; the
  gateway replies `{"type":"keepalive-ack"}`. Data-frame heartbeat survives
  HTTP/2 proxies (Cloudflare Zero Trust, etc.) that can swallow WebSocket
  control ping/pong.
- **Inbound watchdog (~75 s)**: if no frame arrives within the window the
  socket is force-closed and the client reconnects with exponential backoff.
- **Reconnect**: on any disconnect (error, close, watchdog, keepalive send
  failure) the client retries with jittered backoff and preserves the same
  `--id` so the gateway entry returns to the same device slot.

## Flags

| Flag                        | Description                                                            | Default           |
| --------------------------- | ---------------------------------------------------------------------- | ----------------- |
| `--port <n>`                | Listen port                                                            | `7777` or `$PORT` |
| `--bind <addr>`             | Bind address                                                           | `127.0.0.1`       |
| `--token <s>`               | Require `?token=<s>` or `Authorization: Bearer <s>` on every request; in gateway mode also presented to the gateway as the device credential | no auth |
| `--gateway-token <s>`      | Device credential sent to the gateway on connect (overrides `--token`); must match the token registered for `--id` in the gateway | `--token` |
| `--enable-memory`           | Enable remember/forget/recall tools                                    | disabled          |
| `--disallowed-tools <list>` | Comma-separated list of tools to disable                               | none              |
| `--public`                  | Expose via Cloudflare quick tunnel (requires `cloudflared`)            | disabled          |
| `--domain <host>`           | Use existing public hostname (mutually exclusive with `--public`)      | none              |
| `--mcp <path>`              | Aggregate tools from external MCP servers (Claude Desktop JSON config) | none              |
| `--gateway [url]`          | Connect to a gateway server and tunnel requests via WebSocket; bare flag uses the default managed gateway | `wss://code-mcp.tuanm.workers.dev` |
| `--id <uuid>`               | Use specific device ID for gateway connection                          | random UUID       |

### MCP Config Format

```json
{
  "mcpServers": {
    "namespace": {
      "command": "...",
      "args": [...],
      "env": {...}
    }
  }
}
```

Tools are exposed with `<namespace>__` prefix. HTTP transport servers use `{"type": "http", "url": "...", "headers": {...}}`.

## Build

### Python

No build step. Requires Python 3.10+, standard library only:

```bash
python3 code_mcp.py [args...]
```

### Bun

```bash
bun build ./code-mcp.ts --outfile=./code-mcp --target=bun --compile --minify
chmod +x code-mcp
```

### Java

JDK 21+, no external dependencies. Run directly:

```bash
java CodeMCP.java [args...]
```

Or compile first for faster startup:

```bash
javac CodeMCP.java
java CodeMCP [args...]
```

## Security notes

- The server binds to `127.0.0.1` by default. To expose on a LAN, pass `--bind 0.0.0.0` and a `--token`.
- The `--token` is enforced with a constant-time compare; accepts both `?token=…` query string and `Authorization: Bearer …` header.
- Child processes (shell tools and external MCP servers) receive a minimal env (`PATH`, `HOME`, `SHELL`, `LANG`, `LC_CTYPE`, `TZ`, `TMP*` + Windows essentials). Secrets in the parent env (`AWS_*`, `OPENAI_API_KEY`, etc.) are not forwarded.
- Request body, WebSocket frames, and uploads are size-capped to protect against memory-DoS.
