# Code MCP

A minimal MCP (Model Context Protocol) server over HTTP with Streamable HTTP transport and JSON-RPC 2.0.

## Features

- **Tools (always available):** read, write, edit, multi_edit, bash, grep, find, ls, job, mcp
- **Tools (conditional):**
  - `preview` — enabled when `cloudflared` is on PATH
  - `remember`, `forget`, `recall` — enabled with `--enable-memory`
  - `get_upload_link` — enabled with `--public` or `--domain`

## Usage

```bash
# Bun
bun code-mcp.ts [--port <n>] [--token <s>] [--enable-memory] [--public | --domain <host>] [--mcp <path>]

# Java (compile first)
javac CodeMCP.java
java CodeMCP [--port <n>] [--token <s>] [--enable-memory] [--public | --domain <host>] [--mcp <path>]
```

### Gateway Mode

Connect to a [code-mcp-gateway](https://github.com/Tuanm/code-mcp-gateway) to expose this server to the internet without `cloudflared`:

```bash
# Bun
bun code-mcp.ts --gateway wss://gateway.example.workers.dev --port 7777

# Java
java CodeMCP --gateway wss://gateway.example.workers.dev --port 7777
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--port <n>` | Listen port | `7777` or `$PORT` |
| `--token <s>` | Require `?token=<s>` on every request | no auth |
| `--enable-memory` | Enable remember/forget/recall tools (persists to `{cwd}/.memo.jsonl`) | disabled |
| `--disallowed-tools` | Comma-separated list of tools to disable | none |
| `--public` | Expose via Cloudflare quick tunnel (requires `cloudflared`) | disabled |
| `--domain <host>` | Use existing public hostname (mutually exclusive with `--public`) | none |
| `--mcp <path>` | Aggregate tools from external MCP servers (Claude Desktop JSON config) | none |
| `--gateway <url>` | Connect to a gateway server and tunnel requests via WebSocket | none |

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

### Bun

```bash
bun build ./code-mcp.ts --outfile=./code-mcp --target=bun --compile --minify
chmod +x code-mcp
```

### Java

```bash
javac CodeMCP.java
java CodeMCP [args...]
```

Requires JDK 21+. No external dependencies — standard Java APIs only.
