#!/usr/bin/env python3
"""
Code MCP - Minimal MCP server over HTTP with Streamable HTTP transport and JSON-RPC 2.0.
Python 3.10+ only, no external dependencies.
"""

import base64
import concurrent.futures
import hashlib
import hmac
import http.server
import json
import os
import random
import re
import secrets
import shlex
import signal
import socket
import socketserver
import ssl
import stat
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from http.server import HTTPServer, SimpleHTTPRequestHandler
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any, BinaryIO, Optional

# Configuration
DEFAULT_PORT = 7777
TIMEOUT_MS = 30_000
MAX_OUTPUT = 1_000_000
OUTPUT_CAP_KEEP = 500_000
UPLOAD_TTL_MS = 10 * 60 * 1000
MAX_CONCURRENT_JOBS = 10

# Global state
jobs: dict[str, dict] = {}
job_seq = 0
shutting_down = False
port = DEFAULT_PORT
token: Optional[str] = None
gateway_domain: Optional[str] = None
gateway_ws: Optional[socket.socket] = None
gateway_device_id: Optional[str] = None
gateway_lock = threading.Lock()


class ShellType(Enum):
    BASH = "bash"
    SH = "sh"
    CMD = "cmd"
    POWERSHELL = "pwsh"


def detect_shell() -> ShellType:
    if sys.platform == "win32":
        return ShellType.CMD
    return ShellType.BASH


def find_on_path(name: str) -> bool:
    try:
        subprocess.run(
            ["which", name] if sys.platform != "win32" else ["where", name],
            capture_output=True, timeout=5
        )
        return True
    except Exception:
        return False


def has_rg() -> bool:
    return find_on_path("rg")


def has_findstr() -> bool:
    return find_on_path("findstr")


def detect_shell_type() -> ShellType:
    if sys.platform == "win32":
        return ShellType.POWERSHELL if find_on_path("pwsh") else ShellType.CMD
    if find_on_path("bash"):
        return ShellType.BASH
    return ShellType.SH


shell_type = detect_shell_type()


def parse_args(args: list[str]) -> None:
    global port, token, gateway_domain
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--port" and i + 1 < len(args):
            port = int(args[i + 1])
            i += 2
        elif arg == "--token" and i + 1 < len(args):
            token = args[i + 1]
            i += 2
        elif arg == "--gateway" and i + 1 < len(args):
            gateway_domain = args[i + 1]
            i += 2
        elif arg == "-h" or arg == "--help":
            print(USAGE)
            sys.exit(0)
        else:
            i += 1


USAGE = """Code MCP - Minimal MCP server over HTTP

Usage: code_mcp.py [flags]

Flags:
  --port <n>        Listen port (default: 7777)
  --token <s>       Require ?token=<s> on every request
  --gateway <url>   Connect to gateway server (wss:// or https://)

Tools: read, write, edit, multi_edit, bash, grep, find, ls, job, mcp
"""


def jsonrpc_request(method: str, params: dict | None = None) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": method,
        "params": params or {}
    }


def jsonrpc_response(id: str, result: Any) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    }


def jsonrpc_error(id: str, code: int, message: str, data: Any = None) -> dict:
    err = {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}
    if data:
        err["error"]["data"] = data
    return err


def parse_jsonrpc_request(data: dict) -> tuple[str, str, dict | None]:
    method = data.get("method", "")
    params = data.get("params")
    req_id = data.get("id")
    return req_id, method, params


def safe_resolve(cwd: str, user_path: str) -> tuple[bool, Path, str]:
    """Resolve path safely, ensuring it stays within cwd. Returns (ok, resolved_path, error_msg)."""
    try:
        cwd_path = Path(cwd).resolve()
        # Handle both absolute paths and relative paths
        if Path(user_path).is_absolute():
            # Absolute paths: resolve symlinks but keep absolute
            full_path = Path(user_path).resolve()
        else:
            full_path = (cwd_path / user_path).resolve()
        # Ensure the resolved path is within cwd
        try:
            full_path.relative_to(cwd_path)
        except ValueError:
            return False, full_path, f"path escapes cwd: {user_path}"
        return True, full_path, ""
    except Exception as e:
        return False, Path("."), f"invalid path: {user_path}"


def read_file(path: str, cwd: str = ".") -> dict:
    try:
        ok, full_path, err = safe_resolve(cwd, path)
        if not ok:
            return {"error": err, "success": False}
        content = full_path.read_text(errors="replace")
        return {"content": content, "success": True}
    except Exception as e:
        return {"error": str(e), "success": False}


def write_file(path: str, content: str, cwd: str = ".") -> dict:
    try:
        ok, full_path, err = safe_resolve(cwd, path)
        if not ok:
            return {"error": err, "success": False}
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content)
        return {"success": True, "path": str(full_path)}
    except Exception as e:
        return {"error": str(e), "success": False}


def edit_file(path: str, old_str: str, new_str: str, cwd: str = ".") -> dict:
    try:
        ok, full_path, err = safe_resolve(cwd, path)
        if not ok:
            return {"error": err, "success": False}
        content = full_path.read_text()
        if old_str not in content:
            return {"error": "String not found", "success": False}
        new_content = content.replace(old_str, new_str, 1)
        full_path.write_text(new_content)
        return {"success": True}
    except Exception as e:
        return {"error": str(e), "success": False}


def multi_edit_files(edits: list[dict], cwd: str = ".") -> dict:
    results = []
    for edit in edits:
        result = edit_file(edit["path"], edit["old_str"], edit["new_str"], cwd)
        results.append(result)
    return {"results": results}


def execute_bash(command: str, cwd: str = ".") -> dict:
    try:
        result = subprocess.run(
            command,
            shell=True,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, "HOME": os.path.expanduser("~")}
        )
        stdout = result.stdout[-MAX_OUTPUT:] if len(result.stdout) > MAX_OUTPUT else result.stdout
        stderr = result.stderr[-OUTPUT_CAP_KEEP:] if len(result.stderr) > OUTPUT_CAP_KEEP else result.stderr
        return {
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": result.returncode,
            "success": True
        }
    except subprocess.TimeoutExpired:
        return {"error": "Timeout", "exit_code": -1, "success": False}
    except Exception as e:
        return {"error": str(e), "exit_code": -1, "success": False}


def grep_files(pattern: str, paths: list[str], cwd: str = ".") -> dict:
    try:
        # Validate each path is within cwd
        valid_paths = []
        for p in paths:
            ok, full_path, err = safe_resolve(cwd, p)
            if not ok:
                return {"error": err, "success": False}
            valid_paths.append(str(full_path))
        cmd = ["rg", "--json", "-n", pattern] + valid_paths if has_rg() else ["grep", "-rn", pattern] + valid_paths
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=30
        )
        return {"matches": result.stdout, "success": True}
    except Exception as e:
        return {"error": str(e), "success": False}


def find_files(pattern: str, cwd: str = ".") -> dict:
    try:
        ok, full_path, err = safe_resolve(cwd, ".")
        if not ok:
            return {"error": err, "success": False}
        matches = list(full_path.rglob(pattern))
        return {"matches": [str(m) for m in matches[:100]], "success": True}
    except Exception as e:
        return {"error": str(e), "success": False}


def list_directory(path: str = ".", cwd: str = ".") -> dict:
    try:
        ok, full_path, err = safe_resolve(cwd, path)
        if not ok:
            return {"error": err, "success": False}
        entries = []
        for entry in full_path.iterdir():
            try:
                st = entry.stat()
                entries.append({
                    "name": entry.name,
                    "type": "dir" if entry.is_dir() else "file",
                    "size": st.st_size if entry.is_file() else 0
                })
            except PermissionError:
                continue
        return {"entries": entries, "success": True}
    except Exception as e:
        return {"error": str(e), "success": False}


def get_job_status(job_id: str) -> dict:
    if job_id in jobs:
        return {"status": jobs[job_id].get("status", "unknown"), "success": True}
    return {"error": "Job not found", "success": False}


def list_jobs() -> dict:
    return {"jobs": {k: {"status": v.get("status"), "created": v.get("created")}
                     for k, v in jobs.items()}}


class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class MCPRequestHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_json(self, data: dict, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def authenticate(self) -> bool:
        if token:
            parsed = urllib.parse.urlparse(self.path)
            query = dict(urllib.parse.parse_qsl(parsed.query))
            if query.get("token") != token:
                self.send_json({"error": "unauthorized"}, 401)
                return False
        return True

    def do_POST(self):
        if not self.authenticate():
            return

        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/mcp":
            self.send_json({"error": "not found"}, 404)
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode()

        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self.send_json({"error": "invalid json"}, 400)
            return

        req_id, method, params = parse_jsonrpc_request(request)

        if method == "tools/list":
            self.send_json(jsonrpc_response(req_id, {
                "tools": [
                    {"name": "read", "description": "Read file content"},
                    {"name": "write", "description": "Write content to file"},
                    {"name": "edit", "description": "Edit file with string replacement"},
                    {"name": "multi_edit", "description": "Apply multiple edits"},
                    {"name": "bash", "description": "Execute shell command"},
                    {"name": "grep", "description": "Search for pattern in files"},
                    {"name": "find", "description": "Find files by pattern"},
                    {"name": "ls", "description": "List directory contents"},
                    {"name": "job", "description": "Manage background jobs"},
                ]
            }))
            return

        if method == "tools/call":
            tool_name = params.get("name", "") if params else ""
            tool_params = params.get("arguments", {}) if params else {}

            cwd = tool_params.get("cwd", ".") if tool_params else "."

            if tool_name == "read":
                result = read_file(tool_params.get("path", ""), cwd)
            elif tool_name == "write":
                result = write_file(tool_params.get("path", ""), tool_params.get("content", ""), cwd)
            elif tool_name == "edit":
                result = edit_file(tool_params.get("path", ""), tool_params.get("old_str", ""),
                                  tool_params.get("new_str", ""), cwd)
            elif tool_name == "multi_edit":
                result = multi_edit_files(tool_params.get("edits", []), cwd)
            elif tool_name == "bash":
                result = execute_bash(tool_params.get("command", ""), cwd)
            elif tool_name == "grep":
                result = grep_files(tool_params.get("pattern", ""),
                                   tool_params.get("paths", ["."]), cwd)
            elif tool_name == "find":
                result = find_files(tool_params.get("pattern", ""), cwd)
            elif tool_name == "ls":
                result = list_directory(tool_params.get("path", "."), cwd)
            elif tool_name == "job":
                action = tool_params.get("action", "list")
                if action == "list":
                    result = list_jobs()
                else:
                    result = {"error": "Unknown action", "success": False}
            else:
                result = {"error": f"Unknown tool: {tool_name}", "success": False}

            self.send_json(jsonrpc_response(req_id, result))
            return

        self.send_json(jsonrpc_error(req_id, -32601, "Method not found"))

    def do_GET(self):
        if not self.authenticate():
            return

        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/mcp":
            self.send_json({"status": "ok"})
            return
        self.send_json({"error": "not found"}, 404)


def start_gateway_client(domain: str) -> None:
    """Connect to gateway and relay requests."""
    global gateway_ws, gateway_device_id

    def build_url(d: str) -> str:
        if d.startswith("wss://") or d.startswith("https://"):
            return d + "/ws"
        return "wss://" + d + "/ws"

    def send_ws_frame(sock, data: bytes):
        frame = bytearray()
        frame.append(0x81)
        length = len(data)
        if length < 126:
            frame.append(0x80 | length)
        elif length < 65536:
            frame.append(0x80 | 126)
            frame.extend(struct.pack(">H", length))
        else:
            frame.append(0x80 | 127)
            frame.extend(struct.pack(">Q", length))
        mask = secrets.token_bytes(4)
        frame.extend(mask)
        masked = bytearray(data)
        for i in range(len(masked)):
            masked[i] ^= mask[i & 3]
        frame.extend(masked)
        sock.sendall(bytes(frame))

    def recv_ws_frame(sock) -> bytes:
        first = sock.recv(1)[0]
        second = sock.recv(1)[0]
        length = second & 0x7F
        if length == 126:
            length = struct.unpack(">H", sock.recv(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", sock.recv(8))[0]
        payload = b""
        while len(payload) < length:
            chunk = sock.recv(length - len(payload))
            if not chunk:
                break
            payload += chunk
        return payload

    def handle_request(req: dict) -> dict:
        """Handle incoming request from gateway, relay to local MCP."""
        req_id, method, params = parse_jsonrpc_request(req)
        tool_name = params.get("name", "") if params else ""
        tool_params = params.get("params", {}) if params else {}
        cwd = tool_params.get("cwd", ".")

        if tool_name == "read":
            result = read_file(tool_params.get("path", ""), cwd)
        elif tool_name == "write":
            result = write_file(tool_params.get("path", ""), tool_params.get("content", ""), cwd)
        elif tool_name == "edit":
            result = edit_file(tool_params.get("path", ""), tool_params.get("old_str", ""),
                              tool_params.get("new_str", ""), cwd)
        elif tool_name == "bash":
            result = execute_bash(tool_params.get("command", ""), cwd)
        elif tool_name == "grep":
            result = grep_files(tool_params.get("pattern", ""),
                               tool_params.get("paths", ["."]), cwd)
        elif tool_name == "find":
            result = find_files(tool_params.get("pattern", ""), cwd)
        elif tool_name == "ls":
            result = list_directory(tool_params.get("path", "."), cwd)
        else:
            result = {"error": f"Unknown tool: {tool_name}", "success": False}

        return jsonrpc_response(req_id, result)

    while True:
        try:
            url = build_url(domain)
            print(f"[gateway] connecting to {url}", file=sys.stderr)

            uri = urllib.parse.urlparse(url)
            host = uri.hostname or domain
            port = uri.port or 443

            context = ssl.create_default_context()

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print(f"[gateway] connecting socket to {host}:{port}...", file=sys.stderr)
            ssock = context.wrap_socket(sock, server_hostname=host)
            ssock.connect((host, port))
            print(f"[gateway] socket connected", file=sys.stderr)
            ssock.settimeout(60)

            ws_key = base64.b64encode(secrets.token_bytes(16)).decode()
            request = (
                f"GET /ws HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n\r\n"
            )
            print(f"[gateway] sending WebSocket handshake...", file=sys.stderr)
            ssock.sendall(request.encode())

            print(f"[gateway] waiting for response...", file=sys.stderr)
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = ssock.recv(4096)
                if not chunk:
                    print(f"[gateway] received empty chunk", file=sys.stderr)
                    break
                resp += chunk
                print(f"[gateway] received {len(resp)} bytes", file=sys.stderr)

            print(f"[gateway] full response ({len(resp)} bytes): {resp.decode()[:500]}", file=sys.stderr)
            if "101" not in resp.decode():
                print("[gateway] WebSocket upgrade failed", file=sys.stderr)
                time.sleep(3)
                continue

            device_id = str(uuid.uuid4())
            register = json.dumps({"type": "register", "deviceId": device_id})
            send_ws_frame(ssock, register.encode())
            print(f"[gateway] registered as {device_id}", file=sys.stderr)

            while True:
                try:
                    payload = recv_ws_frame(ssock)
                    if not payload:
                        break
                    msg = json.loads(payload.decode())
                    if "request" in msg:
                        resp = handle_request(msg["request"])
                        send_ws_frame(ssock, json.dumps(resp).encode())
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[gateway] error: {e}", file=sys.stderr)
                    break

        except Exception as e:
            print(f"[gateway] error: {e}", file=sys.stderr)
            time.sleep(3)


def signal_handler(sig, frame):
    global shutting_down
    shutting_down = True
    sys.exit(0)


def main():
    global port, token, gateway_domain

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    parse_args(sys.argv[1:])

    if gateway_domain:
        t = threading.Thread(target=start_gateway_client, args=(gateway_domain,), daemon=True)
        t.start()

    server = ThreadingHTTPServer(("0.0.0.0", port), MCPRequestHandler)
    print(f"code-mcp listening on http://localhost:{port}/mcp"
          f"{' (auth: ?token=...)' if token else ' (no auth)'}", file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
