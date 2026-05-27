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
import select
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
import urllib.request
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
MAX_OUTPUT = 1_000_000
OUTPUT_CAP_KEEP = 500_000

# Global state
jobs: dict[str, dict] = {}
job_seq = 0
total_jobs = 0
shutting_down = False
port = DEFAULT_PORT
token: Optional[str] = None
gateway_domain: Optional[str] = None
gateway_device_id: Optional[str] = None
gateway_lock = threading.Lock()
assigned_device_id: Optional[str] = None
memory_enabled = False
has_cloudflared = False
mcp_config_path: Optional[str] = None
cloudflare_tunnel_url: Optional[str] = None

def check_cloudflared() -> bool:
    try:
        result = subprocess.run(
            ["cloudflared", "--version"],
            capture_output=True, timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


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


def parse_args(args: list[str]) -> tuple[int, str | None, str | None, str | None]:
    """Returns (port, token, gateway_domain, device_id). memory_enabled and has_cloudflared are set globally."""
    global memory_enabled, has_cloudflared, mcp_config_path
    port = DEFAULT_PORT
    token = None
    gateway_domain = None
    device_id = None
    memory_enabled = False
    has_cloudflared = check_cloudflared()
    mcp_config_path = None
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
        elif arg == "--id" and i + 1 < len(args):
            device_id = args[i + 1]
            i += 2
        elif arg == "--enable-memory":
            memory_enabled = True
            i += 1
        elif arg == "--mcp" and i + 1 < len(args):
            mcp_config_path = args[i + 1]
            i += 2
        elif arg == "-h" or arg == "--help":
            print(USAGE)
            sys.exit(0)
        else:
            i += 1
    return port, token, gateway_domain, device_id


USAGE = """Code MCP - Minimal MCP server over HTTP

Usage: code_mcp.py [flags]

Flags:
  --port <n>        Listen port (default: 7777)
  --token <s>       Require ?token=<s> on every request
  --gateway <url>   Connect to gateway server (wss:// or https://)
  --id <uuid>       Use specific device ID for gateway connection
  --enable-memory   Enable remember/forget/recall tools

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


def read_file(path: str, cwd: str = ".") -> str:
    try:
        ok, full_path, err = safe_resolve(cwd, path)
        if not ok:
            return f"ERROR: {err}"
        return full_path.read_text(errors="replace")
    except Exception as e:
        return f"ERROR: {e}"


def write_file(path: str, content: str, cwd: str = ".") -> str:
    try:
        ok, full_path, err = safe_resolve(cwd, path)
        if not ok:
            return f"ERROR: {err}"
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content)
        return f"wrote {len(content)} bytes to {path}"
    except Exception as e:
        return f"ERROR: {e}"


def edit_file(path: str, old_str: str, new_str: str, cwd: str = ".") -> str:
    try:
        ok, full_path, err = safe_resolve(cwd, path)
        if not ok:
            return f"ERROR: {err}"
        content = full_path.read_text()
        if old_str not in content:
            return f"ERROR: String not found"
        if content.count(old_str) > 1:
            return f"ERROR: old_str not unique"
        new_content = content.replace(old_str, new_str, 1)
        full_path.write_text(new_content)
        return "ok"
    except Exception as e:
        return f"ERROR: {e}"


def multi_edit_files(edits: list[dict], cwd: str = ".") -> str:
    try:
        originals = {}  # resolved_path(string) -> original_text
        ranges = []  # list of (resolved_path, start, end, replacement, index)

        for i, edit in enumerate(edits):
            path = edit["path"]
            old_str = edit["old_str"]
            new_str = edit["new_str"]
            ok, full_path, err = safe_resolve(cwd, path)
            if not ok:
                return f"ERROR: edit #{i+1}: {err}"
            resolved = str(full_path)
            if resolved not in originals:
                originals[resolved] = full_path.read_text()
            text = originals[resolved]
            if old_str not in text:
                return f"ERROR: edit #{i+1} ({path}): old_str not found"
            if text.count(old_str) > 1:
                return f"ERROR: edit #{i+1} ({path}): old_str not unique"
            first = text.index(old_str)
            start = first
            end = first + len(old_str)
            # Check overlap with existing ranges for same file
            for r_start, r_end, _, r_idx in ranges:
                if resolved == r[0] and start < r_end and end > r_start:
                    return f"ERROR: edit #{i+1} ({path}): overlaps edit #{r_idx+1}"
            ranges.append((resolved, start, end, new_str, i))

        # Apply edits in reverse order so offsets stay valid
        for resolved, start, end, replacement, idx in sorted(ranges, key=lambda x: -x[1]):
            text = originals[resolved]
            originals[resolved] = text[:start] + replacement + text[end:]

        # Write all files
        for resolved, new_content in originals.items():
            Path(resolved).write_text(new_content)
        return "ok"
    except Exception as e:
        return f"ERROR: {e}"


def execute_bash(command: str, cwd: str = ".") -> str:
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
        if stderr:
            return stdout + "\n" + stderr
        return stdout
    except subprocess.TimeoutExpired:
        return "ERROR: Timeout"
    except Exception as e:
        return f"ERROR: {e}"


def execute_shell(command: str, cwd: str = ".") -> str:
    try:
        result = subprocess.run(
            command,
            shell=True,
            executable="/bin/sh",
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, "HOME": os.path.expanduser("~")}
        )
        stdout = result.stdout[-MAX_OUTPUT:] if len(result.stdout) > MAX_OUTPUT else result.stdout
        stderr = result.stderr[-OUTPUT_CAP_KEEP:] if len(result.stderr) > OUTPUT_CAP_KEEP else result.stderr
        if stderr:
            return stdout + "\n" + stderr
        return stdout
    except subprocess.TimeoutExpired:
        return "ERROR: Timeout"
    except Exception as e:
        return f"ERROR: {e}"


def execute_powershell(command: str, cwd: str = ".") -> str:
    # Try pwsh first, fallback to powershell.exe on Windows
    pwsh_cmd = "pwsh" if sys.platform != "win32" else "powershell"
    try:
        result = subprocess.run(
            [pwsh_cmd, "-Command", command],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, "HOME": os.path.expanduser("~")}
        )
        stdout = result.stdout[-MAX_OUTPUT:] if len(result.stdout) > MAX_OUTPUT else result.stdout
        stderr = result.stderr[-OUTPUT_CAP_KEEP:] if len(result.stderr) > OUTPUT_CAP_KEEP else result.stderr
        if stderr:
            return stdout + "\n" + stderr
        return stdout
    except subprocess.TimeoutExpired:
        return "ERROR: Timeout"
    except FileNotFoundError:
        return f"ERROR: PowerShell ({pwsh_cmd}) not found on PATH"
    except Exception as e:
        return f"ERROR: {e}"


def grep_files(pattern: str, paths: list[str], cwd: str = ".", glob: str | None = None) -> str:
    try:
        valid_paths = []
        for p in paths:
            ok, full_path, err = safe_resolve(cwd, p)
            if not ok:
                return f"ERROR: {err}"
            valid_paths.append(str(full_path))
        if has_rg():
            cmd = ["rg", "--line-number", "--no-heading", "--color=never"]
            if glob:
                cmd.extend(["--glob", glob])
            cmd.extend([pattern] + valid_paths)
        else:
            cmd = ["grep", "-rn"]
            if glob:
                cmd.extend(["--include", glob])
            cmd.extend([pattern] + valid_paths)
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.stdout:
            return result.stdout
        if result.returncode == 1:
            return "(no matches)"
        return f"ERROR (exit={result.returncode}): {result.stderr}"
    except Exception as e:
        return f"ERROR: {e}"


def find_files(pattern: str, cwd: str = ".", include_hidden: bool = False) -> str:
    try:
        ok, full_path, err = safe_resolve(cwd, ".")
        if not ok:
            return f"ERROR: {err}"
        pat = pattern if "/" in pattern or "\\" in pattern else f"**/{pattern}"
        matches = list(Path(full_path).glob(pat))
        noise_dirs = {"node_modules", ".git", ".next", ".nuxt", ".turbo", ".cache",
                      "dist", "build", "out", "target", "coverage",
                      ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
                      ".idea", ".vscode"}
        results = []
        for m in matches[:10000]:
            if m.is_dir():
                continue
            parts = m.parts
            skip = False
            for seg in parts:
                if seg in noise_dirs and seg not in parts:
                    skip = True
                    break
                if not include_hidden and seg.startswith(".") and seg not in [".", ".."]:
                    if not pattern.startswith("."):
                        skip = True
                        break
            if not skip:
                results.append(str(m))
        if not results:
            return "(no matches)"
        return "\n".join(results[:100])
    except Exception as e:
        return f"ERROR: {e}"


def list_directory(path: str = ".", cwd: str = ".") -> str:
    try:
        ok, full_path, err = safe_resolve(cwd, path)
        if not ok:
            return f"ERROR: {err}"
        entries = []
        for entry in full_path.iterdir():
            try:
                st = entry.stat()
                prefix = "d" if entry.is_dir() else "-"
                size = st.st_size if entry.is_file() else 0
                entries.append(f"{prefix}{size:>10} {entry.name}")
            except PermissionError:
                entries.append(f"? {entry.name}")
        return "\n".join(sorted(entries))
    except Exception as e:
        return f"ERROR: {e}"


def get_job_status(job_id: str) -> dict:
    if job_id in jobs:
        return {"status": jobs[job_id].get("status", "unknown"), "success": True}
    return {"error": "Job not found", "success": False}


def list_jobs() -> str:
    if not jobs:
        return "(no jobs)"
    lines = []
    for jid, j in jobs.items():
        status = j.get("status", "unknown")
        exit_info = f" {j.get('exit_code')}" if j.get("exit_code") is not None else ""
        lines.append(f"{jid} [{status}{exit_info}] {j.get('command', '')}")
    return "\n".join(lines)


def start_job(command: str, cwd: str) -> str:
    global total_jobs, job_seq
    if total_jobs >= MAX_CONCURRENT_JOBS:
        return f"ERROR: max concurrent jobs ({MAX_CONCURRENT_JOBS}) exceeded"
    if shutting_down:
        return "ERROR: server is shutting down"

    total_jobs += 1
    job_seq += 1
    job_id = f"j{job_seq}"

    try:
        proc = subprocess.Popen(
            command,
            shell=True,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
        )
    except Exception as e:
        total_jobs -= 1
        return f"ERROR: failed to start job: {e}"

    job = {
        "id": job_id,
        "command": command,
        "proc": proc,
        "output": "",
        "status": "running",
        "started_at": time.time(),
    }
    jobs[job_id] = job

    def pump_and_finalize():
        try:
            stdout, stderr = proc.communicate()
            job["output"] = (stdout + stderr)[:MAX_OUTPUT]
        except Exception:
            pass
        finally:
            job["status"] = "exited"
            job["exit_code"] = proc.returncode
            global total_jobs
            total_jobs = max(0, total_jobs - 1)

    t = threading.Thread(target=pump_and_finalize, daemon=True)
    t.start()

    return f"started {job_id}"


def stop_job(job_id: str, timeout_ms: int = 500) -> str:
    if job_id not in jobs:
        return f"ERROR: no such job: {job_id}"
    job = jobs[job_id]
    if job["status"] != "running":
        return f"{job_id} already {job['status']}"

    proc = job["proc"]
    proc.terminate()
    try:
        proc.wait(timeout=timeout_ms / 1000)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    return f"{job_id} stopped"


def view_job(job_id: str) -> str:
    if job_id not in jobs:
        return f"ERROR: no such job: {job_id}"
    job = jobs[job_id]
    status = job.get("status", "unknown")
    exit_code = job.get("exit_code")
    output = job.get("output", "")
    exit_info = f" {exit_code}" if exit_code is not None else ""
    return f"[{job_id}] {job.get('command', '')}\n[{status}{exit_info}]\n{output}"


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

        if method == "initialize":
            # MCP handshake: return server info
            self.send_json(jsonrpc_response(req_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "code-mcp", "version": "0.1.0"}
            }))
            return

        if method == "notifications/initialized":
            # MCP handshake: client notification, no response needed
            return

        if method == "ping":
            self.send_json(jsonrpc_response(req_id, {}))
            return

        if method == "tools/list":
            tools = [
                {"name": "read", "description": "Read a file. Optional line range [start,end] (1-indexed, inclusive). Pass no_truncate=true to disable output truncation.",
                 "inputSchema": {"type": "object", "properties": {"cwd": {"type": "string"}, "path": {"type": "string"}, "range": {"type": "array", "items": {"type": "number"}}, "no_truncate": {"type": "boolean"}}, "required": ["cwd", "path"]}},
                {"name": "write", "description": "Write/overwrite a file with the given content.",
                 "inputSchema": {"type": "object", "properties": {"cwd": {"type": "string"}, "path": {"type": "string"}, "content": {"type": "string"}}, "required": ["cwd", "path", "content"]}},
                {"name": "edit", "description": "Replace old_str with new_str in a file. old_str must occur exactly once.",
                 "inputSchema": {"type": "object", "properties": {"cwd": {"type": "string"}, "path": {"type": "string"}, "old_str": {"type": "string"}, "new_str": {"type": "string"}}, "required": ["cwd", "path", "old_str", "new_str"]}},
                {"name": "multi_edit", "description": "Apply multiple edits atomically across one or more files. Validates every edit first; if any fails, nothing is written. Edits to the same file are applied in order.",
                 "inputSchema": {"type": "object", "properties": {"cwd": {"type": "string"}, "edits": {"type": "array", "items": {"type": "object", "properties": {"path": {"type": "string"}, "old_str": {"type": "string"}, "new_str": {"type": "string"}}, "required": ["path", "old_str", "new_str"]}}}, "required": ["cwd", "edits"]}},
                # Shell tool based on detected OS
                {"name": "bash" if shell_type == ShellType.BASH else "shell" if shell_type == ShellType.SH else "command" if shell_type == ShellType.CMD else "powershell", "description": "Run a command in the detected shell. Block until exit, return combined stdout+stderr.",
                 "inputSchema": {"type": "object", "properties": {"cwd": {"type": "string"}, "command": {"type": "string"}, "timeout_ms": {"type": "number"}}, "required": ["cwd", "command"]}},
                {"name": "grep", "description": "Search files by regex. Uses ripgrep if available, else findstr (Windows) or grep (POSIX).",
                 "inputSchema": {"type": "object", "properties": {"cwd": {"type": "string"}, "pattern": {"type": "string"}, "path": {"type": "string"}, "glob": {"type": "string"}}, "required": ["cwd", "pattern"]}},
                {"name": "find", "description": "Find files by glob pattern. Supports ** for recursive. Skips common noise dirs unless pattern explicitly references them.",
                 "inputSchema": {"type": "object", "properties": {"cwd": {"type": "string"}, "pattern": {"type": "string"}, "path": {"type": "string"}, "include_hidden": {"type": "boolean"}}, "required": ["cwd", "pattern"]}},
                {"name": "ls", "description": "List directory entries with type and size.",
                 "inputSchema": {"type": "object", "properties": {"cwd": {"type": "string"}, "path": {"type": "string"}}, "required": ["cwd"]}},
                {"name": "job", "description": "Manage background jobs. mode: list|view|start|stop. command required for start; id (passed as command) required for view/stop. cwd used only for start.",
                 "inputSchema": {"type": "object", "properties": {"cwd": {"type": "string"}, "mode": {"type": "string", "enum": ["list", "view", "start", "stop"]}, "command": {"type": "string"}, "timeout_ms": {"type": "number"}}, "required": ["cwd", "mode"]}},
            ]
            if memory_enabled:
                tools.extend([
                    {"name": "remember", "description": "Append a memo. Returns the assigned id.",
                     "inputSchema": {"type": "object", "properties": {"cwd": {"type": "string"}, "memo": {"type": "string"}, "tags": {"type": "array", "items": {"type": "string"}}}, "required": ["cwd", "memo"]}},
                    {"name": "forget", "description": "Remove a memo by id.",
                     "inputSchema": {"type": "object", "properties": {"cwd": {"type": "string"}, "memo_id": {"type": "number"}}, "required": ["cwd", "memo_id"]}},
                    {"name": "recall", "description": "Search memos by substring (query) and/or tags (AND). Sorted newest first. Paginated.",
                     "inputSchema": {"type": "object", "properties": {"cwd": {"type": "string"}, "query": {"type": "string"}, "tags": {"type": "array", "items": {"type": "string"}}, "limit": {"type": "number"}, "offset": {"type": "number"}}, "required": ["cwd"]}},
                ])
            if has_cloudflared:
                tools.append({"name": "preview", "description": "Start a Cloudflare quick tunnel.",
                 "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}})
            # mcp tool disabled - not yet implemented in Python
            # tools.append({"name": "mcp", "description": "Manage MCP servers.",
            #  "inputSchema": {"type": "object", "properties": {"cwd": {"type": "string"}, "action": {"type": "string", "enum": ["list", "call", "unload"]}, "server": {"type": "string"}, "tool": {"type": "string"}, "args": {"type": "object"}, "mcpConfigPath": {"type": "string"}}, "required": ["cwd", "action"]}})
            self.send_json(jsonrpc_response(req_id, {"tools": tools}))
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
            elif tool_name == "shell":
                result = execute_shell(tool_params.get("command", ""), cwd)
            elif tool_name == "powershell":
                result = execute_powershell(tool_params.get("command", ""), cwd)
            elif tool_name == "grep":
                result = grep_files(tool_params.get("pattern", ""),
                                   [tool_params.get("path", ".")], cwd,
                                   tool_params.get("glob"))
            elif tool_name == "find":
                result = find_files(tool_params.get("pattern", ""), cwd, tool_params.get("include_hidden", False))
            elif tool_name == "ls":
                result = list_directory(tool_params.get("path", "."), cwd)
            elif tool_name == "job":
                mode = tool_params.get("mode", "list")
                if mode == "list":
                    result = list_jobs()
                elif mode == "start":
                    cmd = tool_params.get("command")
                    if not cmd:
                        result = {"error": "command required", "success": False}
                    else:
                        result = start_job(cmd, cwd)
                elif mode == "stop":
                    cmd = tool_params.get("command")
                    if not cmd:
                        result = {"error": "job id required (pass as command)", "success": False}
                    else:
                        result = stop_job(cmd, tool_params.get("timeout_ms", 500))
                elif mode == "view":
                    cmd = tool_params.get("command")
                    if not cmd:
                        result = {"error": "job id required (pass as command)", "success": False}
                    else:
                        result = view_job(cmd)
                else:
                    result = {"error": f"unknown mode: {mode}", "success": False}
            elif tool_name == "remember":
                result = handle_remember(cwd, tool_params.get("memo", ""),
                                       tool_params.get("tags"))
            elif tool_name == "forget":
                try:
                    result = handle_forget(cwd, tool_params.get("memo_id", 0))
                except ValueError as e:
                    result = {"error": str(e), "success": False}
            elif tool_name == "recall":
                result = handle_recall(cwd,
                                       tool_params.get("query"),
                                       tool_params.get("tags"),
                                       tool_params.get("limit", 20),
                                       tool_params.get("offset", 0))
            elif tool_name == "preview":
                result = handle_preview(tool_params.get("url", ""))
            # mcp tool not implemented in Python
            else:
                result = {"error": f"Unknown tool: {tool_name}", "success": False}

            # Wrap in content format for tools/call (MCP standard)
            text = result if isinstance(result, str) else json.dumps(result)
            result = {"content": [{"type": "text", "text": text}]}

            self.send_json(jsonrpc_response(req_id, result))
            return

        # Handle raw methods directly (like Java/TypeScript MCP servers)
        tool_name = method
        tool_params = params if params else {}
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
                               [tool_params.get("path", ".")], cwd,
                               tool_params.get("glob"))
        elif tool_name == "find":
            result = find_files(tool_params.get("pattern", ""), cwd, tool_params.get("include_hidden", False))
        elif tool_name == "ls":
            result = list_directory(tool_params.get("path", "."), cwd)
        elif tool_name == "job":
            mode = tool_params.get("mode", "list")
            if mode == "list":
                result = list_jobs()
            elif mode == "start":
                cmd = tool_params.get("command")
                result = start_job(cmd, cwd) if cmd else {"error": "command required"}
            elif mode == "stop":
                result = stop_job(tool_params.get("command", ""), tool_params.get("timeout_ms", 500))
            elif mode == "view":
                result = view_job(tool_params.get("command", ""))
            else:
                result = f"ERROR: unknown mode: {mode}"
        elif tool_name == "remember":
            result = handle_remember(cwd, tool_params.get("memo", ""), tool_params.get("tags"))
        elif tool_name == "forget":
            try:
                result = handle_forget(cwd, tool_params.get("memo_id", 0))
            except ValueError as e:
                result = f"ERROR: {e}"
        elif tool_name == "recall":
            result = handle_recall(cwd, tool_params.get("query"), tool_params.get("tags"),
                                   tool_params.get("limit", 20), tool_params.get("offset", 0))
        else:
            result = f"ERROR: Unknown tool: {tool_name}"

        self.send_json(jsonrpc_response(req_id, result))

    def do_GET(self):
        if not self.authenticate():
            return

        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/mcp":
            self.send_json({"status": "ok"})
            return
        self.send_json({"error": "not found"}, 404)


def start_gateway_client(domain: str, device_id: str | None) -> None:
    """Connect to gateway and relay requests."""
    global gateway_ws, gateway_device_id, assigned_device_id

    def build_url(d: str, dev_id: str | None) -> str:
        # Determine scheme: wss for production (anything not localhost/127.x), ws for local
        if d.startswith("wss://") or d.startswith("https://"):
            base = d.replace("https://", "wss://")
        elif d.startswith("ws://") or d.startswith("http://"):
            base = d.replace("http://", "ws://")
        else:
            # No scheme specified - use wss for production, ws for localhost/127.x
            is_local = d.startswith("localhost") or d.startswith("127.") or d.startswith("192.168.") or d.startswith("10.") or d.startswith("172.16.")
            base = ("ws://" if is_local else "wss://") + d
        if dev_id:
            return base + "/ws/" + dev_id
        return base + "/ws"

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

    def recv_ws_frame(sock) -> bytes | None:
        def _recv_exact(sock, size: int) -> bytes | None:
            data = b""
            while len(data) < size:
                try:
                    chunk = sock.recv(size - len(data))
                    if not chunk:
                        return None
                    data += chunk
                except ssl.SSLError as e:
                    # SSL_ERROR_WANT_READ means retry, not connection closed
                    if e.errno == ssl.SSL_ERROR_WANT_READ:
                        continue
                    raise
            return data

        try:
            first = _recv_exact(sock, 1)
            if not first:
                return None
            first = first[0]
            second = _recv_exact(sock, 1)
            if not second:
                return None
            second = second[0]
            length = second & 0x7F
            if length == 126:
                length = struct.unpack(">H", _recv_exact(sock, 2))[0]
            elif length == 127:
                length = struct.unpack(">Q", _recv_exact(sock, 8))[0]
            payload = b""
            while len(payload) < length:
                chunk = _recv_exact(sock, length - len(payload))
                if not chunk:
                    break
                payload += chunk
            return payload
        except ssl.SSLError as e:
            print(f"[gateway] SSL error: {e}", file=sys.stderr)
            return None
        except Exception as e:
            print(f"[gateway] recv error: {e}", file=sys.stderr)
            return None

    def handle_request(req: dict) -> dict:
        """Handle incoming request from gateway, relay to local MCP."""
        req_id, method, params = parse_jsonrpc_request(req)

        # Support both raw method names and tools/call pattern
        is_tools_call = method == "tools/call"
        if is_tools_call:
            tool_name = params.get("name", "") if params else ""
            tool_params = params.get("arguments", {}) if params else {}
        else:
            tool_name = method
            tool_params = params if params else {}

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
                               [tool_params.get("path", ".")], cwd,
                               tool_params.get("glob"))
        elif tool_name == "find":
            result = find_files(tool_params.get("pattern", ""), cwd)
        elif tool_name == "ls":
            result = list_directory(tool_params.get("path", "."), cwd)
        elif tool_name == "job":
            mode = tool_params.get("mode", "list")
            if mode == "list":
                result = list_jobs()
            elif mode == "start":
                cmd = tool_params.get("command")
                result = start_job(cmd, cwd) if cmd else "ERROR: command required"
            elif mode == "stop":
                result = stop_job(tool_params.get("command", ""), tool_params.get("timeout_ms", 500))
            elif mode == "view":
                result = view_job(tool_params.get("command", ""))
            else:
                result = f"ERROR: unknown mode: {mode}"
        elif tool_name == "remember":
            result = handle_remember(cwd, tool_params.get("memo", ""), tool_params.get("tags"))
        elif tool_name == "forget":
            try:
                result = handle_forget(cwd, tool_params.get("memo_id", 0))
            except ValueError as e:
                result = f"ERROR: {e}"
        elif tool_name == "recall":
            result = handle_recall(cwd, tool_params.get("query"), tool_params.get("tags"),
                                   tool_params.get("limit", 20), tool_params.get("offset", 0))
        else:
            result = f"ERROR: Unknown tool: {tool_name}"

        # Wrap in content format for tools/call (MCP standard)
        if is_tools_call:
            text = result if isinstance(result, str) else json.dumps(result)
            result = {"content": [{"type": "text", "text": text}]}

        return jsonrpc_response(req_id, result)

    while True:
        try:
            url = build_url(domain, device_id)
            print(f"[gateway] connecting to {url}", file=sys.stderr)

            uri = urllib.parse.urlparse(url)
            host = uri.hostname or domain
            gateway_port = uri.port or (443 if uri.scheme == "wss" else 80)

            use_ssl = url.startswith("wss://") or url.startswith("https://")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print(f"[gateway] connecting socket to {host}:{gateway_port}...", file=sys.stderr)
            if use_ssl:
                context = ssl.create_default_context()
                ssock = context.wrap_socket(sock, server_hostname=host)
                ssock.connect((host, gateway_port))
            else:
                ssock = sock
                ssock.connect((host, gateway_port))
            print(f"[gateway] socket connected", file=sys.stderr)
            ssock.settimeout(60)

            ws_key = base64.b64encode(secrets.token_bytes(16)).decode()
            request = (
                f"GET {uri.path} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                f"Accept: */*\r\n"
                f"\r\n"
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

            # Extract HTTP headers only (before \r\n\r\n) to check for 101
            header_end = resp.find(b"\r\n\r\n")
            if header_end == -1 or "101" not in resp[:header_end].decode(errors="replace"):
                print("[gateway] WebSocket upgrade failed", file=sys.stderr)
                time.sleep(3)
                continue
            print(f"[gateway] WebSocket upgrade confirmed", file=sys.stderr)

            # Consume any buffered WebSocket frame data from the upgrade response
            # (the 239 bytes included the HTTP response + first frame)
            import errno
            try:
                ssock.setblocking(False)
                while True:
                    try:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                    except BlockingIOError as e:
                        if e.errno == errno.EAGAIN or e.errno == errno.EWOULDBLOCK:
                            break
                        raise
                ssock.setblocking(True)
            except Exception:
                pass

            if not device_id:
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
                        # Forward to local MCP HTTP server like Java/TS clients do
                        tunnel_req = msg["request"]
                        tunnel_id = msg["id"]
                        token = msg.get("token")

                        # Call local MCP server via HTTP
                        token_param = f"?token={token}" if token else ""
                        local_url = f"http://localhost:{port}/mcp{token_param}"

                        req_data = json.dumps(tunnel_req).encode()
                        http_req = urllib.request.Request(local_url, data=req_data, headers={"Content-Type": "application/json"})
                        try:
                            http_resp = urllib.request.urlopen(http_req, timeout=30)
                            resp = json.loads(http_resp.read().decode())
                        except Exception as e:
                            resp = {"jsonrpc": "2.0", "id": tunnel_req.get("id"), "error": {"code": -32603, "message": str(e)}}

                        # Wrap in TunnelResponse format expected by gateway
                        tunnel_resp = {"id": tunnel_id, "response": resp}
                        send_ws_frame(ssock, json.dumps(tunnel_resp).encode())
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[gateway] error: {e}", file=sys.stderr)
                    break

        except Exception as e:
            print(f"[gateway] error: {e}", file=sys.stderr)
            time.sleep(3)


# ---------- memos ----------
MEMO_FILE = ".memo.jsonl"
MEMO_TAIL_BYTES = 8192


def read_memos(cwd: str) -> list[dict]:
    path = Path(cwd) / MEMO_FILE
    if not path.exists():
        return []
    try:
        with open(path, "r") as f:
            content = f.read()
        return [json.loads(line) for line in content.split("\n") if line.strip()]
    except Exception:
        return []


def write_memos(cwd: str, memos: list[dict]):
    path = Path(cwd) / MEMO_FILE
    with open(path, "w") as f:
        for m in memos:
            f.write(json.dumps(m) + "\n")


def last_memo_id(cwd: str) -> int:
    path = Path(cwd) / MEMO_FILE
    if not path.exists():
        return 0
    try:
        size = path.stat().st_size
        if size == 0:
            return 0
        with open(path, "rb") as f:
            f.seek(max(0, size - MEMO_TAIL_BYTES))
            tail = f.read().decode("utf-8", errors="replace")
        lines = tail.split("\n")
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                m = json.loads(line)
                if isinstance(m, dict) and "id" in m:
                    return m["id"]
            except Exception:
                continue
        # fallback: full scan
        memos = read_memos(cwd)
        return max((m["id"] for m in memos if "id" in m), default=0)
    except Exception:
        return 0


def handle_remember(cwd: str, memo: str, tags: list | None = None) -> str:
    memo_id = last_memo_id(cwd) + 1
    entry = {"id": memo_id, "ts": int(time.time() * 1000), "memo": memo}
    if tags:
        entry["tags"] = tags
    path = Path(cwd) / MEMO_FILE
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return f"remembered #{memo_id}"


def handle_forget(cwd: str, memo_id: int) -> str:
    memos = read_memos(cwd)
    before = len(memos)
    kept = [m for m in memos if m.get("id") != memo_id]
    if len(kept) == before:
        raise ValueError(f"no memo with id {memo_id}")
    write_memos(cwd, kept)
    return f"forgot #{memo_id}"


def handle_recall(cwd: str, query: str | None = None, tags: list | None = None,
                  limit: int = 20, offset: int = 0) -> str:
    memos = read_memos(cwd)
    q = query.lower() if query else None
    filtered = []
    for m in memos:
        if q and q not in m.get("memo", "").lower():
            continue
        if tags and not all(t in m.get("tags", []) for t in tags):
            continue
        filtered.append(m)
    filtered.sort(key=lambda m: m.get("id", 0), reverse=True)
    total = len(filtered)
    if not total:
        return "(no matches)"
    page = filtered[offset:offset + limit]
    lines = []
    for m in page:
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(m.get("ts", 0) / 1000))
        tag_str = f" [{','.join(m['tags'])}]" if m.get("tags") else ""
        lines.append(f"#{m['id']} {ts}{tag_str} {m['memo']}")
    end = offset + len(page)
    footer = f"-- {offset + 1}-{end} of {total}"
    if end < total:
        footer += f" (next: offset={end})"
    return "\n".join(lines) + "\n" + footer


def handle_preview(url: str) -> str:
    if not has_cloudflared:
        return "ERROR: cloudflared not found on PATH"
    global cloudflare_tunnel_url
    if cloudflare_tunnel_url:
        return f"tunnel already running: {cloudflare_tunnel_url}"
    try:
        proc = subprocess.Popen(
            ["cloudflared", "tunnel", "--url", url, "--no-autoupdate"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        deadline = time.time() + 20
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    return "ERROR: cloudflared exited"
                continue
            m = re.match(r"https://[a-z0-9-]+\.trycloudflare\.com", line)
            if m:
                cloudflare_tunnel_url = m.group(0)
                return f"tunnel ready: {cloudflare_tunnel_url}"
        proc.terminate()
        return "ERROR: tunnel URL not received within 20s"
    except Exception as e:
        return f"ERROR: {e}"


# MCP server state management
mcp_servers: dict[str, dict] = {}  # key: "cwd:servername"
mcp_processes: dict[str, subprocess.Popen] = {}  # key: "cwd:servername"
mcp_next_id = 0
mcp_lock = threading.Lock()


def handle_mcp(action: str, server: str, tool: str, args: dict, mcp_config_path: str, cwd: str = ".") -> str:
    """Handle mcp tool actions: list, call, unload."""
    config_path = mcp_config_path or ".mcp.json"

    if action == "list":
        # List available servers from config
        try:
            config_full_path = Path(cwd) / config_path
            if not config_full_path.exists():
                return json.dumps({"servers": [], "mcpConfigPath": config_path})
            with open(config_full_path) as f:
                config = json.load(f)
            servers = config.get("mcpServers", {})
            result = []
            for name in servers:
                key = f"{cwd}:{name}"
                is_loaded = key in mcp_servers
                result.append({
                    "name": name,
                    "status": "loaded" if is_loaded else "unloaded",
                    "tools": mcp_servers.get(key, {}).get("tools", []) if is_loaded else []
                })
            return json.dumps({"servers": result, "mcpConfigPath": config_path})
        except Exception as e:
            return json.dumps({"error": str(e)})

    if action == "call":
        if not server:
            return json.dumps({"error": "server name required for call action"})
        if not tool:
            return json.dumps({"error": "tool name required for call action"})

        try:
            config_full_path = Path(cwd) / config_path
            with open(config_full_path) as f:
                config = json.load(f)
            servers = config.get("mcpServers", {})
            if server not in servers:
                return json.dumps({"error": f"server '{server}' not found in .mcp.json"})
            server_config = servers[server]

            # Ensure server is spawned
            key = f"{cwd}:{server}"
            if key not in mcp_processes or mcp_processes[key].poll() is not None:
                # Spawn new server
                cmd = server_config.get("command")
                args_list = server_config.get("args", [])
                if isinstance(cmd, str):
                    cmd = cmd.split()
                proc = subprocess.Popen(
                    cmd + args_list,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=cwd
                )
                mcp_processes[key] = proc

                # Get initial tools/list
                tools_result = mcp_call(key, "tools/list", {})
                mcp_servers[key] = {
                    "tools": [t["name"] for t in tools_result.get("tools", [])]
                }

            # Make the tool call
            result = mcp_call(key, "tools/call", {"name": tool, "arguments": args or {}})
            return json.dumps(result)
        except Exception as e:
            return json.dumps({"error": str(e)})

    if action == "unload":
        key = f"{cwd}:{server}" if server else None
        if server:
            if key in mcp_processes:
                mcp_processes[key].terminate()
                del mcp_processes[key]
                if key in mcp_servers:
                    del mcp_servers[key]
            return json.dumps({"success": True})
        else:
            # Unload all for cwd
            keys_to_remove = [k for k in mcp_processes.keys() if k.startswith(f"{cwd}:")]
            for k in keys_to_remove:
                mcp_processes[k].terminate()
                del mcp_processes[k]
                if k in mcp_servers:
                    del mcp_servers[k]
            return json.dumps({"success": True})

    return json.dumps({"error": f"unknown action: {action}"})


def mcp_call(key: str, method: str, params: dict) -> dict:
    """Make a JSON-RPC call to an MCP server over stdio."""
    global mcp_next_id
    with mcp_lock:
        mcp_next_id += 1
        req_id = mcp_next_id

    proc = mcp_processes[key]
    request = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
    proc.stdin.write((json.dumps(request) + "\n").encode("utf-8"))
    proc.stdin.flush()

    # Read response
    while True:
        ready, _, _ = select.select([proc.stdout], [], [], 30)
        if not ready:
            raise TimeoutError("MCP server response timeout")
        line = proc.stdout.readline()
        if not line:
            raise EOFError("MCP server process ended")
        try:
            response = json.loads(line.decode("utf-8"))
            if isinstance(response, dict) and response.get("id") == req_id:
                if "error" in response:
                    return {"error": response["error"]}
                return response.get("result", {})
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue


def signal_handler(sig, frame):
    global shutting_down
    shutting_down = True
    sys.exit(0)


def main():
    global port, token, gateway_domain, assigned_device_id

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    port, token, gateway_domain, assigned_device_id = parse_args(sys.argv[1:])

    if gateway_domain:
        t = threading.Thread(target=start_gateway_client, args=(gateway_domain, assigned_device_id), daemon=True)
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
