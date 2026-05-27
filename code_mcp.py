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
DEFAULT_BIND = "127.0.0.1"
TIMEOUT_MS = 30_000
MAX_OUTPUT = 1_000_000
OUTPUT_CAP_KEEP = 500_000
UPLOAD_TTL_MS = 10 * 60 * 1000
MAX_CONCURRENT_JOBS = 10
MAX_REQUEST_BYTES = 100 * 1024 * 1024  # cap request body to 100MB (DoS guard)
MAX_GATEWAY_HEADER_BYTES = 64 * 1024   # cap WS handshake response headers
MAX_WS_FRAME_BYTES = 64 * 1024 * 1024  # cap WS frame payload (DoS guard)
DEFAULT_SHELL_TIMEOUT_MS = 30_000  # default kill-after for shell tools when caller doesn't pass timeout_ms
UPLOAD_TTL_S = 10 * 60  # session id valid for 10 minutes


def _timeout_marker(timeout_ms: int) -> str:
    return (f"\n[TIMEOUT after {timeout_ms}ms — long-running? use the `job` tool: "
            f"mode=start to launch, mode=view to check progress]")

# ---------- result spill ----------
# Tool results larger than RESULT_SPILL_THRESHOLD bytes are written to a file
# under RESULT_SPILL_ROOT and replaced in the response with a head + pointer.
# Matches Java/TS behaviour byte-for-byte so the three impls produce
# interchangeable output.
import tempfile as _tempfile
RESULT_SPILL_THRESHOLD = 10_000
RESULT_SPILL_HEAD = 3_000
RESULT_SPILL_ROOT = Path(_tempfile.gettempdir()) / "code-mcp"
try:
    RESULT_SPILL_ROOT.mkdir(parents=True, exist_ok=True)
except OSError:
    pass


def maybe_spill_text(text: str, tool_name: str = "") -> str:
    """If text exceeds RESULT_SPILL_THRESHOLD bytes, write it to a spill file
    and return a head preview + pointer. Otherwise return text unchanged.
    Mirrors maybeSpillText() in CodeMCP.java and code-mcp.ts."""
    if not isinstance(text, str):
        return text
    raw = text.encode("utf-8")
    if len(raw) <= RESULT_SPILL_THRESHOLD:
        return text
    head = raw[:RESULT_SPILL_HEAD].decode("utf-8", errors="replace")
    last_nl = head.rfind("\n")
    if last_nl > 0:
        head = head[:last_nl]
    ts = time.strftime("%Y%m%dT%H%M%S", time.gmtime()) + f"{int((time.time() % 1) * 1000):03d}"
    safe_tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool_name or "unknown")
    short_id = secrets.token_hex(4)
    fname = f"{ts}-{safe_tool}-{short_id}.txt"
    path = RESULT_SPILL_ROOT / fname
    total_lines = text.count("\n") + (0 if text.endswith("\n") else 1)
    try:
        path.write_text(text, encoding="utf-8")
    except OSError as e:
        return (head + f"\n[TRUNCATED: full output is {len(raw)} bytes "
                f"({total_lines} lines); spill to disk FAILED ({e})]\n")
    return (head + f"\n[TRUNCATED: {len(raw)} bytes ({total_lines} lines) "
            f"saved to {path} — use read with range or grep to view the remaining content]\n")

# Global state
jobs: dict[str, dict] = {}
job_seq = 0
total_jobs = 0
jobs_lock = threading.Lock()
memo_lock = threading.Lock()
shutting_down = False
port = DEFAULT_PORT
bind_addr = DEFAULT_BIND
token: Optional[str] = None
gateway_domain: Optional[str] = None
gateway_device_id: Optional[str] = None
gateway_lock = threading.Lock()
assigned_device_id: Optional[str] = None
memory_enabled = False
has_cloudflared = False
mcp_config_path: Optional[str] = None
disallowed_tools: set[str] = set()
public_domain: Optional[str] = None
make_public = False
public_base_url: Optional[str] = None
cloudflare_tunnel_url: Optional[str] = None
_gateway_dispatch_pool: Optional[Any] = None  # lazy-initialized ThreadPoolExecutor, reused across gateway reconnects

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
        result = subprocess.run(
            ["which", name] if sys.platform != "win32" else ["where", name],
            capture_output=True, timeout=5
        )
        return result.returncode == 0
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


_shell_type_cache: Optional[ShellType] = None


def get_shell_type() -> ShellType:
    """Lazy + cached shell detection so importing the module doesn't run subprocess."""
    global _shell_type_cache
    if _shell_type_cache is None:
        _shell_type_cache = detect_shell_type()
    return _shell_type_cache


def parse_args(args: list[str]) -> tuple[int, str | None, str | None, str | None]:
    """Returns (port, token, gateway_domain, device_id). Other flags set as module globals."""
    global memory_enabled, has_cloudflared, mcp_config_path, disallowed_tools
    global public_domain, make_public, bind_addr
    port = DEFAULT_PORT
    env_port = os.environ.get("PORT")
    if env_port:
        try:
            port = int(env_port)
        except ValueError:
            print(f"ERROR: invalid $PORT={env_port}", file=sys.stderr)
            sys.exit(2)
    token = None
    gateway_domain = None
    device_id = None
    memory_enabled = False
    has_cloudflared = check_cloudflared()
    mcp_config_path = None
    disallowed_tools = set()
    public_domain = None
    make_public = False
    bind_addr = DEFAULT_BIND
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--port" and i + 1 < len(args):
            try:
                port = int(args[i + 1])
            except ValueError:
                print(f"ERROR: invalid --port {args[i + 1]}", file=sys.stderr)
                sys.exit(2)
            if not (1 <= port <= 65535):
                print(f"ERROR: --port out of range: {port}", file=sys.stderr)
                sys.exit(2)
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
        elif arg == "--bind" and i + 1 < len(args):
            bind_addr = args[i + 1]
            i += 2
        elif arg == "--enable-memory":
            memory_enabled = True
            i += 1
        elif arg == "--mcp" and i + 1 < len(args):
            mcp_config_path = args[i + 1]
            i += 2
        elif arg == "--public":
            make_public = True
            i += 1
        elif arg == "--domain" and i + 1 < len(args):
            public_domain = args[i + 1]
            i += 2
        elif arg == "--disallowed-tools" and i + 1 < len(args):
            disallowed_tools = {t.strip() for t in args[i + 1].split(",") if t.strip()}
            i += 2
        elif arg == "-h" or arg == "--help":
            print(USAGE)
            sys.exit(0)
        else:
            i += 1
    if make_public and public_domain:
        print("ERROR: --public and --domain are mutually exclusive", file=sys.stderr)
        sys.exit(2)
    return port, token, gateway_domain, device_id


USAGE = """Code MCP - Minimal MCP server over HTTP

Usage: code_mcp.py [flags]

Flags:
  --port <n>            Listen port (default: 7777 or $PORT)
  --bind <addr>         Bind address (default: 127.0.0.1)
  --token <s>           Require ?token=<s> on every request
  --gateway <url>       Connect to gateway server (wss:// or https://)
  --id <uuid>           Use specific device ID for gateway connection
  --enable-memory       Enable remember/forget/recall tools
  --mcp <path>          Aggregate tools from external MCP servers
  --public              Expose via Cloudflare quick tunnel (requires cloudflared)
  --domain <host>       Use existing public hostname (mutually exclusive with --public)
  --disallowed-tools <list>  Comma-separated tools to disable

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


def read_file(path: str, cwd: str = ".",
              range: list[int] | None = None,
              no_truncate: bool = False) -> str:
    try:
        ok, full_path, err = safe_resolve(cwd, path)
        if not ok:
            return f"ERROR: {err}"
        content = full_path.read_text(encoding="utf-8", errors="replace")
        if range and isinstance(range, (list, tuple)) and len(range) == 2:
            try:
                start = int(range[0])
                end = int(range[1])
            except (TypeError, ValueError):
                return "ERROR: range must be [start, end] integers (1-indexed, inclusive)"
            if start < 1 or end < start:
                return f"ERROR: invalid range [{start}, {end}]"
            lines = content.splitlines(keepends=True)
            start_idx = min(start - 1, len(lines))
            end_idx = min(end, len(lines))
            content = "".join(lines[start_idx:end_idx])
        if no_truncate:
            return content
        return maybe_spill_text(content, "read")
    except Exception as e:
        return f"ERROR: {e}"


def write_file(path: str, content: str, cwd: str = ".") -> str:
    try:
        ok, full_path, err = safe_resolve(cwd, path)
        if not ok:
            return f"ERROR: {err}"
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content, encoding="utf-8")
        return f"wrote {len(content.encode('utf-8'))} bytes to {path}"
    except Exception as e:
        return f"ERROR: {e}"


def edit_file(path: str, old_str: str, new_str: str, cwd: str = ".") -> str:
    try:
        ok, full_path, err = safe_resolve(cwd, path)
        if not ok:
            return f"ERROR: {err}"
        content = full_path.read_text(encoding="utf-8", errors="replace")
        if old_str not in content:
            return f"ERROR: String not found"
        if content.count(old_str) > 1:
            return f"ERROR: old_str not unique"
        new_content = content.replace(old_str, new_str, 1)
        full_path.write_text(new_content, encoding="utf-8")
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
                originals[resolved] = full_path.read_text(encoding="utf-8", errors="replace")
            text = originals[resolved]
            if old_str not in text:
                return f"ERROR: edit #{i+1} ({path}): old_str not found"
            if text.count(old_str) > 1:
                return f"ERROR: edit #{i+1} ({path}): old_str not unique"
            first = text.index(old_str)
            start = first
            end = first + len(old_str)
            # Check overlap with existing ranges for same file
            for r_path, r_start, r_end, _, r_idx in ranges:
                if resolved == r_path and start < r_end and end > r_start:
                    return f"ERROR: edit #{i+1} ({path}): overlaps edit #{r_idx+1}"
            ranges.append((resolved, start, end, new_str, i))

        # Apply edits in reverse order so offsets stay valid (group by file)
        ranges_by_file: dict[str, list] = {}
        for r_path, r_start, r_end, replacement, r_idx in ranges:
            ranges_by_file.setdefault(r_path, []).append((r_start, r_end, replacement))
        for r_path, file_ranges in ranges_by_file.items():
            text = originals[r_path]
            for r_start, r_end, replacement in sorted(file_ranges, key=lambda x: -x[0]):
                text = text[:r_start] + replacement + text[r_end:]
            originals[r_path] = text

        # Write all files
        for resolved, new_content in originals.items():
            Path(resolved).write_text(new_content, encoding="utf-8")
        return "ok"
    except Exception as e:
        return f"ERROR: {e}"


def _format_exec_result(exit_code: int, stdout: str, stderr: str) -> str:
    """Format process output as 'exit=N\\n<combined>' (matches Java/TS)."""
    combined = stdout
    if stderr:
        combined = combined + ("\n" if combined and not combined.endswith("\n") else "") + stderr
    if len(combined) > MAX_OUTPUT:
        combined = combined[:OUTPUT_CAP_KEEP] + f"\n[TRUNCATED: {len(combined)} bytes]"
    return f"exit={exit_code}\n{combined}"


SPAWN_ENV_ALLOWLIST = {
    "PATH", "HOME", "USER", "SHELL", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
    "TMPDIR", "TEMP", "TMP",
    "SystemRoot", "SystemDrive", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
    "PROGRAMFILES", "PROGRAMDATA", "WINDIR", "COMSPEC", "PATHEXT",
}


def _upload_root() -> str:
    if sys.platform == "darwin":
        return "/private/tmp"
    if sys.platform.startswith("linux"):
        return "/tmp"
    return os.environ.get("TMP") or os.environ.get("TEMP") or "/tmp"


UPLOAD_ROOT = _upload_root()


def _b64url(buf: bytes) -> str:
    return base64.urlsafe_b64encode(buf).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def mint_upload_session_id() -> str:
    if not token:
        raise RuntimeError("--token is required to mint upload sessions")
    exp = int(time.time()) + UPLOAD_TTL_S
    nonce = secrets.token_hex(8)
    payload = f"{exp}.{nonce}"
    sig = hmac.new(token.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
    return f"{_b64url(payload.encode())}.{_b64url(sig)}"


def verify_upload_session_id(sid: str) -> tuple[bool, str]:
    if not token:
        return False, "server has no token configured"
    parts = sid.split(".")
    if len(parts) != 2:
        return False, "malformed"
    try:
        payload = _b64url_decode(parts[0]).decode("utf-8")
        sig = _b64url_decode(parts[1])
        expected = hmac.new(token.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return False, "bad signature"
        exp_part = payload.split(".", 1)[0]
        if int(time.time()) > int(exp_part):
            return False, "expired"
        return True, ""
    except Exception:
        return False, "malformed"


def _resolve_public_base_url() -> Optional[str]:
    if public_domain:
        return f"https://{public_domain}"
    if cloudflare_tunnel_url:
        return cloudflare_tunnel_url
    return None


def handle_get_upload_link() -> str:
    base = _resolve_public_base_url()
    if not base:
        return "ERROR: get_upload_link requires --public or --domain"
    if not token:
        return "ERROR: get_upload_link requires --token"
    sid = mint_upload_session_id()
    return json.dumps({"url": f"{base}/upload/{sid}", "expiresInMinutes": UPLOAD_TTL_S // 60})


_UPLOAD_PAGE_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>Upload</title>
<style>body{font-family:system-ui;max-width:560px;margin:3rem auto;padding:1rem}
input[type=file]{display:block;margin:1rem 0}
.btn{padding:.5rem 1rem;background:#2d5fb3;color:#fff;border:0;border-radius:6px;cursor:pointer}
.result{margin-top:1rem;padding:.5rem;background:#f4f4f4;border-radius:6px;white-space:pre-wrap}</style>
</head><body><h2>Upload to local machine</h2>
<form id="f" enctype="multipart/form-data" method="post">
<input type="file" name="file" required><button class="btn">Upload</button></form>
<div id="r" class="result" style="display:none"></div>
<script>
document.getElementById('f').addEventListener('submit', async (e) => {
  e.preventDefault();
  const r = document.getElementById('r');
  r.style.display='block'; r.textContent='Uploading...';
  try {
    const res = await fetch(location.pathname, {method:'POST', body: new FormData(e.target)});
    r.textContent = JSON.stringify(await res.json(), null, 2);
  } catch (err) { r.textContent = 'ERROR: ' + err.message; }
});
</script></body></html>"""


def _parse_multipart_part_headers(blob: bytes) -> tuple[Optional[str], bytes]:
    """Given a multipart part's bytes (without leading boundary CRLF and without
    trailing CRLF-before-next-boundary), return (filename or None, body_bytes)."""
    header_end = blob.find(b"\r\n\r\n")
    if header_end < 0:
        return None, b""
    header_text = blob[:header_end].decode("iso-8859-1", errors="replace")
    body = blob[header_end + 4:]
    fname = None
    for line in header_text.split("\r\n"):
        if line.lower().startswith("content-disposition:"):
            m = re.search(r'filename="([^"]+)"', line)
            if m:
                fname = m.group(1)
                break
    return fname, body


def _split_multipart(body: bytes, boundary: bytes) -> list[bytes]:
    """Byte-level split of multipart body. Returns list of part blobs."""
    parts: list[bytes] = []
    idx = 0
    blen = len(boundary)
    n = len(body)
    while idx < n:
        b = body.find(boundary, idx)
        if b < 0:
            break
        part_start = b + blen
        if body[part_start:part_start + 2] == b"\r\n":
            part_start += 2
        if body[part_start:part_start + 2] == b"--":
            break
        nxt = body.find(boundary, part_start)
        if nxt < 0:
            break
        part_end = nxt - 2 if body[nxt - 2:nxt] == b"\r\n" else nxt
        parts.append(body[part_start:part_end])
        idx = nxt
    return parts


def _sanitize_filename(name: str) -> str:
    # Strip path components first, then non-printable / non-portable chars.
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    if not name or name in (".", ".."):
        name = f"upload-{int(time.time() * 1000)}"
    return name


def handle_upload_post(content_type: str, body: bytes, session_id: str) -> tuple[int, dict]:
    if not content_type or "multipart/form-data" not in content_type:
        return 400, {"error": "expected multipart/form-data"}
    if len(body) > MAX_REQUEST_BYTES:
        return 413, {"error": f"upload exceeds {MAX_REQUEST_BYTES} bytes"}
    m = re.search(r'boundary="?([^";]+)"?', content_type)
    if not m:
        return 400, {"error": "no boundary"}
    boundary = b"--" + m.group(1).encode("ascii", errors="replace")

    fname = None
    file_bytes = b""
    for part in _split_multipart(body, boundary):
        f, content = _parse_multipart_part_headers(part)
        if f is not None:
            fname = f
            file_bytes = content
            break
    if fname is None:
        return 400, {"error": "no file provided"}

    safe_name = _sanitize_filename(fname)
    target_dir = Path(UPLOAD_ROOT) / session_id
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / safe_name
    target.write_bytes(file_bytes)

    sha = hashlib.sha256(file_bytes).hexdigest()
    import mimetypes
    mime = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
    return 200, {"path": str(target), "size": len(file_bytes), "sha256": sha, "mime": mime}


def build_child_env(extra: dict | None = None) -> dict:
    """Spawn-time env allow-list — limits blast radius of MCP token compromise.

    Only forwards POSIX/Windows essentials (PATH, HOME, SHELL, etc.). Secrets
    like AWS_*, OPENAI_API_KEY, ANTHROPIC_API_KEY are dropped. Users who need
    extra vars in commands should set them inline (`FOO=bar my-cmd`).
    """
    base = {}
    for k in SPAWN_ENV_ALLOWLIST:
        v = os.environ.get(k)
        if v is not None:
            base[k] = v
    base.setdefault("HOME", os.path.expanduser("~"))
    if extra:
        base.update(extra)
    return base


def _run_proc(cmd, cwd: str, timeout_ms: int | None, executable: str | None = None, shell: bool = True) -> str:
    effective_ms = timeout_ms if (timeout_ms and timeout_ms > 0) else DEFAULT_SHELL_TIMEOUT_MS
    timeout_s = effective_ms / 1000.0
    popen_kwargs = dict(
        shell=shell,
        executable=executable,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=build_child_env(),
    )
    if sys.platform != "win32":
        # Own process group so we can SIGKILL all descendants (sleep etc.) on timeout.
        popen_kwargs["start_new_session"] = True
    try:
        proc = subprocess.Popen(cmd, **popen_kwargs)
    except Exception as e:
        return f"exit=-1\nERROR: {e}"
    try:
        try:
            stdout, stderr = proc.communicate(timeout=timeout_s)
            return _format_exec_result(proc.returncode, stdout or "", stderr or "")
        except subprocess.TimeoutExpired:
            # Tree-kill: signal the whole session so shell children die too.
            if sys.platform != "win32":
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    proc.kill()
            else:
                proc.kill()
            try:
                stdout, stderr = proc.communicate(timeout=1.0)
            except subprocess.TimeoutExpired:
                stdout, stderr = "", ""
            body = _format_exec_result(124, stdout or "", stderr or "")
            return body + _timeout_marker(effective_ms)
    except Exception as e:
        try: proc.kill()
        except Exception: pass
        return f"exit=-1\nERROR: {e}"


def execute_bash(command: str, cwd: str = ".", timeout_ms: int | None = None) -> str:
    return _run_proc(command, cwd, timeout_ms)


def execute_shell(command: str, cwd: str = ".", timeout_ms: int | None = None) -> str:
    return _run_proc(command, cwd, timeout_ms, executable="/bin/sh")


def execute_powershell(command: str, cwd: str = ".", timeout_ms: int | None = None) -> str:
    pwsh_cmd = "pwsh" if sys.platform != "win32" else "powershell"
    try:
        return _run_proc([pwsh_cmd, "-Command", command], cwd, timeout_ms, shell=False)
    except FileNotFoundError:
        return f"exit=-1\nERROR: PowerShell ({pwsh_cmd}) not found on PATH"


def execute_command(command: str, cwd: str = ".", timeout_ms: int | None = None) -> str:
    """Windows cmd.exe execution."""
    try:
        return _run_proc(["cmd.exe", "/c", command], cwd, timeout_ms, shell=False)
    except FileNotFoundError:
        return "exit=-1\nERROR: cmd.exe not found"


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
            # `--` so a pattern starting with `-` isn't parsed as a flag.
            cmd.append("--")
            cmd.extend([pattern] + valid_paths)
        else:
            cmd = ["grep", "-rn"]
            if glob:
                cmd.extend(["--include", glob])
            cmd.append("--")
            cmd.extend([pattern] + valid_paths)
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=build_child_env(),
            timeout=30
        )
        if result.stdout:
            return result.stdout
        if result.returncode == 1:
            return "(no matches)"
        return f"ERROR (exit={result.returncode}): {result.stderr}"
    except Exception as e:
        return f"ERROR: {e}"


def find_files(pattern: str, cwd: str = ".", path: str = ".", include_hidden: bool = False) -> str:
    try:
        ok, base_path, err = safe_resolve(cwd, path)
        if not ok:
            return f"ERROR: {err}"
        if not base_path.exists():
            return f"ERROR: path not found: {path}"
        pat = pattern if ("/" in pattern or "\\" in pattern) else f"**/{pattern}"
        cwd_resolved = Path(cwd).resolve()
        noise_dirs = {"node_modules", ".git", ".next", ".nuxt", ".turbo", ".cache",
                      "dist", "build", "out", "target", "coverage",
                      ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
                      ".idea", ".vscode"}
        explicit_noise = any(seg in pattern for seg in noise_dirs)
        results = []
        for m in base_path.glob(pat):
            if m.is_dir():
                continue
            try:
                rel = m.resolve().relative_to(cwd_resolved)
                parts = rel.parts
            except ValueError:
                parts = m.parts
                rel = m
            skip = False
            for seg in parts:
                if seg in noise_dirs and not explicit_noise:
                    skip = True
                    break
                if not include_hidden and seg.startswith(".") and seg not in (".", ".."):
                    if not pattern.startswith("."):
                        skip = True
                        break
            if not skip:
                results.append(str(rel))
                if len(results) >= 10000:
                    break
        if not results:
            return "(no matches)"
        return "\n".join(results)
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
    with jobs_lock:
        if total_jobs >= MAX_CONCURRENT_JOBS:
            return f"ERROR: max concurrent jobs ({MAX_CONCURRENT_JOBS}) exceeded"
        if shutting_down:
            return "ERROR: server is shutting down"
        total_jobs += 1
        job_seq += 1
        job_id = f"j{job_seq}"

    popen_kwargs = dict(
        shell=True,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=build_child_env(),
    )
    if sys.platform != "win32":
        popen_kwargs["start_new_session"] = True
    try:
        proc = subprocess.Popen(command, **popen_kwargs)
    except Exception as e:
        with jobs_lock:
            total_jobs = max(0, total_jobs - 1)
        return f"ERROR: failed to start job: {e}"

    job = {
        "id": job_id,
        "command": command,
        "proc": proc,
        "output": "",
        "status": "running",
        "started_at": time.time(),
    }
    with jobs_lock:
        jobs[job_id] = job

    def pump_and_finalize():
        global total_jobs
        try:
            stdout, stderr = proc.communicate()
            combined = (stdout or "") + (stderr or "")
            if len(combined) > MAX_OUTPUT:
                combined = combined[:OUTPUT_CAP_KEEP] + f"\n[TRUNCATED: {len(combined)} bytes]"
            job["output"] = combined
        except Exception as e:
            job["output"] = f"ERROR: {e}"
        finally:
            job["status"] = "exited"
            job["exit_code"] = proc.returncode
            with jobs_lock:
                total_jobs = max(0, total_jobs - 1)

    t = threading.Thread(target=pump_and_finalize, daemon=True)
    t.start()

    return f"started {job_id}"


def stop_job(job_id: str, timeout_ms: int = 500) -> str:
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        return f"ERROR: no such job: {job_id}"
    if job["status"] != "running":
        return f"{job_id} already {job['status']}"

    proc = job["proc"]
    # Kill the whole process group on POSIX so children die with the leader.
    if sys.platform != "win32":
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            proc.terminate()
    else:
        proc.terminate()
    try:
        proc.wait(timeout=timeout_ms / 1000)
    except subprocess.TimeoutExpired:
        if sys.platform != "win32":
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
        else:
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


def _shell_tool_name() -> str:
    return {
        ShellType.BASH: "bash",
        ShellType.SH: "shell",
        ShellType.CMD: "command",
        ShellType.POWERSHELL: "powershell",
    }.get(get_shell_type(), "bash")


def build_tools_list() -> list[dict]:
    tools: list[dict] = [
        {"name": "read", "description": "Read a file. Optional line range [start,end] (1-indexed, inclusive). Pass no_truncate=true to disable output truncation.",
         "inputSchema": {"type": "object", "properties": {"cwd": {"type": "string"}, "path": {"type": "string"}, "range": {"type": "array", "items": {"type": "number"}, "minItems": 2, "maxItems": 2}, "no_truncate": {"type": "boolean"}}, "required": ["cwd", "path"]}},
        {"name": "write", "description": "Write/overwrite a file with the given content.",
         "inputSchema": {"type": "object", "properties": {"cwd": {"type": "string"}, "path": {"type": "string"}, "content": {"type": "string"}}, "required": ["cwd", "path", "content"]}},
        {"name": "edit", "description": "Replace old_str with new_str in a file. old_str must occur exactly once.",
         "inputSchema": {"type": "object", "properties": {"cwd": {"type": "string"}, "path": {"type": "string"}, "old_str": {"type": "string"}, "new_str": {"type": "string"}}, "required": ["cwd", "path", "old_str", "new_str"]}},
        {"name": "multi_edit", "description": "Apply multiple edits atomically across one or more files.",
         "inputSchema": {"type": "object", "properties": {"cwd": {"type": "string"}, "edits": {"type": "array", "minItems": 1, "items": {"type": "object", "properties": {"path": {"type": "string"}, "old_str": {"type": "string"}, "new_str": {"type": "string"}}, "required": ["path", "old_str", "new_str"]}}}, "required": ["cwd", "edits"]}},
        {"name": _shell_tool_name(), "description": "Run a command in the detected shell. Block until exit, returns 'exit=N\\n' + combined stdout+stderr.",
         "inputSchema": {"type": "object", "properties": {"cwd": {"type": "string"}, "command": {"type": "string"}, "timeout_ms": {"type": "number"}}, "required": ["cwd", "command"]}},
        {"name": "grep", "description": "Search files by regex. Uses ripgrep if available, else findstr (Windows) or grep (POSIX).",
         "inputSchema": {"type": "object", "properties": {"cwd": {"type": "string"}, "pattern": {"type": "string"}, "path": {"type": "string"}, "glob": {"type": "string"}}, "required": ["cwd", "pattern"]}},
        {"name": "find", "description": "Find files by glob pattern. Supports ** for recursive. Skips common noise dirs unless pattern explicitly references them.",
         "inputSchema": {"type": "object", "properties": {"cwd": {"type": "string"}, "pattern": {"type": "string"}, "path": {"type": "string"}, "include_hidden": {"type": "boolean"}}, "required": ["cwd", "pattern"]}},
        {"name": "ls", "description": "List directory entries with type and size.",
         "inputSchema": {"type": "object", "properties": {"cwd": {"type": "string"}, "path": {"type": "string"}}, "required": ["cwd"]}},
        {"name": "job", "description": "Manage background jobs. mode: list|view|start|stop. command required for start; id (passed as command) required for view/stop.",
         "inputSchema": {"type": "object", "properties": {"cwd": {"type": "string"}, "mode": {"type": "string", "enum": ["list", "view", "start", "stop"]}, "command": {"type": "string"}, "timeout_ms": {"type": "number"}}, "required": ["cwd", "mode"]}},
        {"name": "mcp", "description": "Manage MCP servers: list available, call a tool, or unload a server.",
         "inputSchema": {"type": "object", "properties": {"cwd": {"type": "string"}, "action": {"type": "string", "enum": ["list", "call", "unload"]}, "server": {"type": "string"}, "tool": {"type": "string"}, "args": {"type": "object"}, "mcpConfigPath": {"type": "string"}}, "required": ["cwd", "action"]}},
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
    if (public_domain or make_public) and token:
        tools.append({"name": "get_upload_link",
                      "description": "Return a short-lived upload URL (10-minute TTL) for sending a file to the local machine.",
                      "inputSchema": {"type": "object", "properties": {}}})
    return [t for t in tools if t["name"] not in disallowed_tools]


def dispatch_tool(tool_name: str, params: dict) -> Any:
    """Dispatch a single tool call. Used by both tools/call and raw-method handlers."""
    if tool_name in disallowed_tools:
        return f"ERROR: tool '{tool_name}' disabled"
    # Only allow the shell tool matching the detected shell (parity with Java/TS).
    shell_aliases = {"bash": ShellType.BASH, "shell": ShellType.SH,
                     "command": ShellType.CMD, "powershell": ShellType.POWERSHELL}
    if tool_name in shell_aliases and shell_aliases[tool_name] != get_shell_type():
        return f"ERROR: tool '{tool_name}' not available on this shell ({get_shell_type().value})"
    cwd = params.get("cwd", ".") if isinstance(params, dict) else "."
    try:
        if tool_name == "read":
            return read_file(params.get("path", ""), cwd,
                             range=params.get("range"),
                             no_truncate=bool(params.get("no_truncate", False)))
        if tool_name == "write":
            return write_file(params.get("path", ""), params.get("content", ""), cwd)
        if tool_name == "edit":
            return edit_file(params.get("path", ""), params.get("old_str", ""),
                             params.get("new_str", ""), cwd)
        if tool_name == "multi_edit":
            return multi_edit_files(params.get("edits", []), cwd)
        if tool_name == "bash":
            return execute_bash(params.get("command", ""), cwd, params.get("timeout_ms"))
        if tool_name == "shell":
            return execute_shell(params.get("command", ""), cwd, params.get("timeout_ms"))
        if tool_name == "command":
            return execute_command(params.get("command", ""), cwd, params.get("timeout_ms"))
        if tool_name == "powershell":
            return execute_powershell(params.get("command", ""), cwd, params.get("timeout_ms"))
        if tool_name == "grep":
            return grep_files(params.get("pattern", ""),
                              [params.get("path", ".")], cwd,
                              params.get("glob"))
        if tool_name == "find":
            return find_files(params.get("pattern", ""), cwd,
                              params.get("path", "."),
                              bool(params.get("include_hidden", False)))
        if tool_name == "ls":
            return list_directory(params.get("path", "."), cwd)
        if tool_name == "job":
            mode = params.get("mode", "list")
            if mode == "list":
                return list_jobs()
            if mode == "start":
                cmd = params.get("command")
                return start_job(cmd, cwd) if cmd else "ERROR: command required"
            if mode == "stop":
                cmd = params.get("command")
                return stop_job(cmd, params.get("timeout_ms", 500)) if cmd else "ERROR: job id required (pass as command)"
            if mode == "view":
                cmd = params.get("command")
                return view_job(cmd) if cmd else "ERROR: job id required (pass as command)"
            return f"ERROR: unknown mode: {mode}"
        if tool_name == "remember":
            if not memory_enabled:
                return "ERROR: memory disabled (start server with --enable-memory)"
            return handle_remember(cwd, params.get("memo", ""), params.get("tags"))
        if tool_name == "forget":
            if not memory_enabled:
                return "ERROR: memory disabled"
            try:
                return handle_forget(cwd, params.get("memo_id", 0))
            except ValueError as e:
                return f"ERROR: {e}"
        if tool_name == "recall":
            if not memory_enabled:
                return "ERROR: memory disabled"
            return handle_recall(cwd, params.get("query"), params.get("tags"),
                                 params.get("limit", 20), params.get("offset", 0))
        if tool_name == "preview":
            if not has_cloudflared:
                return "ERROR: cloudflared not on PATH"
            return handle_preview(params.get("url", ""))
        if tool_name == "get_upload_link":
            return handle_get_upload_link()
        if tool_name == "mcp":
            return handle_mcp(params.get("action", ""),
                              params.get("server", ""),
                              params.get("tool", ""),
                              params.get("args") or {},
                              params.get("mcpConfigPath") or (mcp_config_path or ".mcp.json"),
                              cwd)
        return f"ERROR:-32601: unknown method: {tool_name}"
    except Exception as e:
        return f"ERROR: {e}"


class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class MCPRequestHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def authenticate(self) -> bool:
        if token:
            parsed = urllib.parse.urlparse(self.path)
            query = dict(urllib.parse.parse_qsl(parsed.query))
            req_token = query.get("token")
            # Also accept Authorization: Bearer <token>
            if not req_token:
                auth_hdr = self.headers.get("Authorization", "")
                if auth_hdr.startswith("Bearer "):
                    req_token = auth_hdr[7:].strip()
            if not req_token or not hmac.compare_digest(req_token, token):
                self.send_json({"error": "unauthorized"}, 401)
                return False
        return True

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith("/upload/"):
            self._handle_upload_post(parsed.path[len("/upload/"):])
            return
        if not self.authenticate():
            return
        if parsed.path != "/mcp":
            self.send_json({"error": "not found"}, 404)
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self.send_json({"error": "invalid Content-Length"}, 400)
            return
        if content_length < 0 or content_length > MAX_REQUEST_BYTES:
            self.send_json({"error": "Content-Length too large"}, 413)
            return
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")

        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self.send_json({"jsonrpc": "2.0", "id": None,
                            "error": {"code": -32700, "message": "Parse error"}}, 400)
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

        if method and method.startswith("notifications/"):
            # MCP handshake: client notification, no response body needed.
            self.send_response(204)
            self.end_headers()
            return

        if method == "ping":
            self.send_json(jsonrpc_response(req_id, {}))
            return

        if method == "tools/list":
            self.send_json(jsonrpc_response(req_id, {"tools": build_tools_list()}))
            return

        # JSON-RPC 2.0: params (when present) must be an object or array. We use object-style; reject arrays/scalars with -32602.
        if params is not None and not isinstance(params, dict):
            self.send_json(jsonrpc_error(req_id, -32602, "Invalid params: expected object"))
            return

        if method == "tools/call":
            if not isinstance(params, dict):
                self.send_json(jsonrpc_error(req_id, -32602, "Invalid params: expected object"))
                return
            tool_name = params.get("name", "")
            tool_params = params.get("arguments", {})
            result = dispatch_tool(tool_name, tool_params)
            text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)
            # read+no_truncate: caller explicitly asked for full content; don't re-spill.
            skip_spill = tool_name == "read" and isinstance(tool_params, dict) and bool(tool_params.get("no_truncate"))
            final_text = text if skip_spill else maybe_spill_text(text, tool_name)
            self.send_json(jsonrpc_response(req_id, {"content": [{"type": "text", "text": final_text}]}))
            return

        # Handle raw methods directly (like Java/TypeScript MCP servers)
        tool_params = params if isinstance(params, dict) else {}
        result = dispatch_tool(method, tool_params)
        # Emit JSON-RPC error for "method not found"-style results.
        if isinstance(result, str) and result.startswith("ERROR:-32601:"):
            msg = result[len("ERROR:-32601:"):].strip()
            self.send_json(jsonrpc_error(req_id, -32601, msg))
            return
        self.send_json(jsonrpc_response(req_id, result))

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith("/upload/"):
            self._handle_upload_get(parsed.path[len("/upload/"):])
            return
        if not self.authenticate():
            return
        if parsed.path == "/mcp":
            self.send_json({"status": "ok"})
            return
        self.send_json({"error": "not found"}, 404)

    def _handle_upload_get(self, sid: str):
        # GET serves the HTML uploader page. Auth lives in the signed sid.
        ok, reason = verify_upload_session_id(sid)
        if not ok:
            body = f"Upload session {reason}.".encode("utf-8")
            self.send_response(401)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = _UPLOAD_PAGE_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_upload_post(self, sid: str):
        ok, reason = verify_upload_session_id(sid)
        if not ok:
            self.send_json({"error": reason}, 401)
            return
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self.send_json({"error": "invalid Content-Length"}, 400)
            return
        if content_length < 0 or content_length > MAX_REQUEST_BYTES:
            self.send_json({"error": "request too large"}, 413)
            return
        body = self.rfile.read(content_length)
        ctype = self.headers.get("Content-Type", "")
        status, payload = handle_upload_post(ctype, body, sid)
        self.send_json(payload, status)


def start_gateway_client(domain: str, device_id: str | None) -> None:
    """Connect to gateway and relay requests."""
    global gateway_device_id, assigned_device_id

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
        """Return next non-control text/binary message payload. Handles fragmentation,
        ping/pong (auto-reply), and close. Returns None on close or error."""
        def _recv_exact(sock, size: int) -> bytes | None:
            data = b""
            while len(data) < size:
                try:
                    chunk = sock.recv(size - len(data))
                    if not chunk:
                        return None
                    data += chunk
                except ssl.SSLError as e:
                    if e.errno == ssl.SSL_ERROR_WANT_READ:
                        continue
                    raise
            return data

        buffer = bytearray()
        try:
            while True:
                first = _recv_exact(sock, 1)
                if not first:
                    return None
                b0 = first[0]
                fin = (b0 & 0x80) != 0
                opcode = b0 & 0x0F
                second = _recv_exact(sock, 1)
                if not second:
                    return None
                b1 = second[0]
                masked = (b1 & 0x80) != 0
                length = b1 & 0x7F
                if length == 126:
                    ext = _recv_exact(sock, 2)
                    if not ext:
                        return None
                    length = struct.unpack(">H", ext)[0]
                elif length == 127:
                    ext = _recv_exact(sock, 8)
                    if not ext:
                        return None
                    length = struct.unpack(">Q", ext)[0]
                if length > MAX_WS_FRAME_BYTES:
                    print(f"[gateway] frame too large: {length}", file=sys.stderr)
                    return None
                mask_key = b""
                if masked:
                    mask_key = _recv_exact(sock, 4) or b""
                payload = b""
                if length > 0:
                    payload = _recv_exact(sock, length) or b""
                    if masked and mask_key:
                        payload = bytes(p ^ mask_key[i & 3] for i, p in enumerate(payload))
                # Control frames (0x8 close, 0x9 ping, 0xA pong) — never fragmented.
                if opcode == 0x8:
                    # Close: best-effort echo and bail.
                    try:
                        send_ws_frame_with_opcode(sock, 0x8, payload[:125])
                    except Exception:
                        pass
                    return None
                if opcode == 0x9:
                    try:
                        send_ws_frame_with_opcode(sock, 0xA, payload)
                    except Exception:
                        pass
                    continue
                if opcode == 0xA:
                    continue
                if opcode in (0x1, 0x2, 0x0):
                    buffer.extend(payload)
                    if fin:
                        return bytes(buffer)
                    continue
                # Unknown opcode — drop connection.
                print(f"[gateway] unknown opcode: {opcode}", file=sys.stderr)
                return None
        except ssl.SSLError as e:
            print(f"[gateway] SSL error: {e}", file=sys.stderr)
            return None
        except Exception as e:
            print(f"[gateway] recv error: {e}", file=sys.stderr)
            return None

    def send_ws_frame_with_opcode(sock, opcode: int, data: bytes):
        frame = bytearray()
        frame.append(0x80 | (opcode & 0x0F))
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

    def handle_request(req: dict) -> dict:
        """Handle incoming request from gateway, dispatch like local /mcp."""
        req_id, method, params = parse_jsonrpc_request(req)

        if method == "initialize":
            return jsonrpc_response(req_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "code-mcp", "version": "0.1.0"},
            })
        if method == "notifications/initialized":
            return {}  # no response needed
        if method == "ping":
            return jsonrpc_response(req_id, {})
        if method == "tools/list":
            return jsonrpc_response(req_id, {"tools": build_tools_list()})

        is_tools_call = method == "tools/call"
        if is_tools_call:
            if not isinstance(params, dict):
                return jsonrpc_error(req_id, -32602, "Invalid params: expected object")
            tool_name = params.get("name", "")
            tool_params = params.get("arguments", {})
        else:
            tool_name = method
            tool_params = params if isinstance(params, dict) else {}

        result = dispatch_tool(tool_name, tool_params)
        if is_tools_call:
            text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)
            skip_spill = tool_name == "read" and isinstance(tool_params, dict) and bool(tool_params.get("no_truncate"))
            final_text = text if skip_spill else maybe_spill_text(text, tool_name)
            result = {"content": [{"type": "text", "text": final_text}]}
        return jsonrpc_response(req_id, result)

    WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    # Singleton pool reused across reconnects so a churning gateway can't leak
    # 8-worker pools per attempt.
    global _gateway_dispatch_pool
    if _gateway_dispatch_pool is None:
        _gateway_dispatch_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=8, thread_name_prefix="gw-dispatch")
    dispatch_pool = _gateway_dispatch_pool
    send_lock = threading.Lock()

    def safe_send(sock, payload: bytes):
        with send_lock:
            send_ws_frame(sock, payload)

    while True:
        try:
            url = build_url(domain, device_id)
            print(f"[gateway] connecting to {url}", file=sys.stderr)

            uri = urllib.parse.urlparse(url)
            host = uri.hostname or domain
            gateway_port = uri.port or (443 if uri.scheme == "wss" else 80)

            use_ssl = url.startswith("wss://") or url.startswith("https://")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if use_ssl:
                context = ssl.create_default_context()
                ssock = context.wrap_socket(sock, server_hostname=host)
                ssock.connect((host, gateway_port))
            else:
                ssock = sock
                ssock.connect((host, gateway_port))
            ssock.settimeout(60)

            ws_key = base64.b64encode(secrets.token_bytes(16)).decode()
            # Host header uses the gateway host:port (not local port).
            host_header = host if gateway_port in (80, 443) else f"{host}:{gateway_port}"
            request = (
                f"GET {uri.path} HTTP/1.1\r\n"
                f"Host: {host_header}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"User-Agent: code-mcp/0.1.0\r\n"
                f"Accept: */*\r\n"
                f"\r\n"
            )
            ssock.sendall(request.encode())

            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = ssock.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if len(resp) > MAX_GATEWAY_HEADER_BYTES:
                    raise ValueError(f"gateway handshake response too large: {len(resp)} bytes")

            header_end = resp.find(b"\r\n\r\n")
            if header_end == -1:
                raise ValueError("gateway closed before sending headers")
            headers_text = resp[:header_end].decode("iso-8859-1", errors="replace")
            status_line = headers_text.split("\r\n", 1)[0]
            if " 101 " not in (" " + status_line + " "):
                print(f"[gateway] WebSocket upgrade failed: {status_line}", file=sys.stderr)
                ssock.close()
                time.sleep(3)
                continue
            # Verify Sec-WebSocket-Accept = base64(SHA1(key + magic))
            expected = base64.b64encode(hashlib.sha1((ws_key + WS_MAGIC).encode()).digest()).decode()
            accept_hdr = None
            for line in headers_text.split("\r\n")[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    if k.strip().lower() == "sec-websocket-accept":
                        accept_hdr = v.strip()
                        break
            if not accept_hdr or not hmac.compare_digest(accept_hdr, expected):
                print("[gateway] Sec-WebSocket-Accept mismatch — aborting", file=sys.stderr)
                ssock.close()
                time.sleep(3)
                continue

            # Drain anything after the handshake (rare but possible frame buffering).
            import errno
            try:
                ssock.setblocking(False)
                while True:
                    try:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                    except BlockingIOError as e:
                        if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                            break
                        raise
                ssock.setblocking(True)
            except Exception:
                pass

            if not device_id:
                device_id = str(uuid.uuid4())
            register = json.dumps({"type": "register", "deviceId": device_id}, ensure_ascii=False)
            safe_send(ssock, register.encode("utf-8"))
            print(f"[gateway] registered as {device_id}", file=sys.stderr)

            def dispatch_async(msg, sock_ref):
                try:
                    tunnel_req = msg["request"]
                    tunnel_id = msg["id"]
                    tok = msg.get("token")
                    token_param = f"?token={tok}" if tok else ""
                    local_url = f"http://127.0.0.1:{port}/mcp{token_param}"
                    req_data = json.dumps(tunnel_req, ensure_ascii=False).encode("utf-8")
                    http_req = urllib.request.Request(
                        local_url, data=req_data,
                        headers={"Content-Type": "application/json; charset=utf-8"})
                    try:
                        http_resp = urllib.request.urlopen(http_req, timeout=30)
                        resp_obj = json.loads(http_resp.read().decode("utf-8", errors="replace"))
                    except Exception as e:
                        resp_obj = {"jsonrpc": "2.0", "id": tunnel_req.get("id"),
                                    "error": {"code": -32603, "message": str(e)}}
                    tunnel_resp = {"id": tunnel_id, "response": resp_obj}
                    safe_send(sock_ref, json.dumps(tunnel_resp, ensure_ascii=False).encode("utf-8"))
                except Exception as e:
                    print(f"[gateway] dispatch error: {e}", file=sys.stderr)

            while True:
                try:
                    payload = recv_ws_frame(ssock)
                    if not payload:
                        break
                    try:
                        msg = json.loads(payload.decode("utf-8", errors="replace"))
                    except json.JSONDecodeError:
                        continue
                    if "request" in msg:
                        dispatch_pool.submit(dispatch_async, msg, ssock)
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[gateway] read loop error: {e}", file=sys.stderr)
                    break
            try:
                ssock.close()
            except Exception:
                pass

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
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return [json.loads(line) for line in content.split("\n") if line.strip()]
    except Exception:
        return []


def write_memos(cwd: str, memos: list[dict]):
    path = Path(cwd) / MEMO_FILE
    tmp = path.with_suffix(path.suffix + ".tmp")
    with memo_lock:
        with open(tmp, "w", encoding="utf-8") as f:
            for m in memos:
                f.write(json.dumps(m, ensure_ascii=False) + "\n")
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(tmp, path)


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
    with memo_lock:
        memo_id = last_memo_id(cwd) + 1
        entry = {"id": memo_id, "ts": int(time.time() * 1000), "memo": memo}
        if tags:
            entry["tags"] = tags
        path = Path(cwd) / MEMO_FILE
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
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
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            encoding="utf-8", errors="replace",
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
        try:
            config_full_path = Path(cwd) / config_path
            if not config_full_path.exists():
                return json.dumps({"servers": [], "mcpConfigPath": config_path}, ensure_ascii=False)
            with open(config_full_path, "r", encoding="utf-8") as f:
                config = json.load(f)
            servers = config.get("mcpServers", {})
            result = []
            with mcp_lock:
                loaded_snapshot = {k: dict(v) for k, v in mcp_servers.items()}
            for name in servers:
                key = f"{cwd}:{name}"
                is_loaded = key in loaded_snapshot
                result.append({
                    "name": name,
                    "status": "loaded" if is_loaded else "unloaded",
                    "tools": loaded_snapshot.get(key, {}).get("tools", []) if is_loaded else [],
                })
            return json.dumps({"servers": result, "mcpConfigPath": config_path}, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)}, ensure_ascii=False)

    if action == "call":
        if not server:
            return json.dumps({"error": "server name required for call action"}, ensure_ascii=False)
        if not tool:
            return json.dumps({"error": "tool name required for call action"}, ensure_ascii=False)

        try:
            config_full_path = Path(cwd) / config_path
            with open(config_full_path, "r", encoding="utf-8") as f:
                config = json.load(f)
            servers = config.get("mcpServers", {})
            if server not in servers:
                return json.dumps({"error": f"server '{server}' not found in .mcp.json"}, ensure_ascii=False)
            server_config = servers[server]

            key = f"{cwd}:{server}"
            # Spawn under lock; clean up if probe fails.
            with mcp_lock:
                existing = mcp_processes.get(key)
                needs_spawn = (existing is None) or (existing.poll() is not None)
                if needs_spawn:
                    cmd = server_config.get("command")
                    args_list = server_config.get("args", []) or []
                    if isinstance(cmd, str):
                        cmd = cmd.split()
                    extra_env = server_config.get("env") or {}
                    if not isinstance(extra_env, dict):
                        extra_env = {}
                    proc = subprocess.Popen(
                        list(cmd) + list(args_list),
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        cwd=cwd,
                        env=build_child_env({k: str(v) for k, v in extra_env.items()}),
                    )
                    mcp_processes[key] = proc
            if needs_spawn:
                try:
                    tools_result = mcp_call(key, "tools/list", {})
                    with mcp_lock:
                        mcp_servers[key] = {
                            "tools": [t["name"] for t in tools_result.get("tools", [])]
                        }
                except Exception as probe_err:
                    # Probe failed — kill the half-initialized child and clear state.
                    with mcp_lock:
                        p = mcp_processes.pop(key, None)
                        mcp_servers.pop(key, None)
                    if p is not None:
                        try: p.terminate()
                        except Exception: pass
                    return json.dumps({"error": f"failed to probe server '{server}': {probe_err}"}, ensure_ascii=False)

            result = mcp_call(key, "tools/call", {"name": tool, "arguments": args or {}})
            return json.dumps(result, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e)}, ensure_ascii=False)

    if action == "unload":
        with mcp_lock:
            if server:
                key = f"{cwd}:{server}"
                proc = mcp_processes.pop(key, None)
                mcp_servers.pop(key, None)
                to_terminate = [proc] if proc else []
            else:
                keys = [k for k in list(mcp_processes.keys()) if k.startswith(f"{cwd}:")]
                to_terminate = [mcp_processes.pop(k) for k in keys]
                for k in keys:
                    mcp_servers.pop(k, None)
        for p in to_terminate:
            try: p.terminate()
            except Exception: pass
        return json.dumps({"success": True}, ensure_ascii=False)

    return json.dumps({"error": f"unknown action: {action}"}, ensure_ascii=False)


def mcp_call(key: str, method: str, params: dict) -> dict:
    """Make a JSON-RPC call to an MCP server over stdio."""
    global mcp_next_id
    with mcp_lock:
        mcp_next_id += 1
        req_id = mcp_next_id
        proc = mcp_processes[key]
        request = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
        try:
            proc.stdin.write((json.dumps(request) + "\n").encode("utf-8"))
            proc.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise IOError(f"MCP server pipe broken: {e}")

        deadline = time.time() + 30
        while time.time() < deadline:
            if sys.platform == "win32":
                # select() on Windows doesn't support pipes; fall back to readline w/o timeout polling.
                line = proc.stdout.readline()
            else:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                ready, _, _ = select.select([proc.stdout], [], [], remaining)
                if not ready:
                    raise TimeoutError("MCP server response timeout")
                line = proc.stdout.readline()
            if not line:
                raise EOFError("MCP server process ended")
            try:
                response = json.loads(line.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            if isinstance(response, dict) and response.get("id") == req_id:
                if "error" in response:
                    return {"error": response["error"]}
                return response.get("result", {})
        raise TimeoutError("MCP server response timeout")


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

    server = ThreadingHTTPServer((bind_addr, port), MCPRequestHandler)
    bind_label = bind_addr if bind_addr not in ("0.0.0.0", "::") else "localhost"
    print(f"code-mcp listening on http://{bind_label}:{port}/mcp"
          f"{' (auth)' if token else ' (no auth)'}", file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
