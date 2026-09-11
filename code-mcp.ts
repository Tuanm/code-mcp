#!/usr/bin/env bun
// Minimal MCP server over HTTP (Streamable HTTP transport, JSON-RPC 2.0).
//
// Tools (always on): read, write, edit, multi_edit, bash, shell, command, powershell, grep, find, ls, job, mcp.
// Tools (conditional):
//   - preview              enabled only if `cloudflared` is on PATH
//   - remember, forget, recall  enabled only with --enable-memory
//   - get_upload_link      enabled only with --public or --domain
//
// Shell tools: only one enabled based on detected shell (bash/shell/command/powershell).
//
// Flags:
//   --port <n>         listen port (default: 7777, or $PORT)
//   --token <s>        require ?token=<s> on every request (default: no auth)
//   --enable-memory    enable the remember/forget/recall tools
//   --public           expose via a Cloudflare quick tunnel (requires cloudflared)
//   --domain <host>    use the given public hostname (assumes tunnel already routes it to this port). Mutex with --public.
//   --mcp <path>       aggregate tools from external MCP servers defined in the given JSON config (Claude Desktop format).

import { spawn, spawnSync, file, write } from "bun";
import { readdirSync, statSync, mkdirSync, rmSync, realpathSync, lstatSync, constants as fsConstants } from "node:fs";
import { open as fsOpen, rename as fsRename, unlink as fsUnlink, stat as fsStat } from "node:fs/promises";
import { resolve, sep, basename, dirname } from "node:path";
import { tmpdir } from "node:os";
import { createHmac, randomBytes, timingSafeEqual, randomUUID } from "node:crypto";
import { parseArgs } from "util";

type Json = any;
type Tool = {
  description: string;
  inputSchema: Json;
  handler: (args: Json) => Promise<Json> | Json;
};

// ---------- jobs ----------
type Job = {
  id: string;
  command: string;
  proc: ReturnType<typeof spawn>;
  output: string;
  status: "running" | "exited";
  exitCode?: number;
  startedAt: number;
};
const jobs = new Map<string, Job>();
let jobSeq = 0;
let shuttingDown = false;
let totalJobs = 0;

// Shell command wrappers for each shell type.
function bashCmd(command: string): string[] { return ["bash", "-c", command]; }
function shCmd(command: string): string[] { return ["sh", "-c", command]; }
function cmdCmd(command: string): string[] { return ["cmd.exe", "/d", "/s", "/c", command]; }
function pwshCmd(command: string): string[] {
  // Fall back to "pwsh" name if neither variant is on PATH so spawn surfaces a
  // clear "command not found" rather than throwing earlier.
  const bin = POWERSHELL_BIN ?? "pwsh";
  // -EncodedCommand (base64 UTF-16LE) instead of raw -Command: the Windows
  // command line mangles embedded double quotes, so a quoted "|" separator
  // became a real pipeline and PowerShell tried to run "PLAT=..." as a command.
  // Base64 has no shell metacharacters, so the script arrives intact.
  return [bin, "-NoProfile", "-EncodedCommand", Buffer.from(command, "utf16le").toString("base64")];
}

// Detect running shell at startup.
type ShellType = "bash" | "sh" | "cmd" | "powershell";
const IS_WINDOWS = process.platform === "win32";

// Detect which PowerShell binary is available, using raw spawn (don't go through
// shellCmd → chicken-and-egg with DETECTED_SHELL).
function detectPowerShellBinary(): string | null {
  const probe = (bin: string) => {
    try {
      return spawnSync({
        cmd: IS_WINDOWS
          ? ["cmd.exe", "/d", "/s", "/c", `where ${bin}`]
          : ["sh", "-c", `command -v ${bin}`],
        stdout: "ignore",
        stderr: "ignore",
      }).exitCode === 0;
    } catch { return false; }
  };
  if (probe("pwsh")) return "pwsh";
  if (probe("powershell")) return "powershell";
  return null;
}
const POWERSHELL_BIN = detectPowerShellBinary();

function detectShell(): ShellType {
  if (IS_WINDOWS) {
    // PSModulePath is set inside any PowerShell session (5.1 or 7+). Use that as
    // the authoritative signal AND require a usable powershell binary; otherwise
    // fall back to cmd (which is always present).
    if (process.env.PSModulePath && POWERSHELL_BIN) return "powershell";
    return "cmd";
  }
  // Prefer bash if present (matches Python/Java); fall back to $SHELL hint then sh.
  if (spawnSync({ cmd: ["sh", "-c", "command -v bash"], stdout: "ignore", stderr: "ignore" }).exitCode === 0) return "bash";
  const shell = process.env.SHELL;
  if (shell && /\/(bash|zsh|fish|ksh)$/.test(shell)) return shell.endsWith("bash") ? "bash" : "sh";
  return "sh";
}
const DETECTED_SHELL = detectShell();
const shellCmd = DETECTED_SHELL === "bash" ? bashCmd
  : DETECTED_SHELL === "sh" ? shCmd
  : DETECTED_SHELL === "powershell" ? pwshCmd
  : cmdCmd;

// Detect optional external binaries once at startup. Use the platform's
// own binary-locator: `where` on Windows, `command -v` on POSIX. Both
// exit 0 iff the binary is found.
function hasOnPath(bin: string): boolean {
  const probe = IS_WINDOWS ? `where ${bin}` : `command -v ${bin}`;
  return spawnSync({ cmd: shellCmd(probe), stdout: "ignore", stderr: "ignore" }).exitCode === 0;
}
const hasRg = hasOnPath("rg");
const hasFindstr = hasOnPath("findstr");
const hasCloudflared = hasOnPath("cloudflared");

// ---------- args ----------
const USAGE = `Usage: bun code-mcp.ts [options]

Options:
  --port <n>             Listen port (default: 7777, or $PORT)
  --bind <addr>          Bind address (default: 127.0.0.1)
  --token <s>            Require ?token=<s> or Bearer auth on every request
  --enable-memory        Enable remember/forget/recall tools
  --disallowed-tools     Comma-separated list of tools to disable (highest priority)
  --public               Expose via Cloudflare quick tunnel (requires cloudflared)
  --domain <host>        Use given public hostname (mutually exclusive with --public)
  --mcp <path>           Aggregate tools from external MCP servers (JSON config)
  --gateway [domain]     Connect to gateway server; bare flag uses the default
                         (wss://code-mcp.tuanm.workers.dev)
  --id <uuid>            Use specific device ID for gateway connection
  --gateway-token <s>    Device credential sent to the gateway on connect
                         (defaults to --token; must match the token registered
                         for --id in the gateway device registry)
  -h, --help             Show this help and exit`;

// Bare --gateway (no value) connects to the default managed gateway.
const DEFAULT_GATEWAY = "code-mcp.tuanm.workers.dev";
const cliArgs = Bun.argv.slice(2);
for (let i = 0; i < cliArgs.length; i++) {
  if (cliArgs[i] === "--gateway" && (i + 1 >= cliArgs.length || cliArgs[i + 1].startsWith("--"))) {
    cliArgs.splice(i + 1, 0, DEFAULT_GATEWAY);
    break;
  }
}

let args!: Record<string, any>;
try {
  ({ values: args } = parseArgs({
    args: cliArgs,
    options: {
      port: { type: "string" },
      bind: { type: "string" },
      token: { type: "string" },
      "enable-memory": { type: "boolean" },
      "disallowed-tools": { type: "string" },
      public: { type: "boolean" },
      domain: { type: "string" },
      mcp: { type: "string" },
      gateway: { type: "string" },
      id: { type: "string" },
      "gateway-token": { type: "string" },
      help: { type: "boolean", short: "h" },
    },
    strict: true,
    allowPositionals: false,
  }));
} catch (e: any) {
  console.error(`error: ${e?.message ?? e}\n`);
  console.error(USAGE);
  process.exit(2);
}
if (args.help) {
  console.log(USAGE);
  process.exit(0);
}
const portRaw = args.port ?? process.env.PORT ?? 7777;
const port = Number(portRaw);
if (!Number.isFinite(port) || port < 1 || port > 65535 || !Number.isInteger(port)) {
  console.error(`error: invalid port: ${portRaw}`);
  process.exit(2);
}
const bindAddr: string = typeof args.bind === "string" ? args.bind : "127.0.0.1";
const token: string | undefined = args.token;
// Device credential presented to the gateway on the /ws upgrade: explicit
// --gateway-token wins, otherwise --token (the token registered for the
// device id in the gateway is what authenticates the tunnel).
const gatewayToken: string | undefined = args["gateway-token"] ?? token;
const memoryEnabled = args["enable-memory"] === true;
const disallowedTools: string[] = args["disallowed-tools"]
  ? args["disallowed-tools"].split(",").map((s: string) => s.trim()).filter(Boolean)
  : [];
const makePublic = args.public === true;
const domain: string | undefined = args.domain;
const gatewayDomain: string | undefined = args.gateway;
const assignedDeviceId: string | undefined = args.id;
const mcpConfigPath: string | undefined = args.mcp;

if (makePublic && domain) {
  console.error("error: --public and --domain are mutually exclusive\n");
  console.error(USAGE);
  process.exit(2);
}
// Exposing the server to the internet without a token is an unauthenticated
// remote shell (read/write/bash). Refuse instead of silently enabling it.
if ((makePublic || domain) && !token) {
  console.error("error: --public/--domain require --token (otherwise the server is an unauthenticated remote shell)\n");
  console.error(USAGE);
  process.exit(2);
}
if (domain && !/^[A-Za-z0-9.\-]+(:[0-9]{1,5})?$/.test(domain)) {
  console.error(`error: invalid --domain: ${domain}`);
  process.exit(2);
}

// publicBaseUrl is set either synchronously (from --domain) or asynchronously
// after the cloudflared quick tunnel prints its URL. Tools that need it must
// check for `null` at call time.
let publicBaseUrl: string | null = domain ? `https://${domain}` : null;

// Upload root: /private/tmp on macOS (canonical path; /tmp is a symlink there),
// /tmp on Linux, else whatever Node says. Detected once at startup.
const UPLOAD_ROOT =
  process.platform === "darwin" ? "/private/tmp" :
  process.platform === "linux" ? "/tmp" :
  tmpdir();

// ---------- result spill ----------
// Tool results larger than RESULT_SPILL_THRESHOLD bytes are written to a file
// under RESULT_SPILL_ROOT and replaced in the response with a head+tail
// preview plus a pointer to the full file. This protects the agent's context
// window even when the in-memory cap (OUTPUT_CAP_MAX = 1MB) hasn't kicked in.
//
// Threshold and preview sizes are intentionally hard-coded — see project
// CLAUDE.md and the conversation that introduced this feature for the
// rationale (avoid yet-another-flag).
const RESULT_SPILL_ROOT = resolve(tmpdir(), "code-mcp");
const RESULT_SPILL_THRESHOLD = 10_000; // bytes
const RESULT_SPILL_HEAD = 3_000;
const MAX_READ_BYTES = 100 * 1024 * 1024; // cap single-file reads (memory DoS guard)

// Best-effort cleanup of any stale spill files from a previous run. Failure
// is non-fatal: the spill directory may not exist yet, may belong to another
// user, or may be on a read-only filesystem.
// We DO NOT rmSync the shared root because concurrent instances would clobber
// each other; we just ensure our per-PID subdirectory exists.
try {
  mkdirSync(RESULT_SPILL_ROOT, { recursive: true });
  // Spill files hold tool output (potentially secrets): keep the root private
  // and sweep files older than 24h so a long session can't fill the disk or
  // leave world-readable data behind.
  try { chmodSync(RESULT_SPILL_ROOT, 0o700); } catch {}
  const cutoff = Date.now() - 86_400_000;
  for (const name of readdirSync(RESULT_SPILL_ROOT)) {
    try {
      const p = resolve(RESULT_SPILL_ROOT, name);
      const st = statSync(p);
      if (st.isFile() && st.mtimeMs < cutoff) rmSync(p, { force: true });
    } catch {}
  }
} catch (e: any) {
  console.error(`[spill] failed to prepare ${RESULT_SPILL_ROOT}: ${e?.message ?? e}`);
}

// If `text` exceeds the threshold, write it to a metadata-named file in the
// spill directory and return a preview string with a pointer. Otherwise
// pass through unchanged. Async so we don't block the event loop on the
// write; the caller is already awaiting the tool response.
//
// Preview semantics:
//   - HEAD is measured in bytes (UTF-8), matching the threshold.
//   - Slicing is byte-exact; decoding tolerates half-characters at the slice
//     boundary instead of corrupting them.
//   - After byte-slicing, head is trimmed back to the last newline, so the
//     preview lands on a line boundary. This makes log/JSON/code output
//     readable without forcing the agent to guess where the cut happened.
//   - The truncated content is not shown; only a marker pointing to the spill file.
async function maybeSpillText(text: string, toolName?: string): Promise<string> {
  const bytes = Buffer.byteLength(text, "utf8");
  if (bytes <= RESULT_SPILL_THRESHOLD) return text;

  // Byte-exact head. Use `fatal: false` so a multibyte char straddling
  // the cut is replaced (U+FFFD) rather than throwing.
  const buf = Buffer.from(text, "utf8");
  const dec = new TextDecoder("utf-8", { fatal: false });
  let head = dec.decode(buf.subarray(0, RESULT_SPILL_HEAD));

  // Snap to line boundaries when possible. If a line is longer than the
  // window (e.g., a 50 KB single-line JSON), fall back to the byte cut.
  const lastNl = head.lastIndexOf("\n");
  if (lastNl > 0) head = head.slice(0, lastNl);

  // Filename: <ISO compact>-<tool>-<uuid8>.txt. Sortable by time, greppable
  // by tool. UUID suffix keeps it unique within the same millisecond.
  const ts = new Date().toISOString().replace(/[-:.]/g, "").replace(/Z$/, "");
  const safeTool = (toolName ?? "unknown").replace(/[^A-Za-z0-9_.-]/g, "_");
  const shortId = randomUUID().slice(0, 8);
  const fname = `${ts}-${safeTool}-${shortId}.txt`;
  const path = resolve(RESULT_SPILL_ROOT, fname);

  // Count total lines for the marker. This is the only O(N) operation.
  const totalLines = text.length === 0 ? 0 : (text.match(/\n/g)?.length ?? 0) + 1;

  try {
    await Bun.write(path, text);
    try { chmodSync(path, 0o600); } catch {}
  } catch (e: any) {
    // Spill failed (full disk, read-only fs, permission). Do NOT fall back
    // to returning the full text — that would blow the agent's context.
    // Return the preview with a marker explaining what happened.
    console.error(`[spill] failed to write ${path}: ${e?.message ?? e}`);
    const failMarker =
      `\n[TRUNCATED: full output is ${bytes} bytes (${totalLines} lines); ` +
      `spill to disk FAILED (${e?.message ?? "unknown error"})]\n`;
    return head + failMarker;
  }

  const marker =
    `\n[TRUNCATED: ${bytes} bytes (${totalLines} lines) saved to ${path} — ` +
    `use read with range or grep to view the remaining content]\n`;
  return head + marker;
}

// ---------- upload session HMAC ----------
// session_id = base64url(payload).base64url(HMAC-SHA256(token, payload))
// payload = `${exp_unix_ms}.${nonce_hex}`. TTL = 10 minutes.
const UPLOAD_TTL_MS = 10 * 60 * 1000;

function b64url(buf: Buffer | string): string {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(s: string): Buffer {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Buffer.from(s, "base64");
}

function mintUploadSessionId(): string {
  if (!token) throw new Error("--token is required to mint upload sessions");
  const exp = Date.now() + UPLOAD_TTL_MS;
  const nonce = randomBytes(8).toString("hex");
  const payload = `${exp}.${nonce}`;
  const sig = createHmac("sha256", token).update(payload).digest();
  return `${b64url(payload)}.${b64url(sig)}`;
}

function verifyUploadSessionId(id: string): { ok: true } | { ok: false; reason: string } {
  if (!token) return { ok: false, reason: "server has no token configured" };
  const parts = id.split(".");
  if (parts.length !== 2) return { ok: false, reason: "malformed" };
  let payload: string;
  let sig: Buffer;
  try {
    payload = b64urlDecode(parts[0]).toString("utf8");
    sig = b64urlDecode(parts[1]);
  } catch {
    return { ok: false, reason: "malformed" };
  }
  const expected = createHmac("sha256", token).update(payload).digest();
  if (sig.length !== expected.length || !timingSafeEqual(sig, expected)) {
    return { ok: false, reason: "bad signature" };
  }
  const [expStr] = payload.split(".");
  const exp = Number(expStr);
  if (!Number.isFinite(exp) || Date.now() > exp) return { ok: false, reason: "expired" };
  return { ok: true };
}

// Cap how much output we keep in memory for any captured stream. When the
// buffer exceeds CAP_MAX, we trim back to CAP_KEEP from the tail. This
// matters for grep across large trees, cat-ing big files via bash, and any
// long-running background job that floods output.
const OUTPUT_CAP_MAX = 1_000_000;
const OUTPUT_CAP_KEEP = 500_000;
const DEFAULT_SHELL_TIMEOUT_MS = 60_000;

function timeoutMarker(ms: number): string {
  return `\n[TIMEOUT after ${ms}ms — long-running? use the \`job\` tool: `
    + `mode=start to launch, mode=view to check progress]`;
}

function backgroundedMarker(ms: number, jobId: string): string {
  return `\n[BACKGROUNDED after ${ms}ms — process still running as job ${jobId}. `
    + `Above output is a snapshot at handoff; further output continues into the job. `
    + `Use \`job\` tool: mode=view command=${jobId} to read, mode=stop command=${jobId} to kill. `
    + `Pass explicit timeout_ms to disable auto-background and force kill-on-timeout instead.]`;
}

// Kill a process and all its descendants. Bun's proc.kill() only signals the
// direct child; orphaned grandchildren (e.g. `sleep` spawned by a killed
// `bash`) keep stdout pipes open and stall proc.exited. Use pgrep -P to walk
// the tree and SIGKILL each pid.
function killProcessTree(pid: number) {
  if (process.platform === "win32") {
    try { spawnSync({ cmd: ["taskkill", "/F", "/T", "/PID", String(pid)], stdout: "ignore", stderr: "ignore" }); } catch {}
    return;
  }
  // Walk descendants depth-first so children die before parents (cleaner).
  let children: number[] = [];
  try {
    const out = spawnSync({ cmd: ["pgrep", "-P", String(pid)], stdout: "pipe", stderr: "ignore" })
      .stdout.toString().trim();
    if (out) children = out.split("\n").map((s) => parseInt(s, 10)).filter((n) => Number.isFinite(n));
  } catch {}
  for (const c of children) killProcessTree(c);
  try { process.kill(pid, "SIGKILL"); } catch {}
}

// Shared runner for bash/shell/command/powershell tools.
//
// Two paths depending on whether the caller passed timeout_ms:
//   - explicit timeout_ms > 0: classic kill-on-timeout behaviour (exit=124 + timeoutMarker).
//   - no timeout_ms: at DEFAULT_SHELL_TIMEOUT_MS (60s) the still-running process is
//     adopted into the `job` system instead of being killed, and we return
//     exit=running + backgroundedMarker so the agent can poll with the `job` tool.
//
// Uses a single combined sink (stdout+stderr interleaved by arrival, matching the
// `job` tool's behaviour) so the sink can be handed off to the adopted Job
// without merging buffers.
// Bound concurrent shell executions (parity with Java/Python's 5 permits):
// an agent firing many bash calls in parallel must not spawn unbounded
// subprocesses (resource-DoS guard).
const MAX_CONCURRENT_SHELL = 5;
let shellActive = 0;
const shellWaiters: Array<() => void> = [];

async function acquireShellSlot(timeoutMs = 30_000): Promise<boolean> {
  if (shellActive < MAX_CONCURRENT_SHELL) { shellActive++; return true; }
  return new Promise<boolean>((resolve) => {
    let done = false;
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      const i = shellWaiters.indexOf(wake);
      if (i >= 0) shellWaiters.splice(i, 1);
      resolve(false);
    }, timeoutMs);
    const wake = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      shellActive++;
      resolve(true);
    };
    shellWaiters.push(wake);
  });
}

function releaseShellSlot(): void {
  shellActive--;
  const w = shellWaiters.shift();
  if (w) w();
}

async function runShell(cmd: string[], cwd: string, command: string, timeout_ms?: number): Promise<string> {
  if (!(await acquireShellSlot())) {
    return "ERROR: Too many concurrent shell executions, please try again later";
  }
  try {
    return await runShellInner(cmd, cwd, command, timeout_ms);
  } finally {
    releaseShellSlot();
  }
}

async function runShellInner(cmd: string[], cwd: string, command: string, timeout_ms?: number): Promise<string> {
  const explicit = typeof timeout_ms === "number" && timeout_ms > 0;
  const effective = explicit ? (timeout_ms as number) : DEFAULT_SHELL_TIMEOUT_MS;
  let proc: ReturnType<typeof spawn>;
  try {
    proc = spawn({
      cmd,
      cwd,
      stdout: "pipe",
      stderr: "pipe",
      stdin: "ignore",
      env: buildChildEnv({}),
      // Own process group so killJobTree's negative-PID kill reaches
      // grandchildren (tree-kill parity with Python/Java).
      detached: process.platform !== "win32",
    });
  } catch (e) {
    // Match Python's exit=-1 + ERROR shape so MCP clients see a uniform error format
    // (bad cwd, missing binary, fork failure) instead of an unhandled exception.
    const reason = (e as Error).message || String(e);
    return `exit=-1\nERROR: ${reason}`;
  }
  const sink = { text: "" };
  // .catch on each inner promise: on the auto-background path the outer Promise.all
  // is never awaited, so a pump rejection (reader error, decoder hiccup) would
  // surface as an unhandledRejection and crash the server.
  const pumps = Promise.all([
    pumpCapped(proc.stdout as any, sink).catch(() => {}),
    pumpCapped(proc.stderr as any, sink).catch(() => {}),
  ]);
  let timerHandle: ReturnType<typeof setTimeout> | null = null;
  const timerPromise = new Promise<"timeout">((resolve) => {
    timerHandle = setTimeout(() => resolve("timeout"), effective);
  });
  type ExitWin = { kind: "exit"; code: number };
  const exitPromise: Promise<ExitWin> = proc.exited.then((code: number) => ({ kind: "exit", code }));

  try {
    const winner = await Promise.race([exitPromise, timerPromise]);
    if (winner !== "timeout") {
      await pumps;
      return `exit=${(winner as ExitWin).code}\n${sink.text}`;
    }

    // Timer fired. Process still running (or just exited within race window).
    if (explicit) {
      const pid = (proc as any)?.pid;
      if (pid) killProcessTree(pid);
      await proc.exited;
      await pumps;
      return `exit=124\n${sink.text}${timeoutMarker(effective)}`;
    }

    // No explicit timeout: hand off to the job system instead of killing.
    try {
      const job = adoptJob(command, proc as any, sink);
      return `exit=running\n${sink.text}${backgroundedMarker(effective, job.id)}`;
    } catch (e) {
      // Adoption failed (MAX_JOBS reached, shutting down, …) — degrade to kill.
      const pid = (proc as any)?.pid;
      if (pid) killProcessTree(pid);
      await proc.exited;
      await pumps;
      const reason = (e as Error).message || String(e);
      return `exit=124\n${sink.text}\n[Auto-background failed: ${reason}; process killed.]`;
    }
  } finally {
    if (timerHandle) clearTimeout(timerHandle);
  }
}

// Spawn-time env allow-list. Used for both .mcp.json children AND user-invoked
// shell tools. The MCP token is itself sensitive (full RCE on hand-off), so we
// limit blast radius: even if an attacker phishes the token, they can't trivially
// exfiltrate AWS_*, OPENAI_API_KEY, etc. — those vars are not forwarded.
// Users who need extra vars in their commands should set them inline:
//   bash -c "FOO=$FOO_FROM_FILE my-cmd"
const SPAWN_ENV_ALLOWLIST = new Set([
  "PATH", "HOME", "USER", "SHELL", "LANG", "LC_ALL", "TZ",
  "TMPDIR", "TEMP", "TMP",
  "SystemRoot", "SystemDrive", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
  "PROGRAMFILES", "PROGRAMDATA", "WINDIR", "COMSPEC", "PATHEXT",
]);

function buildChildEnv(extra: Record<string, string>): Record<string, string> {
  const base: Record<string, string> = {};
  for (const k of SPAWN_ENV_ALLOWLIST) {
    const v = process.env[k];
    if (typeof v === "string") base[k] = v;
  }
  return { ...base, ...extra };
}

// Pump a readable stream into `sink.text`, capping in-place. Used by both the
// background-job harness (startJob) and one-shot tool handlers (bash, grep)
// so memory use is bounded everywhere we capture subprocess output.
//
// Decoder uses {stream:true} so a UTF-8 sequence split across chunk boundaries
// is held until completion instead of being emitted as U+FFFD. Cap is measured
// in bytes (via Buffer.byteLength) to stay consistent with maybeSpillText and
// to give honest accounting for multibyte content; when trimming, we slice the
// underlying bytes and re-decode with `fatal: false` so a half-character at
// the head of the kept tail is replaced rather than throwing.
async function pumpCapped(stream: ReadableStream<Uint8Array> | null, sink: { text: string }): Promise<void> {
  if (!stream) return;
  const reader = stream.getReader();
  const dec = new TextDecoder("utf-8");
  // Only re-cap when text has grown noticeably past the limit so we don't
  // re-encode the whole buffer on every single chunk during log spam.
  const RECAP_THRESHOLD = OUTPUT_CAP_MAX + (OUTPUT_CAP_MAX - OUTPUT_CAP_KEEP);
  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      sink.text += dec.decode();
      break;
    }
    sink.text += dec.decode(value, { stream: true });
    if (Buffer.byteLength(sink.text, "utf8") > RECAP_THRESHOLD) {
      const buf = Buffer.from(sink.text, "utf8");
      sink.text = new TextDecoder("utf-8").decode(buf.subarray(buf.length - OUTPUT_CAP_KEEP));
    }
  }
}

function startJob(command: string, cwd: string): Job {
  return startJobImpl(shellCmd(command), command, cwd);
}

// Like startJob but spawns argv directly (no shell interpolation): use for
// tool inputs that must never reach a shell (e.g. preview's URL).
function startJobArgv(argv: string[], displayCommand: string, cwd: string): Job {
  return startJobImpl(argv, displayCommand, cwd);
}

function startJobImpl(argv: string[], displayCommand: string, cwd: string): Job {
  if (totalJobs >= MAX_JOBS) throw new Error(`max concurrent jobs (${MAX_JOBS}) exceeded`);
  if (shuttingDown) throw new Error("server is shutting down");
  totalJobs++;
  const id = `j${++jobSeq}`;
  let proc: any;
  try {
    proc = spawn({
      cmd: argv,
      cwd,
      stdout: "pipe",
      stderr: "pipe",
      stdin: "ignore",
      env: buildChildEnv({}),
      // Own process group so killJobTree's negative-PID kill reaches
      // grandchildren too (tree-kill parity with Python/Java).
      detached: process.platform !== "win32",
    });
  } catch (e) {
    totalJobs--;
    throw e;
  }
  const job: Job = { id, command: displayCommand, proc, output: "", status: "running", startedAt: Date.now() };
  jobs.set(id, job);

  const sink = { get text() { return job.output; }, set text(v: string) { job.output = v; } };
  // Fire-and-forget pumps — same unhandled-rejection guard as runShell.
  pumpCapped(proc.stdout as any, sink).catch(() => {});
  pumpCapped(proc.stderr as any, sink).catch(() => {});
  proc.exited.then((code: number) => {
    totalJobs--;
    job.status = "exited";
    job.exitCode = code;
    // Exited jobs are kept briefly for view_job, then evicted so the map
    // cannot grow without bound (memory-leak guard).
    setTimeout(() => { jobs.delete(id); }, 60 * 60 * 1000);
  });
  return job;
}

// Adopt an already-spawned process (whose stdout/stderr are being pumped into `sink`)
// into the job registry. Reuses the existing sink so in-flight pump writes continue
// to land in job.output without dropping data; the sink's `text` accessor is rebound
// to delegate to job.output so subsequent reads and appends stay coherent.
function adoptJob(command: string, proc: any, sink: { text: string }): Job {
  if (totalJobs >= MAX_JOBS) throw new Error(`max concurrent jobs (${MAX_JOBS}) exceeded`);
  if (shuttingDown) throw new Error("server is shutting down");
  totalJobs++;
  const id = `j${++jobSeq}`;
  const job: Job = { id, command, proc, output: sink.text, status: "running", startedAt: Date.now() };
  jobs.set(id, job);
  Object.defineProperty(sink, "text", {
    get: () => job.output,
    set: (v: string) => { job.output = v; },
    configurable: true,
    enumerable: true,
  });
  proc.exited.then((code: number) => {
    totalJobs--;
    job.status = "exited";
    job.exitCode = code;
  });
  return job;
}

// ---------- memos ----------
type Memo = { id: number; ts: number; memo: string; tags?: string[] };

// Filter to a clean string[] or undefined. Drops null/numbers/empty strings.
function sanitizeTags(tags: unknown): string[] | undefined {
  if (!Array.isArray(tags)) return undefined;
  const out: string[] = [];
  for (const t of tags) {
    if (typeof t === "string" && t.length > 0) out.push(t);
  }
  return out.length ? out : undefined;
}

async function readMemos(cwd: string): Promise<Memo[]> {
  const f = file(resolve(cwd, ".memo.jsonl"));
  if (!(await f.exists())) return [];
  const text = await f.text();
  const memos: Memo[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const m = JSON.parse(trimmed) as Memo;
      if (typeof m?.id === "number" && typeof m?.memo === "string" && typeof m?.ts === "number") {
        const cleanTags = sanitizeTags((m as { tags?: unknown }).tags);
        if (cleanTags) m.tags = cleanTags; else delete m.tags;
        memos.push(m);
      }
    } catch {
      // skip malformed line — survives partial writes, manual edits, encoding glitches
    }
  }
  return memos;
}

// Atomic overwrite: write to tmp, fsync, rename. Survives crash mid-write.
async function writeMemos(cwd: string, memos: Memo[]): Promise<void> {
  const text = memos.map((m) => JSON.stringify(m)).join("\n") + (memos.length ? "\n" : "");
  const target = resolve(cwd, ".memo.jsonl");
  const tmp = target + ".tmp";
  const fh = await fsOpen(tmp, "w");
  try {
    await fh.writeFile(text);
    await fh.sync();
  } finally {
    await fh.close();
  }
  await fsRename(tmp, target);
}

// ---------- cross-process memo lock ----------
// Multiple Claude agents on the same device may share a cwd. Coordinate via
// an EEXIST lockfile so remember/forget never interleave across processes.
const MEMO_LOCK_TIMEOUT_MS = 30_000;
const STALE_MEMO_LOCK_MS = 60_000;
const MEMO_LOCK_RETRY_MS = 40;

async function acquireMemoLock(cwd: string): Promise<() => Promise<void>> {
  const lockPath = resolve(cwd, ".memo.lock");
  const start = Date.now();
  while (Date.now() - start < MEMO_LOCK_TIMEOUT_MS) {
    try {
      const fh = await fsOpen(
        lockPath,
        fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
      );
      try { await fh.writeFile(`${process.pid}\n`); } catch { /* best-effort */ }
      await fh.close();
      return async () => { try { await fsUnlink(lockPath); } catch { /* gone is fine */ } };
    } catch (e) {
      if ((e as NodeJS.ErrnoException)?.code !== "EEXIST") throw e;
      try {
        const st = await fsStat(lockPath);
        if (Date.now() - st.mtimeMs > STALE_MEMO_LOCK_MS) {
          try { await fsUnlink(lockPath); } catch { /* race ok */ }
          continue;
        }
      } catch {
        // lock vanished between EEXIST and stat — retry immediately
        continue;
      }
      await new Promise((r) => setTimeout(r, MEMO_LOCK_RETRY_MS + Math.random() * 30));
    }
  }
  throw new Error(`could not acquire memo lock at ${lockPath} within ${MEMO_LOCK_TIMEOUT_MS}ms`);
}

// Read the last memo id from {cwd}/.memo.jsonl without loading the whole file.
// Reads a tail window and parses the last complete JSON line. Falls back to a
// full scan if the tail can't be parsed (e.g. a single memo longer than the
// tail window, or a partial write from a crash).
const MEMO_TAIL_BYTES = 8192;
async function lastMemoId(cwd: string): Promise<number> {
  const f = file(resolve(cwd, ".memo.jsonl"));
  if (!(await f.exists())) return 0;
  const size = f.size;
  if (size === 0) return 0;
  const tail = await f.slice(Math.max(0, size - MEMO_TAIL_BYTES), size).text();
  const lines = tail.split("\n").filter((l) => l.trim());
  // Try from the last line backward — a partial last line will fail to parse.
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const m = JSON.parse(lines[i]) as Memo;
      if (typeof m.id === "number") return m.id;
    } catch { /* try previous */ }
  }
  // Tail window didn't contain a complete line (single huge memo, or all
  // corrupted). Fall back to full scan.
  const memos = await readMemos(cwd);
  return memos.reduce((m, x) => Math.max(m, x.id), 0);
}

// ---------- guide ----------
// Renders an XML-block operating manual for the agent. Reflects live state
// of this server (enabled tools, memos in cwd, project docs, external MCP
// servers). Called by the `guide` tool.

function xmlAttr(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

async function collectMemoState(cwd: string): Promise<{ count: number; latest: string | null; lockHeld: boolean }> {
  const memos = await readMemos(cwd);
  let latest: string | null = null;
  if (memos.length) {
    const newest = memos.reduce((a, b) => (a.id > b.id ? a : b));
    const ts = new Date(newest.ts).toISOString();
    const tagStr = newest.tags?.length ? `, tags=[${newest.tags.join(",")}]` : "";
    latest = `${ts}${tagStr}`;
  }
  let lockHeld = false;
  try {
    const st = await fsStat(resolve(cwd, ".memo.lock"));
    lockHeld = Date.now() - st.mtimeMs <= STALE_MEMO_LOCK_MS;
  } catch { /* no lock = not held */ }
  return { count: memos.length, latest, lockHeld };
}

async function collectProjectDocs(cwd: string): Promise<string[]> {
  const docs: string[] = [];
  for (const name of ["CLAUDE.md", "README.md"]) {
    try {
      const st = await fsStat(resolve(cwd, name));
      if (st.isFile()) docs.push(name);
    } catch { /* not present */ }
  }
  return docs;
}

// Lightweight scan of <cwd>/.mcp.json for the guide block: name + transport only.
// Lenient (e.g. accepts http://localhost URLs) because the guide is informational;
// the strict validation happens when the mcp tool actually loads the server.
async function collectLoadableServers(cwd: string): Promise<Array<{ ns: string; transport: "stdio" | "http" }>> {
  try {
    const raw = await file(resolve(cwd, ".mcp.json")).text();
    const parsed = JSON.parse(raw);
    const servers = parsed?.mcpServers;
    if (!servers || typeof servers !== "object") return [];
    const out: Array<{ ns: string; transport: "stdio" | "http" }> = [];
    for (const [ns, cfg] of Object.entries(servers as Record<string, any>)) {
      if (!NAMESPACE_RE.test(ns)) continue;
      if (!cfg || typeof cfg !== "object") continue;
      const transport: "stdio" | "http" = cfg.type === "http" ? "http" : "stdio";
      if (transport === "http" && typeof cfg.url !== "string") continue;
      if (transport === "stdio" && typeof cfg.command !== "string") continue;
      out.push({ ns, transport });
    }
    return out.sort((a, b) => a.ns.localeCompare(b.ns));
  } catch { return []; }
}

function listExternalServers(): Array<{ ns: string; tools: string[] }> {
  // Source of truth: aggregatorKnownServers (declared in --mcp config).
  // Tool names come from aggregatedTools (only populated for probed servers).
  const probedByNs = new Map<string, string[]>();
  for (const [, tool] of aggregatedTools) {
    const list = probedByNs.get(tool.namespace) ?? [];
    list.push(tool.originalName);
    probedByNs.set(tool.namespace, list);
  }
  return [...aggregatorKnownServers].sort().map((ns) => ({
    ns,
    tools: (probedByNs.get(ns) ?? []).slice().sort(),
  }));
}

async function renderGuide(cwd: string): Promise<string> {
  const lines: string[] = [];
  lines.push(`<guide tool="code-mcp">`);
  lines.push("");

  const memoState = memoryEnabled ? await collectMemoState(cwd) : null;
  const docs = await collectProjectDocs(cwd);

  // state block
  lines.push(`<state cwd="${xmlAttr(cwd)}">`);
  if (memoState) {
    const latest = memoState.latest ? ` (latest ${memoState.latest})` : "";
    lines.push(`memos: ${memoState.count}${latest}`);
    lines.push(`concurrent_writer: ${memoState.lockHeld ? "yes" : "no"}`);
  }
  if (docs.length) {
    lines.push(`project_docs: ${docs.join(", ")}  (read for project rules)`);
  }
  lines.push(`</state>`);

  // session_start
  if (memoryEnabled || docs.length) {
    lines.push("");
    lines.push(`<session_start>`);
    let step = 1;
    if (memoryEnabled) lines.push(`${step++}. call recall(cwd) first to load prior memos`);
    if (docs.length) lines.push(`${step++}. read ${docs.join(" and ")} for project rules`);
    if (memoryEnabled) lines.push(`${step++}. "(no matches)" from recall = fresh session`);
    lines.push(`</session_start>`);
  }

  if (memoryEnabled) {
    lines.push("");
    lines.push(`<when_to_remember>`);
    lines.push(`- user signals handoff (e.g. "handoff", "wrap up"): tags=["handoff"],`);
    lines.push(`  include file paths, last action, next step`);
    lines.push(`- design or architectural decisions: tags=["decision"]`);
    lines.push(`- non-obvious behaviors, surprising bugs: tags=["gotcha"]`);
    lines.push(`- followups: tags=["todo"]`);
    lines.push(`</when_to_remember>`);

    lines.push("");
    lines.push(`<memory_rules>`);
    lines.push(`- memos are private to this cwd; never access the storage file directly,`);
    lines.push(`  always go through recall / remember / forget`);
    lines.push(`- tags are case-insensitive; multiple tags = AND filter`);
    lines.push(`- non-string tags are dropped on write`);
    lines.push(`- multiple agents on the same cwd are serialized automatically`);
    lines.push(`- recall: limit default 20 (max 1000), offset default 0`);
    lines.push(`- paging past end returns "(no matches at offset=N; total=M)"`);
    lines.push(`</memory_rules>`);
  }

  // tools block
  lines.push("");
  lines.push(`<tools>`);
  const builtin = Object.keys(tools).sort().join(", ");
  lines.push(`built-in: ${builtin}`);
  const externals = listExternalServers();
  const loadable = await collectLoadableServers(cwd);
  const loadableSet = new Set(loadable.map((l) => l.ns));
  const externalsSet = new Set(externals.map((e) => e.ns));
  if (externals.length) {
    lines.push(`external (via mcp tool, prefix "<server>__<tool>"):`);
    const nsWidth = Math.max(...externals.map((e) => e.ns.length));
    for (const e of externals) {
      const padded = e.ns.padEnd(nsWidth);
      const alsoNote = loadableSet.has(e.ns) ? "  [also in .mcp.json]" : "";
      if (e.tools.length) {
        const preview = e.tools.slice(0, 6).join(", ");
        const hint = e.tools.length > 6 ? `${preview}, ... (${e.tools.length} total)` : preview;
        lines.push(`- ${padded}  tools: ${hint}${alsoNote}`);
      } else {
        lines.push(`- ${padded}  (tools not yet probed; call mcp(action="list") to discover)${alsoNote}`);
      }
    }
    lines.push(`call mcp(action="list") for full schemas of external tools.`);
  }
  const loadableOnly = loadable.filter((l) => !externalsSet.has(l.ns));
  if (loadableOnly.length) {
    if (externals.length) lines.push("");
    lines.push(`loadable (via mcp tool from .mcp.json in cwd):`);
    const lWidth = Math.max(...loadableOnly.map((l) => l.ns.length));
    for (const l of loadableOnly) {
      lines.push(`- ${l.ns.padEnd(lWidth)}  ${l.transport}`);
    }
    lines.push(`call mcp(action="list", server="<name>") to load tools on demand.`);
  }
  lines.push(`</tools>`);

  // cheat_sheet
  lines.push("");
  lines.push(`<cheat_sheet>`);
  if (memoryEnabled) {
    lines.push(`recall(cwd)`);
    lines.push(`recall(cwd, query="webhook")`);
    lines.push(`recall(cwd, tags=["decision"], limit=5)`);
    lines.push(`remember(cwd, "fixed bug at file.py:42", tags=["bug","fix"])`);
    lines.push(`forget(cwd, 7)`);
  }
  lines.push(`guide(cwd)`);
  if (externals.length) lines.push(`mcp(action="list")`);
  if (loadableOnly.length) lines.push(`mcp(action="list", server="${loadableOnly[0].ns}")`);
  lines.push(`</cheat_sheet>`);

  lines.push("");
  lines.push(`</guide>`);
  return lines.join("\n");
}

// ---------- upload page ----------
// Full HTML page served at GET /upload/<session_id>. The page embeds a drop
// zone that POSTs back to the same URL. Auth lives in the URL path.
const UPLOAD_PAGE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Upload to local machine</title>
<style>
  :root {
    --bg: #faf9f5;
    --surface: #ffffff;
    --text-primary: #181818;
    --text-secondary: #6b6b63;
    --text-tertiary: #96958b;
    --text-info: #2d5fb3;
    --text-success: #0f6e56;
    --text-warning: #854f0b;
    --text-danger: #a32d2d;
    --border-tertiary: rgba(24, 24, 24, 0.08);
    --border-secondary: rgba(24, 24, 24, 0.16);
    --border-info: rgba(45, 95, 179, 0.3);
    --bg-info: rgba(45, 95, 179, 0.06);
    --bg-tertiary: #f1efe8;
    --radius-md: 8px;
    --radius-lg: 12px;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text-primary);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    font-size: 16px;
    line-height: 1.5;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 2rem 1rem;
  }
  .container {
    width: 100%;
    max-width: 560px;
  }
  .dropzone {
    display: block;
    background: transparent;
    border: 0.5px dashed var(--border-secondary);
    border-radius: var(--radius-lg);
    padding: 2rem 1.25rem;
    text-align: center;
    cursor: pointer;
    transition: background 120ms ease, border-color 120ms ease;
    user-select: none;
    -webkit-user-select: none;
    -webkit-tap-highlight-color: transparent;
  }
  .dropzone:hover {
    background: var(--bg-info);
    border-color: var(--border-info);
  }
  .dropzone.hover {
    background: var(--bg-info);
    border-color: var(--border-info);
  }
  .dropzone.disabled {
    cursor: not-allowed;
    opacity: 0.5;
  }
  .dropzone .icon { display: flex; justify-content: center; margin-bottom: 12px; color: var(--text-secondary); }
  .dropzone .title { margin: 0; font-size: 14px; color: var(--text-primary); }
  .dropzone .browse { color: var(--text-info); text-decoration: underline; }
  .file-list { margin-top: 0.75rem; display: none; flex-direction: column; gap: 6px; }
  .file-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 8px 12px;
    background: var(--surface);
    border: 0.5px solid var(--border-tertiary);
    border-radius: var(--radius-md);
  }
  .file-row .info { display: flex; align-items: baseline; gap: 8px; min-width: 0; flex: 1; }
  .file-row .name { font-size: 13px; color: var(--text-primary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .file-row .size { font-size: 12px; color: var(--text-tertiary); flex-shrink: 0; }
  .file-row button {
    flex-shrink: 0;
    width: 24px;
    height: 24px;
    padding: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    color: var(--text-tertiary);
    background: transparent;
    border: none;
    cursor: pointer;
    border-radius: 4px;
  }
  .file-row button:hover { background: var(--bg-tertiary); color: var(--text-primary); }
  .file-row button:disabled { cursor: not-allowed; opacity: 0.4; }
  .progress-wrap { margin-top: 0.75rem; display: none; }
  .progress-track {
    background: var(--bg-tertiary);
    border-radius: 999px;
    height: 4px;
    overflow: hidden;
  }
  .progress-bar {
    height: 100%;
    width: 0%;
    background: var(--text-info);
    transition: width 120ms ease;
  }
  .progress-message { margin: 8px 0 0; font-size: 12px; color: var(--text-secondary); }
  .actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 0.75rem; }
  .actions button {
    font-family: inherit;
    font-size: 14px;
    padding: 8px 16px;
    background: transparent;
    color: var(--text-primary);
    border: 0.5px solid var(--border-secondary);
    border-radius: var(--radius-md);
    cursor: pointer;
    transition: background 100ms ease, transform 100ms ease;
  }
  .actions button:hover:not(:disabled) { background: var(--bg-tertiary); }
  .actions button:active:not(:disabled) { transform: scale(0.98); }
  .actions button:disabled { opacity: 0.5; cursor: not-allowed; }
</style>
</head>
<body>
  <div class="container">
    <input type="file" id="file-input" multiple style="position: absolute; left: -9999px; width: 1px; height: 1px; opacity: 0;" />
    <label id="dropzone" class="dropzone" for="file-input">
      <div class="icon">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
          <polyline points="17 8 12 3 7 8"/>
          <line x1="12" y1="3" x2="12" y2="15"/>
        </svg>
      </div>
      <p class="title">Drop files here, or <span class="browse">browse</span></p>
    </label>

    <div id="file-list" class="file-list"></div>

    <div id="progress-wrap" class="progress-wrap">
      <div class="progress-track"><div id="progress-bar" class="progress-bar"></div></div>
      <p id="progress-message" class="progress-message"></p>
    </div>

    <div class="actions">
      <button id="cancel-btn">Cancel</button>
      <button id="upload-btn" disabled>Upload</button>
    </div>
  </div>

<script data-cfasync="false">
(function () {
  var dropzone = document.getElementById('dropzone');
  var fileInput = document.getElementById('file-input');
  var fileList = document.getElementById('file-list');
  var progressWrap = document.getElementById('progress-wrap');
  var progressBar = document.getElementById('progress-bar');
  var progressMessage = document.getElementById('progress-message');
  var uploadBtn = document.getElementById('upload-btn');
  var cancelBtn = document.getElementById('cancel-btn');

  var UPLOAD_URL = window.location.href;

  var queue = [];
  var uploading = false;
  var cancelled = false;
  var currentXhr = null;
  var finished = false;

  function fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + ' MB';
    return (n / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
  }

  function setBtn(btn, enabled) {
    btn.disabled = !enabled;
  }

  function refreshButtons() {
    if (finished) {
      setBtn(uploadBtn, false);
      setBtn(cancelBtn, false);
      return;
    }
    setBtn(uploadBtn, !uploading && queue.length > 0);
    setBtn(cancelBtn, true);
  }

  function renderList() {
    if (queue.length === 0) {
      fileList.style.display = 'none';
      fileList.innerHTML = '';
      refreshButtons();
      return;
    }
    fileList.style.display = 'flex';
    fileList.innerHTML = '';
    queue.forEach(function (file, idx) {
      var row = document.createElement('div');
      row.className = 'file-row';

      var info = document.createElement('div');
      info.className = 'info';
      var name = document.createElement('span');
      name.className = 'name';
      name.textContent = file.name;
      var size = document.createElement('span');
      size.className = 'size';
      size.textContent = fmtBytes(file.size);
      info.appendChild(name);
      info.appendChild(size);

      var remove = document.createElement('button');
      remove.setAttribute('aria-label', 'Remove ' + file.name);
      remove.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
      remove.disabled = uploading || finished;
      remove.addEventListener('click', function (e) {
        e.stopPropagation();
        if (uploading || finished) return;
        queue.splice(idx, 1);
        renderList();
      });

      row.appendChild(info);
      row.appendChild(remove);
      fileList.appendChild(row);
    });
    refreshButtons();
  }

  function addFiles(files) {
    if (uploading || finished) return;
    for (var i = 0; i < files.length; i++) queue.push(files[i]);
    renderList();
  }

  function uploadOne(file, onProgress) {
    return new Promise(function (resolve) {
      var xhr = new XMLHttpRequest();
      currentXhr = xhr;
      var form = new FormData();
      form.append('file', file);

      xhr.upload.addEventListener('progress', function (e) {
        if (e.lengthComputable) onProgress(e.loaded, e.total);
      });
      xhr.addEventListener('load', function () {
        if (xhr.status >= 200 && xhr.status < 300) {
          var body = {};
          try { body = JSON.parse(xhr.responseText); } catch (e) {}
          resolve({ ok: true, path: body.path || file.name, file: file });
        } else {
          resolve({ ok: false, status: xhr.status, file: file });
        }
      });
      xhr.addEventListener('error', function () {
        resolve({ ok: false, networkError: true, file: file });
      });
      xhr.addEventListener('abort', function () {
        resolve({ ok: false, aborted: true, file: file });
      });
      xhr.open('POST', UPLOAD_URL);
      xhr.send(form);
    });
  }

  function disableAll() {
    finished = true;
    dropzone.classList.add('disabled');
    fileInput.disabled = true;
    refreshButtons();
    // re-render list so the remove buttons get disabled
    renderList();
  }

  function runUpload() {
    if (uploading || queue.length === 0) return;
    uploading = true;
    cancelled = false;
    refreshButtons();
    progressWrap.style.display = 'block';
    progressBar.style.background = 'var(--text-info)';
    progressBar.style.width = '0%';
    progressMessage.style.color = 'var(--text-secondary)';

    var files = queue.slice();
    var totalBytes = files.reduce(function (s, f) { return s + f.size; }, 0);
    var completedBytes = 0;
    var results = [];

    function next(i) {
      if (cancelled || i >= files.length) return finish(results, files, i);
      var f = files[i];
      progressMessage.textContent = 'Uploading ' + f.name + ' (' + (i + 1) + '/' + files.length + ')';
      uploadOne(f, function (loaded) {
        var pct = totalBytes === 0 ? 0 : ((completedBytes + loaded) / totalBytes) * 100;
        progressBar.style.width = pct + '%';
      }).then(function (res) {
        completedBytes += f.size;
        results.push(res);
        next(i + 1);
      });
    }

    function finish(results, allFiles, stoppedAt) {
      uploading = false;
      currentXhr = null;
      var ok = results.filter(function (r) { return r.ok; });
      var failed = results.filter(function (r) { return !r.ok && !r.aborted; });

      progressBar.style.width = '100%';

      if (cancelled) {
        progressBar.style.background = 'var(--text-warning)';
        progressMessage.textContent = 'Cancelled — ' + ok.length + ' uploaded before stop';
        progressMessage.style.color = 'var(--text-warning)';
      } else if (failed.length === 0) {
        progressBar.style.background = 'var(--text-success)';
        progressMessage.textContent = 'Uploaded ' + ok.length + ' file' + (ok.length === 1 ? '' : 's') + '. Tell Claude where they landed:';
        progressMessage.style.color = 'var(--text-success)';
      } else {
        progressBar.style.background = 'var(--text-danger)';
        progressMessage.textContent = ok.length + ' uploaded, ' + failed.length + ' failed';
        progressMessage.style.color = 'var(--text-danger)';
      }

      if (ok.length > 0) {
        var summaryWrap = document.createElement('div');
        summaryWrap.style.cssText = 'position: relative; margin-top: 12px;';
        var summary = document.createElement('pre');
        summary.style.cssText = 'margin: 0; padding: 12px 40px 12px 12px; background: var(--bg-tertiary); border-radius: var(--radius-md); font-size: 12px; font-family: ui-monospace, "SF Mono", Menlo, monospace; color: var(--text-primary); white-space: pre-wrap; overflow-wrap: anywhere;';
        var text = ok.map(function (r) { return r.path; }).join('\\n');
        summary.textContent = text;
        var copyBtn = document.createElement('button');
        copyBtn.type = 'button';
        copyBtn.setAttribute('aria-label', 'Copy paths');
        copyBtn.style.cssText = 'position: absolute; top: 8px; right: 8px; width: 28px; height: 28px; padding: 0; display: inline-flex; align-items: center; justify-content: center; color: var(--text-tertiary); background: transparent; border: none; cursor: pointer; border-radius: 4px;';
        copyBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
        copyBtn.addEventListener('mouseenter', function () { copyBtn.style.background = 'var(--surface)'; copyBtn.style.color = 'var(--text-primary)'; });
        copyBtn.addEventListener('mouseleave', function () { copyBtn.style.background = 'transparent'; copyBtn.style.color = 'var(--text-tertiary)'; });
        copyBtn.addEventListener('click', function () {
          var done = function () {
            var prev = copyBtn.innerHTML;
            copyBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
            copyBtn.style.color = 'var(--text-success)';
            setTimeout(function () { copyBtn.innerHTML = prev; copyBtn.style.color = 'var(--text-tertiary)'; }, 1500);
          };
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(done).catch(function () {});
          } else {
            // fallback for older browsers / non-secure contexts
            var ta = document.createElement('textarea');
            ta.value = text;
            ta.style.cssText = 'position: fixed; left: -9999px;';
            document.body.appendChild(ta);
            ta.select();
            try { document.execCommand('copy'); done(); } catch (err) {}
            document.body.removeChild(ta);
          }
        });
        summaryWrap.appendChild(summary);
        summaryWrap.appendChild(copyBtn);
        progressWrap.appendChild(summaryWrap);
      }

      // clear queue, disable the page
      queue = [];
      fileList.style.display = 'none';
      fileList.innerHTML = '';
      disableAll();
    }

    next(0);
  }

  function runCancel() {
    if (uploading) {
      cancelled = true;
      if (currentXhr) try { currentXhr.abort(); } catch (e) {}
    } else {
      queue = [];
      progressWrap.style.display = 'none';
      renderList();
      progressMessage.textContent = 'Upload cancelled.';
      progressMessage.style.color = 'var(--text-warning)';
      progressWrap.style.display = 'block';
      progressBar.style.background = 'var(--text-warning)';
      progressBar.style.width = '100%';
      disableAll();
    }
  }

  dropzone.addEventListener('click', function (e) {
    // <label for="file-input"> handles the click natively. JS click() is
    // unreliable on mobile browsers — we let the label do its job.
    if (uploading || finished) e.preventDefault();
  });
  fileInput.addEventListener('change', function (e) {
    var files = e.target.files || fileInput.files;
    if (files && files.length) {
      // copy FileList to array — some mobile browsers invalidate it after value reset
      var arr = [];
      for (var i = 0; i < files.length; i++) arr.push(files[i]);
      addFiles(arr);
    }
    fileInput.value = '';
  });
  dropzone.addEventListener('dragover', function (e) { e.preventDefault(); if (!uploading && !finished) dropzone.classList.add('hover'); });
  dropzone.addEventListener('dragleave', function () { dropzone.classList.remove('hover'); });
  dropzone.addEventListener('drop', function (e) {
    e.preventDefault();
    dropzone.classList.remove('hover');
    if (uploading || finished) return;
    if (e.dataTransfer.files && e.dataTransfer.files.length) addFiles(e.dataTransfer.files);
  });

  uploadBtn.addEventListener('click', runUpload);
  cancelBtn.addEventListener('click', runCancel);
})();
</script>
</body>
</html>
`;

function renderUploadPage(): string {
  return UPLOAD_PAGE_HTML;
}

// ---------- mcp aggregator ----------
// Spawn external MCP servers (stdio transport) and forward tool calls to them.
// Tools are exposed to clients with a "<namespace>__" prefix to avoid collisions
// (Anthropic's tool name regex disallows ":", so we use double underscore).
// Lazy spawn + per-server idle timeout. Tool list is probed once at startup
// and cached (so tools/list works without keeping every subprocess alive).

type StdioServerConfig = {
  type?: "stdio"; // default
  command: string;
  args?: string[];
  env?: Record<string, string>;
  idleTimeoutMs?: number;
};

type HttpServerConfig = {
  type: "http";
  url: string;
  headers?: Record<string, string>;
  // idleTimeoutMs is accepted but ignored for HTTP (no subprocess to stop).
  idleTimeoutMs?: number;
};

type McpServerConfig = StdioServerConfig | HttpServerConfig;

type AggregatedTool = {
  namespace: string;
  originalName: string;
  description: string;
  inputSchema: Json;
};

// Common fields for both transports.
type BaseServerState = {
  nextId: number;
  initialized: boolean;
  initPromise: Promise<void> | null;
  consecutiveSpawnFails: number;
  isProbe: boolean;
};

type StdioServerState = BaseServerState & {
  transport: "stdio";
  config: StdioServerConfig;
  proc: ReturnType<typeof spawn> | null;
  stdoutBuf: string;
  idleTimer: ReturnType<typeof setTimeout> | null;
  stderrLogPath: string;
  // Outstanding RPC calls: id -> resolver. Only stdio needs this because
  // responses arrive interleaved on a single stream. HTTP responses come
  // back as the body of the originating fetch() and don't need routing.
  pending: Map<number, { resolve: (v: Json) => void; reject: (e: Error) => void }>;
};

type HttpServerState = BaseServerState & {
  transport: "http";
  config: HttpServerConfig;
  sessionId: string | null; // Mcp-Session-Id assigned by server after initialize
};

type ServerState = StdioServerState | HttpServerState;

const NAMESPACE_RE = /^[a-z][a-z0-9-]*$/;
const DEFAULT_IDLE_TIMEOUT_MS = 10 * 60 * 1000;
const SUBPROCESS_CALL_TIMEOUT_MS = 90_000;
const MAX_CONSECUTIVE_SPAWN_FAILS = 3;
const MAX_JOBS = 10;

function safeResolve(cwd: string, userPath: string, allowSpill = false): { ok: true; path: string } | { ok: false; reason: string } {
  const cwdResolved = resolve(cwd);
  try {
    const p = resolve(cwdResolved, userPath);
    let base: string;
    try { base = realpathSync(cwdResolved); } catch { base = cwdResolved; } // cwd missing: fall back to lexical base
    // path.resolve() is lexical: a symlinked INTERMEDIATE directory could
    // smuggle the target outside the cwd. Real-path the deepest existing
    // ancestor, re-append the non-existent tail, then enforce the boundary.
    let probe: string = p;
    const tail: string[] = [];
    let real: string | null = null;
    for (;;) {
      try { real = realpathSync(probe); break; }
      catch {
        const parent = dirname(probe);
        if (parent === probe) break;
        tail.unshift(basename(probe));
        probe = parent;
      }
    }
    const final = real !== null ? resolve(real, ...tail) : p;
    if (final !== base && !final.startsWith(base + sep)) {
      // Spill files live under RESULT_SPILL_ROOT, outside cwd. read/grep must
      // reach them because spill markers point callers at that path.
      if (allowSpill) {
        let spillBase: string;
        try { spillBase = realpathSync(RESULT_SPILL_ROOT); } catch { spillBase = RESULT_SPILL_ROOT; }
        if (final === spillBase || final.startsWith(spillBase + sep)) return { ok: true, path: final };
      }
      return { ok: false, reason: `path escapes cwd: ${userPath}` };
    }
    return { ok: true, path: final };
  } catch {
    return { ok: false, reason: `invalid path: ${userPath}` };
  }
}

const aggregatorServers = new Map<string, ServerState>();
const aggregatedTools = new Map<string, AggregatedTool>(); // prefixed name -> info
// All namespaces declared in --mcp config (including those whose probe failed).
// Source of truth for guide's external block — never re-read the config file.
const aggregatorKnownServers = new Set<string>();

// ---------- mcp tool: per-cwd server cache ----------

const MAX_CONCURRENT_SPAWNS = 3;
const MAX_SERVERS_PER_CWD = 10;
const MAX_TOTAL_CACHED_SERVERS = 50;
const SPAWN_TIMEOUT_MS = 30_000;

const cwdServers = new Map<string, Map<string, ServerState>>(); // key: "${cwd}:${serverName}"
const serverMetadata = new Map<string, { tools: AggregatedTool[]; loadedAt: number }>(); // key: "${cwd}:${serverName}"
const activeSpawns = new Set<string>(); // "${cwd}:${serverName}" currently spawning
const spawnWaiters: Array<() => void> = []; // FIFO of resolvers waiting for a slot
const perKeyWaiters = new Map<string, Array<() => void>>(); // waiters blocked on a specific key
function notifySpawnWaiters(key: string) {
  const list = perKeyWaiters.get(key);
  if (list) {
    perKeyWaiters.delete(key);
    for (const r of list) r();
  }
  // Wake one queued spawn-slot waiter (FIFO)
  const next = spawnWaiters.shift();
  if (next) next();
}

// ---------- mcp tool: validation functions ----------

function validateMcpConfigPath(cwd: string, mcpConfigPath: string): { ok: true; path: string } | { ok: false; reason: string } {
  const cwdResolved = resolve(cwd);
  try {
    if (!statSync(cwdResolved).isDirectory()) {
      return { ok: false, reason: `cwd is not a directory: ${cwd}` };
    }
  } catch {
    return { ok: false, reason: `cwd does not exist: ${cwd}` };
  }
  const resolved = resolve(cwdResolved, mcpConfigPath);
  if (!resolved.startsWith(cwdResolved + sep)) {
    return { ok: false, reason: `config path escapes cwd: ${mcpConfigPath}` };
  }
  if (!file(resolved).exists()) {
    return { ok: false, reason: `.mcp.json not found at ${mcpConfigPath}` };
  }
  return { ok: true, path: resolved };
}

function validateServerName(servers: Record<string, McpServerConfig>, serverName: string): { ok: true } | { ok: false; reason: string } {
  if (!servers || typeof servers !== "object") {
    return { ok: false, reason: "invalid .mcp.json: missing mcpServers object" };
  }
  if (!(serverName in servers)) {
    const names = Object.keys(servers).join(", ");
    return { ok: false, reason: `server '${serverName}' not found in .mcp.json (available: ${names})` };
  }
  if (!NAMESPACE_RE.test(serverName)) {
    return { ok: false, reason: `invalid server name '${serverName}' (must match ${NAMESPACE_RE})` };
  }
  return { ok: true };
}

function validateToolArgs(args: any): { ok: true; sanitized: Record<string, any> } | { ok: false; reason: string } {
  if (args === null || args === undefined) {
    return { ok: true, sanitized: {} };
  }
  if (typeof args !== "object" || Array.isArray(args)) {
    return { ok: false, reason: "args must be a plain object" };
  }
  if (Object.prototype.hasOwnProperty.call(args, "__proto__") ||
      Object.prototype.hasOwnProperty.call(args, "constructor") ||
      Object.prototype.hasOwnProperty.call(args, "prototype")) {
    return { ok: false, reason: "args contains forbidden prototype properties" };
  }
  const seen = new WeakSet();
  const queue = [args];
  while (queue.length > 0) {
    const val = queue.pop();
    if (typeof val === "function") {
      return { ok: false, reason: "args contains functions" };
    }
    if (typeof val === "object" && val !== null) {
      if (seen.has(val)) continue;
      seen.add(val);
      for (const key of Object.keys(val)) {
        queue.push(val[key]);
      }
    }
  }
  return { ok: true, sanitized: JSON.parse(JSON.stringify(args)) };
}

function validateServerConfig(ns: string, cfg: McpServerConfig): { ok: true } | { ok: false; reason: string } {
  if (cfg == null || typeof cfg !== "object") {
    return { ok: false, reason: `server '${ns}': config must be an object` };
  }
  if (cfg.type === "http") {
    try {
      const url = new URL(cfg.url);
      // Plain http is fine for loopback (localhost/127.0.0.1) — the repo's own
      // .mcp.json uses it — but remote hosts must be https so tokens/headers
      // never cross the wire unencrypted.
      const isLoopback = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "::1";
      if (url.protocol !== "https:" && !isLoopback) {
        return { ok: false, reason: `server '${ns}': http transport requires https URL, got ${url.protocol}` };
      }
    } catch {
      return { ok: false, reason: `server '${ns}': invalid http url` };
    }
  } else if (cfg.type === "stdio" || cfg.type === undefined) {
    const stdioCfg = cfg as StdioServerConfig;
    const command = stdioCfg.command;
    if (!command || typeof command !== "string") {
      return { ok: false, reason: `server '${ns}': missing command` };
    }
    // We spawn with shell:false (array form) so the command is exec'd directly.
    // Still reject shell metacharacters in case a future change re-enables shell mode,
    // and reject NUL anywhere — process spawning treats it as terminator.
    if (/[;|<>&\x00]/.test(command)) {
      return { ok: false, reason: `server '${ns}': command contains shell operators or NUL` };
    }
    if (stdioCfg.args !== undefined) {
      if (!Array.isArray(stdioCfg.args)) {
        return { ok: false, reason: `server '${ns}': 'args' must be an array of strings` };
      }
      for (const a of stdioCfg.args) {
        if (typeof a !== "string") {
          return { ok: false, reason: `server '${ns}': all args must be strings` };
        }
        if (a.includes("\x00")) {
          return { ok: false, reason: `server '${ns}': args may not contain NUL` };
        }
      }
    }
    if (stdioCfg.env !== undefined) {
      if (typeof stdioCfg.env !== "object" || Array.isArray(stdioCfg.env) || stdioCfg.env === null) {
        return { ok: false, reason: `server '${ns}': 'env' must be an object` };
      }
      for (const [k, v] of Object.entries(stdioCfg.env)) {
        if (typeof v !== "string") {
          return { ok: false, reason: `server '${ns}': env.${k} must be a string` };
        }
        if (k.includes("=") || k.includes("\x00") || v.includes("\x00")) {
          return { ok: false, reason: `server '${ns}': env contains invalid characters` };
        }
      }
    }
  } else {
    return { ok: false, reason: `server '${ns}': unsupported transport type '${cfg.type}'` };
  }
  return { ok: true };
}

// ---------- mcp tool: helper functions ----------

function getOrCreateServerState(cwd: string, ns: string, cfg: McpServerConfig): ServerState {
  const key = `${cwd}:${ns}`;
  const existing = cwdServers.get(cwd)?.get(ns);
  if (existing) return existing;
  if (!cwdServers.has(cwd)) {
    cwdServers.set(cwd, new Map());
  }
  const cwdMap = cwdServers.get(cwd)!;
  if (cwdMap.size >= MAX_SERVERS_PER_CWD) {
    throw new Error(`max servers per cwd (${MAX_SERVERS_PER_CWD}) exceeded for ${cwd}`);
  }
  let totalServers = 0;
  for (const m of cwdServers.values()) totalServers += m.size;
  if (totalServers >= MAX_TOTAL_CACHED_SERVERS) {
    throw new Error(`max total cached servers (${MAX_TOTAL_CACHED_SERVERS}) exceeded`);
  }
  const state = makeServerState(ns, cfg, false);
  cwdMap.set(ns, state);
  return state;
}

async function loadMcpConfig(cwd: string, mcpConfigPath: string): Promise<{ path: string; servers: Record<string, McpServerConfig> } | { error: string }> {
  const validation = validateMcpConfigPath(cwd, mcpConfigPath);
  if (!validation.ok) {
    return { error: validation.reason };
  }
  let raw: string;
  try {
    raw = await file(validation.path).text();
  } catch (e: any) {
    return { error: `failed to read .mcp.json: ${e?.message ?? e}` };
  }
  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch (e: any) {
    return { error: `.mcp.json is not valid JSON: ${e?.message ?? e}` };
  }
  const servers = parsed?.mcpServers;
  if (!servers || typeof servers !== "object") {
    return { error: `.mcp.json has no 'mcpServers' object` };
  }
  for (const [ns, cfg] of Object.entries(servers as Record<string, McpServerConfig>)) {
    const v = validateServerConfig(ns, cfg as McpServerConfig);
    if (!v.ok) {
      return { error: v.reason };
    }
  }
  return { path: validation.path, servers };
}

// Per-key results published when a spawn completes so waiters see success or failure.
const spawnResults = new Map<string, { ok: boolean; error?: any }>();

async function spawnServerWithLimit(cwd: string, ns: string, state: ServerState): Promise<void> {
  const key = `${cwd}:${ns}`;
  // Another caller is already spawning this same server — wait, then propagate their outcome.
  if (activeSpawns.has(key)) {
    await new Promise<void>((resolve) => {
      let list = perKeyWaiters.get(key);
      if (!list) { list = []; perKeyWaiters.set(key, list); }
      list.push(resolve);
    });
    const result = spawnResults.get(key);
    if (result && !result.ok) {
      throw result.error instanceof Error ? result.error : new Error(String(result.error));
    }
    return;
  }
  // Wait for a global spawn slot to open up.
  while (activeSpawns.size >= MAX_CONCURRENT_SPAWNS) {
    await new Promise<void>((resolve) => spawnWaiters.push(resolve));
  }
  activeSpawns.add(key);
  try {
    await ensureSpawned(ns, state);
    spawnResults.set(key, { ok: true });
  } catch (e) {
    spawnResults.set(key, { ok: false, error: e });
    throw e;
  } finally {
    activeSpawns.delete(key);
    notifySpawnWaiters(key);
    // Clear after notification so next spawn cycle starts fresh.
    setTimeout(() => spawnResults.delete(key), 0);
  }
}

function unloadServer(cwd: string, ns: string): { success: boolean; error?: string } {
  const cwdMap = cwdServers.get(cwd);
  if (!cwdMap) return { success: true };
  const state = cwdMap.get(ns);
  if (!state) return { success: true };
  if (state.transport === "stdio") {
    if (state.idleTimer) { clearTimeout(state.idleTimer); state.idleTimer = null; }
    if (state.proc) {
      try { (state.proc.stdin as import("bun").FileSink).end(); } catch {}
      setTimeout(() => { try { state.proc?.kill("SIGTERM"); } catch {} }, 500);
    }
    for (const p of state.pending.values()) { p.reject(new Error("server unloaded")); }
    state.pending.clear();
  }
  cwdMap.delete(ns);
  serverMetadata.delete(`${cwd}:${ns}`);
  if (cwdMap.size === 0) cwdServers.delete(cwd);
  return { success: true };
}

function unloadAllForCwd(cwd: string): { success: boolean } {
  const cwdMap = cwdServers.get(cwd);
  if (!cwdMap) return { success: true };
  for (const [ns, state] of cwdMap) {
    if (state.transport === "stdio") {
      if (state.idleTimer) { clearTimeout(state.idleTimer); state.idleTimer = null; }
      if (state.proc) {
        try { (state.proc.stdin as import("bun").FileSink).end(); } catch {}
        setTimeout(() => { try { state.proc?.kill("SIGTERM"); } catch {} }, 500);
      }
      for (const p of state.pending.values()) { p.reject(new Error("server unloaded")); }
      state.pending.clear();
    }
    serverMetadata.delete(`${cwd}:${ns}`);
  }
  cwdServers.delete(cwd);
  return { success: true };
}

function aggregatorLogDir(): string {
  const dir = resolve(process.env.HOME ?? process.cwd(), ".code-mcp", "logs");
  mkdirSync(dir, { recursive: true });
  return dir;
}

const MAX_STDIO_BUFFER_BYTES = 10 * 1024 * 1024;
function readJsonRpcLines(state: StdioServerState, chunk: string): Json[] {
  state.stdoutBuf += chunk;
  // Cap the buffer so a misbehaving child can't OOM us by never emitting \n.
  if (state.stdoutBuf.length > MAX_STDIO_BUFFER_BYTES) {
    state.stdoutBuf = state.stdoutBuf.slice(-MAX_STDIO_BUFFER_BYTES);
  }
  const out: Json[] = [];
  let nl: number;
  while ((nl = state.stdoutBuf.indexOf("\n")) !== -1) {
    const line = state.stdoutBuf.slice(0, nl).trim();
    state.stdoutBuf = state.stdoutBuf.slice(nl + 1);
    if (!line) continue;
    try { out.push(JSON.parse(line)); } catch { /* ignore non-JSON noise */ }
  }
  return out;
}

// Handle a server-initiated request from a downstream MCP server. Returns a
// reply payload to send back. Used by both transports.
function handleServerRequest(msg: any): Json {
  if (msg.method === "roots/list") return { roots: [] };
  return {};
}

function attachStdioIO(ns: string, state: StdioServerState) {
  const proc = state.proc!;
  // Narrow Bun's stdio union (`number | ReadableStream` / `number | FileSink`)
  // to the concrete types we get when spawning with `pipe`. These are runtime
  // invariants from spawnStdioServer(); the casts only quiet the type checker.
  const procStdout = proc.stdout as ReadableStream<Uint8Array>;
  const procStderr = proc.stderr as ReadableStream<Uint8Array>;
  // Stdout: parse JSON-RPC responses, route to pending requests.
  (async () => {
    const reader = procStdout.getReader();
    const dec = new TextDecoder();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        for (const msg of readJsonRpcLines(state, dec.decode(value))) {
          // Server-initiated request: respond minimally so the subprocess
          // doesn't block. MCP servers may request roots/list, sampling, etc.
          if (msg.method && msg.id != null) {
            const reply = JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: handleServerRequest(msg) }) + "\n";
            try {
              const stdin = state.proc!.stdin as import("bun").FileSink;
              stdin.write(reply);
              stdin.flush();
            } catch { /* subprocess may be exiting */ }
            continue;
          }
          // Server notification: ignore.
          if (msg.method && msg.id == null) continue;
          // Response to our request.
          if (msg.id != null && state.pending.has(msg.id)) {
            const p = state.pending.get(msg.id)!;
            state.pending.delete(msg.id);
            if (msg.error) p.reject(new Error(msg.error.message ?? "rpc error"));
            else p.resolve(msg.result);
          }
        }
      }
    } catch (e: any) {
      // Reader throws when the stream is forcibly closed. The exit handler
      // below covers normal shutdown; only surface errors that happen
      // while the subprocess is still considered live.
      if (!shuttingDown && !state.isProbe && state.proc) {
        console.error(`[mcp:${ns}] stdout reader error: ${e?.message ?? e}`);
      }
    }
  })();
  // Stderr: append to log file.
  (async () => {
    const reader = procStderr.getReader();
    const dec = new TextDecoder();
    const sink = Bun.file(state.stderrLogPath).writer();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        sink.write(dec.decode(value));
        sink.flush();
      }
    } catch (e: any) {
      if (!shuttingDown && !state.isProbe && state.proc) {
        console.error(`[mcp:${ns}] stderr reader error: ${e?.message ?? e}`);
      }
    } finally { sink.end(); }
  })();
  // Exit: reject all pending, mark dead.
  (async () => {
    const code = await proc.exited;
    for (const p of state.pending.values()) p.reject(new Error(`subprocess exited (code=${code})`));
    state.pending.clear();
    state.proc = null;
    state.initialized = false;
    state.initPromise = null;
    if (state.idleTimer) { clearTimeout(state.idleTimer); state.idleTimer = null; }
    if (code !== 0 && code != null && !shuttingDown && !state.isProbe) {
      console.error(`[mcp:${ns}] subprocess exited code=${code}; see ${state.stderrLogPath}`);
    }
  })();
}

async function spawnStdioServer(ns: string, state: StdioServerState): Promise<void> {
  const { command, args: cmdArgs = [], env = {} } = state.config;
  const proc = spawn({
    cmd: [command, ...cmdArgs],
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
    env: buildChildEnv(env),
  });
  state.proc = proc;
  state.stdoutBuf = "";
  state.pending = new Map();
  state.nextId = 1;
  state.initialized = false;
  attachStdioIO(ns, state);

  // MCP handshake: initialize + notifications/initialized.
  await rpcCall(state, "initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "code-mcp-aggregator", version: "0.1.0" },
  });
  await rpcNotify(state, "notifications/initialized", {});
  state.initialized = true;
  state.consecutiveSpawnFails = 0;
}

async function ensureSpawned(ns: string, state: ServerState): Promise<void> {
  // HTTP transport has no `proc`; the `initialized` flag alone gates it.
  if (state.transport === "stdio" ? state.proc && state.initialized : state.initialized) return;
  if (state.initPromise) return state.initPromise;
  if (state.consecutiveSpawnFails >= MAX_CONSECUTIVE_SPAWN_FAILS) {
    throw new Error(`server '${ns}' marked broken after ${MAX_CONSECUTIVE_SPAWN_FAILS} consecutive spawn failures`);
  }
  state.initPromise = (async () => {
    try {
      if (state.transport === "stdio") {
        await spawnStdioServer(ns, state);
      } else {
        await initHttpServer(ns, state);
      }
    } catch (e) {
      state.consecutiveSpawnFails++;
      if (state.transport === "stdio") {
        try { state.proc?.kill("SIGKILL"); } catch {}
        state.proc = null;
      } else {
        state.sessionId = null;
      }
      state.initialized = false;
      throw e;
    } finally {
      state.initPromise = null;
    }
  })();
  return state.initPromise;
}

function rpcNotify(state: ServerState, method: string, params: Json): Promise<void> {
  if (state.transport === "stdio") {
    if (!state.proc) return Promise.reject(new Error("subprocess not running"));
    const msg = JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n";
    const stdin = state.proc.stdin as import("bun").FileSink;
    stdin.write(msg);
    stdin.flush();
    return Promise.resolve();
  }
  // HTTP transport: notifications are POSTs without expecting a response body.
  return httpSend(state, { jsonrpc: "2.0", method, params }).then(() => {});
}

function rpcCall(state: ServerState, method: string, params: Json): Promise<Json> {
  if (state.transport === "stdio") {
    if (!state.proc) return Promise.reject(new Error("subprocess not running"));
    const id = state.nextId++;
    const msg = JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n";
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (state.pending.has(id)) {
          state.pending.delete(id);
          reject(new Error(`rpc timeout after ${SUBPROCESS_CALL_TIMEOUT_MS}ms: ${method}`));
        }
      }, SUBPROCESS_CALL_TIMEOUT_MS);
      state.pending.set(id, {
        resolve: (v) => { clearTimeout(timer); resolve(v); },
        reject: (e) => { clearTimeout(timer); reject(e); },
      });
      try {
        const stdin = state.proc!.stdin as import("bun").FileSink;
        stdin.write(msg);
        stdin.flush();
      } catch (e: any) {
        clearTimeout(timer);
        state.pending.delete(id);
        reject(e);
      }
    });
  }
  // HTTP transport
  const id = state.nextId++;
  return httpSend(state, { jsonrpc: "2.0", id, method, params })
    .then((resp) => {
      if (!resp) throw new Error(`rpc no response: ${method}`);
      if (resp.error) throw new Error(resp.error.message ?? "rpc error");
      return resp.result;
    });
}

// ---- HTTP transport ----

async function httpSend(state: HttpServerState, body: Json): Promise<any | null> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    ...(state.config.headers ?? {}),
  };
  if (state.sessionId) headers["Mcp-Session-Id"] = state.sessionId;

  // Keep the abort deadline alive until the BODY is consumed: clearing it at
  // the response headers left the body read unbounded (a stalled server could
  // pin the request forever).
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), SUBPROCESS_CALL_TIMEOUT_MS);
  const resp = await fetch(state.config.url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
    signal: ctrl.signal,
  });
  try {
    // Capture session ID assigned by server on initialize. It is echoed back
    // as a header on later requests, so reject values that could smuggle
    // headers (CR/LF, controls).
    const sid = resp.headers.get("Mcp-Session-Id");
    if (sid && !/[\r\n\0]/.test(sid) && !state.sessionId) state.sessionId = sid;

    if (!resp.ok) {
      throw new Error(`http ${resp.status}: ${await readBodyCapped(resp, MCP_HTTP_RESP_MAX)}`);
    }

    // Notifications return 202 No Content (or empty 200) — no body to parse.
    if (resp.status === 202 || resp.headers.get("content-length") === "0") return null;

    const ct = resp.headers.get("content-type") ?? "";
    if (ct.includes("text/event-stream")) {
      return parseSseSingleResponse(resp);
    }
    // Plain JSON response — read with a byte cap.
    const text = await readBodyCapped(resp, MCP_HTTP_RESP_MAX);
    if (!text.trim()) return null;
    return JSON.parse(text);
  } finally {
    clearTimeout(timer);
  }
}

// Max bytes to buffer from an external MCP HTTP server (memory-DoS guard).
const MCP_HTTP_RESP_MAX = 16 * 1024 * 1024;

async function readBodyCapped(resp: Response, max: number): Promise<string> {
  const cl = Number(resp.headers.get("content-length") ?? "0");
  if (Number.isFinite(cl) && cl > max) {
    throw new Error(`response too large (${cl} bytes > ${max})`);
  }
  if (!resp.body) return "";
  const reader = resp.body.getReader();
  const dec = new TextDecoder();
  let out = "";
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > max) {
        throw new Error(`response too large (> ${max} bytes)`);
      }
      out += dec.decode(value, { stream: true });
    }
    return out + dec.decode();
  } finally {
    try { reader.releaseLock(); } catch {}
  }
}

// Parse SSE stream and return the first JSON-RPC response it contains.
// MCP servers often return a single response then close the stream.
async function parseSseSingleResponse(resp: Response): Promise<any | null> {
  if (!resp.body) return null;
  const reader = resp.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  const MAX_SSE_BUF = 8 * 1024 * 1024;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      // A server streaming endless events without a JSON-RPC response must not
      // grow the buffer without bound (OOM guard).
      if (buf.length > MAX_SSE_BUF) {
        throw new Error(`SSE stream exceeded ${MAX_SSE_BUF} bytes without a response`);
      }
      // Split on double-newline (SSE event separator).
      let idx;
      while ((idx = buf.indexOf("\n\n")) !== -1) {
        const event = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        const dataLines = event.split("\n").filter(l => l.startsWith("data:"));
        if (!dataLines.length) continue;
        const payload = dataLines.map(l => l.slice(5).trim()).join("\n");
        try {
          const msg = JSON.parse(payload);
          // Take the first response (skip server-initiated requests).
          if (msg.id != null && (msg.result !== undefined || msg.error !== undefined)) {
            try { reader.cancel(); } catch {}
            return msg;
          }
        } catch { /* ignore non-JSON */ }
      }
    }
  } finally {
    try { reader.releaseLock(); } catch {}
  }
  return null;
}

async function initHttpServer(ns: string, state: HttpServerState): Promise<void> {
  state.nextId = 1;
  state.initialized = false;
  state.sessionId = null;
  // MCP handshake.
  await rpcCall(state, "initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "code-mcp-aggregator", version: "0.1.0" },
  });
  await rpcNotify(state, "notifications/initialized", {});
  state.initialized = true;
  state.consecutiveSpawnFails = 0;
}

// ---- end HTTP transport ----

function resetIdleTimer(ns: string, state: ServerState) {
  if (state.transport !== "stdio") return; // HTTP has no subprocess to expire
  if (state.idleTimer) clearTimeout(state.idleTimer);
  const ttl = state.config.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS;
  if (ttl <= 0) return;
  state.idleTimer = setTimeout(async () => {
    if (!state.proc) return;
    console.error(`[mcp:${ns}] idle for ${ttl}ms; shutting down subprocess`);
    try {
      (state.proc.stdin as import("bun").FileSink).end();
    } catch {}
    setTimeout(() => {
      try { state.proc?.kill("SIGTERM"); } catch {}
    }, 500);
  }, ttl);
}

function makeServerState(ns: string, cfg: McpServerConfig, isProbe: boolean): ServerState {
  const base = {
    nextId: 1,
    initialized: false,
    initPromise: null,
    consecutiveSpawnFails: 0,
    isProbe,
  };
  if (cfg.type === "http") {
    return {
      ...base,
      transport: "http",
      config: cfg,
      sessionId: null,
    };
  }
  return {
    ...base,
    transport: "stdio",
    config: cfg,
    proc: null,
    stdoutBuf: "",
    idleTimer: null,
    stderrLogPath: resolve(aggregatorLogDir(), `${ns}.stderr.log`),
    pending: new Map(),
  };
}

async function probeServer(ns: string, config: McpServerConfig): Promise<AggregatedTool[]> {
  const state = makeServerState(ns, config, true);
  try {
    if (state.transport === "stdio") {
      await spawnStdioServer(ns, state);
    } else {
      await initHttpServer(ns, state);
    }
    const result = await rpcCall(state, "tools/list", {});
    const list: AggregatedTool[] = (result?.tools ?? []).map((t: any) => ({
      namespace: ns,
      originalName: t.name,
      description: t.description ?? "",
      inputSchema: t.inputSchema ?? { type: "object" },
    }));
    return list;
  } finally {
    if (state.transport === "stdio") {
      try { state.proc?.kill("SIGTERM"); } catch {}
      setTimeout(() => { try { state.proc?.kill("SIGKILL"); } catch {} }, 500);
    }
    // HTTP probe has no resource to clean up beyond GC.
  }
}

async function loadAggregator(configPath: string): Promise<void> {
  let raw: string;
  try {
    raw = await file(configPath).text();
  } catch (e: any) {
    console.error(`[mcp] failed to read config ${configPath}: ${e?.message ?? e}`);
    return;
  }
  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch (e: any) {
    console.error(`[mcp] config is not valid JSON: ${e?.message ?? e}`);
    return;
  }
  const servers = parsed?.mcpServers;
  if (!servers || typeof servers !== "object") {
    console.error(`[mcp] config has no 'mcpServers' object; aggregation disabled`);
    return;
  }

  // Phase 1: validate all entries synchronously, collecting the valid ones.
  // Invalid entries get their skip messages out immediately so config errors
  // are obvious even if a probe later hangs.
  type Entry = { ns: string; cfg: McpServerConfig };
  const valid: Entry[] = [];
  for (const [ns, cfg] of Object.entries(servers as Record<string, McpServerConfig>)) {
    if (!NAMESPACE_RE.test(ns)) {
      console.error(`[mcp] skipping invalid namespace '${ns}' (must match ${NAMESPACE_RE})`);
      continue;
    }
    if (!cfg || typeof cfg !== "object") {
      console.error(`[mcp] skipping '${ns}': not an object`);
      continue;
    }
    if (cfg.type === "http") {
      if (typeof cfg.url !== "string") {
        console.error(`[mcp] skipping '${ns}': http server missing 'url'`);
        continue;
      }
    } else if (typeof (cfg as any).command !== "string") {
      console.error(`[mcp] skipping '${ns}': stdio server missing 'command'`);
      continue;
    }
    valid.push({ ns, cfg });
    aggregatorKnownServers.add(ns);
  }
  if (valid.length === 0) return;

  // Phase 2: probe with bounded fan-out. Each probe spawns its own subprocess
  // (or initializes its own HTTP session), so startup time is bounded by the
  // slowest server rather than the sum - but never fire more than
  // MAX_PROBE_CONCURRENCY at once (resource guard).
  const MAX_PROBE_CONCURRENCY = 5;
  const results: Array<{ ns: string; cfg: McpServerConfig; ok: boolean; list?: any; error?: string }> = [];
  let probeIdx = 0;
  async function worker() {
    while (probeIdx < valid.length) {
      const { ns, cfg } = valid[probeIdx++];
      try {
        const list = await probeServer(ns, cfg);
        results.push({ ns, cfg, ok: true, list });
      } catch (e: any) {
        results.push({ ns, cfg, ok: false, error: e?.message ?? String(e) });
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(MAX_PROBE_CONCURRENCY, valid.length) }, worker));

  // Phase 3: register and log in the original config order so output is
  // deterministic regardless of which probe finished first.
  for (const r of results) {
    if (!r.ok) {
      console.error(`[mcp] probe '${r.ns}' failed: ${r.error}`);
      continue;
    }
    const state = makeServerState(r.ns, r.cfg, false);
    aggregatorServers.set(r.ns, state);
    for (const tool of r.list) {
      const prefixed = `${r.ns}__${tool.originalName}`;
      aggregatedTools.set(prefixed, tool);
    }
    const transport = r.cfg.type === "http" ? "http" : "stdio";
    console.error(`[mcp] probed '${r.ns}' (${transport}): ${r.list.length} tool(s) cached`);
  }
}

async function callAggregated(prefixed: string, args: Json): Promise<Json> {
  const tool = aggregatedTools.get(prefixed);
  if (!tool) throw new Error(`unknown aggregated tool: ${prefixed}`);
  const state = aggregatorServers.get(tool.namespace);
  if (!state) throw new Error(`no server state for namespace '${tool.namespace}'`);
  await ensureSpawned(tool.namespace, state);
  resetIdleTimer(tool.namespace, state);
  const result = await rpcCall(state, "tools/call", {
    name: tool.originalName,
    arguments: args,
  });
  return result;
}

function shutdownAggregator() {
  for (const [ns, state] of aggregatorServers) {
    if (state.transport === "stdio") {
      if (state.idleTimer) { clearTimeout(state.idleTimer); state.idleTimer = null; }
      if (state.proc) {
        try { state.proc.kill("SIGTERM"); } catch {}
      }
    }
  }
  // Also unload all per-cwd servers from mcp tool
  for (const [cwd] of cwdServers) {
    unloadAllForCwd(cwd);
  }
}

// ---------- tools ----------
const tools: Record<string, Tool> = {
  read: {
    description: "Read a file. Optional line range [start,end] (1-indexed, inclusive). Pass no_truncate=true to disable output truncation.",
    inputSchema: {
      type: "object",
      properties: {
        cwd: { type: "string" },
        path: { type: "string" },
        range: { type: "array", items: { type: "number" }, minItems: 2, maxItems: 2 },
        no_truncate: { type: "boolean" },
      },
      required: ["cwd", "path"],
    },
    handler: async ({ cwd, path, range, no_truncate }) => {
      const r = safeResolve(cwd, path, true);
      if (!r.ok) throw new Error(r.reason);
      // Memory-DoS guard: never buffer a huge file (or device node) whole.
      // Missing paths surface as "not a regular file" (parity with PY/JV),
      // not a raw ENOENT.
      try {
        const st = statSync(r.path);
        if (!st.isFile()) throw new Error("not a regular file");
        if (st.size > MAX_READ_BYTES) {
          throw new Error(`file too large (${st.size} bytes > ${MAX_READ_BYTES}); use a range, or grep the file instead`);
        }
      } catch (e: any) {
        if (e instanceof Error && (e.message.startsWith("file too large") || e.message === "not a regular file")) throw e;
        if (e && (e as any).code === "ENOENT") throw new Error("not a regular file");
      }
      const text = await file(r.path).text();
      if (no_truncate) return text;
      if (!range) return text;
      const lines = text.split("\n");
      const [s, e] = range;
      return lines.slice(Math.max(0, s - 1), e).join("\n");
    },
  },

  write: {
    description: "Write/overwrite a file with the given content.",
    inputSchema: {
      type: "object",
      properties: {
        cwd: { type: "string" },
        path: { type: "string" },
        content: { type: "string" },
      },
      required: ["cwd", "path", "content"],
    },
    handler: async ({ cwd, path, content }) => {
      const r = safeResolve(cwd, path);
      if (!r.ok) throw new Error(r.reason);
      const bytes = await write(r.path, content);
      return `wrote ${bytes} bytes to ${path}`;
    },
  },

  edit: {
    description: "Replace old_str with new_str in a file. old_str must occur exactly once.",
    inputSchema: {
      type: "object",
      properties: {
        cwd: { type: "string" },
        path: { type: "string" },
        old_str: { type: "string" },
        new_str: { type: "string" },
      },
      required: ["cwd", "path", "old_str", "new_str"],
    },
    handler: async ({ cwd, path, old_str, new_str }) => {
      const r = safeResolve(cwd, path);
      if (!r.ok) throw new Error(r.reason);
      const text = await file(r.path).text();
      const first = text.indexOf(old_str);
      if (first === -1) throw new Error("old_str not found");
      if (text.indexOf(old_str, first + 1) !== -1) throw new Error("old_str not unique");
      await write(r.path, text.slice(0, first) + new_str + text.slice(first + old_str.length));
      return "ok";
    },
  },

  multi_edit: {
    description: "Apply multiple edits atomically across one or more files. Validates every edit first; if any fails, nothing is written. Edits to the same file are applied in order.",
    inputSchema: {
      type: "object",
      properties: {
        cwd: { type: "string" },
        edits: {
          type: "array",
          minItems: 1,
          items: {
            type: "object",
            properties: {
              path: { type: "string" },
              old_str: { type: "string" },
              new_str: { type: "string" },
            },
            required: ["path", "old_str", "new_str"],
          },
        },
      },
      required: ["cwd", "edits"],
    },
    handler: async ({ cwd, edits }) => {
      // Two-phase: phase 1 validates every edit against the ORIGINAL file
      // text and records [start, end, replacement) ranges. Phase 2 applies
      // each file's ranges in reverse order (so earlier offsets stay valid).
      //
      // This guarantees:
      //  - old_str uniqueness is checked on the original text, not on the
      //    intermediate result of preceding edits.
      //  - overlapping edits are rejected up front instead of silently
      //    clobbering each other.
      //  - if any edit fails, no file on disk is touched.
      type Range = { start: number; end: number; replacement: string; index: number };
      const originals = new Map<string, string>();
      const ranges = new Map<string, Range[]>();

      for (let i = 0; i < edits.length; i++) {
        const { path, old_str, new_str } = edits[i];
        const sr = safeResolve(cwd, path);
        if (!sr.ok) throw new Error(`edit #${i + 1}: ${sr.reason}`);
        if (!originals.has(sr.path)) originals.set(sr.path, await file(sr.path).text());
        const text = originals.get(sr.path)!;
        const first = text.indexOf(old_str);
        if (first === -1) throw new Error(`edit #${i + 1} (${path}): old_str not found`);
        if (text.indexOf(old_str, first + 1) !== -1) {
          throw new Error(`edit #${i + 1} (${path}): old_str not unique`);
        }
        const start = first;
        const end = first + old_str.length;
        const list = ranges.get(sr.path) ?? [];
        // Check overlap with edits already queued for this file.
        for (const existing of list) {
          if (start < existing.end && end > existing.start) {
            throw new Error(
              `edit #${i + 1} (${path}): overlaps edit #${existing.index + 1} ` +
              `(both target bytes ${Math.max(start, existing.start)}..${Math.min(end, existing.end)})`
            );
          }
        }
        list.push({ start, end, replacement: new_str, index: i });
        ranges.set(sr.path, list);
      }

      // All edits validated — apply in reverse order per file.
      for (const [filePath, list] of ranges) {
        const sorted = [...list].sort((a, b) => b.start - a.start);
        let text = originals.get(filePath)!;
        for (const edit of sorted) {
          text = text.slice(0, edit.start) + edit.replacement + text.slice(edit.end);
        }
        await write(filePath, text);
      }
      const summary = [...ranges]
        .map(([filePath, list]) => `${filePath} (${list.length} edit${list.length > 1 ? "s" : ""})`)
        .join(", ");
      return `applied ${edits.length} edit(s) across ${ranges.size} file(s): ${summary}`;
    },
  },

  bash: {
    description: "Run a bash command. Returns combined stdout+stderr. If still running at 60s with no timeout_ms set, auto-detaches into the `job` tool (the return value carries the job id). Pass an explicit timeout_ms to force kill-on-timeout instead.",
    inputSchema: {
      type: "object",
      properties: {
        cwd: { type: "string" },
        command: { type: "string" },
        timeout_ms: { type: "number" },
      },
      required: ["cwd", "command"],
    },
    handler: async ({ command, cwd, timeout_ms }) => {
      return runShell(bashCmd(command), cwd, command, timeout_ms);
    },
  },

  shell: {
    description: "Run a POSIX sh command. Returns combined stdout+stderr. If still running at 60s with no timeout_ms set, auto-detaches into the `job` tool (the return value carries the job id). Pass an explicit timeout_ms to force kill-on-timeout instead.",
    inputSchema: {
      type: "object",
      properties: {
        cwd: { type: "string" },
        command: { type: "string" },
        timeout_ms: { type: "number" },
      },
      required: ["cwd", "command"],
    },
    handler: async ({ command, cwd, timeout_ms }) => {
      return runShell(shCmd(command), cwd, command, timeout_ms);
    },
  },

  command: {
    description: "Run a Windows CMD command. Returns combined stdout+stderr. If still running at 60s with no timeout_ms set, auto-detaches into the `job` tool (the return value carries the job id). Pass an explicit timeout_ms to force kill-on-timeout instead.",
    inputSchema: {
      type: "object",
      properties: {
        cwd: { type: "string" },
        command: { type: "string" },
        timeout_ms: { type: "number" },
      },
      required: ["cwd", "command"],
    },
    handler: async ({ command, cwd, timeout_ms }) => {
      return runShell(cmdCmd(command), cwd, command, timeout_ms);
    },
  },

  powershell: {
    description: "Run a PowerShell command. Returns combined stdout+stderr. If still running at 60s with no timeout_ms set, auto-detaches into the `job` tool (the return value carries the job id). Pass an explicit timeout_ms to force kill-on-timeout instead.",
    inputSchema: {
      type: "object",
      properties: {
        cwd: { type: "string" },
        command: { type: "string" },
        timeout_ms: { type: "number" },
      },
      required: ["cwd", "command"],
    },
    handler: async ({ command, cwd, timeout_ms }) => {
      return runShell(pwshCmd(command), cwd, command, timeout_ms);
    },
  },

  grep: {
    description: "Search files by regex. Uses ripgrep if available, else findstr (Windows) or grep (POSIX).",
    inputSchema: {
      type: "object",
      properties: {
        cwd: { type: "string" },
        pattern: { type: "string" },
        path: { type: "string" },
        glob: { type: "string" },
      },
      required: ["cwd", "pattern"],
    },
    handler: async ({ cwd, pattern, path = ".", glob }) => {
      const sr = safeResolve(cwd, path, true);
      if (!sr.ok) throw new Error(sr.reason);
      if (glob) {
        const normGlob = glob.replace(/\\/g, "/");
        if (normGlob.startsWith("/") || normGlob.startsWith("~") || /^[A-Za-z]:/.test(normGlob)) {
          throw new Error("glob must be relative");
        }
        if (normGlob.split("/").some((seg) => seg === "..")) {
          throw new Error("glob may not contain '..'");
        }
      }
      let cmd: string[];
      if (hasRg) {
        // Insert `--` so a user-supplied pattern that starts with `-` isn't parsed as a flag.
        cmd = ["rg", "--line-number", "--no-heading", "--color=never",
           ...(glob ? ["--glob", glob] : []), "--", pattern, sr.path];
      } else if (IS_WINDOWS && hasFindstr) {
        // Windows findstr: /r = regex, /n = line numbers
        // Note: findstr regex syntax differs slightly from grep
        // Glob patterns (e.g. *.txt) must be part of path argument, not a separate flag
        const args = ["/r", "/n"];
        const searchPath = glob ? `${sr.path}\\${glob.replace(/\*/g, "*")}` : sr.path;
        cmd = ["findstr", ...args, pattern, searchPath];
      } else {
        // Insert `--` so a user-supplied pattern that starts with `-` isn't parsed as a flag.
        cmd = ["grep", "-rEn", ...(glob ? ["--include", glob] : []), "--", pattern, sr.path];
      }
      const proc = spawn({
        cmd,
        // sr.path may be a spill file (not a dir); spawn cwd must be a directory.
        cwd: resolve(cwd),
        stdout: "pipe",
        stderr: "pipe",
        stdin: "ignore",
        env: buildChildEnv({}),
      });
      const outSink = { text: "" };
      const errSink = { text: "" };
      const [, , exitCode] = await Promise.all([
        pumpCapped(proc.stdout as any, outSink),
        pumpCapped(proc.stderr as any, errSink),
        proc.exited,
      ]);
      if (outSink.text) return outSink.text;
      if (exitCode === 1) return "(no matches)";
      return `ERROR (exit=${exitCode}): ${errSink.text}`;
    },
  },

  find: {
    description:
      "Find files by glob pattern. Supports ** for recursive. Bare patterns like '*.ts' match at any depth. " +
      "Skips common noise dirs (node_modules, .git, .next, dist, build, target, .venv, __pycache__) " +
      "unless the pattern explicitly references them. Pass include_hidden=true to include dot-files.",
    inputSchema: {
      type: "object",
      properties: {
        cwd: { type: "string" },
        pattern: { type: "string" },
        path: { type: "string" },
        include_hidden: { type: "boolean" },
      },
      required: ["cwd", "pattern"],
    },
    handler: async ({ cwd, pattern, path = ".", include_hidden = false }) => {
      const sr = safeResolve(cwd, path);
      if (!sr.ok) throw new Error(sr.reason);
      // The glob must stay inside the cwd sandbox: reject absolute roots,
      // drive letters and ".." components (parity with Python's find).
      const normPat = pattern.replace(/\\/g, "/");
      if (normPat.startsWith("/") || normPat.startsWith("~") || /^[A-Za-z]:/.test(normPat)) {
        throw new Error("pattern must be relative to the working directory");
      }
      if (normPat.split("/").some((seg) => seg === "..")) {
        throw new Error("pattern may not contain '..'");
      }
      const pat = pattern.includes("/") || pattern.includes("\\") ? pattern : `**/${pattern}`;
      const glob = new Bun.Glob(pat);

      // Heavy directories Bun.Glob will happily traverse if we don't filter
      // them out. ripgrep skips these by default; find didn't, which made
      // results unusable inside any JS/Python repo.
      const NOISE_DIRS = new Set([
        "node_modules", ".git", ".next", ".nuxt", ".turbo", ".cache",
        "dist", "build", "out", "target", "coverage",
        ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
        ".idea", ".vscode",
      ]);
      // Honour the user's intent: if they explicitly mention a noise dir in
      // the pattern (e.g. "node_modules/foo/index.js"), don't filter it out.
      const patternRefs = new Set(
        pat.split(/[\/\\]/).filter((seg: string) => NOISE_DIRS.has(seg))
      );

      const results: string[] = [];
      for await (const f of glob.scan({ cwd: sr.path, onlyFiles: false })) {
        // Split on both separators so Windows paths from Bun.Glob match.
        const segments = f.split(/[\/\\]/);
        let skip = false;
        for (const seg of segments) {
          if (NOISE_DIRS.has(seg) && !patternRefs.has(seg)) { skip = true; break; }
          if (!include_hidden && seg.startsWith(".") && seg !== "." && seg !== "..") {
            // Allow the pattern itself to opt back in (e.g. ".env*").
            if (!pat.includes(seg) && !pat.startsWith(".")) { skip = true; break; }
          }
        }
        if (skip) continue;
        results.push(f);
        if (results.length >= 10_000) break;
      }
      return results.length ? results.join("\n") : "(no matches)";
    },
  },

  ls: {
    description: "List directory entries with type and size.",
    inputSchema: {
      type: "object",
      properties: {
        cwd: { type: "string" },
        path: { type: "string" },
      },
      required: ["cwd"],
    },
    handler: ({ cwd, path = "." }) => {
      const sr = safeResolve(cwd, path);
      if (!sr.ok) throw new Error(sr.reason);
      try {
        if (!statSync(sr.path).isDirectory()) throw new Error(`Expected directory, got file: ${path}`);
      } catch (e: any) {
        if (e instanceof Error && e.message.startsWith("Expected directory")) throw e;
      }
      return readdirSync(sr.path)
        .map((name) => {
          try {
            const s = statSync(`${sr.path}/${name}`);
            return `${s.isDirectory() ? "d" : "-"}${String(s.size).padStart(10)} ${name}`;
          } catch {
            return `? ${name}`;
          }
        })
        .sort()
        .join("\n");
    },
  },

  job: {
    description: "Manage background jobs. mode: list|view|start|stop. command required for start; id (passed as command) required for view/stop. cwd used only for start.",
    inputSchema: {
      type: "object",
      properties: {
        cwd: { type: "string" },
        mode: { type: "string", enum: ["list", "view", "start", "stop"] },
        command: { type: "string" },
        timeout_ms: { type: "number" },
      },
      required: ["cwd", "mode"],
    },
    handler: async ({ cwd, mode, command, timeout_ms = 500 }) => {
      if (mode !== "list" && mode !== "start" && mode !== "view" && mode !== "stop") {
        throw new Error(`unknown mode: ${mode}`);
      }
      if (mode === "list") {
        if (jobs.size === 0) return "(no jobs)";
        return [...jobs.values()]
          .map((j) => `${j.id} [${j.status}${j.exitCode != null ? ` ${j.exitCode}` : ""}] ${j.command}`)
          .join("\n");
      }
      if (mode === "start") {
        if (!command) throw new Error("command required");
        const j = startJob(command, cwd);
        return `started ${j.id}`;
      }
      if (!command) throw new Error("job id required (pass as command)");
      const j = jobs.get(command);
      if (!j) throw new Error(`no such job: ${command}`);
      if (mode === "view") {
        return `[${j.id}] ${j.command}\n[${j.status}${j.exitCode != null ? ` ${j.exitCode}` : ""}]\n${j.output}`;
      }
      if (mode === "stop") {
        if (j.status !== "running") return `${j.id} already ${j.status}`;
        // Try to kill the whole process group so shell children die too.
        // Fall back to single-pid kill if pgid signalling fails.
        killJobTree(j as any, "SIGTERM");
        let timedOut = false;
        const timer = new Promise<void>((resolve) => {
          setTimeout(() => { timedOut = true; resolve(); }, timeout_ms);
        });
        await Promise.race([j.proc.exited, timer]);
        if (timedOut && j.status === "running") {
          killJobTree(j as any, "SIGKILL");
          await j.proc.exited;
        }
        return `${j.id} stopped`;
      }
      throw new Error(`bad mode: ${mode}`);
    },
  },

  preview: {
    description: "Start a Cloudflare quick tunnel to the given local URL and return the public URL.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string" },
      },
      required: ["url"],
    },
    handler: async ({ url }) => {
      if (typeof url !== "string" || !url) throw new Error("url required");
      let parsed: URL;
      try { parsed = new URL(url); } catch { throw new Error("invalid url"); }
      if (!/^https?$/.test(parsed.protocol.slice(0, -1))) throw new Error("url must be http(s)");
      // The tunnel exposes the target to the public internet: never allow
      // cloud-metadata / internal hosts (SSRF-as-a-service guard).
      const host = parsed.hostname.toLowerCase();
      if (host === "169.254.169.254" || host === "metadata.google.internal" || host === "metadata"
          || host === "localhost" || host.endsWith(".internal")) {
        throw new Error("url targets a protected host");
      }
      // Spawn as argv (no shell) so the URL can never inject commands.
      const j = startJobArgv(["cloudflared", "tunnel", "--url", url, "--no-autoupdate"],
        `cloudflared tunnel --url ${url} --no-autoupdate`, process.cwd());
      const deadline = Date.now() + 20_000;
      const re = /https:\/\/[a-z0-9-]+\.trycloudflare\.com/i;
      while (Date.now() < deadline) {
        const m = j.output.match(re);
        if (m) return `${m[0]} (job ${j.id})`;
        if (j.status === "exited") throw new Error(`cloudflared exited: ${j.output.slice(-500)}`);
        await Bun.sleep(250);
      }
      throw new Error(`timeout waiting for tunnel URL. output:\n${j.output.slice(-500)}`);
    },
  },

  remember: {
    description: "Append a memo. Returns the assigned id.",
    inputSchema: {
      type: "object",
      properties: {
        cwd: { type: "string" },
        memo: { type: "string" },
        tags: { type: "array", items: { type: "string" } },
      },
      required: ["cwd", "memo"],
    },
    handler: async ({ cwd, memo, tags }) => {
      const cleanTags = sanitizeTags(tags);
      const release = await acquireMemoLock(cwd);
      try {
        const id = (await lastMemoId(cwd)) + 1;
        const entry: Memo = { id, ts: Date.now(), memo, ...(cleanTags ? { tags: cleanTags } : {}) };
        const line = JSON.stringify(entry) + "\n";
        const fh = await fsOpen(resolve(cwd, ".memo.jsonl"), "a");
        try {
          await fh.writeFile(line);
          await fh.sync();
        } finally {
          await fh.close();
        }
        return `remembered #${id}`;
      } finally {
        await release();
      }
    },
  },

  forget: {
    description: "Remove a memo by id.",
    inputSchema: {
      type: "object",
      properties: {
        cwd: { type: "string" },
        memo_id: { type: "number" },
      },
      required: ["cwd", "memo_id"],
    },
    handler: async ({ cwd, memo_id }) => {
      const release = await acquireMemoLock(cwd);
      try {
        const memos = await readMemos(cwd);
        const before = memos.length;
        const kept = memos.filter((m) => m.id !== memo_id);
        if (kept.length === before) throw new Error(`no memo with id ${memo_id}`);
        await writeMemos(cwd, kept);
        return `forgot #${memo_id}`;
      } finally {
        await release();
      }
    },
  },

  recall: {
    description: "Search memos by substring (query) and/or tags (AND). Both are case-insensitive. Sorted newest first. Paginated.",
    inputSchema: {
      type: "object",
      properties: {
        cwd: { type: "string" },
        query: { type: "string" },
        tags: { type: "array", items: { type: "string" } },
        limit: { type: "number" },
        offset: { type: "number" },
      },
      required: ["cwd"],
    },
    handler: async ({ cwd, query, tags, limit, offset }) => {
      const lim = Number.isFinite(limit) && limit >= 1 ? Math.min(Math.floor(limit), 1000) : 20;
      const off = Number.isFinite(offset) && offset >= 0 ? Math.floor(offset) : 0;
      const memos = await readMemos(cwd);
      const q = typeof query === "string" && query.length ? query.toLowerCase() : null;
      const cleanTags = sanitizeTags(tags);
      const tagSet = cleanTags ? cleanTags.map((t) => t.toLowerCase()) : null;
      const filtered = memos.filter((m) => {
        if (q && !m.memo.toLowerCase().includes(q)) return false;
        if (tagSet) {
          const memoTags = (m.tags ?? []).map((t) => t.toLowerCase());
          if (!tagSet.every((t) => memoTags.includes(t))) return false;
        }
        return true;
      });
      filtered.sort((a, b) => b.id - a.id);
      const total = filtered.length;
      if (!total) return "(no matches)";
      if (off >= total) return `(no matches at offset=${off}; total=${total})`;
      const page = filtered.slice(off, off + lim);
      const lines = page.map((m) => {
        const ts = new Date(m.ts).toISOString();
        const tagStr = m.tags?.length ? ` [${m.tags.join(",")}]` : "";
        return `#${m.id} ${ts}${tagStr} ${m.memo}`;
      });
      const end = off + page.length;
      const hasMore = end < total;
      const footer = `-- ${off + 1}-${end} of ${total}${hasMore ? ` (next: offset=${end})` : ""}`;
      return lines.join("\n") + "\n" + footer;
    },
  },

  guide: {
    description: "Operating manual for this code-mcp server: live state, session-start ritual, when to remember, tool catalog. Call at session start.",
    inputSchema: {
      type: "object",
      properties: {
        cwd: { type: "string" },
      },
      required: ["cwd"],
    },
    handler: async ({ cwd }) => renderGuide(cwd),
  },

  get_upload_link: {
    description:
      "Return an upload link the user can open to upload files to Tuan's local machine. " +
      "Files are saved to `${UPLOAD_ROOT}/<session_id>/`. Session is valid for 10 minutes. " +
      "Returns a JSON object with: `url` (the upload URL), `expiresInMinutes` (10), " +
      "`widget` (an HTML button matching the upload page style), and `hint`. " +
      "When responding to the user, render the `widget` HTML by calling the " +
      "`visualize:show_widget` tool (or equivalent) so the user sees a clickable button " +
      "instead of a raw URL. Also include the URL as a markdown link in your response " +
      "as a fallback for clients that don't render widgets.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
    handler: () => {
      if (!publicBaseUrl) {
        throw new Error(
          "get_upload_link requires --public or --domain; the server has no public base URL."
        );
      }
      if (!token) {
        throw new Error("get_upload_link requires --token to sign upload sessions.");
      }
      const sessionId = mintUploadSessionId();
      const url = `${publicBaseUrl}/upload/${sessionId}`;
      const widget =
        // Outer wrapper: stack code-block + button vertically
        `<div style="display: flex; flex-direction: column; gap: 12px; max-width: 560px;">` +
          // Code block with copy icon (matches upload page summary style)
          `<div style="position: relative;">` +
            `<pre style="margin: 0; padding: 12px 40px 12px 12px; ` +
              `background: var(--color-background-secondary); ` +
              `border-radius: var(--border-radius-md); ` +
              `font-size: 12px; font-family: var(--font-mono); ` +
              `color: var(--color-text-primary); ` +
              `white-space: pre-wrap; overflow-wrap: anywhere;">` +
              url +
            `</pre>` +
            `<button type="button" aria-label="Copy URL" ` +
              `data-url="${url}" ` +
              `style="position: absolute; top: 8px; right: 8px; ` +
                `width: 28px; height: 28px; padding: 0; ` +
                `display: inline-flex; align-items: center; justify-content: center; ` +
                `color: var(--color-text-tertiary); background: transparent; ` +
                `border: none; cursor: pointer; border-radius: 4px;" ` +
              `onmouseover="this.style.background='var(--color-background-primary)'; ` +
                `this.style.color='var(--color-text-primary)';" ` +
              `onmouseout="this.style.background='transparent'; ` +
                `this.style.color='var(--color-text-tertiary)';" ` +
              `onclick="(function(b){` +
                `var u=b.getAttribute('data-url');` +
                `var prev=b.innerHTML;` +
                `var done=function(){` +
                  `b.innerHTML='<svg width=\\'14\\' height=\\'14\\' viewBox=\\'0 0 24 24\\' fill=\\'none\\' stroke=\\'currentColor\\' stroke-width=\\'2\\' stroke-linecap=\\'round\\' stroke-linejoin=\\'round\\'><polyline points=\\'20 6 9 17 4 12\\'/></svg>';` +
                  `b.style.color='var(--color-text-success)';` +
                  `setTimeout(function(){b.innerHTML=prev;b.style.color='var(--color-text-tertiary)';},1500);` +
                `};` +
                `if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(u).then(done).catch(function(){});}` +
                `else{var ta=document.createElement('textarea');ta.value=u;ta.style.cssText='position:fixed;left:-9999px;';document.body.appendChild(ta);ta.select();try{document.execCommand('copy');done();}catch(e){}document.body.removeChild(ta);}` +
              `})(this)">` +
              `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" ` +
                `stroke="currentColor" stroke-width="2" stroke-linecap="round" ` +
                `stroke-linejoin="round" aria-hidden="true">` +
                `<rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>` +
                `<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>` +
              `</svg>` +
            `</button>` +
          `</div>` +
          // Open button (matches upload page .actions button style)
          `<a href="${url}" target="_blank" rel="noopener" style="` +
            `display: inline-block; align-self: flex-start; ` +
            `font-family: var(--font-sans); font-size: 14px; ` +
            `padding: 8px 16px; ` +
            `background: transparent; color: var(--color-text-primary); ` +
            `border: 0.5px solid var(--color-border-secondary); ` +
            `border-radius: var(--border-radius-md); ` +
            `text-decoration: none; cursor: pointer; ` +
            `transition: background 100ms ease, transform 100ms ease;" ` +
            `onmouseover="this.style.background='var(--color-background-secondary)'" ` +
            `onmouseout="this.style.background='transparent'" ` +
            `onmousedown="this.style.transform='scale(0.98)'" ` +
            `onmouseup="this.style.transform='scale(1)'">` +
            `Open` +
          `</a>` +
        `</div>`;
      return JSON.stringify({
        url,
        expiresInMinutes: 10,
        widget,
        hint:
          "Render the `widget` HTML by calling visualize:show_widget. " +
          "Also show the `url` as a markdown link as fallback.",
      });
    },
  },

  mcp: {
    description:
      "Manage MCP servers from local .mcp.json files. " +
      "Actions: " +
      "  list: List all servers defined in .mcp.json for cwd " +
      "  list server=X: Load server X and return its tools " +
      "  call server=X tool=Y args={}: Call tool Y on loaded server X " +
      "  unload: Unload all servers for this cwd " +
      "  unload server=X: Unload specific server X",
    inputSchema: {
      type: "object",
      properties: {
        cwd: { type: "string", description: "Working directory containing .mcp.json" },
        action: { type: "string", enum: ["list", "call", "unload"], description: "Action to perform" },
        server: { type: "string", description: "Server name (required for call, optional for list/unload)" },
        tool: { type: "string", description: "Tool name (required for call)" },
        args: { type: "object", description: "Tool arguments (required for call)", additionalProperties: true },
        mcpConfigPath: { type: "string", default: ".mcp.json", description: "Path to .mcp.json relative to cwd" },
      },
      required: ["cwd", "action"],
    },
    handler: async ({ cwd, action, server, tool, args, mcpConfigPath = ".mcp.json" }) => {
      const config = await loadMcpConfig(cwd, mcpConfigPath);
      if ("error" in config) throw new Error(config.error);

      if (action === "list" && !server) {
        const servers: any[] = [];
        for (const [name, cfg] of Object.entries(config.servers)) {
          const key = `${cwd}:${name}`;
          const meta = serverMetadata.get(key);
          const cwdMap = cwdServers.get(cwd);
          const isLoaded = cwdMap?.get(name)?.initialized ?? false;
          servers.push({
            name,
            status: isLoaded ? "loaded" : "unloaded",
            tools: meta?.tools.map((t: AggregatedTool) => t.originalName) ?? [],
            idleTimeoutMs: cfg.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS,
          });
        }
        return { servers, mcpConfigPath };
      }

      if (action === "list" && server) {
        const v = validateServerName(config.servers, server);
        if (!v.ok) throw new Error(v.reason);
        const cfg = config.servers[server];
        const key = `${cwd}:${server}`;
        let state = cwdServers.get(cwd)?.get(server);
        if (!state || !state.initialized) {
          state = getOrCreateServerState(cwd, server, cfg);
          let spawnTimer: ReturnType<typeof setTimeout> | null = null;
          try {
            await Promise.race([
              spawnServerWithLimit(cwd, server, state),
              new Promise<void>((_, reject) => {
                spawnTimer = setTimeout(() => reject(new Error(`spawn timeout after ${SPAWN_TIMEOUT_MS}ms`)), SPAWN_TIMEOUT_MS);
              }),
            ]);
          } finally {
            if (spawnTimer) clearTimeout(spawnTimer);
          }
        }
        const toolsResult = await rpcCall(state, "tools/list", {});
        const tools: AggregatedTool[] = ((toolsResult as any)?.tools ?? []).map((t: any) => ({
          namespace: server,
          originalName: t.name,
          description: t.description ?? "",
          inputSchema: t.inputSchema ?? { type: "object" },
        }));
        serverMetadata.set(key, { tools, loadedAt: Date.now() });
        return {
          server,
          status: "loaded",
          tools: tools.map((t: AggregatedTool) => ({ name: t.originalName, description: t.description, inputSchema: t.inputSchema })),
          idleTimeoutMs: cfg.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS,
        };
      }

      if (action === "call") {
        if (!server) throw new Error("server name required for call action");
        if (!tool) throw new Error("tool name required for call action");
        const v = validateServerName(config.servers, server);
        if (!v.ok) throw new Error(v.reason);
        const argsValidation = validateToolArgs(args);
        if (!argsValidation.ok) throw new Error(argsValidation.reason);
        const cfg = config.servers[server];
        let state = cwdServers.get(cwd)?.get(server);
        if (!state || !state.initialized) {
          state = getOrCreateServerState(cwd, server, cfg);
          let spawnTimer: ReturnType<typeof setTimeout> | null = null;
          try {
            await Promise.race([
              spawnServerWithLimit(cwd, server, state),
              new Promise<void>((_, reject) => {
                spawnTimer = setTimeout(() => reject(new Error(`spawn timeout after ${SPAWN_TIMEOUT_MS}ms`)), SPAWN_TIMEOUT_MS);
              }),
            ]);
          } finally {
            if (spawnTimer) clearTimeout(spawnTimer);
          }
        }
        resetIdleTimer(server, state);
        const result = await rpcCall(state, "tools/call", { name: tool, arguments: argsValidation.sanitized });
        resetIdleTimer(server, state);
        return result;
      }

      if (action === "unload" && server) {
        return unloadServer(cwd, server);
      }

      if (action === "unload" && !server) {
        return unloadAllForCwd(cwd);
      }

      throw new Error(`unknown action: ${action}`);
    },
  },
};

// Prune tools based on startup flags and binary availability. Always apply
// the default pruning first (cloudflared, memory, public, shell match), then
// remove anything listed in --disallowed-tools on top.
if (!hasCloudflared) delete tools.preview;
if (!memoryEnabled) {
  delete tools.remember;
  delete tools.forget;
  delete tools.recall;
}
if (!publicBaseUrl && !makePublic) {
  delete (tools as any).get_upload_link;
}
if (DETECTED_SHELL !== "bash") delete tools.bash;
if (DETECTED_SHELL !== "sh") delete tools.shell;
if (DETECTED_SHELL !== "cmd") delete tools.command;
if (DETECTED_SHELL !== "powershell") delete tools.powershell;
for (const name of disallowedTools) {
  delete tools[name];
}

// Load external MCP aggregation config if --mcp was given. Pass the user's
// path through unchanged — Bun/Node resolve relative paths against the
// process cwd at file-open time, so an explicit resolve here is redundant.
if (mcpConfigPath) {
  await loadAggregator(mcpConfigPath);
}

// Walk an MCP `content` array and spill any oversized blocks. Text blocks
// go through maybeSpillText. Image and resource blocks with large embedded
// base64 payloads (`data` field, or `resource.blob` / `resource.text`) are
// spilled too — otherwise a downstream MCP returning, say, a screenshot
// blob will still blow the agent's context window. The replacement text
// block points at the spill file and preserves the original mimeType.
async function spillContentBlocks(content: any, toolName?: string): Promise<any> {
  if (!Array.isArray(content)) return content;
  return await Promise.all(content.map(async (block) => {
    if (!block || typeof block !== "object") return block;
    if (block.type === "text" && typeof block.text === "string") {
      return { ...block, text: await maybeSpillText(block.text, toolName) };
    }
    if (block.type === "image" && typeof block.data === "string") {
      const spilled = await maybeSpillBinaryBlock(block.data, block.mimeType ?? "image/png", toolName);
      return spilled ?? block;
    }
    if (block.type === "resource" && block.resource && typeof block.resource === "object") {
      const r = block.resource;
      if (typeof r.text === "string") {
        return { ...block, resource: { ...r, text: await maybeSpillText(r.text, toolName) } };
      }
      if (typeof r.blob === "string") {
        const spilled = await maybeSpillBinaryBlock(r.blob, r.mimeType ?? "application/octet-stream", toolName);
        return spilled ?? block;
      }
    }
    return block;
  }));
}

// Spill an oversized base64 payload to disk and return a text-block summary
// pointing at the file. Returns null if under threshold (caller keeps the
// original block). The raw bytes (not the base64 string) are what's written,
// so the spilled file is directly usable.
async function maybeSpillBinaryBlock(b64: string, mimeType: string, toolName?: string): Promise<any | null> {
  // base64 length ≈ ceil(bytes / 3) * 4. Skip the decode if obviously small.
  if (b64.length < (RESULT_SPILL_THRESHOLD * 4) / 3) return null;

  let raw: Buffer;
  try {
    raw = Buffer.from(b64, "base64");
  } catch {
    return null;
  }
  if (raw.byteLength <= RESULT_SPILL_THRESHOLD) return null;

  const ts = new Date().toISOString().replace(/[-:.]/g, "").replace(/Z$/, "");
  const safeTool = (toolName ?? "unknown").replace(/[^A-Za-z0-9_.-]/g, "_");
  const shortId = randomUUID().slice(0, 8);
  // Extension hint from mime type, best-effort only.
  const ext = mimeType.includes("/") ? mimeType.split("/")[1]!.replace(/[^A-Za-z0-9]/g, "") : "bin";
  const fname = `${ts}-${safeTool}-${shortId}.${ext || "bin"}`;
  const path = resolve(RESULT_SPILL_ROOT, fname);
  try {
    await Bun.write(path, raw);
  } catch (e: any) {
    console.error(`[spill] failed to write binary ${path}: ${e?.message ?? e}`);
    return {
      type: "text",
      text:
        `[TRUNCATED: ${mimeType} payload of ${raw.byteLength} bytes; ` +
        `spill to disk FAILED (${e?.message ?? "unknown error"}). Payload dropped.]`,
    };
  }
  return {
    type: "text",
    text:
      `[TRUNCATED: ${mimeType} payload of ${raw.byteLength} bytes, ` +
      `saved to ${path} — read the file directly to access it.]`,
  };
}

// ---------- JSON-RPC dispatch ----------
async function handle(msg: Json): Promise<Json | null> {
  const { id, method, params } = (msg ?? {}) as any;
  const ok = (result: Json) => ({ jsonrpc: "2.0", id, result });
  const err = (code: number, message: string) => ({ jsonrpc: "2.0", id, error: { code, message } });

  // params (when present) must be an object or array per JSON-RPC 2.0. We use
  // object-style throughout; reject array / scalar with -32602 rather than
  // tripping over typeof errors deeper in handlers.
  if (params !== undefined && params !== null && (typeof params !== "object" || Array.isArray(params))) {
    return err(-32602, "Invalid params: expected object");
  }
  try {
    if (method === "initialize") {
      return ok({
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "code-mcp", version: "0.1.0" },
      });
    }
    if (method === "notifications/initialized") return null; // notification
    if (method === "ping") return ok({});
    if (method === "tools/list") {
      const builtin = Object.entries(tools).map(([name, t]) => ({
        name,
        description: t.description,
        inputSchema: t.inputSchema,
      }));
      const aggregated = [...aggregatedTools.entries()].map(([name, info]) => ({
        name,
        description: info.description,
        inputSchema: info.inputSchema,
      }));
      return ok({ tools: [...builtin, ...aggregated] });
    }
    if (method === "tools/call") {
      const { name, arguments: args } = params ?? {};
      // Aggregated tool: forward to subprocess, spill oversized blocks
      // before returning so the agent's context window stays bounded.
      if (aggregatedTools.has(name)) {
        const result = await callAggregated(name, args ?? {});
        if (result && typeof result === "object" && "content" in result) {
          return ok({ ...result, content: await spillContentBlocks(result.content, name) });
        }
        return ok(result);
      }
      // Explicit disallowed check BEFORE lookup: PY/JV report a tool that was
      // stripped by --disallowed-tools as "disabled", not as "unknown".
      if (disallowedTools.includes(name)) {
        return ok({ content: [{ type: "text", text: `ERROR: tool '${name}' disabled` }], isError: true });
      }
      const t = tools[name];
      if (!t) return err(-32601, `unknown tool: ${name}`);
      const result = await t.handler(args ?? {});
      const text = typeof result === "string" ? result : JSON.stringify(result);
      // `read` honors a no_truncate flag end-to-end: the handler already returned
      // the full content, so don't re-spill it here.
      const skipSpill = name === "read" && (args as any)?.no_truncate === true;
      const finalText = skipSpill ? text : await maybeSpillText(text, name);
      return ok({ content: [{ type: "text", text: finalText }] });
    }
    return err(-32601, `unknown method: ${method}`);
  } catch (e: any) {
    // Notifications (no id) must not get a response body even on error.
    if (id == null) return null;
    const text = `ERROR: ${e?.message ?? e}`;
    return ok({ content: [{ type: "text", text: await maybeSpillText(text) }], isError: true });
  }
}

// ---------- server ----------
const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400",
};

// Hard cap per file to avoid memory blowup on a single upload.
const MAX_UPLOAD_BYTES = 100 * 1024 * 1024; // 100 MB

async function handleUpload(req: Request, sessionId: string): Promise<Response> {
  const check = verifyUploadSessionId(sessionId);
  if (!check.ok) {
    return new Response(JSON.stringify({ error: check.reason }), {
      status: 401,
      headers: { "Content-Type": "application/json", ...CORS_HEADERS },
    });
  }
  // Reject early via Content-Length before parsing the entire body into memory.
  const declaredLen = Number(req.headers.get("content-length") ?? "0");
  if (Number.isFinite(declaredLen) && declaredLen > MAX_UPLOAD_BYTES) {
    return new Response(JSON.stringify({ error: `upload exceeds ${MAX_UPLOAD_BYTES} bytes` }), {
      status: 413,
      headers: { "Content-Type": "application/json", ...CORS_HEADERS },
    });
  }
  let form: FormData;
  try {
    form = await req.formData();
  } catch (e: any) {
    return new Response(JSON.stringify({ error: `bad form: ${e?.message ?? e}` }), {
      status: 400,
      headers: { "Content-Type": "application/json", ...CORS_HEADERS },
    });
  }
  const f = form.get("file");
  if (!(f instanceof File)) {
    return new Response(JSON.stringify({ error: "missing 'file' field" }), {
      status: 400,
      headers: { "Content-Type": "application/json", ...CORS_HEADERS },
    });
  }
  if (f.size > MAX_UPLOAD_BYTES) {
    return new Response(JSON.stringify({ error: `file too large (max ${MAX_UPLOAD_BYTES} bytes)` }), {
      status: 413,
      headers: { "Content-Type": "application/json", ...CORS_HEADERS },
    });
  }

  // Sanitise: strip directory components, reject empty/dotfile/traversal names.
  const raw = f.name || "upload.bin";
  const base = raw.split(/[\\/]/).pop() || "upload.bin";
  let safe = base.replace(/[\x00-\x1f]/g, "_");
  if (!safe || safe === "." || safe === "..") {
    safe = `upload-${Date.now()}`;
  }

  const destDir = resolve(UPLOAD_ROOT, sessionId);
  try {
    mkdirSync(destDir, { recursive: true, mode: 0o700 });
  } catch (e: any) {
    return new Response(JSON.stringify({ error: `mkdir failed: ${e?.message ?? e}` }), {
      status: 500,
      headers: { "Content-Type": "application/json", ...CORS_HEADERS },
    });
  }
  // A local attacker who guesses a session id must not redirect the write via
  // a pre-created symlink under the world-writable tmpdir.
  try {
    if (lstatSync(destDir).isSymbolicLink()) {
      return new Response(JSON.stringify({ error: "upload path invalid" }), {
        status: 500,
        headers: { "Content-Type": "application/json", ...CORS_HEADERS },
      });
    }
  } catch {
    // destDir vanished between mkdir and lstat — treat as failure.
    return new Response(JSON.stringify({ error: "upload path invalid" }), {
      status: 500,
      headers: { "Content-Type": "application/json", ...CORS_HEADERS },
    });
  }
  const path = resolve(destDir, safe);
  try {
    const buf = await f.arrayBuffer();
    await write(path, buf);
    try { chmodSync(path, 0o600); } catch {}
    // TTL sweep: links expire after 10 minutes; drop stale session dirs so a
    // long-lived server can't fill the disk (disk-DoS guard).
    const cutoff = Date.now() - 900_000;
    try {
      for (const name of readdirSync(UPLOAD_ROOT)) {
        try {
          const d = resolve(UPLOAD_ROOT, name);
          const st = lstatSync(d);
          if (st.isDirectory() && !st.isSymbolicLink() && st.mtimeMs < cutoff) {
            rmSync(d, { recursive: true, force: true });
          }
        } catch {}
      }
    } catch {}
    const hash = new Bun.CryptoHasher("sha256");
    hash.update(buf);
    const sha256 = hash.digest("hex");
    return new Response(
      JSON.stringify({ path, size: f.size, sha256, mime: f.type || null }),
      { status: 200, headers: { "Content-Type": "application/json", ...CORS_HEADERS } }
    );
  } catch (e: any) {
    return new Response(JSON.stringify({ error: `write failed: ${e?.message ?? e}` }), {
      status: 500,
      headers: { "Content-Type": "application/json", ...CORS_HEADERS },
    });
  }
}

Bun.serve({
  port,
  hostname: bindAddr,
  // Reject oversized request bodies at the server level (chunked uploads have
  // no Content-Length, so the handler-level check alone can be bypassed).
  maxRequestBodySize: MAX_UPLOAD_BYTES + 1024 * 1024,
  async fetch(req) {
    const url = new URL(req.url);

    // CORS preflight — also handle /mcp so browser-based clients work.
    if (req.method === "OPTIONS" && (url.pathname.startsWith("/upload/") || url.pathname === "/mcp")) {
      return new Response(null, {
        status: 204,
        headers: {
          ...CORS_HEADERS,
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      });
    }

    // Upload endpoint: /upload/<session_id>
    // GET → HTML page with drop zone. POST → accept file upload.
    // Both methods validate the session_id (HMAC + TTL).
    if (url.pathname.startsWith("/upload/")) {
      const sessionId = url.pathname.slice("/upload/".length);
      if (!sessionId) return new Response("missing session_id", { status: 400, headers: CORS_HEADERS });

      if (req.method === "GET") {
        const check = verifyUploadSessionId(sessionId);
        if (!check.ok) {
          return new Response(`Upload session ${check.reason}.`, {
            status: 401,
            headers: { "Content-Type": "text/plain; charset=utf-8" },
          });
        }
        return new Response(renderUploadPage(), {
          status: 200,
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            // Tell Cloudflare not to inject Rocket Loader / minifiers / etc.
            "Cache-Control": "no-transform",
          },
        });
      }
      if (req.method === "POST") return handleUpload(req, sessionId);
      return new Response("GET or POST /upload/<session_id>", { status: 405, headers: CORS_HEADERS });
    }

    // MCP JSON-RPC endpoint
    if (url.pathname !== "/mcp") return new Response("not found", { status: 404 });
    if (req.method !== "POST") return new Response("POST /mcp", { status: 405 });

    // Token check: ?token=… or Authorization: Bearer …, constant-time compare.
    if (token) {
      let given = url.searchParams.get("token") ?? "";
      if (!given) {
        const auth = req.headers.get("authorization") ?? "";
        if (auth.startsWith("Bearer ")) given = auth.slice(7).trim();
      }
      const expectedBuf = Buffer.from(token);
      const givenBuf = Buffer.from(given);
      const ok = givenBuf.length === expectedBuf.length && timingSafeEqual(givenBuf, expectedBuf);
      if (!ok) return new Response("unauthorized", { status: 401, headers: CORS_HEADERS });
    }

    let body: any;
    try {
      body = await req.json();
    } catch {
      return Response.json(
        { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } },
        { status: 400, headers: CORS_HEADERS });
    }
    const resp = await handle(body);
    if (resp === null) return new Response(null, { status: 204, headers: CORS_HEADERS });
    return Response.json(resp, { headers: CORS_HEADERS });
  },
});

const bindLabel = (bindAddr === "0.0.0.0" || bindAddr === "::") ? "localhost" : bindAddr;
console.error(
  `code-mcp listening on http://${bindLabel}:${port}/mcp` +
  `${token ? " (auth)" : " (no auth)"}` +
  ` — tools: ${Object.keys(tools).join(", ")}`
);
if (publicBaseUrl) {
  console.error(`public base: ${publicBaseUrl} — upload saves to ${UPLOAD_ROOT}/<session_id>/`);
}

// ---------- public tunnel ----------
// If --public is set, open a Cloudflare quick tunnel to our own port.
// The tunnel is tracked as a background job so the shutdown hook kills it.
// Sets publicBaseUrl once the URL is known so get_upload_link becomes usable.
if (makePublic) {
  if (!hasCloudflared) {
    console.error("warning: --public given but `cloudflared` not found on PATH; skipping tunnel");
  } else {
    const j = startJob(`cloudflared tunnel --url http://localhost:${port} --no-autoupdate 2>&1`, process.cwd());
    const re = /https:\/\/[a-z0-9-]+\.trycloudflare\.com/i;
    const deadline = Date.now() + 20_000;
    (async () => {
      while (Date.now() < deadline) {
        const m = j.output.match(re);
        if (m) {
          publicBaseUrl = m[0];
          console.error(`public URL: ${m[0]}/mcp${token ? `?token=${token}` : ""}`);
          return;
        }
        if (j.status === "exited") {
          console.error(`warning: cloudflared exited before printing URL:\n${j.output.slice(-500)}`);
          return;
        }
        await Bun.sleep(250);
      }
      console.error("warning: cloudflared did not print a URL within 20s");
    })();
  }
}

// ---------- gateway client ----------
// If --gateway is set, connect to the gateway server via WebSocket and
// tunnel remote requests to the local MCP handler.
if (gatewayDomain) {
  const deviceId = assignedDeviceId ?? randomUUID();
  const BASE_DELAY_MS = 1000;
  const MAX_DELAY_MS = 60_000;
  let retries = 0;
  let everOpened = false;

  (function connect() {
    // Normalize the gateway domain: accept bare host, ws(s):// or http(s)://
    // prefixes (README examples use wss://). Bare hosts default to wss for
    // anything that is not a loopback/LAN address.
    const isLocal = /^(localhost|127\.|192\.168\.|10\.|172\.16\.|ws:\/\/|http:\/\/)/.test(gatewayDomain);
    let base: string;
    if (/^wss:\/\//i.test(gatewayDomain)) base = gatewayDomain;
    else if (/^https:\/\//i.test(gatewayDomain)) base = gatewayDomain.replace(/^https:\/\//i, "wss://");
    else if (/^ws:\/\//i.test(gatewayDomain)) base = gatewayDomain;
    else if (/^http:\/\//i.test(gatewayDomain)) base = gatewayDomain.replace(/^http:\/\//i, "ws://");
    else base = (isLocal ? "ws://" : "wss://") + gatewayDomain;
    const url = assignedDeviceId ? `${base}/ws/${assignedDeviceId}` : `${base}/ws`;
    console.error(`[${deviceId}] Connecting to gateway ${url} ...`);
    // Device credential: the hardened gateway requires the token registered for
    // this device id (X-Device-Token header); legacy gateways ignore it.
    // Defensive: never let a token inject headers into the handshake.
    const safeTok = gatewayToken?.replace(/[\r\n]/g, "");
    const ws = new WebSocket(url, safeTok ? { headers: { "X-Device-Token": safeTok } } : undefined);

    // App-layer keepalive: HTTP/2 tunnels (cloudflared) can swallow WS control
    // frames, so a data-frame heartbeat is what actually proves liveness.
    // Browser-style WebSocket API has no .ping() — we send JSON instead.
    let keepaliveTimer: ReturnType<typeof setInterval> | null = null;
    let watchdogTimer: ReturnType<typeof setTimeout> | null = null;
    const WATCHDOG_MS = 75_000;
    const armWatchdog = () => {
      if (watchdogTimer) clearTimeout(watchdogTimer);
      watchdogTimer = setTimeout(() => {
        console.error(`[${deviceId}] no inbound for ${WATCHDOG_MS}ms; forcing reconnect`);
        try { ws.close(); } catch {}
      }, WATCHDOG_MS);
    };
    const cleanup = () => {
      if (keepaliveTimer) { clearInterval(keepaliveTimer); keepaliveTimer = null; }
      if (watchdogTimer) { clearTimeout(watchdogTimer); watchdogTimer = null; }
    };

    ws.addEventListener("open", () => {
      console.error(`[${deviceId}] Connected to gateway`);
      everOpened = true;
      retries = 0;
      ws.send(JSON.stringify({ type: "register", deviceId }));
      armWatchdog();
      keepaliveTimer = setInterval(() => {
        try { ws.send(JSON.stringify({ type: "keepalive" })); }
        catch (err) {
          console.error(`[${deviceId}] keepalive send failed:`, (err as any)?.message ?? err);
          try { ws.close(); } catch {}
        }
      }, 25_000);
    });

    ws.addEventListener("message", async (e) => {
      armWatchdog();
      try {
        const msg = JSON.parse(e.data as string) as { id?: string; request?: Json; token?: string; type?: string };
        if (msg.type === "keepalive-ack") return;
        if (msg.id == null || !msg.request) return;
        // In-process dispatch: handle() mirrors the /mcp HTTP handler exactly
        // (initialize, ping, tools/list, tools/call, raw methods, aggregated
        // tools). Bypassing the local HTTP round trip removes per-call TCP +
        // HTTP overhead and keeps the relay responsive under heavy load.
        const resp = await handle(msg.request as Json);
        if (resp === null) {
          // Notification: acknowledge with response:null so the gateway
          // answers 204 No Content (strict clients reject error bodies).
          ws.send(JSON.stringify({ id: msg.id, response: null }));
          return;
        }
        ws.send(JSON.stringify({ id: msg.id, response: resp }));
      } catch (err) {
        console.error(`[${deviceId}] handle error:`, err);
      }
    });

    ws.addEventListener("close", () => {
      cleanup();
      // If the very first attempt never opened, the upgrade was rejected (e.g.
      // 401): give an actionable hint once, then keep retrying.
      if (!everOpened && retries === 0) {
        console.error(`[${deviceId}] hint: gateway rejected the upgrade (likely 401) - check that --id and --token (or --gateway-token) match the device id and its registered token in the gateway`);
      }
      // Exponential backoff with jitter — never kill the local server.
      const delay = Math.min(MAX_DELAY_MS, BASE_DELAY_MS * 2 ** Math.min(retries, 6))
        + Math.floor(Math.random() * 500);
      retries++;
      console.error(`[${deviceId}] Disconnected; retry #${retries} in ${delay}ms`);
      setTimeout(connect, delay);
    });

    ws.addEventListener("error", (err) => {
      console.error(`[${deviceId}] Gateway WS error:`, (err as any)?.message ?? err);
    });
  })();
}

// ---------- shutdown ----------
function killJobTree(j: { proc: any; status: string }, sig: "SIGTERM" | "SIGKILL") {
  if (j.status !== "running") return;
  const pid = j.proc?.pid;
  if (process.platform !== "win32" && pid) {
    // Negative PID targets the whole process group when start_new_session was used.
    try { process.kill(-pid, sig); return; } catch {}
  }
  try { j.proc.kill(sig); } catch {}
}

function shutdown(signal: string) {
  if (shuttingDown) return;
  shuttingDown = true;
  shutdownAggregator();
  console.error(`\n[${signal}] stopping ${jobs.size} job(s)...`);
  for (const j of jobs.values()) killJobTree(j as any, "SIGTERM");
  setTimeout(() => {
    for (const j of jobs.values()) killJobTree(j as any, "SIGKILL");
    process.exit(0);
  }, 500);
}
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
