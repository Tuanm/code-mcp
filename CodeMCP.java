// CodeMCP.java - Minimal MCP server over HTTP with Streamable HTTP transport and JSON-RPC 2.0
// JDK 21+ with NO external libraries - standard Java APIs only

import com.sun.net.httpserver.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.*;
import java.util.stream.*;

/**
 * Minimal MCP server over HTTP (Streamable HTTP transport, JSON-RPC 2.0).
 * 
 * Tools (always on): read, write, edit, multi_edit, bash, shell, command, powershell, grep, find, ls, job, mcp.
 * Tools (conditional):
 *   - preview              enabled only if cloudflared is on PATH
 *   - remember, forget, recall  enabled only with --enable-memory
 *   - get_upload_link      enabled only with --public or --domain
 * 
 * Shell tools: only one enabled based on detected shell (bash/shell/command/powershell).
 */
public final class CodeMCP {
    
    // ===== CONSTANTS =====
    private static final int DEFAULT_PORT = 7777;
    private static final int OUTPUT_CAP_MAX = 1_000_000;
    private static final int OUTPUT_CAP_KEEP = 500_000;
    private static final int RESULT_SPILL_THRESHOLD = 10_000;
    private static final int RESULT_SPILL_HEAD = 3_000;
    private static final int UPLOAD_TTL_MS = 10 * 60 * 1000;
    private static final int MEMO_TAIL_BYTES = 8192;
    private static final int MAX_CONCURRENT_JOBS = 10;
    private static final int MAX_SHELL_SEMAPHORE_PERMITS = 5;
    private static final long MAX_UPLOAD_BYTES = 100L * 1024 * 1024;
    private static final long MAX_WS_FRAME_BYTES = 64L * 1024 * 1024;
    private static final int MAX_GATEWAY_HEADER_BYTES = 64 * 1024;
    private static final int MAX_REQUEST_BYTES = 100 * 1024 * 1024;
    private static final int MAX_HTTP_THREADS = 64;
    private static final String DEFAULT_BIND = "127.0.0.1";
    private static final int MAX_RETRIES = 30;
    private static final long RECONNECT_DELAY_MS = 3000L;
    private static final long DEFAULT_SHELL_TIMEOUT_MS = 30_000L;

    private static String timeoutMarker(long ms) {
        return "\n[TIMEOUT after " + ms + "ms — long-running? use the `job` tool: "
            + "mode=start to launch, mode=view to check progress]";
    }

    // Allow-list of env vars to forward to spawned children. Limits blast radius
    // of MCP token compromise: even if the token leaks, AWS_*/OPENAI_API_KEY/etc.
    // are not handed to user-invoked commands or external MCP children.
    private static final Set<String> SPAWN_ENV_ALLOWLIST = Set.of(
        "PATH", "HOME", "USER", "SHELL", "LANG", "LC_ALL", "TZ",
        "TMPDIR", "TEMP", "TMP",
        "SystemRoot", "SystemDrive", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
        "PROGRAMFILES", "PROGRAMDATA", "WINDIR", "COMSPEC", "PATHEXT"
    );

    private static void scrubEnv(ProcessBuilder pb) {
        Map<String, String> env = pb.environment();
        env.keySet().removeIf(k -> !SPAWN_ENV_ALLOWLIST.contains(k));
    }
    
    // ===== STATIC STATE =====
    private static final Map<String, Job> jobs = new ConcurrentHashMap<>();
    private static final AtomicInteger jobSeq = new AtomicInteger(0);
    private static final Semaphore shellSemaphore = new Semaphore(MAX_SHELL_SEMAPHORE_PERMITS, true);
    private static volatile boolean shuttingDown = false;

    // ===== MCP SERVER STATE =====
    private static final Map<String, Process> mcpProcesses = new ConcurrentHashMap<>(); // key: "cwd:serverName"
    private static final Map<String, List<String>> mcpServerTools = new ConcurrentHashMap<>(); // key: "cwd:serverName"
    private static int mcpNextId = 0;
    private static final Object mcpIdLock = new Object();
    
    // ===== CONFIGURATION =====
    private static int port = DEFAULT_PORT;
    private static String bindAddr = DEFAULT_BIND;
    private static String token = null;
    private static boolean memoryEnabled = false;
    private static boolean makePublic = false;
    private static String domain = null;
    private static String mcpConfigPath = null;
    private static String publicBaseUrl = null;
    private static String gatewayDomain = null;
    private static String assignedDeviceId = null;
    private static final Set<String> disallowedTools = new HashSet<>();
    private static final Object memoLock = new Object();
    private static String uploadRoot;
    private static String spillRoot;
    private static boolean hasRg = false;
    private static boolean hasFindstr = false;
    private static boolean hasCloudflared = false;
    private static ShellType detectedShell = ShellType.SH;
    private static boolean isWindows = false;
    
    // ===== SHELL TYPES =====
    private enum ShellType { BASH, SH, CMD, POWERSHELL }
    
    // ===== MAIN ENTRY POINT =====
    public static void main(String[] args) throws Exception {
        System.err.println("[main] starting...");
        parseArgs(args);
        
        isWindows = System.getProperty("os.name").toLowerCase().startsWith("windows");
        detectedShell = detectShell();
        
        // Detect optional binaries
        hasRg = hasOnPath("rg");
        hasFindstr = hasOnPath("findstr");
        hasCloudflared = hasOnPath("cloudflared");
        
        // Set upload root
        String osName = System.getProperty("os.name");
        if (osName.equals("Mac OS X")) {
            uploadRoot = "/private/tmp";
        } else if (osName.equals("Linux")) {
            uploadRoot = "/tmp";
        } else {
            uploadRoot = System.getProperty("java.io.tmpdir");
        }
        
        // Prepare spill directory
        spillRoot = Path.of(System.getProperty("java.io.tmpdir"), "code-mcp").toString();
        try {
            Files.createDirectories(Path.of(spillRoot));
        } catch (IOException e) {
            System.err.println("[spill] warning: " + spillRoot + ": " + e.getMessage());
        }
        
        // Set public base URL
        if (domain != null) {
            publicBaseUrl = "https://" + domain;
        }
        
        // Create HTTP server bound to selected address (default 127.0.0.1).
        HttpServer server = HttpServer.create(new InetSocketAddress(bindAddr, port), 0);

        // Routes
        server.createContext("/mcp", new MCPRouteHandler());
        server.createContext("/upload/", new UploadRouteHandler());

        // Bounded thread pool with backpressure (caller-runs) instead of unbounded cached pool.
        server.setExecutor(new ThreadPoolExecutor(
            8, MAX_HTTP_THREADS,
            60L, TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(256),
            r -> { Thread t = new Thread(r, "http-" + System.nanoTime()); t.setDaemon(true); return t; },
            new ThreadPoolExecutor.CallerRunsPolicy()));
        server.start();

        String bindLabel = (bindAddr.equals("0.0.0.0") || bindAddr.equals("::")) ? "localhost" : bindAddr;
        System.err.println("code-mcp listening on http://" + bindLabel + ":" + port + "/mcp" +
            (token != null ? " (auth)" : " (no auth)"));
        
        // Handle shutdown
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            shuttingDown = true;
            server.stop(5);
        }));

        // Start gateway client if --gateway is set
        if (gatewayDomain != null) {
            try {
                startGatewayClient(gatewayDomain, assignedDeviceId);
            } catch (Exception e) {
                System.err.println("[gateway] failed to start: " + e.getMessage());
            }
        }
    }
    
    // ===== ARGUMENT PARSING =====
    private static void parseArgs(String[] args) {
        String envPort = System.getenv("PORT");
        if (envPort != null && !envPort.isBlank()) {
            try {
                port = Integer.parseInt(envPort);
            } catch (NumberFormatException e) {
                System.err.println("error: invalid $PORT=" + envPort);
                System.exit(2);
            }
        }
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--port" -> {
                    if (++i >= args.length) usage();
                    try {
                        port = Integer.parseInt(args[i]);
                    } catch (NumberFormatException e) {
                        System.err.println("error: invalid --port " + args[i]);
                        System.exit(2);
                    }
                    if (port < 1 || port > 65535) {
                        System.err.println("error: --port out of range: " + port);
                        System.exit(2);
                    }
                }
                case "--bind" -> {
                    if (++i >= args.length) usage();
                    bindAddr = args[i];
                }
                case "--token" -> {
                    if (++i >= args.length) usage();
                    token = args[i];
                }
                case "--enable-memory" -> memoryEnabled = true;
                case "--public" -> makePublic = true;
                case "--domain" -> {
                    if (++i >= args.length) usage();
                    domain = args[i];
                }
                case "--mcp" -> {
                    if (++i >= args.length) usage();
                    mcpConfigPath = args[i];
                }
                case "--gateway" -> {
                    if (++i >= args.length) usage();
                    gatewayDomain = args[i];
                }
                case "--id" -> {
                    if (++i >= args.length) usage();
                    assignedDeviceId = args[i];
                }
                case "--disallowed-tools" -> {
                    if (++i >= args.length) usage();
                    for (String t : args[i].split(",")) {
                        String name = t.trim();
                        if (!name.isEmpty()) disallowedTools.add(name);
                    }
                }
                case "-h", "--help" -> {
                    System.out.println(USAGE);
                    System.exit(0);
                }
                default -> usage();
            }
        }

        if (makePublic && domain != null) {
            System.err.println("error: --public and --domain are mutually exclusive");
            System.exit(2);
        }
        if (domain != null && !domain.matches("[A-Za-z0-9.\\-]+(:[0-9]{1,5})?")) {
            System.err.println("error: invalid --domain: " + domain);
            System.exit(2);
        }
    }
    
    private static void usage() {
        System.err.println(USAGE);
        System.exit(2);
    }
    
    private static final String USAGE = """
        Usage: java CodeMCP.java [options]

        Options:
          --port <n>                  Listen port (default: 7777 or $PORT)
          --bind <addr>               Bind address (default: 127.0.0.1)
          --token <s>                 Require ?token=<s> or Bearer auth on every request
          --enable-memory             Enable remember/forget/recall tools
          --public                    Expose via Cloudflare quick tunnel (requires cloudflared)
          --domain <host>             Use given public hostname (mutually exclusive with --public)
          --mcp <path>                Aggregate tools from external MCP servers (JSON config)
          --gateway <domain>          Connect to gateway server (wss://{domain}/ws)
          --id <uuid>                 Use specific device ID for gateway connection
          --disallowed-tools <list>   Comma-separated tools to disable
          -h, --help                  Show this help and exit
        """;
    
    // ===== SECURITY: PATH VALIDATION =====
    
    // Resolve path and verify it stays within allowed directory (prevents path traversal)
    private static Path safeResolve(String cwd, String userPath) throws IOException {
        if (userPath == null || userPath.contains("\0")) {
            throw new IOException("Invalid path");
        }
        Path base = Path.of(cwd).toAbsolutePath().normalize();
        Path resolved = base.resolve(userPath).normalize();
        if (!resolved.startsWith(base)) {
            throw new IOException("Access denied: path outside working directory");
        }
        // If the target exists, follow symlinks via toRealPath so a symlink can't escape `base`.
        if (Files.exists(resolved, LinkOption.NOFOLLOW_LINKS) && Files.isSymbolicLink(resolved)) {
            Path real = resolved.toRealPath();
            Path realBase = base.toRealPath();
            if (!real.startsWith(realBase)) {
                throw new IOException("Access denied: symlink escapes working directory");
            }
            return real;
        }
        return resolved;
    }
    
    // Same as safeResolve but also verifies result is a file (not directory)
    private static Path safeResolveFile(String cwd, String userPath) throws IOException {
        Path p = safeResolve(cwd, userPath);
        if (Files.isDirectory(p)) {
            throw new IOException("Expected file, got directory: " + userPath);
        }
        return p;
    }
    
    // Same as safeResolve but also verifies result is a directory
    private static Path safeResolveDir(String cwd, String userPath) throws IOException {
        Path p = safeResolve(cwd, userPath);
        if (Files.exists(p) && !Files.isDirectory(p)) {
            throw new IOException("Expected directory, got file: " + userPath);
        }
        return p;
    }
    
    // ===== SECURITY: SHELL ESCAPING =====
    
    // Escape string for bash -c to prevent command injection
    private static String escapeBash(String cmd) {
        if (cmd == null) return "";
        // No escaping needed - bash -c interprets the string directly
        return cmd;
    }
    
    // Escape string for sh -c
    private static String escapeSh(String cmd) {
        if (cmd == null) return "";
        // No escaping needed - sh -c interprets the string directly
        return cmd;
    }
    
    // Escape string for cmd.exe /c
    private static String escapeCmd(String cmd) {
        if (cmd == null) return "";
        // cmd.exe escapes " by doubling ("") inside quoted strings, NOT with backslash.
        // We escape shell metacharacters with caret; we wrap the command in /c so the entire
        // string is interpreted by cmd.exe directly without our quoting.
        return cmd.replace("^", "^^")
                  .replace("%", "^%")
                  .replace("&", "^&")
                  .replace("|", "^|")
                  .replace("<", "^<")
                  .replace(">", "^>");
    }
    
    // Escape string for PowerShell -Command
    private static String escapePowerShell(String cmd) {
        if (cmd == null) return "";
        return "'" + cmd.replace("'", "''") + "'";
    }
    
    // ===== SHELL DETECTION =====
    private static volatile String powerShellBinary = null;
    private static volatile boolean powerShellChecked = false;

    private static String detectPowerShellBinary() {
        if (!powerShellChecked) {
            synchronized (CodeMCP.class) {
                if (!powerShellChecked) {
                    if (hasOnPath("pwsh")) powerShellBinary = "pwsh";
                    else if (hasOnPath("powershell")) powerShellBinary = "powershell";
                    powerShellChecked = true;
                }
            }
        }
        return powerShellBinary;
    }

    private static ShellType detectShell() {
        if (isWindows) {
            // PSModulePath is set inside any PowerShell session (5.1 or 7+). Use that
            // as the authoritative signal AND require a usable powershell binary.
            if (System.getenv("PSModulePath") != null && detectPowerShellBinary() != null) {
                return ShellType.POWERSHELL;
            }
            return ShellType.CMD;
        }
        // Prefer bash when available regardless of $SHELL (matches Python/TS behavior).
        if (hasOnPath("bash")) return ShellType.BASH;
        return ShellType.SH;
    }
    
    private static String[] bashCmd(String command) {
        return new String[]{"bash", "-c", escapeBash(command)};
    }
    
    private static String[] shCmd(String command) {
        return new String[]{"sh", "-c", escapeSh(command)};
    }
    
    private static String[] cmdCmd(String command) {
        return new String[]{"cmd.exe", "/d", "/s", "/c", escapeCmd(command)};
    }
    
    private static String[] pwshCmd(String command) {
        // Fall back to literal "pwsh" if neither is on PATH so the caller gets a
        // useful "command not found" error instead of an NPE.
        String bin = detectPowerShellBinary();
        if (bin == null) bin = "pwsh";
        return new String[]{bin, "-NoProfile", "-Command", escapePowerShell(command)};
    }
    
    private static String[] shellCmd(String command) {
        return switch (detectedShell) {
            case BASH -> bashCmd(command);
            case SH -> shCmd(command);
            case CMD -> cmdCmd(command);
            case POWERSHELL -> pwshCmd(command);
        };
    }
    
    private static boolean hasOnPath(String bin) {
        String probe = isWindows ? "where " + bin : "command -v " + bin;
        try {
            ProcessBuilder pb = new ProcessBuilder(isWindows
                ? new String[]{"cmd.exe", "/d", "/s", "/c", probe}
                : new String[]{"sh", "-c", probe});
            pb.redirectInput(ProcessBuilder.Redirect.PIPE);
            pb.redirectOutput(ProcessBuilder.Redirect.DISCARD);
            pb.redirectError(ProcessBuilder.Redirect.DISCARD);
            Process p = pb.start();
            try { p.getOutputStream().close(); } catch (IOException ignored) {}
            return p.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }
    
    // ===== HMAC UTILITIES =====
    private static String b64url(byte[] buf) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }
    
    private static String b64url(String str) {
        return b64url(str.getBytes(StandardCharsets.UTF_8));
    }
    
    private static byte[] b64urlDecode(String s) {
        s = s.replace('-', '+').replace('_', '/');
        while (s.length() % 4 != 0) s += "=";
        return Base64.getDecoder().decode(s);
    }
    
    private static String mintUploadSessionId() {
        if (token == null) throw new RuntimeException("--token is required to mint upload sessions");
        long exp = System.currentTimeMillis() + UPLOAD_TTL_MS;
        String nonce = String.format("%016x", new SecureRandom().nextLong());
        String payload = exp + "." + nonce;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(token.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] sig = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            return b64url(payload) + "." + b64url(sig);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
    
    private static VerificationResult verifyUploadSessionId(String id) {
        if (token == null) return new VerificationResult(false, "server has no token configured");
        String[] parts = id.split("\\.");
        if (parts.length != 2) return new VerificationResult(false, "malformed");
        
        try {
            String payload = new String(b64urlDecode(parts[0]), StandardCharsets.UTF_8);
            byte[] sig = b64urlDecode(parts[1]);
            
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(token.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] expected = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            
            // Use MessageDigest.isEqual for constant-time comparison (prevents timing attacks)
            if (!MessageDigest.isEqual(sig, expected)) {
                return new VerificationResult(false, "bad signature");
            }
            
            String[] payloadParts = payload.split("\\.");
            long exp = Long.parseLong(payloadParts[0]);
            if (System.currentTimeMillis() > exp) {
                return new VerificationResult(false, "expired");
            }
            return new VerificationResult(true, null);
        } catch (Exception e) {
            return new VerificationResult(false, "malformed");
        }
    }
    
    private record VerificationResult(boolean ok, String reason) {}
    
    // ===== RESULT SPILL =====
    private static String maybeSpillText(String text, String toolName) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        if (bytes.length <= RESULT_SPILL_THRESHOLD) return text;
        
        // Byte-exact head
        ByteBuffer buf = ByteBuffer.wrap(bytes);
        ByteBuffer headBuf = ByteBuffer.allocate(RESULT_SPILL_HEAD);
        buf.get(headBuf.array(), 0, RESULT_SPILL_HEAD);
        String head = StandardCharsets.UTF_8.decode(headBuf).toString();
        
        // Snap to line boundary
        int lastNl = head.lastIndexOf('\n');
        if (lastNl > 0) head = head.substring(0, lastNl);
        
        // Generate filename: keep full timestamp incl. time so files spilled in
        // the same second don't collide on the prefix (parity with Python/TS).
        String ts = java.time.Instant.now().toString().replaceAll("[-:.Z]", "");
        String safeTool = (toolName != null ? toolName : "unknown").replaceAll("[^A-Za-z0-9_.-]", "_");
        String shortId = String.format("%08x", new SecureRandom().nextInt());
        String fname = ts + "-" + safeTool + "-" + shortId + ".txt";
        Path path = Path.of(spillRoot, fname);
        
        // Count lines
        int totalLines = text.isEmpty() ? 0 : (int) text.chars().filter(c -> c == '\n').count() + 1;
        
        try {
            Files.writeString(path, text, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (IOException e) {
            System.err.println("[spill] failed to write " + path + ": " + e.getMessage());
            return head + "\n[TRUNCATED: full output is " + bytes.length + " bytes (" + totalLines + " lines); spill to disk FAILED (" + e.getMessage() + ")]\n";
        }
        
        String marker = "\n[TRUNCATED: " + bytes.length + " bytes (" + totalLines + " lines) saved to " + path + " — use read with range or grep to view the remaining content]\n";
        return head + marker;
    }
    
    // ===== OUTPUT CAPPING =====
    private static String capOutput(String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        if (bytes.length <= OUTPUT_CAP_MAX) return text;
        ByteBuffer buf = ByteBuffer.wrap(bytes);
        buf.position(bytes.length - OUTPUT_CAP_KEEP);
        ByteBuffer tail = ByteBuffer.allocate(OUTPUT_CAP_KEEP);
        buf.get(tail.array());
        return StandardCharsets.UTF_8.decode(tail).toString();
    }
    
    // ===== PROCESS EXECUTION =====
    private static class ProcessResult {
        final int exitCode;
        final String output;
        
        ProcessResult(int exitCode, String output) {
            this.exitCode = exitCode;
            this.output = output;
        }
    }
    
    private static ProcessResult runCommand(String[] cmd, String cwd, long timeoutMs) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(new File(cwd));
        pb.redirectErrorStream(true);              // merge stderr into stdout (matches Python/TS combined output)
        pb.redirectInput(ProcessBuilder.Redirect.PIPE);
        scrubEnv(pb);

        Process p = pb.start();
        try { p.getOutputStream().close(); } catch (IOException ignored) {}

        Thread reader = null;
        StringBuilder sb = new StringBuilder();
        reader = new Thread(() -> {
            try (var in = p.getInputStream();
                 var br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    synchronized (sb) {
                        sb.append(line).append('\n');
                        if (sb.length() > OUTPUT_CAP_MAX) {
                            String capped = capOutput(sb.toString());
                            sb.setLength(0);
                            sb.append(capped);
                        }
                    }
                }
            } catch (IOException ignored) {}
        }, "proc-stdout-" + p.pid());
        reader.setDaemon(true);
        reader.start();

        long timeout = timeoutMs > 0 ? timeoutMs : DEFAULT_SHELL_TIMEOUT_MS;
        boolean finished;
        try {
            finished = p.waitFor(timeout, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            p.descendants().forEach(ProcessHandle::destroyForcibly);
            p.destroyForcibly();
            Thread.currentThread().interrupt();
            reader.join(500);
            return new ProcessResult(-1, capOutput(sb.toString()) + "\n[INTERRUPTED]");
        }
        if (!finished) {
            p.descendants().forEach(ProcessHandle::destroyForcibly);
            p.destroyForcibly();
            reader.join(500);
            return new ProcessResult(124, capOutput(sb.toString()) + timeoutMarker(timeout));
        }
        reader.join();                              // EOF → reader exits naturally
        return new ProcessResult(p.exitValue(), capOutput(sb.toString()));
    }
    
    // ===== JOB MANAGEMENT =====
    private static class Job {
        final String id;
        final String command;
        final Process process;
        final AtomicReference<String> output = new AtomicReference<>("");
        volatile String status = "running";
        volatile Integer exitCode;
        final long startedAt;
        
        Job(String id, String command, Process process) {
            this.id = id;
            this.command = command;
            this.process = process;
            this.startedAt = System.currentTimeMillis();
        }
    }
    
    private static Job startJob(String command, String cwd) {
        if (countRunningJobs() >= MAX_CONCURRENT_JOBS) {
            throw new RuntimeException("max concurrent jobs (" + MAX_CONCURRENT_JOBS + ") exceeded");
        }
        String id = "j" + jobSeq.incrementAndGet();
        ProcessBuilder pb = new ProcessBuilder(shellCmd(command));
        pb.directory(new File(cwd));
        pb.redirectInput(ProcessBuilder.Redirect.PIPE);
        pb.redirectErrorStream(true);
        scrubEnv(pb);

        try {
            Process process = pb.start();
            try { process.getOutputStream().close(); } catch (IOException ignored) {}
            Job job = new Job(id, command, process);
            jobs.put(id, job);

            // Use a thread-safe StringBuilder; cap on append. O(n) amortized vs O(n^2) string concat.
            final StringBuilder sb = new StringBuilder();
            CompletableFuture.runAsync(() -> {
                try (var reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        synchronized (sb) {
                            sb.append(line).append('\n');
                            if (sb.length() > OUTPUT_CAP_MAX) {
                                String capped = capOutput(sb.toString());
                                sb.setLength(0);
                                sb.append(capped);
                            }
                            job.output.set(sb.toString());
                        }
                    }
                } catch (IOException e) {
                    // Stream closed
                }
            });

            CompletableFuture.runAsync(() -> {
                try {
                    int code = process.waitFor();
                    job.status = "exited";
                    job.exitCode = code;
                    // Keep entry so view_job after exit still works (matches Python/TS).
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });

            return job;
        } catch (IOException e) {
            throw new RuntimeException("Failed to start job: " + e.getMessage(), e);
        }
    }

    private static int countRunningJobs() {
        int n = 0;
        for (Job j : jobs.values()) if ("running".equals(j.status)) n++;
        return n;
    }
    
    // ===== MEMO MANAGEMENT =====
    private record Memo(int id, long ts, String memo, List<String> tags) {}
    
    private static List<Memo> readMemos(String cwd) throws IOException {
        Path memoFile = Path.of(cwd, ".memo.jsonl");
        if (!Files.exists(memoFile)) return List.of();
        
        List<Memo> memos = new ArrayList<>();
        for (String line : Files.readString(memoFile).split("\n")) {
            line = line.trim();
            if (line.isEmpty()) continue;
            try {
                memos.add(parseMemo(line));
            } catch (Exception e) {
                // Skip malformed lines
            }
        }
        return memos;
    }
    
    @SuppressWarnings("unchecked")
    private static Memo parseMemo(String json) {
        Map<String, Object> m = parseJsonObject(json);
        List<String> tags = null;
        if (m.containsKey("tags")) {
            Object t = m.get("tags");
            if (t instanceof List<?>) {
                tags = new ArrayList<>();
                for (Object item : (List<?>) t) {
                    if (item instanceof String) tags.add((String) item);
                    else tags.add(String.valueOf(item));
                }
            }
        }
        return new Memo(
            ((Number) m.get("id")).intValue(),
            ((Number) m.get("ts")).longValue(),
            (String) m.get("memo"),
            tags
        );
    }
    
    // ----- JSON parser (FSM-based, RFC 8259 subset) -----
    private static final class JsonParser {
        private static final int MAX_DEPTH = 256;
        private final String src;
        private int pos;
        private int depth = 0;
        JsonParser(String s) { this.src = s; this.pos = 0; }

        Object parse() {
            skipWs();
            Object v = readValue();
            skipWs();
            if (pos != src.length()) {
                throw new RuntimeException("JSON: trailing data at pos " + pos);
            }
            return v;
        }

        private void skipWs() {
            while (pos < src.length()) {
                char c = src.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++;
                else break;
            }
        }

        private Object readValue() {
            skipWs();
            if (pos >= src.length()) throw new RuntimeException("JSON: unexpected EOF");
            char c = src.charAt(pos);
            if (c == '{') return readObject();
            if (c == '[') return readArray();
            if (c == '"') return readString();
            if (c == 't' || c == 'f') return readBool();
            if (c == 'n') return readNull();
            if (c == '-' || (c >= '0' && c <= '9')) return readNumber();
            throw new RuntimeException("JSON: unexpected char '" + c + "' at pos " + pos);
        }

        private Map<String, Object> readObject() {
            if (++depth > MAX_DEPTH) throw new RuntimeException("JSON: too deeply nested (>" + MAX_DEPTH + ")");
            expect('{');
            Map<String, Object> m = new LinkedHashMap<>();
            skipWs();
            if (peek() == '}') { pos++; depth--; return m; }
            while (true) {
                skipWs();
                if (peek() != '"') throw new RuntimeException("JSON: expected string key at pos " + pos);
                String key = readString();
                skipWs();
                expect(':');
                Object value = readValue();
                m.put(key, value);
                skipWs();
                char c = peek();
                if (c == ',') { pos++; continue; }
                if (c == '}') { pos++; depth--; return m; }
                throw new RuntimeException("JSON: expected ',' or '}' at pos " + pos);
            }
        }

        private List<Object> readArray() {
            if (++depth > MAX_DEPTH) throw new RuntimeException("JSON: too deeply nested (>" + MAX_DEPTH + ")");
            expect('[');
            List<Object> list = new ArrayList<>();
            skipWs();
            if (peek() == ']') { pos++; depth--; return list; }
            while (true) {
                list.add(readValue());
                skipWs();
                char c = peek();
                if (c == ',') { pos++; continue; }
                if (c == ']') { pos++; depth--; return list; }
                throw new RuntimeException("JSON: expected ',' or ']' at pos " + pos);
            }
        }

        private String readString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (pos < src.length()) {
                char c = src.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    if (pos >= src.length()) throw new RuntimeException("JSON: dangling escape");
                    char esc = src.charAt(pos++);
                    switch (esc) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            if (pos + 4 > src.length()) throw new RuntimeException("JSON: bad unicode escape");
                            int code = Integer.parseInt(src.substring(pos, pos + 4), 16);
                            pos += 4;
                            // Surrogate pair handling
                            if (code >= 0xD800 && code <= 0xDBFF && pos + 6 <= src.length()
                                    && src.charAt(pos) == '\\' && src.charAt(pos + 1) == 'u') {
                                int low = Integer.parseInt(src.substring(pos + 2, pos + 6), 16);
                                if (low >= 0xDC00 && low <= 0xDFFF) {
                                    sb.appendCodePoint(0x10000 + (((code - 0xD800) << 10) | (low - 0xDC00)));
                                    pos += 6;
                                    break;
                                }
                            }
                            sb.append((char) code);
                            break;
                        default: throw new RuntimeException("JSON: bad escape '\\" + esc + "'");
                    }
                } else if (c < 0x20) {
                    throw new RuntimeException("JSON: unescaped control char 0x" + Integer.toHexString(c));
                } else {
                    sb.append(c);
                }
            }
            throw new RuntimeException("JSON: unterminated string");
        }

        private Object readNumber() {
            int start = pos;
            if (peek() == '-') pos++;
            while (pos < src.length()) {
                char c = src.charAt(pos);
                if ((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') pos++;
                else break;
            }
            String num = src.substring(start, pos);
            if (num.contains(".") || num.contains("e") || num.contains("E")) {
                return Double.parseDouble(num);
            }
            try {
                return Long.parseLong(num);
            } catch (NumberFormatException e) {
                return Double.parseDouble(num);
            }
        }

        private Boolean readBool() {
            if (src.regionMatches(pos, "true", 0, 4)) { pos += 4; return Boolean.TRUE; }
            if (src.regionMatches(pos, "false", 0, 5)) { pos += 5; return Boolean.FALSE; }
            throw new RuntimeException("JSON: invalid literal at pos " + pos);
        }

        private Object readNull() {
            if (src.regionMatches(pos, "null", 0, 4)) { pos += 4; return null; }
            throw new RuntimeException("JSON: invalid literal at pos " + pos);
        }

        private char peek() {
            if (pos >= src.length()) throw new RuntimeException("JSON: unexpected EOF");
            return src.charAt(pos);
        }

        private void expect(char c) {
            if (pos >= src.length() || src.charAt(pos) != c) {
                throw new RuntimeException("JSON: expected '" + c + "' at pos " + pos);
            }
            pos++;
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> parseJsonObject(String json) {
        Object v = new JsonParser(json).parse();
        if (!(v instanceof Map)) throw new RuntimeException("JSON: expected object, got " + (v == null ? "null" : v.getClass().getSimpleName()));
        return (Map<String, Object>) v;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> parseJsonArray(String json) {
        Object v = new JsonParser(json).parse();
        if (!(v instanceof List)) throw new RuntimeException("JSON: expected array");
        return (List<Object>) v;
    }

    private static Object parseJsonValue(String json) {
        return new JsonParser(json).parse();
    }
    
    private static void writeMemos(String cwd, List<Memo> memos) throws IOException {
        StringBuilder sb = new StringBuilder();
        for (Memo m : memos) {
            sb.append(memoToJsonLine(m)).append('\n');
        }
        synchronized (memoLock) {
            Path target = Path.of(cwd, ".memo.jsonl");
            Path tmp = Path.of(cwd, ".memo.jsonl.tmp");
            Files.writeString(tmp, sb.toString(),
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
            try {
                Files.move(tmp, target,
                    StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        }
    }

    private static String memoToJsonLine(Memo m) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"id\":").append(m.id)
          .append(",\"ts\":").append(m.ts)
          .append(",\"memo\":\"").append(escapeJson(m.memo)).append("\"");
        if (m.tags != null && !m.tags.isEmpty()) {
            sb.append(",\"tags\":[");
            boolean first = true;
            for (String t : m.tags) {
                if (!first) sb.append(',');
                first = false;
                sb.append('"').append(escapeJson(t)).append('"');
            }
            sb.append(']');
        }
        sb.append('}');
        return sb.toString();
    }
    
    private static String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"':  sb.append("\\\""); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                        // Valid surrogate pair — pass through as two raw UTF-16 chars; UTF-8 encoder will produce 4 bytes.
                        sb.append(c);
                        sb.append(s.charAt(++i));
                    } else if (Character.isSurrogate(c)) {
                        // Lone surrogate — emit as \\uXXXX escape so resulting JSON is well-formed UTF-8.
                        sb.append(String.format("\\u%04x", (int) c));
                    } else if (c < 0x20 || c == 0x7F || (c >= 0x80 && c <= 0x9F) || c == 0x2028 || c == 0x2029) {
                        // C0+C1 controls, DEL, and JS-hostile U+2028/U+2029.
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }
    
    private static int lastMemoId(String cwd) throws IOException {
        Path memoFile = Path.of(cwd, ".memo.jsonl");
        if (!Files.exists(memoFile)) return 0;
        
        long size = Files.size(memoFile);
        if (size == 0) return 0;
        
        long readSize = Math.min(size, MEMO_TAIL_BYTES);
        byte[] buf = new byte[(int) readSize];
        try (var channel = Files.newByteChannel(memoFile)) {
            channel.position(size - readSize);
            channel.read(ByteBuffer.wrap(buf));
        }
        
        String tail = new String(buf, StandardCharsets.UTF_8);
        String[] lines = tail.split("\n");
        
        for (int i = lines.length - 1; i >= 0; i--) {
            String line = lines[i].trim();
            if (line.isEmpty()) continue;
            try {
                Memo m = parseMemo(line);
                return m.id;
            } catch (Exception e) {
                // Try previous
            }
        }
        
        List<Memo> memos = readMemos(cwd);
        return memos.stream().mapToInt(m -> m.id).max().orElse(0);
    }
    
    // ===== TOOL HANDLERS =====
    
    // --- read tool ---
    private static String handleRead(String cwd, String path, int[] range, boolean noTruncate) throws IOException {
        Path file = safeResolveFile(cwd, path);
        String content = Files.readString(file);
        if (range != null) {
            if (range.length != 2) throw new RuntimeException("range must be [start, end]");
            if (range[0] < 1 || range[1] < range[0]) throw new RuntimeException("invalid range [" + range[0] + ", " + range[1] + "]");
            // Preserve trailing CR if present so original line endings round-trip.
            String[] lines = content.split("\n", -1);
            int start = Math.min(range[0] - 1, lines.length);
            int end = Math.min(range[1], lines.length);
            content = String.join("\n", Arrays.copyOfRange(lines, start, end));
        }
        if (noTruncate) return content;
        return maybeSpillText(content, "read");
    }
    
    // --- write tool ---
    private static String handleWrite(String cwd, String path, String content) throws IOException {
        Path file = safeResolve(cwd, path);
        Files.writeString(file, content);
        long bytes = content.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        return "wrote " + bytes + " bytes to " + path;
    }
    
    // --- edit tool ---
    private static String handleEdit(String cwd, String path, String oldStr, String newStr) throws IOException {
        Path file = safeResolveFile(cwd, path);
        String text = Files.readString(file);
        int first = text.indexOf(oldStr);
        if (first == -1) throw new RuntimeException("old_str not found");
        if (text.indexOf(oldStr, first + 1) != -1) throw new RuntimeException("old_str not unique");
        String result = text.substring(0, first) + newStr + text.substring(first + oldStr.length());
        Files.writeString(file, result);
        return "ok";
    }
    
    // --- multi_edit tool ---
    private static class Edit {
        final String path;
        final String oldStr;
        final String newStr;
        
        Edit(String path, String oldStr, String newStr) {
            this.path = path;
            this.oldStr = oldStr;
            this.newStr = newStr;
        }
    }
    
    private static String handleMultiEdit(String cwd, List<Edit> edits) throws IOException {
        Map<String, String> originals = new LinkedHashMap<>();
        List<EditRange> ranges = new ArrayList<>();
        
        for (int i = 0; i < edits.size(); i++) {
            Edit edit = edits.get(i);
            Path p = safeResolveFile(cwd, edit.path);
            String fullPath = p.toString();
            
            if (!originals.containsKey(fullPath)) {
                originals.put(fullPath, Files.readString(p));
            }
            String text = originals.get(fullPath);
            
            int first = text.indexOf(edit.oldStr);
            if (first == -1) throw new RuntimeException("edit #" + (i + 1) + " (" + edit.path + "): old_str not found");
            if (text.indexOf(edit.oldStr, first + 1) != -1) {
                throw new RuntimeException("edit #" + (i + 1) + " (" + edit.path + "): old_str not unique");
            }
            
            int start = first;
            int end = first + edit.oldStr.length();
            for (EditRange r : ranges) {
                if (r.path.equals(fullPath) && start < r.end && end > r.start) {
                    throw new RuntimeException("edit #" + (i + 1) + " (" + edit.path + "): overlaps edit #" + (r.index + 1));
                }
            }
            ranges.add(new EditRange(fullPath, start, end, edit.newStr, i));
        }
        
        // Apply edits in reverse order
        for (EditRange r : ranges.stream().sorted((a, b) -> b.start - a.start).collect(Collectors.toList())) {
            String text = originals.get(r.path);
            text = text.substring(0, r.start) + r.replacement + text.substring(r.end);
            originals.put(r.path, text);
        }
        
        // Write all files
        for (Map.Entry<String, String> e : originals.entrySet()) {
            Files.writeString(Path.of(e.getKey()), e.getValue());
        }
        
        Map<String, Long> counts = ranges.stream()
            .collect(Collectors.groupingBy(r -> r.path, Collectors.counting()));
        String summary = counts.entrySet().stream()
            .map(e -> e.getKey() + " (" + e.getValue() + " edit" + (e.getValue() > 1 ? "s" : "") + ")")
            .collect(Collectors.joining(", "));
        return "applied " + edits.size() + " edit(s) across " + counts.size() + " file(s): " + summary;
    }
    
    private record EditRange(String path, int start, int end, String replacement, int index) {}
    
    // --- bash/shell/command/powershell tools ---
    private static String handleBash(String cwd, String command, Long timeoutMs) throws Exception {
        if (!shellSemaphore.tryAcquire(30, TimeUnit.SECONDS)) {
            throw new RuntimeException("Too many concurrent shell executions, please try again later");
        }
        try {
            ProcessResult result = runCommand(bashCmd(command), cwd, timeoutMs != null ? timeoutMs : 0);
            return "exit=" + result.exitCode + "\n" + result.output;
        } finally {
            shellSemaphore.release();
        }
    }
    
    private static String handleShell(String cwd, String command, Long timeoutMs) throws Exception {
        if (!shellSemaphore.tryAcquire(30, TimeUnit.SECONDS)) {
            throw new RuntimeException("Too many concurrent shell executions, please try again later");
        }
        try {
            ProcessResult result = runCommand(shCmd(command), cwd, timeoutMs != null ? timeoutMs : 0);
            return "exit=" + result.exitCode + "\n" + result.output;
        } finally {
            shellSemaphore.release();
        }
    }
    
    private static String handleCommand(String cwd, String command, Long timeoutMs) throws Exception {
        if (!shellSemaphore.tryAcquire(30, TimeUnit.SECONDS)) {
            throw new RuntimeException("Too many concurrent shell executions, please try again later");
        }
        try {
            ProcessResult result = runCommand(cmdCmd(command), cwd, timeoutMs != null ? timeoutMs : 0);
            return "exit=" + result.exitCode + "\n" + result.output;
        } finally {
            shellSemaphore.release();
        }
    }
    
    private static String handlePowershell(String cwd, String command, Long timeoutMs) throws Exception {
        if (!shellSemaphore.tryAcquire(30, TimeUnit.SECONDS)) {
            throw new RuntimeException("Too many concurrent shell executions, please try again later");
        }
        try {
            ProcessResult result = runCommand(pwshCmd(command), cwd, timeoutMs != null ? timeoutMs : 0);
            return "exit=" + result.exitCode + "\n" + result.output;
        } finally {
            shellSemaphore.release();
        }
    }
    
    // --- grep tool ---
    private static String handleGrep(String cwd, String pattern, String path, String glob) throws Exception {
        String[] cmd;
        if (hasRg) {
            cmd = new String[]{"rg", "--line-number", "--no-heading", "--color=never"};
            if (glob != null) cmd = append(cmd, "--glob", glob);
            // `--` so a pattern starting with `-` isn't parsed as a flag.
            cmd = append(cmd, "--", pattern, path != null ? path : ".");
        } else if (isWindows && hasFindstr) {
            cmd = new String[]{"findstr", "/r", "/n", pattern, glob != null ? path + "\\" + glob.replace("*", "*") : (path != null ? path : ".")};
        } else {
            cmd = new String[]{"grep", "-rEn"};
            if (glob != null) cmd = append(cmd, "--include", glob);
            cmd = append(cmd, "--", pattern, path != null ? path : ".");
        }
        
        ProcessResult result = runCommand(cmd, cwd, 0);
        if (!result.output.isEmpty()) return result.output;
        if (result.exitCode == 1) return "(no matches)";
        return "ERROR (exit=" + result.exitCode + "): " + result.output;
    }
    
    private static String[] append(String[] arr, String... elements) {
        String[] result = new String[arr.length + elements.length];
        System.arraycopy(arr, 0, result, 0, arr.length);
        System.arraycopy(elements, 0, result, arr.length, elements.length);
        return result;
    }
    
    // --- find tool ---
    private static String handleFind(String cwd, String pattern, String path, boolean includeHidden) throws IOException {
        path = path != null ? path : ".";
        Path base = safeResolveDir(cwd, path);
        
        Set<String> noiseDirs = Set.of(
            "node_modules", ".git", ".next", ".nuxt", ".turbo", ".cache",
            "dist", "build", "out", "target", "coverage",
            ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
            ".idea", ".vscode"
        );
        
        boolean hasRecursive = pattern.contains("**");
        String globPattern = pattern;
        if (!pattern.contains("/") && !pattern.contains("\\")) {
            globPattern = "**/" + pattern;
        }
        
        List<Path> results = new ArrayList<>();
        PathMatcher matcher = FileSystems.getDefault().getPathMatcher("glob:" + globPattern);
        
        AtomicInteger count = new AtomicInteger(0);
        AtomicBoolean aborted = new AtomicBoolean(false);
        
        ExecutorService exec = Executors.newSingleThreadExecutor();
        Future<?> future = exec.submit(() -> {
            try (var stream = Files.walk(base, hasRecursive ? Integer.MAX_VALUE : 1)) {
                stream.forEach(p -> {
                    if (aborted.get()) return;
                    if (results.size() >= 10_000) {
                        aborted.set(true);
                        return;
                    }
                    
                    Path relative = base.relativize(p);
                    String name = p.getFileName() != null ? p.getFileName().toString() : "";
                    
                    boolean skip = false;
                    for (Path seg : relative) {
                        String segName = seg.toString();
                        if (noiseDirs.contains(segName)) {
                            if (!pattern.contains(segName)) {
                                skip = true;
                                break;
                            }
                        }
                        if (!includeHidden && segName.startsWith(".") && !segName.equals(".") && !segName.equals("..")) {
                            if (!pattern.contains("." + segName) && !pattern.startsWith(".")) {
                                skip = true;
                                break;
                            }
                        }
                    }
                    if (!skip && matcher.matches(p) && Files.isRegularFile(p)) {
                        results.add(p);
                    }
                });
            } catch (IOException e) {
                // Walk failed
            }
        });
        
        try {
            future.get(30, TimeUnit.SECONDS);
        } catch (Exception e) {
            aborted.set(true);
        } finally {
            exec.shutdownNow();
        }
        
        return results.stream()
            .map(p -> base.relativize(p).toString().replace('\\', '/'))
            .collect(Collectors.joining("\n"));
    }
    
    // --- ls tool ---
    private static String handleLs(String cwd, String path) throws IOException {
        Path dir = safeResolveDir(cwd, path != null ? path : ".");
        try (var stream = Files.list(dir)) {
            return stream.map(p -> {
                try {
                    boolean isDir = Files.isDirectory(p);
                    long size = isDir ? 0 : Files.size(p);
                    String name = p.getFileName().toString();
                    return (isDir ? "d" : "-") + String.format("%10d", size) + " " + name;
                } catch (IOException e) {
                    return "? " + p.getFileName();
                }
            }).sorted().collect(Collectors.joining("\n"));
        }
    }
    
    // --- job tool ---
    private static String handleJob(String cwd, String mode, String command, Long timeoutMs) {
        if (mode.equals("list")) {
            if (jobs.isEmpty()) return "(no jobs)";
            return jobs.values().stream()
                .map(j -> j.id + " [" + j.status + (j.exitCode != null ? " " + j.exitCode : "") + "] " + j.command)
                .collect(Collectors.joining("\n"));
        }
        
        if (mode.equals("start")) {
            if (command == null || command.isEmpty()) throw new RuntimeException("command required");
            Job j = startJob(command, cwd);
            return "started " + j.id;
        }
        
        if (command == null || command.isEmpty()) throw new RuntimeException("job id required (pass as command)");
        
        Job j = jobs.get(command);
        if (j == null) throw new RuntimeException("no such job: " + command);
        
        if (mode.equals("view")) {
            return "[" + j.id + "] " + j.command + "\n[" + j.status + (j.exitCode != null ? " " + j.exitCode : "") + "]\n" + j.output.get();
        }
        
        if (mode.equals("stop")) {
            if (!j.status.equals("running")) return j.id + " already " + j.status;
            long timeout = timeoutMs != null ? timeoutMs : 500;
            // Kill the process AND its descendants so shell children don't orphan.
            j.process.descendants().forEach(ProcessHandle::destroy);
            j.process.destroy();
            try {
                if (!j.process.waitFor(timeout, TimeUnit.MILLISECONDS)) {
                    j.process.descendants().forEach(ProcessHandle::destroyForcibly);
                    j.process.destroyForcibly();
                    j.process.waitFor();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return j.id + " stopped";
        }
        
        throw new RuntimeException("bad mode: " + mode);
    }
    
    // --- mcp tool ---
    @SuppressWarnings("unchecked")
    private static Map<String, Object> loadMcpServers(Path configFullPath) throws IOException {
        String content = Files.readString(configFullPath, StandardCharsets.UTF_8);
        Map<String, Object> parsed = parseJsonObject(content);
        Object servers = parsed.get("mcpServers");
        if (!(servers instanceof Map)) return Map.of();
        return (Map<String, Object>) servers;
    }

    private static String handleMcp(String cwd, String action, String server, String tool, Map<String, Object> args, String mcpCfgPath) {
        String cfgPath = mcpCfgPath != null ? mcpCfgPath : ".mcp.json";
        Path configFullPath = Path.of(cwd, cfgPath);

        if (action.equals("list")) {
            try {
                if (!Files.exists(configFullPath)) {
                    return "{\"servers\":[],\"mcpConfigPath\":\"" + escapeJson(cfgPath) + "\"}";
                }
                Map<String, Object> servers = loadMcpServers(configFullPath);
                List<String> result = new ArrayList<>();
                for (String name : servers.keySet()) {
                    String key = cwd + ":" + name;
                    Process p = mcpProcesses.get(key);
                    boolean isLoaded = (p != null) && p.isAlive();
                    result.add("{\"name\":\"" + escapeJson(name) + "\",\"status\":\"" + (isLoaded ? "loaded" : "unloaded") + "\",\"tools\":[]}");
                }
                return "{\"servers\":[" + String.join(",", result) + "],\"mcpConfigPath\":\"" + escapeJson(cfgPath) + "\"}";
            } catch (Exception e) {
                return "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}";
            }
        }

        if (action.equals("call")) {
            if (server == null || server.isEmpty()) return "{\"error\":\"server name required for call action\"}";
            if (tool == null || tool.isEmpty()) return "{\"error\":\"tool name required for call action\"}";
            try {
                if (!Files.exists(configFullPath)) {
                    return "{\"error\":\".mcp.json not found at " + escapeJson(cfgPath) + "\"}";
                }
                Map<String, Object> servers = loadMcpServers(configFullPath);
                @SuppressWarnings("unchecked")
                Map<String, Object> serverCfg = (Map<String, Object>) servers.get(server);
                if (serverCfg == null) {
                    return "{\"error\":\"server '" + escapeJson(server) + "' not found in .mcp.json\"}";
                }
                String cmd = (String) serverCfg.get("command");
                if (cmd == null) return "{\"error\":\"server '" + escapeJson(server) + "' missing 'command'\"}";
                List<String> cmdArgs = new ArrayList<>();
                cmdArgs.add(cmd);
                Object cfgArgs = serverCfg.get("args");
                if (cfgArgs instanceof List) {
                    for (Object a : (List<?>) cfgArgs) cmdArgs.add(String.valueOf(a));
                }
                String key = cwd + ":" + server;
                // Serialize spawn-and-handshake to avoid two concurrent calls each spawning.
                Process proc;
                synchronized (mcpProcesses) {
                    proc = mcpProcesses.get(key);
                    if (proc == null || !proc.isAlive()) {
                        ProcessBuilder pb = new ProcessBuilder(cmdArgs);
                        pb.directory(Path.of(cwd).toFile());
                        pb.redirectErrorStream(true);
                        scrubEnv(pb);
                        proc = pb.start();
                        mcpProcesses.put(key, proc);
                    }
                }
                Map<String, Object> callArgs = new LinkedHashMap<>();
                callArgs.put("name", tool);
                callArgs.put("arguments", args != null ? args : Map.of());
                try {
                    Map<?, ?> result = mcpCall(key, proc, "tools/call", callArgs);
                    return toJson(result);
                } catch (Exception callErr) {
                    // Probe failed — clean up so the next attempt re-spawns fresh.
                    synchronized (mcpProcesses) {
                        Process tracked = mcpProcesses.get(key);
                        if (tracked == proc) {
                            mcpProcesses.remove(key);
                            mcpServerTools.remove(key);
                        }
                    }
                    try { proc.destroy(); } catch (Exception ignored) {}
                    return "{\"error\":\"" + escapeJson(callErr.getMessage()) + "\"}";
                }
            } catch (Exception e) {
                return "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}";
            }
        }

        if (action.equals("unload")) {
            String key = server != null ? cwd + ":" + server : null;
            if (key != null) {
                Process proc = mcpProcesses.remove(key);
                if (proc != null) proc.destroy();
                mcpServerTools.remove(key);
            } else {
                mcpProcesses.keySet().stream().filter(k -> k.startsWith(cwd + ":")).toList()
                    .forEach(k -> { Process p = mcpProcesses.remove(k); if (p != null) p.destroy(); });
                mcpServerTools.keySet().removeIf(k -> k.startsWith(cwd + ":"));
            }
            return "{ \"success\": true }";
        }

        return "{ \"error\": \"unknown action: " + escapeJson(action) + "\" }";
    }

    private static Map<?, ?> mcpCall(String key, Process proc, String method, Map<String, Object> params) throws Exception {
        // Allocate id under the lock so concurrent callers don't both read the same value.
        int reqId;
        synchronized (mcpIdLock) {
            mcpNextId++;
            reqId = mcpNextId;
        }
        String json = "{\"jsonrpc\":\"2.0\",\"id\":" + reqId + ",\"method\":\"" + method + "\",\"params\":" + toJson(params) + "}\n";
        try {
            proc.getOutputStream().write(json.getBytes(StandardCharsets.UTF_8));
            proc.getOutputStream().flush();
        } catch (IOException e) {
            throw new IOException("MCP server pipe broken: " + e.getMessage(), e);
        }

        BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8));
        long deadline = System.currentTimeMillis() + 30000;
        while (System.currentTimeMillis() < deadline) {
            String line;
            try {
                line = reader.readLine();
            } catch (IOException e) {
                throw new IOException("MCP server read failed: " + e.getMessage(), e);
            }
            if (line == null) {
                throw new EOFException("MCP server process ended");
            }
            if (line.isBlank()) continue;
            // Match the id exactly by parsing the JSON response — substring contains() would
            // match id=1 against id=10/11/100 etc.
            try {
                Map<String, Object> resp = parseJsonObject(line);
                Object respId = resp.get("id");
                if (respId == null) continue;
                long respIdLong = (respId instanceof Number) ? ((Number) respId).longValue() : -1;
                if (respIdLong != reqId) continue;
                if (resp.containsKey("error")) return Map.of("error", resp.get("error"));
                Object result = resp.get("result");
                return result instanceof Map ? (Map<?, ?>) result : Map.of("result", result);
            } catch (RuntimeException ex) {
                // Not a valid JSON line — skip (could be stderr that leaked into stdout).
                continue;
            }
        }
        throw new RuntimeException("MCP server response timeout");
    }

    private static String toJson(Object obj) {
        if (obj == null) return "null";
        if (obj instanceof String) return "\"" + escapeJson((String) obj) + "\"";
        if (obj instanceof Boolean) return String.valueOf(obj);
        if (obj instanceof Number) {
            // Avoid NaN/Infinity which are not valid JSON.
            Number n = (Number) obj;
            if (n instanceof Double || n instanceof Float) {
                double d = n.doubleValue();
                if (Double.isNaN(d) || Double.isInfinite(d)) return "null";
            }
            return n.toString();
        }
        if (obj instanceof List) {
            List<?> list = (List<?>) obj;
            StringBuilder sb = new StringBuilder("[");
            String sep = "";
            for (Object item : list) {
                sb.append(sep).append(toJson(item));
                sep = ",";
            }
            return sb.append("]").toString();
        }
        if (obj instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) obj;
            StringBuilder sb = new StringBuilder("{");
            String sep = "";
            for (Map.Entry<?, ?> e : map.entrySet()) {
                sb.append(sep).append("\"").append(escapeJson(String.valueOf(e.getKey()))).append("\":").append(toJson(e.getValue()));
                sep = ",";
            }
            return sb.append("}").toString();
        }
        return "\"" + escapeJson(String.valueOf(obj)) + "\"";
    }

    // --- preview tool ---
    private static String handlePreview(String url) {
        if (!hasCloudflared) throw new RuntimeException("cloudflared not found on PATH");
        try {
            Job j = startJob("cloudflared tunnel --url " + url + " --no-autoupdate 2>&1", System.getProperty("user.dir"));
            Pattern pattern = Pattern.compile("https://[a-z0-9-]+\\.trycloudflare\\.com", Pattern.CASE_INSENSITIVE);
            long deadline = System.currentTimeMillis() + 20_000;
            
            while (System.currentTimeMillis() < deadline) {
                String output = j.output.get();
                Matcher m = pattern.matcher(output);
                if (m.find()) {
                    return m.group() + " (job " + j.id + ")";
                }
                if (j.status.equals("exited")) {
                    throw new RuntimeException("cloudflared exited");
                }
                Thread.sleep(250);
            }
            throw new RuntimeException("timeout waiting for tunnel URL");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("interrupted");
        }
    }
    
    // --- memory tools (remember/forget/recall) ---
    private static String handleRemember(String cwd, String memo, List<String> tags) throws IOException {
        synchronized (memoLock) {
            int id = lastMemoId(cwd) + 1;
            Memo m = new Memo(id, System.currentTimeMillis(), memo, tags);
            Files.writeString(Path.of(cwd, ".memo.jsonl"), memoToJsonLine(m) + "\n",
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            return "remembered #" + id;
        }
    }
    
    private static String handleForget(String cwd, int memoId) throws IOException {
        List<Memo> memos = readMemos(cwd);
        int before = memos.size();
        memos = memos.stream().filter(m -> m.id != memoId).collect(Collectors.toList());
        if (memos.size() == before) throw new RuntimeException("no memo with id " + memoId);
        writeMemos(cwd, memos);
        return "forgot #" + memoId;
    }
    
    private static String handleRecall(String cwd, String query, List<String> tags, int limit, int offset) throws IOException {
        List<Memo> memos = readMemos(cwd);
        
        memos = memos.stream().filter(m -> {
            if (query != null && !m.memo.toLowerCase().contains(query.toLowerCase())) return false;
            if (tags != null && !tags.isEmpty()) {
                if (m.tags == null) return false;
                for (String t : tags) {
                    if (!m.tags.contains(t)) return false;
                }
            }
            return true;
        }).sorted((a, b) -> Integer.compare(b.id, a.id)).collect(Collectors.toList());
        
        int fromIndex = Math.min(offset, memos.size());
        int toIndex = Math.min(offset + limit, memos.size());
        List<Memo> page = memos.subList(fromIndex, toIndex);
        
        if (page.isEmpty()) return "(no matches)";
        
        return page.stream()
            .map(m -> "#" + m.id + " " + java.time.Instant.ofEpochMilli(m.ts).toString() + (m.tags != null && !m.tags.isEmpty() ? " [" + String.join(",", m.tags) + "]" : "") + " " + m.memo)
            .collect(Collectors.joining("\n"));
    }
    
    // --- get_upload_link tool ---
    private static String handleGetUploadLink() {
        if (publicBaseUrl == null) throw new RuntimeException("get_upload_link requires --public or --domain");
        if (token == null) throw new RuntimeException("get_upload_link requires --token");
        String sessionId = mintUploadSessionId();
        String url = publicBaseUrl + "/upload/" + sessionId;
        return String.format("{\"url\":\"%s\",\"expiresInMinutes\":10}", url);
    }
    
    // ===== MCP HTTP ROUTE HANDLER =====
    private static class MCPRouteHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (exchange.getRequestMethod().equals("POST") && exchange.getRequestURI().getPath().equals("/mcp")) {
                handleMcpRequest(exchange);
            } else {
                exchange.sendResponseHeaders(404, 0);
                exchange.close();
            }
        }
        
        private void handleMcpRequest(HttpExchange exchange) throws IOException {
            Headers headers = exchange.getResponseHeaders();
            headers.add("Access-Control-Allow-Origin", "*");
            headers.add("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
            headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization");

            if (exchange.getRequestMethod().equals("OPTIONS")) {
                exchange.sendResponseHeaders(204, -1);
                exchange.close();
                return;
            }

            // Token check (constant-time compare, supports ?token=… and Authorization: Bearer …)
            if (token != null) {
                String reqToken = parseQueryParam(exchange.getRequestURI(), "token");
                if (reqToken == null) {
                    String authHdr = exchange.getRequestHeaders().getFirst("Authorization");
                    if (authHdr != null && authHdr.startsWith("Bearer ")) {
                        reqToken = authHdr.substring(7).trim();
                    }
                }
                byte[] expected = token.getBytes(StandardCharsets.UTF_8);
                byte[] given = reqToken == null ? new byte[0] : reqToken.getBytes(StandardCharsets.UTF_8);
                if (!MessageDigest.isEqual(expected, given)) {
                    writeJsonResponse(exchange, 401, "{\"error\":\"unauthorized\"}");
                    return;
                }
            }

            // Cap request body size
            long contentLen = -1;
            String clHdr = exchange.getRequestHeaders().getFirst("Content-Length");
            if (clHdr != null) {
                try { contentLen = Long.parseLong(clHdr); } catch (NumberFormatException ignored) {}
            }
            if (contentLen > MAX_REQUEST_BYTES) {
                writeJsonResponse(exchange, 413, "{\"error\":\"request too large\"}");
                return;
            }
            String body = readBodyCapped(exchange.getRequestBody(), MAX_REQUEST_BYTES);

            String idStr;
            try {
                Map<String, Object> request = parseJsonObject(body);
                idStr = request.containsKey("id") ? toJson(request.get("id")) : "null";
                String method = (String) request.get("method");
                @SuppressWarnings("unchecked")
                Object paramsObj = request.get("params");
                if (paramsObj != null && !(paramsObj instanceof Map)) {
                    String response = "{\"jsonrpc\":\"2.0\",\"id\":" + idStr + ",\"error\":{\"code\":-32602,\"message\":\"Invalid params: expected object\"}}";
                    writeJsonResponse(exchange, 400, response);
                    return;
                }
                Map<String, Object> params = (Map<String, Object>) paramsObj;

                // Notifications have no id and expect no response body.
                if (method != null && method.startsWith("notifications/")) {
                    exchange.sendResponseHeaders(204, -1);
                    exchange.close();
                    return;
                }

                Object result = handleMcpMethod(method, params);

                String response;
                if (result instanceof String && ((String) result).startsWith("ERROR")) {
                    String errMsg = (String) result;
                    int code = -32603;
                    if (errMsg.startsWith("ERROR:-32601:")) {
                        code = -32601;
                        errMsg = errMsg.substring("ERROR:-32601:".length()).trim();
                    } else if (errMsg.startsWith("ERROR:-32602:")) {
                        code = -32602;
                        errMsg = errMsg.substring("ERROR:-32602:".length()).trim();
                    }
                    response = "{\"jsonrpc\":\"2.0\",\"id\":" + idStr + ",\"error\":{\"code\":" + code + ",\"message\":" + jsonQuote(errMsg) + "}}";
                } else {
                    String resultJson = serializeResult(result);
                    response = "{\"jsonrpc\":\"2.0\",\"id\":" + idStr + ",\"result\":" + resultJson + "}";
                }
                writeJsonResponse(exchange, 200, response);
            } catch (Exception e) {
                String response = "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32700,\"message\":" + jsonQuote(e.getMessage()) + "}}";
                writeJsonResponse(exchange, 400, response);
            }
        }

        private static void writeJsonResponse(HttpExchange exchange, int status, String body) throws IOException {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
            exchange.sendResponseHeaders(status, bytes.length);
            try (var os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }

        private static String readBodyCapped(InputStream in, long maxBytes) throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            long total = 0;
            int n;
            while ((n = in.read(buf)) != -1) {
                total += n;
                if (total > maxBytes) throw new IOException("request body exceeds " + maxBytes + " bytes");
                out.write(buf, 0, n);
            }
            return out.toString(StandardCharsets.UTF_8);
        }
        
        private String parseQueryParam(URI uri, String param) {
            String query = uri.getRawQuery();
            if (query == null) return null;
            for (String pair : query.split("&")) {
                String[] kv = pair.split("=", 2);
                String key;
                try {
                    key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                } catch (Exception e) {
                    key = kv[0];
                }
                if (key.equals(param)) {
                    if (kv.length < 2) return "";
                    try {
                        return URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    } catch (Exception e) {
                        return kv[1];
                    }
                }
            }
            return null;
        }
        
        private String jsonQuote(String s) {
            if (s == null) return "\"\"";
            return "\"" + escapeJson(s) + "\"";
        }
        
        private static String serializeResult(Object result) {
            if (result == null) return "null";
            if (result instanceof String) {
                return "\"" + escapeJson((String) result) + "\"";
            }
            if (result instanceof List) {
                List<?> list = (List<?>) result;
                if (list.isEmpty()) return "[]";
                StringBuilder sb = new StringBuilder("[");
                for (int i = 0; i < list.size(); i++) {
                    sb.append(serializeResult(list.get(i)));
                    if (i < list.size() - 1) sb.append(",");
                }
                sb.append("]");
                return sb.toString();
            }
            if (result instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> map = (Map<String, Object>) result;
                if (map.isEmpty()) return "{}";
                StringBuilder sb = new StringBuilder("{");
                boolean first = true;
                for (Map.Entry<String, Object> e : map.entrySet()) {
                    if (!first) sb.append(",");
                    first = false;
                    sb.append("\"").append(escapeJson(e.getKey())).append("\":");
                    sb.append(serializeResult(e.getValue()));
                }
                sb.append("}");
                return sb.toString();
            }
            return String.valueOf(result);
        }
        
        private static Object handleMcpMethod(String method, Map<String, Object> params) {
            if (method == null) return "ERROR: missing method";
            // Handshake notifications & ping
            if (method.startsWith("notifications/")) return Map.of();
            if (method.equals("ping")) return Map.of();
            return switch (method) {
                case "initialize" -> Map.of(
                    "protocolVersion", "2024-11-05",
                    "capabilities", Map.of("tools", Map.of()),
                    "serverInfo", Map.of("name", "code-mcp", "version", "0.1.0")
                );
                case "tools/list" -> {
                    List<Map<String, Object>> tools = new ArrayList<>();
                    tools.add(makeTool("read", "Read a file. Optional line range [start,end] (1-indexed, inclusive). Pass no_truncate=true to disable output truncation.",
                        List.of(Map.of("name", "cwd", "type", "string"),
                               Map.of("name", "path", "type", "string"),
                               Map.of("name", "range", "type", "array", "items", Map.of("type", "number")),
                               Map.of("name", "no_truncate", "type", "boolean"))));

                    tools.add(makeTool("write", "Write/overwrite a file with the given content.",
                        List.of(Map.of("name", "cwd", "type", "string", "required", true),
                               Map.of("name", "path", "type", "string", "required", true),
                               Map.of("name", "content", "type", "string", "required", true))));
                    tools.add(makeTool("edit", "Replace old_str with new_str in a file. old_str must occur exactly once.",
                        List.of(Map.of("name", "cwd", "type", "string", "required", true),
                               Map.of("name", "path", "type", "string", "required", true),
                               Map.of("name", "old_str", "type", "string", "required", true),
                               Map.of("name", "new_str", "type", "string", "required", true))));
                    tools.add(makeTool("multi_edit", "Apply multiple edits atomically across one or more files.",
                        List.of(Map.of("name", "cwd", "type", "string", "required", true),
                               Map.of("name", "edits", "type", "array", "items", Map.of("type", "object"), "required", true))));

                    tools.add(switch (detectedShell) {
                        case BASH -> makeTool("bash", "Run a bash command. Block until exit, return combined stdout+stderr.",
                            List.of(Map.of("name", "cwd", "type", "string", "required", true),
                                   Map.of("name", "command", "type", "string", "required", true),
                                   Map.of("name", "timeout_ms", "type", "number")));
                        case SH -> makeTool("shell", "Run a POSIX sh command.",
                            List.of(Map.of("name", "cwd", "type", "string", "required", true),
                                   Map.of("name", "command", "type", "string", "required", true),
                                   Map.of("name", "timeout_ms", "type", "number")));
                        case CMD -> makeTool("command", "Run a Windows CMD command.",
                            List.of(Map.of("name", "cwd", "type", "string", "required", true),
                                   Map.of("name", "command", "type", "string", "required", true),
                                   Map.of("name", "timeout_ms", "type", "number")));
                        case POWERSHELL -> makeTool("powershell", "Run a PowerShell command.",
                            List.of(Map.of("name", "cwd", "type", "string", "required", true),
                                   Map.of("name", "command", "type", "string", "required", true),
                                   Map.of("name", "timeout_ms", "type", "number")));
                    });

                    tools.add(makeTool("grep", "Search files by regex.",
                        List.of(Map.of("name", "cwd", "type", "string", "required", true),
                               Map.of("name", "pattern", "type", "string", "required", true),
                               Map.of("name", "path", "type", "string"),
                               Map.of("name", "glob", "type", "string"))));

                    tools.add(makeTool("find", "Find files by glob pattern.",
                        List.of(Map.of("name", "cwd", "type", "string", "required", true),
                               Map.of("name", "pattern", "type", "string", "required", true),
                               Map.of("name", "path", "type", "string"),
                               Map.of("name", "include_hidden", "type", "boolean"))));

                    tools.add(makeTool("ls", "List directory entries with type and size.",
                        List.of(Map.of("name", "cwd", "type", "string", "required", true),
                               Map.of("name", "path", "type", "string"))));

                    tools.add(makeTool("job", "Manage background jobs.",
                        List.of(Map.of("name", "cwd", "type", "string", "required", true),
                               Map.of("name", "mode", "type", "string", "enum", List.of("list", "view", "start", "stop"), "required", true),
                               Map.of("name", "command", "type", "string"),
                               Map.of("name", "timeout_ms", "type", "number"))));

                    
                    tools.add(makeTool("mcp", "Manage MCP servers.",
                        List.of(Map.of("name", "cwd", "type", "string", "required", true),
                               Map.of("name", "action", "type", "string", "enum", List.of("list", "call", "unload"), "required", true),
                               Map.of("name", "server", "type", "string"),
                               Map.of("name", "tool", "type", "string"),
                               Map.of("name", "args", "type", "object"),
                               Map.of("name", "mcpConfigPath", "type", "string"))));
                    
                    if (hasCloudflared) {
                        tools.add(makeTool("preview", "Start a Cloudflare quick tunnel.",
                            List.of(Map.of("name", "url", "type", "string", "required", true))));

                    }
                    
                    if (memoryEnabled) {
                        tools.add(makeTool("remember", "Append a memo.",
                            List.of(Map.of("name", "cwd", "type", "string", "required", true),
                                   Map.of("name", "memo", "type", "string", "required", true),
                                   Map.of("name", "tags", "type", "array", "items", Map.of("type", "string")))));

                        tools.add(makeTool("forget", "Remove a memo by id.",
                            List.of(Map.of("name", "cwd", "type", "string", "required", true),
                                   Map.of("name", "memo_id", "type", "number", "required", true))));

                        tools.add(makeTool("recall", "Search memos.",
                            List.of(Map.of("name", "cwd", "type", "string", "required", true),
                                   Map.of("name", "query", "type", "string"),
                                   Map.of("name", "tags", "type", "array"),
                                   Map.of("name", "limit", "type", "number"),
                                   Map.of("name", "offset", "type", "number"))));

                    }
                    
                    if (publicBaseUrl != null && token != null) {
                        tools.add(makeTool("get_upload_link", "Return an upload link.",
                            List.of()));
                    }

                    // Strip any tool that was disabled via --disallowed-tools.
                    if (!disallowedTools.isEmpty()) {
                        tools.removeIf(t -> disallowedTools.contains((String) t.get("name")));
                    }

                    yield Map.of("tools", tools);
                }
                case "tools/call" -> {
                    String name = params != null ? (String) params.get("name") : null;
                    @SuppressWarnings("unchecked")
                    Map<String, Object> args = params != null ? (Map<String, Object>) params.get("arguments") : Map.of();
                    
                    if (name == null) {
                        yield "ERROR: tool name required";
                    }
                    if (disallowedTools.contains(name)) {
                        yield Map.of("content", List.of(Map.of("type", "text",
                            "text", "ERROR: tool '" + name + "' disabled")));
                    }
                    // Only allow the shell tool matching the detected shell.
                    if ((name.equals("bash") && detectedShell != ShellType.BASH)
                            || (name.equals("shell") && detectedShell != ShellType.SH)
                            || (name.equals("command") && detectedShell != ShellType.CMD)
                            || (name.equals("powershell") && detectedShell != ShellType.POWERSHELL)) {
                        yield Map.of("content", List.of(Map.of("type", "text",
                            "text", "ERROR: tool '" + name + "' not available on this shell (" + detectedShell + ")")));
                    }

                    String result;
                    try {
                        result = switch (name) {
                            case "read" -> handleRead(
                                (String) args.get("cwd"),
                                (String) args.get("path"),
                                parseRange(args.get("range")),
                                Boolean.TRUE.equals(args.get("no_truncate")));
                            case "write" -> handleWrite(
                                (String) args.get("cwd"),
                                (String) args.get("path"),
                                (String) args.get("content"));
                            case "edit" -> handleEdit(
                                (String) args.get("cwd"),
                                (String) args.get("path"),
                                (String) args.get("old_str"),
                                (String) args.get("new_str"));
                            case "multi_edit" -> {
                                @SuppressWarnings("unchecked")
                                List<Map<String, String>> editsRaw = (List<Map<String, String>>) args.get("edits");
                                List<Edit> edits = editsRaw.stream()
                                    .map(e -> new Edit(e.get("path"), e.get("old_str"), e.get("new_str")))
                                    .collect(Collectors.toList());
                                yield handleMultiEdit((String) args.get("cwd"), edits);
                            }
                            case "bash" -> handleBash(
                                (String) args.get("cwd"),
                                (String) args.get("command"),
                                parseNumber(args.get("timeout_ms")));
                            case "shell" -> handleShell(
                                (String) args.get("cwd"),
                                (String) args.get("command"),
                                parseNumber(args.get("timeout_ms")));
                            case "command" -> handleCommand(
                                (String) args.get("cwd"),
                                (String) args.get("command"),
                                parseNumber(args.get("timeout_ms")));
                            case "powershell" -> handlePowershell(
                                (String) args.get("cwd"),
                                (String) args.get("command"),
                                parseNumber(args.get("timeout_ms")));
                            case "grep" -> handleGrep(
                                (String) args.get("cwd"),
                                (String) args.get("pattern"),
                                (String) args.get("path"),
                                (String) args.get("glob"));
                            case "find" -> handleFind(
                                (String) args.get("cwd"),
                                (String) args.get("pattern"),
                                (String) args.get("path"),
                                Boolean.TRUE.equals(args.get("include_hidden")));
                            case "ls" -> handleLs(
                                (String) args.get("cwd"),
                                (String) args.get("path"));
                            case "job" -> handleJob(
                                (String) args.get("cwd"),
                                (String) args.get("mode"),
                                (String) args.get("command"),
                                parseNumber(args.get("timeout_ms")));
                            case "preview" -> handlePreview((String) args.get("url"));
                            case "remember" -> {
                                @SuppressWarnings("unchecked")
                                List<String> tags = (List<String>) args.get("tags");
                                yield handleRemember((String) args.get("cwd"), (String) args.get("memo"), tags);
                            }
                            case "forget" -> handleForget(
                                (String) args.get("cwd"),
                                ((Number) args.get("memo_id")).intValue());
                            case "recall" -> {
                                @SuppressWarnings("unchecked")
                                List<String> tags = (List<String>) (Object) args.get("tags");
                                yield handleRecall(
                                    (String) args.get("cwd"),
                                    (String) args.get("query"),
                                    tags,
                                    args.containsKey("limit") ? ((Number) args.get("limit")).intValue() : 20,
                                    args.containsKey("offset") ? ((Number) args.get("offset")).intValue() : 0);
                            }
                            case "mcp" -> handleMcp(
                                (String) args.get("cwd"),
                                (String) args.get("action"),
                                (String) args.get("server"),
                                (String) args.get("tool"),
                                args.get("args") != null ? (Map<String, Object>) args.get("args") : Map.of(),
                                (String) args.get("mcpConfigPath"));
                            case "get_upload_link" -> handleGetUploadLink();
                            default -> "ERROR: unknown tool: " + name;
                        };
                    } catch (RuntimeException e) {
                        result = "ERROR: " + e.getMessage();
                    } catch (Exception e) {
                        result = "ERROR: " + e.getMessage();
                    }
                    
                    yield Map.of("content", List.of(Map.of("type", "text", "text", result)));
                }
                default -> "ERROR:-32601: unknown method: " + method;
            };
        }
        
        private static Map<String, Object> makeTool(String name, String desc, List<Map<String, Object>> props) {
            return Map.of(
                "name", name,
                "description", desc,
                "inputSchema", Map.of("type", "object", "properties", 
                    props.stream().collect(Collectors.toMap(
                        p -> (String) p.get("name"),
                        p -> {
                            Map<String, Object> prop = new LinkedHashMap<>(p);
                            prop.remove("name");
                            return prop;
                        }
                    ))
                )
            );
        }
        
        private static int[] parseRange(Object range) {
            if (range == null) return null;
            if (!(range instanceof List)) {
                throw new RuntimeException("range must be [start, end]");
            }
            List<?> r = (List<?>) range;
            if (r.size() != 2) {
                throw new RuntimeException("range must have exactly 2 elements, got " + r.size());
            }
            Object a = r.get(0), b = r.get(1);
            if (!(a instanceof Number) || !(b instanceof Number)) {
                throw new RuntimeException("range must be [start, end] integers");
            }
            return new int[]{((Number) a).intValue(), ((Number) b).intValue()};
        }
        
        private static Long parseNumber(Object n) {
            if (n == null) return null;
            if (n instanceof Number) return ((Number) n).longValue();
            try {
                return Long.parseLong(String.valueOf(n));
            } catch (NumberFormatException e) {
                return null;
            }
        }
    }
    
    // ===== UPLOAD HTTP ROUTE HANDLER =====
    private static class UploadRouteHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String path = exchange.getRequestURI().getPath();
            if (!path.startsWith("/upload/")) {
                exchange.sendResponseHeaders(404, 0);
                exchange.close();
                return;
            }
            
            String sessionId = path.substring("/upload/".length());
            
            Headers headers = exchange.getResponseHeaders();
            headers.add("Access-Control-Allow-Origin", "*");
            headers.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            headers.add("Access-Control-Allow-Headers", "Content-Type");
            
            if (exchange.getRequestMethod().equals("OPTIONS")) {
                exchange.sendResponseHeaders(204, -1);
                exchange.close();
                return;
            }
            
            VerificationResult check = verifyUploadSessionId(sessionId);
            if (!check.ok()) {
                String response = "{\"error\":" + jsonQuote(check.reason()) + "}";
                byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
                headers.add("Content-Type", "application/json; charset=utf-8");
                exchange.sendResponseHeaders(401, bytes.length);
                try (var os = exchange.getResponseBody()) { os.write(bytes); }
                return;
            }
            
            if (exchange.getRequestMethod().equals("GET")) {
                String html = getUploadPageHtml(sessionId);
                headers.add("Content-Type", "text/html; charset=utf-8");
                byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.close();
                return;
            }
            
            if (exchange.getRequestMethod().equals("POST")) {
                handleUpload(exchange, sessionId);
                return;
            }
            
            exchange.sendResponseHeaders(405, 0);
            exchange.close();
        }
        
        private String jsonQuote(String s) {
            if (s == null) return "\"\"";
            return "\"" + escapeJson(s) + "\"";
        }
        
        private void handleUpload(HttpExchange exchange, String sessionId) throws IOException {
            Headers respHdr = exchange.getResponseHeaders();
            respHdr.add("Content-Type", "application/json; charset=utf-8");

            try {
                String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
                if (contentType == null || !contentType.contains("multipart/form-data")) {
                    writeJson(exchange, 400, "{\"error\":\"expected multipart/form-data\"}");
                    return;
                }
                long contentLen = -1;
                String clHdr = exchange.getRequestHeaders().getFirst("Content-Length");
                if (clHdr != null) {
                    try { contentLen = Long.parseLong(clHdr); } catch (NumberFormatException ignored) {}
                }
                if (contentLen > MAX_UPLOAD_BYTES) {
                    writeJson(exchange, 413, "{\"error\":\"upload exceeds " + MAX_UPLOAD_BYTES + " bytes\"}");
                    return;
                }

                // Read body with hard byte cap.
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buf = new byte[64 * 1024];
                long total = 0;
                try (InputStream in = exchange.getRequestBody()) {
                    int n;
                    while ((n = in.read(buf)) != -1) {
                        total += n;
                        if (total > MAX_UPLOAD_BYTES) {
                            writeJson(exchange, 413, "{\"error\":\"upload exceeds " + MAX_UPLOAD_BYTES + " bytes\"}");
                            return;
                        }
                        baos.write(buf, 0, n);
                    }
                }
                byte[] body = baos.toByteArray();

                Matcher m = Pattern.compile("boundary=\"?([^\";]+)\"?").matcher(contentType);
                if (!m.find()) {
                    writeJson(exchange, 400, "{\"error\":\"no boundary\"}");
                    return;
                }
                byte[] boundary = ("--" + m.group(1)).getBytes(StandardCharsets.US_ASCII);

                List<int[]> parts = splitMultipart(body, boundary);
                String fileName = null;
                byte[] fileContent = null;
                for (int[] range : parts) {
                    int hdrEnd = findBytes(body, range[0], range[1], new byte[]{'\r','\n','\r','\n'});
                    if (hdrEnd < 0) continue;
                    String partHeaders = new String(body, range[0], hdrEnd - range[0], StandardCharsets.ISO_8859_1);
                    Matcher fn = Pattern.compile("filename=\"([^\"]+)\"").matcher(partHeaders);
                    if (!fn.find()) continue;
                    fileName = fn.group(1);
                    int contentStart = hdrEnd + 4;
                    int contentEnd = range[1];
                    // Strip trailing CRLF before boundary delimiter.
                    if (contentEnd - 2 >= contentStart && body[contentEnd - 2] == '\r' && body[contentEnd - 1] == '\n') {
                        contentEnd -= 2;
                    }
                    fileContent = Arrays.copyOfRange(body, contentStart, contentEnd);
                    break;
                }

                if (fileName == null || fileContent == null) {
                    writeJson(exchange, 400, "{\"error\":\"no file provided\"}");
                    return;
                }

                // Strip path components fully before sanitising — defends against `..` and `/`.
                fileName = fileName.replace("\\", "/");
                int slash = fileName.lastIndexOf('/');
                if (slash >= 0) fileName = fileName.substring(slash + 1);
                fileName = fileName.replaceAll("[^A-Za-z0-9._-]", "_");
                if (fileName.isEmpty() || fileName.equals(".") || fileName.equals("..")) {
                    fileName = "upload-" + System.currentTimeMillis();
                }

                Path uploadDir = Path.of(uploadRoot, sessionId);
                Files.createDirectories(uploadDir);
                Path filePath = uploadDir.resolve(fileName);
                Files.write(filePath, fileContent,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(fileContent);
                StringBuilder hashHex = new StringBuilder();
                for (byte b : hash) hashHex.append(String.format("%02x", b));

                String mime = Files.probeContentType(filePath);
                if (mime == null) mime = "application/octet-stream";

                String response = String.format(
                    "{\"path\":%s,\"size\":%d,\"sha256\":%s,\"mime\":%s}",
                    jsonQuote(filePath.toString()),
                    fileContent.length,
                    jsonQuote(hashHex.toString()),
                    jsonQuote(mime));
                writeJson(exchange, 200, response);
            } catch (Exception e) {
                writeJson(exchange, 500, "{\"error\":" + jsonQuote(e.getMessage()) + "}");
            }
        }

        private static void writeJson(HttpExchange exchange, int status, String body) throws IOException {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length);
            try (var os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }

        private static List<int[]> splitMultipart(byte[] body, byte[] boundary) {
            // Return list of [start, end) ranges per part, excluding leading boundary line and trailing CRLF.
            List<int[]> ranges = new ArrayList<>();
            int idx = 0;
            int n = body.length;
            int bLen = boundary.length;
            while (idx < n) {
                int b = findBytes(body, idx, n, boundary);
                if (b < 0) break;
                int partStart = b + bLen;
                // Skip CRLF after boundary
                if (partStart + 1 < n && body[partStart] == '\r' && body[partStart + 1] == '\n') partStart += 2;
                // Check for final boundary marker "--"
                if (partStart + 1 < n && body[partStart] == '-' && body[partStart + 1] == '-') break;
                int next = findBytes(body, partStart, n, boundary);
                if (next < 0) break;
                // Trim the "\r\n" before the next boundary marker.
                int partEnd = next;
                if (partEnd - 2 >= partStart && body[partEnd - 2] == '\r' && body[partEnd - 1] == '\n') {
                    partEnd -= 2;
                }
                ranges.add(new int[]{partStart, partEnd});
                idx = next;
            }
            return ranges;
        }

        private static int findBytes(byte[] haystack, int from, int to, byte[] needle) {
            outer:
            for (int i = from; i <= to - needle.length; i++) {
                for (int j = 0; j < needle.length; j++) {
                    if (haystack[i + j] != needle[j]) continue outer;
                }
                return i;
            }
            return -1;
        }
        
        private String getUploadPageHtml(String sessionId) {
            String baseUrl = publicBaseUrl != null ? publicBaseUrl : "http://localhost:" + port;
            return """
                <!DOCTYPE html>
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
                  .container { width: 100%; max-width: 560px; }
                  .dropzone {
                    display: block;
                    background: transparent;
                    border: 0.5px dashed var(--border-secondary);
                    border-radius: var(--radius-lg);
                    padding: 2rem 1.25rem;
                    text-align: center;
                    cursor: pointer;
                    transition: background 120ms ease, border-color 120ms ease;
                  }
                  .dropzone:hover { background: var(--bg-info); border-color: var(--border-info); }
                  .dropzone.hover { background: var(--bg-info); border-color: var(--border-info); }
                  .dropzone .icon { display: flex; justify-content: center; margin-bottom: 12px; color: var(--text-secondary); }
                  .dropzone .title { margin: 0; font-size: 14px; color: var(--text-primary); }
                  .dropzone .browse { color: var(--text-info); text-decoration: underline; }
                  .file-list { margin-top: 0.75rem; display: none; flex-direction: column; gap: 6px; }
                  .file-row {
                    display: flex; align-items: center; justify-content: space-between; gap: 12px;
                    padding: 8px 12px; background: var(--surface); border: 0.5px solid var(--border-tertiary); border-radius: var(--radius-md);
                  }
                  .file-row .info { display: flex; align-items: baseline; gap: 8px; min-width: 0; flex: 1; }
                  .file-row .name { font-size: 13px; color: var(--text-primary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
                  .file-row .size { font-size: 12px; color: var(--text-tertiary); flex-shrink: 0; }
                  .file-row button {
                    flex-shrink: 0; width: 24px; height: 24px; padding: 0; display: inline-flex; align-items: center; justify-content: center;
                    color: var(--text-tertiary); background: transparent; border: none; cursor: pointer; border-radius: 4px;
                  }
                  .file-row button:hover { background: var(--bg-tertiary); color: var(--text-primary); }
                  .progress-wrap { margin-top: 0.75rem; display: none; }
                  .progress-track { background: var(--bg-tertiary); border-radius: 999px; height: 4px; overflow: hidden; }
                  .progress-bar { height: 100%; width: 0%; background: var(--text-info); transition: width 120ms ease; }
                  .actions { margin-top: 1rem; display: flex; gap: 0.5rem; }
                  .btn {
                    flex: 1; padding: 0.625rem 1rem; font-size: 14px; font-weight: 500; border-radius: var(--radius-md); cursor: pointer; transition: opacity 120ms ease;
                  }
                  .btn-secondary { background: var(--bg-tertiary); border: none; color: var(--text-primary); }
                  .btn-primary { background: var(--text-info); border: none; color: white; }
                  .btn:disabled { opacity: 0.5; cursor: not-allowed; }
                  .result { margin-top: 1rem; display: none; }
                  .result-item {
                    display: flex; align-items: center; justify-content: space-between; gap: 8px;
                    padding: 10px 14px; background: var(--surface); border: 0.5px solid var(--border-tertiary); border-radius: var(--radius-md); margin-bottom: 6px;
                  }
                  .result-item .path { font-size: 13px; color: var(--text-primary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
                  .result-item .copy { font-size: 12px; color: var(--text-info); cursor: pointer; }
                  input[type="file"] { display: none; }
                </style>
                </head>
                <body>
                <div class="container">
                  <div class="dropzone" id="dropzone">
                    <div class="icon">
                      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
                      </svg>
                    </div>
                    <p class="title">Drop files here, or <span class="browse">browse</span></p>
                  </div>
                  <input type="file" id="fileInput" multiple>
                  <div class="file-list" id="fileList"></div>
                  <div class="progress-wrap" id="progressWrap">
                    <div class="progress-track"><div class="progress-bar" id="progressBar"></div></div>
                  </div>
                  <div class="actions" id="actions" style="display:none;">
                    <button class="btn btn-secondary" id="cancelBtn">Cancel</button>
                    <button class="btn btn-primary" id="uploadBtn">Upload</button>
                  </div>
                  <div class="result" id="result"></div>
                </div>
                <script>
                  const dropzone = document.getElementById('dropzone');
                  const fileInput = document.getElementById('fileInput');
                  const fileList = document.getElementById('fileList');
                  const progressWrap = document.getElementById('progressWrap');
                  const progressBar = document.getElementById('progressBar');
                  const actions = document.getElementById('actions');
                  const cancelBtn = document.getElementById('cancelBtn');
                  const uploadBtn = document.getElementById('uploadBtn');
                  const result = document.getElementById('result');
                  let files = [];
                  let uploading = false;
                  let currentXhr = null;
                  dropzone.onclick = () => !uploading && fileInput.click();
                  dropzone.ondragover = (e) => { e.preventDefault(); dropzone.classList.add('hover'); };
                  dropzone.ondragleave = () => dropzone.classList.remove('hover');
                  dropzone.ondrop = (e) => { e.preventDefault(); dropzone.classList.remove('hover'); addFiles(e.dataTransfer.files); };
                  fileInput.onchange = () => { addFiles(fileInput.files); fileInput.value = ''; };
                  function addFiles(newFiles) {
                    files = Array.from(newFiles);
                    if (files.length === 0) return;
                    fileList.style.display = 'flex';
                    fileList.innerHTML = files.map((f, i) => `
                      <div class="file-row">
                        <div class="info"><span class="name">${f.name}</span><span class="size">${formatSize(f.size)}</span></div>
                        <button onclick="removeFile(${i})" ${uploading ? 'disabled' : ''}>✕</button>
                      </div>
                    `).join('');
                    actions.style.display = 'flex';
                    result.style.display = 'none';
                  }
                  function removeFile(i) { files.splice(i, 1); if (files.length === 0) { fileList.style.display = 'none'; actions.style.display = 'none'; } else renderFiles(); }
                  function renderFiles() { fileList.innerHTML = files.map((f, i) => `<div class="file-row"><div class="info"><span class="name">${f.name}</span><span class="size">${formatSize(f.size)}</span></div><button onclick="removeFile(${i})" ${uploading ? 'disabled' : ''}>✕</button></div>`).join(''); }
                  function formatSize(bytes) { if (bytes < 1024) return bytes + ' B'; if (bytes < 1048576) return (bytes/1024).toFixed(1) + ' KB'; return (bytes/1048576).toFixed(1) + ' MB'; }
                  cancelBtn.onclick = () => { if (currentXhr) currentXhr.abort(); uploading = false; actions.style.display = 'flex'; progressWrap.style.display = 'none'; };
                  uploadBtn.onclick = runUpload;
                  async function runUpload() {
                    if (files.length === 0 || uploading) return;
                    uploading = true; actions.style.display = 'none'; progressWrap.style.display = 'block'; progressBar.style.width = '0%'; result.style.display = 'none';
                    const results = [];
                    for (let i = 0; i < files.length; i++) {
                      const f = files[i];
                      try {
                        const formData = new FormData();
                        formData.append('file', f);
                        const response = await new Promise((resolve, reject) => {
                          const xhr = new XMLHttpRequest();
                          currentXhr = xhr;
                          xhr.upload.onprogress = (e) => { if (e.lengthComputable) progressBar.style.width = ((e.loaded / e.total) * 100).toFixed(0) + '%'; };
                          xhr.onload = () => resolve(xhr);
                          xhr.onerror = () => reject(new Error('Upload failed'));
                          xhr.onabort = () => reject(new Error('Cancelled'));
                          xhr.open('POST', '/upload/' + sessionId + ');
                          xhr.send(formData);
                        });
                        const data = JSON.parse(response.responseText);
                        if (data.error) throw new Error(data.error);
                        results.push(data);
                      } catch (e) {
                        results.push({ error: e.message, name: f.name });
                      }
                    }
                    uploading = false; currentXhr = null;
                    progressWrap.style.display = 'none';
                    result.style.display = 'block';
                    result.innerHTML = results.map(r => {
                      if (r.error) return `<div class="result-item"><span class="name">${r.name}: ${r.error}</span><span style="color:#a32d2d">Failed</span></div>`;
                      return `<div class="result-item"><span class="name">${r.path}</span><span class="copy" onclick="navigator.clipboard.writeText('${r.path.replace(/'/g, "\\'")}')">Copy</span></div>`;
                    }).join('');
                    fileList.style.display = 'none';
                    actions.style.display = 'none';
                    files = [];
                  }
                </script>
                </body>
                </html>
                """;
        }
    }

    private static final String WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    private static final SecureRandom WS_RNG = new SecureRandom();

    // Shared HTTP client + dispatch pool for gateway tunnel — reused across all messages.
    private static final HttpClient GATEWAY_HTTP = HttpClient.newBuilder()
            .connectTimeout(java.time.Duration.ofSeconds(10))
            .build();
    // Bounded queue + caller-runs policy so a slow handler can't OOM the server
    // by accumulating thousands of pending tunnel messages.
    private static final ExecutorService GATEWAY_DISPATCH = new ThreadPoolExecutor(
        4, 16, 60L, TimeUnit.SECONDS,
        new LinkedBlockingQueue<>(64),
        r -> {
            Thread t = new Thread(r, "gw-dispatch-" + System.nanoTime());
            t.setDaemon(true);
            return t;
        },
        new ThreadPoolExecutor.CallerRunsPolicy());

    // ===== GATEWAY CLIENT =====
    private static void startGatewayClient(String domain, String deviceIdParam) {
        final String deviceId = deviceIdParam != null ? deviceIdParam : UUID.randomUUID().toString();

        Thread t = new Thread(() -> {
            int retries = 0;
            System.err.println("[gateway] starting client for: " + domain + " (deviceId=" + deviceId + ")");
            while (!shuttingDown) {
                Socket sock = null;
                try {
                    boolean isLocal = domain.startsWith("localhost") || domain.startsWith("127.") ||
                            domain.startsWith("192.168.") || domain.startsWith("10.") ||
                            domain.startsWith("172.16.") || domain.startsWith("ws://") || domain.startsWith("http://");
                    String scheme = isLocal ? "ws" : "wss";
                    String baseUrl = domain.startsWith("wss://") || domain.startsWith("https://")
                            ? domain.replace("https://", "wss://")
                            : scheme + "://" + domain;
                    String url = deviceIdParam != null
                            ? baseUrl + "/ws/" + deviceIdParam
                            : baseUrl + "/ws";
                    URI uri = URI.create(url);
                    String host = uri.getHost();
                    int gatewayPort = uri.getPort() > 0 ? uri.getPort() : (isLocal ? 80 : 443);
                    String wsPath = uri.getPath();

                    if (isLocal) {
                        sock = new Socket(host, gatewayPort);
                    } else {
                        SSLSocketFactory sf = SSLContext.getDefault().getSocketFactory();
                        SSLSocket ssl = (SSLSocket) sf.createSocket(host, gatewayPort);
                        ssl.startHandshake();
                        sock = ssl;
                    }
                    sock.setSoTimeout(60_000);

                    DataOutputStream out = new DataOutputStream(sock.getOutputStream());
                    InputStream in = sock.getInputStream();

                    byte[] keyBytes = new byte[16];
                    WS_RNG.nextBytes(keyBytes);
                    String wsKey = Base64.getEncoder().encodeToString(keyBytes);
                    String hostHeader = (gatewayPort == 80 || gatewayPort == 443) ? host : host + ":" + gatewayPort;
                    String request = "GET " + wsPath + " HTTP/1.1\r\n" +
                            "Host: " + hostHeader + "\r\n" +
                            "Upgrade: websocket\r\nConnection: Upgrade\r\n" +
                            "Sec-WebSocket-Key: " + wsKey + "\r\nSec-WebSocket-Version: 13\r\n" +
                            "User-Agent: code-mcp/0.1.0\r\n\r\n";
                    out.write(request.getBytes(StandardCharsets.US_ASCII));
                    out.flush();

                    // Read response headers (byte-level until \r\n\r\n) with cap.
                    ByteArrayOutputStream hdr = new ByteArrayOutputStream();
                    int b;
                    while ((b = in.read()) != -1) {
                        hdr.write(b);
                        if (hdr.size() > MAX_GATEWAY_HEADER_BYTES) {
                            throw new IOException("gateway handshake too large");
                        }
                        byte[] cur = hdr.toByteArray();
                        if (cur.length >= 4 && cur[cur.length - 4] == '\r' && cur[cur.length - 3] == '\n'
                                && cur[cur.length - 2] == '\r' && cur[cur.length - 1] == '\n') {
                            break;
                        }
                    }
                    String headersText = hdr.toString(StandardCharsets.ISO_8859_1);
                    String[] hdrLines = headersText.split("\r\n");
                    if (hdrLines.length == 0 || !hdrLines[0].contains(" 101 ")) {
                        throw new IOException("WebSocket upgrade failed: " + (hdrLines.length > 0 ? hdrLines[0] : "<empty>"));
                    }
                    String accept = null;
                    for (int i = 1; i < hdrLines.length; i++) {
                        int idx = hdrLines[i].indexOf(':');
                        if (idx > 0) {
                            String k = hdrLines[i].substring(0, idx).trim();
                            String v = hdrLines[i].substring(idx + 1).trim();
                            if (k.equalsIgnoreCase("Sec-WebSocket-Accept")) { accept = v; break; }
                        }
                    }
                    String expected = Base64.getEncoder().encodeToString(
                            MessageDigest.getInstance("SHA-1").digest((wsKey + WS_MAGIC).getBytes(StandardCharsets.US_ASCII)));
                    if (accept == null || !MessageDigest.isEqual(
                            accept.getBytes(StandardCharsets.US_ASCII),
                            expected.getBytes(StandardCharsets.US_ASCII))) {
                        throw new IOException("Sec-WebSocket-Accept mismatch");
                    }

                    retries = 0;
                    System.err.println("[gateway] connected, registering as " + deviceId);
                    String register = "{\"type\":\"register\",\"deviceId\":\"" + deviceId + "\"}";
                    sendFrame(out, register.getBytes(StandardCharsets.UTF_8), (byte) 0x81);

                    webSocketReadLoop(in, out, sock);
                } catch (Exception e) {
                    System.err.println("[gateway] error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
                } finally {
                    if (sock != null) try { sock.close(); } catch (IOException ignored) {}
                }
                if (++retries > MAX_RETRIES) {
                    // Backoff hard but keep HTTP server alive (do NOT System.exit).
                    System.err.println("[gateway] max retries reached; backing off 60s");
                    try { Thread.sleep(60_000); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); return; }
                    retries = 0;
                    continue;
                }
                try { Thread.sleep(RECONNECT_DELAY_MS); } catch (InterruptedException ignored) { return; }
            }
        }, "gw-client");
        t.setDaemon(true);
        t.start();
    }

    private static void handleGatewayMessage(DataOutputStream out, String data) {
        // Submit to dispatch pool so a slow tool call doesn't block the WebSocket read loop.
        GATEWAY_DISPATCH.submit(() -> {
            try {
                Map<String, Object> json = parseJsonObject(data);
                String id = String.valueOf(json.get("id"));
                @SuppressWarnings("unchecked")
                Map<String, Object> req = (Map<String, Object>) json.get("request");
                String tok = json.containsKey("token") ? String.valueOf(json.get("token")) : null;

                String tokenParam = (tok != null && !tok.isBlank()) ? "?token=" + tok : "";
                String localUrl = "http://127.0.0.1:" + port + "/mcp" + tokenParam;

                HttpRequest httpReq = HttpRequest.newBuilder()
                        .uri(URI.create(localUrl))
                        .header("Content-Type", "application/json")
                        .timeout(java.time.Duration.ofSeconds(60))
                        .POST(HttpRequest.BodyPublishers.ofString(MCPRouteHandler.serializeResult(req), StandardCharsets.UTF_8))
                        .build();

                Map<String, Object> mcpRes;
                try {
                    HttpResponse<String> httpRes = GATEWAY_HTTP.send(httpReq, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                    mcpRes = parseJsonObject(httpRes.body());
                } catch (Exception e) {
                    Map<String, Object> err = new LinkedHashMap<>();
                    err.put("jsonrpc", "2.0");
                    err.put("id", req.get("id"));
                    err.put("error", Map.of("code", -32603, "message", e.getMessage()));
                    mcpRes = err;
                }

                Map<String, Object> tunnelRes = new LinkedHashMap<>();
                tunnelRes.put("id", id);
                tunnelRes.put("response", mcpRes);

                sendFrame(out, MCPRouteHandler.serializeResult(tunnelRes).getBytes(StandardCharsets.UTF_8), (byte) 0x81);
            } catch (Exception e) {
                System.err.println("[gateway] dispatch error: " + e.getMessage());
            }
        });
    }

    private static void webSocketReadLoop(InputStream in, DataOutputStream out, Socket sock) throws IOException {
        ByteArrayOutputStream messageBuf = new ByteArrayOutputStream();
        while (true) {
            int b0;
            try {
                b0 = in.read();
            } catch (SocketTimeoutException e) {
                continue;
            }
            if (b0 == -1) break;
            boolean fin = (b0 & 0x80) != 0;
            int opcode = b0 & 0x0F;

            int b1 = in.read();
            if (b1 == -1) break;
            boolean masked = (b1 & 0x80) != 0;
            long len = b1 & 0x7F;
            if (len == 126) {
                int h = in.read();
                int l = in.read();
                if (h == -1 || l == -1) break;
                len = ((h & 0xFFL) << 8) | (l & 0xFFL);
            } else if (len == 127) {
                len = 0;
                for (int j = 0; j < 8; j++) {
                    int x = in.read();
                    if (x == -1) return;
                    len = (len << 8) | (x & 0xFFL);
                }
            }
            if (len < 0 || len > MAX_WS_FRAME_BYTES) {
                throw new IOException("ws frame too large: " + len);
            }
            byte[] mask = new byte[4];
            if (masked) {
                if (readFully(in, mask, 0, 4) != 4) break;
            }
            byte[] payload = new byte[(int) len];
            if (len > 0) {
                int got = readFully(in, payload, 0, (int) len);
                if (got != (int) len) break;
            }
            if (masked) {
                for (int j = 0; j < payload.length; j++) {
                    payload[j] = (byte) (payload[j] ^ mask[j & 3]);
                }
            }

            switch (opcode) {
                case 0x8: // close
                    try { sendFrame(out, payload.length > 0 ? Arrays.copyOf(payload, Math.min(payload.length, 125)) : new byte[0], (byte) 0x88); } catch (IOException ignored) {}
                    return;
                case 0x9: // ping → pong
                    try { sendFrame(out, payload, (byte) 0x8A); } catch (IOException ignored) {}
                    continue;
                case 0xA: // pong
                    continue;
                case 0x0: case 0x1: case 0x2:
                    messageBuf.write(payload);
                    if (fin) {
                        String msg = messageBuf.toString(StandardCharsets.UTF_8);
                        messageBuf.reset();
                        if (msg.contains("\"request\"")) {
                            handleGatewayMessage(out, msg);
                        }
                    }
                    break;
                default:
                    throw new IOException("ws: unknown opcode " + opcode);
            }
        }
    }

    private static int readFully(InputStream in, byte[] buf, int off, int len) throws IOException {
        int total = 0;
        while (total < len) {
            int n;
            try {
                n = in.read(buf, off + total, len - total);
            } catch (SocketTimeoutException e) {
                continue;
            }
            if (n == -1) break;
            total += n;
        }
        return total;
    }

    private static void sendFrame(DataOutputStream out, byte[] data, byte opcodeByte) throws IOException {
        // opcodeByte already encodes FIN + opcode (eg. 0x81 = FIN | text).
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(opcodeByte & 0xFF);
        if (data.length < 126) {
            baos.write(data.length | 0x80);
        } else if (data.length < 65536) {
            baos.write(126 | 0x80);
            baos.write((data.length >> 8) & 0xFF);
            baos.write(data.length & 0xFF);
        } else {
            baos.write(127 | 0x80);
            long n = data.length;
            for (int i = 7; i >= 0; i--) baos.write((int) ((n >> (i * 8)) & 0xFF));
        }
        byte[] mask = new byte[4];
        WS_RNG.nextBytes(mask);
        baos.write(mask[0] & 0xFF);
        baos.write(mask[1] & 0xFF);
        baos.write(mask[2] & 0xFF);
        baos.write(mask[3] & 0xFF);
        for (int i = 0; i < data.length; i++) {
            baos.write(data[i] ^ mask[i & 3]);
        }
        synchronized (out) {
            out.write(baos.toByteArray());
            out.flush();
        }
    }
}
