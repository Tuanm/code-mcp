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
    
    // ===== STATIC STATE =====
    private static final Map<String, Job> jobs = new ConcurrentHashMap<>();
    private static final AtomicInteger jobSeq = new AtomicInteger(0);
    private static final Semaphore shellSemaphore = new Semaphore(MAX_SHELL_SEMAPHORE_PERMITS, true);
    private static volatile boolean shuttingDown = false;
    
    // ===== CONFIGURATION =====
    private static int port = DEFAULT_PORT;
    private static String token = null;
    private static boolean memoryEnabled = false;
    private static boolean makePublic = false;
    private static String domain = null;
    private static String mcpConfigPath = null;
    private static String publicBaseUrl = null;
    private static String gatewayDomain = null;
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
        
        // Create HTTP server
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        
        // Routes
        server.createContext("/mcp", new MCPRouteHandler());
        server.createContext("/upload/", new UploadRouteHandler());
        
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        
        System.err.println("code-mcp listening on http://localhost:" + port + "/mcp" +
            (token != null ? " (auth: ?token=...)" : " (no auth)"));
        
        // Handle shutdown
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            shuttingDown = true;
            server.stop(5);
        }));

        // Start gateway client if --gateway is set
        if (gatewayDomain != null) {
            try {
                startGatewayClient(gatewayDomain);
            } catch (Exception e) {
                System.err.println("[gateway] failed to start: " + e.getMessage());
            }
        }
    }
    
    // ===== ARGUMENT PARSING =====
    private static void parseArgs(String[] args) {
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--port" -> {
                    if (++i >= args.length) usage();
                    port = Integer.parseInt(args[i]);
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
    }
    
    private static void usage() {
        System.err.println(USAGE);
        System.exit(2);
    }
    
    private static final String USAGE = """
        Usage: java CodeMCP.java [options]
        
        Options:
          --port <n>             Listen port (default: 7777, or $PORT)
          --token <s>            Require ?token=<s> on every request (default: no auth)
          --enable-memory        Enable remember/forget/recall tools ($PWD/.memo.jsonl)
          --public               Expose via a Cloudflare quick tunnel (requires cloudflared)
          --domain <host>        Use the given public hostname (tunnel must already route it here)
          --mcp <path>           Aggregate tools from external MCP servers defined in JSON config
          --gateway <domain>     Connect to a gateway server and tunnel requests (wss://{domain}/ws)
          -h, --help            Show this help and exit
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
        return cmd.replace("%", "^%")
                  .replace("&", "^&")
                  .replace("|", "^|")
                  .replace("<", "^<")
                  .replace(">", "^>")
                  .replace("^", "^^")
                  .replace("\"", "\\\"");
    }
    
    // Escape string for PowerShell -Command
    private static String escapePowerShell(String cmd) {
        if (cmd == null) return "";
        return "'" + cmd.replace("'", "''") + "'";
    }
    
    // ===== SHELL DETECTION =====
    private static ShellType detectShell() {
        if (isWindows) {
            if (System.getenv("PSModulePath") != null) return ShellType.POWERSHELL;
            return ShellType.CMD;
        }
        String shell = System.getenv("SHELL");
        if (shell != null && shell.endsWith("bash")) return ShellType.BASH;
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
        return new String[]{"pwsh", "-Command", escapePowerShell(command)};
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
            ProcessBuilder pb = new ProcessBuilder(isWindows ? new String[]{"cmd.exe", "/d", "/s", "/c", probe} : new String[]{"sh", "-c", probe});
            pb.redirectInput(ProcessBuilder.Redirect.INHERIT);
            pb.redirectError(ProcessBuilder.Redirect.INHERIT);
            Process p = pb.start();
            int exit = p.waitFor();
            return exit == 0;
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
        
        // Generate filename
        String ts = java.time.Instant.now().toString().replaceAll("[-:.Z]", "").replaceAll("T.*", "");
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
            return head + "\n... [TRUNCATED: full output is " + bytes.length + " bytes (" + totalLines + " lines); spill to disk FAILED (" + e.getMessage() + ")] ...\n";
        }
        
        String marker = "\n... [TRUNCATED: " + bytes.length + " bytes (" + totalLines + " lines) saved to " + path + " — use read with range or grep to view the remaining content] ...\n";
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
        pb.redirectInput(ProcessBuilder.Redirect.INHERIT);
        
        Process p = pb.start();
        ExecutorService exec = Executors.newCachedThreadPool();
        try {
            Future<String> outFuture = exec.submit(() -> {
                StringBuilder sb = new StringBuilder();
                try (var stdout = p.getInputStream();
                     var reader = new BufferedReader(new InputStreamReader(stdout, StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line).append('\n');
                        if (sb.length() > OUTPUT_CAP_MAX) {
                            return capOutput(sb.toString());
                        }
                    }
                }
                return sb.toString();
            });
            
            Future<String> errFuture = exec.submit(() -> {
                StringBuilder sb = new StringBuilder();
                try (var stderr = p.getErrorStream();
                     var reader = new BufferedReader(new InputStreamReader(stderr, StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line).append('\n');
                    }
                }
                return sb.toString();
            });
            
            long timeout = timeoutMs > 0 ? timeoutMs : Long.MAX_VALUE;
            try {
                boolean finished = p.waitFor(timeout, TimeUnit.MILLISECONDS);
                if (!finished) {
                    p.destroyForcibly();
                    return new ProcessResult(-1, "TIMEOUT");
                }
            } catch (InterruptedException e) {
                p.destroyForcibly();
                Thread.currentThread().interrupt();
                return new ProcessResult(-1, "INTERRUPTED");
            }
            
            String stdoutText = outFuture.get(1, TimeUnit.SECONDS);
            String stderrText = errFuture.get(1, TimeUnit.SECONDS);
            
            String result = stdoutText + stderrText;
            return new ProcessResult(p.exitValue(), capOutput(result));
        } finally {
            exec.shutdownNow();
        }
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
        if (jobs.size() >= MAX_CONCURRENT_JOBS) {
            throw new RuntimeException("max concurrent jobs (" + MAX_CONCURRENT_JOBS + ") exceeded");
        }
        String id = "j" + jobSeq.incrementAndGet();
        ProcessBuilder pb = new ProcessBuilder(shellCmd(command));
        pb.directory(new File(cwd));
        pb.redirectInput(ProcessBuilder.Redirect.INHERIT);
        
        try {
            Process process = pb.start();
            Job job = new Job(id, command, process);
            jobs.put(id, job);
            
            // Pump output in background
            CompletableFuture.runAsync(() -> {
                try ( var reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        final String l = line;
                        sb.append(l).append('\n');
                        job.output.updateAndGet(curr -> {
                            
                            String updated = curr + l + '\n';
                            return updated.length() > OUTPUT_CAP_MAX ? capOutput(updated) : updated;
                        });
                    }
                } catch (IOException e) {
                    // Stream closed
                }
            });
            
            CompletableFuture.runAsync(() -> {
                try ( var reader = new BufferedReader(new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        final String l = line;
                        sb.append(l).append('\n');
                        job.output.updateAndGet(curr -> {
                            
                            String updated = curr + l + '\n';
                            return updated.length() > OUTPUT_CAP_MAX ? capOutput(updated) : updated;
                        });
                    }
                } catch (IOException e) {
                    // Stream closed
                }
            });
            
            // Monitor exit
            CompletableFuture.runAsync(() -> {
                try {
                    int code = process.waitFor();
                    job.status = "exited";
                    job.exitCode = code;
                    jobs.remove(id);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
            
            return job;
        } catch (IOException e) {
            throw new RuntimeException("Failed to start job: " + e.getMessage(), e);
        }
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
        return new Memo(
            ((Number) m.get("id")).intValue(),
            ((Number) m.get("ts")).longValue(),
            (String) m.get("memo"),
            m.containsKey("tags") ? (List<String>) m.get("tags") : null
        );
    }
    
    private static Map<String, Object> parseJsonObject(String json) {
        Map<String, Object> result = new LinkedHashMap<>();
        json = json.trim();
        if (!json.startsWith("{") || !json.endsWith("}")) {
            throw new RuntimeException("Not a JSON object");
        }
        json = json.substring(1, json.length() - 1);
        
        int depth = 0;
        StringBuilder current = new StringBuilder();
        List<String> tokens = new ArrayList<>();
        
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '{' || c == '[') depth++;
            if (c == '}' || c == ']') depth--;
            if (c == ',' && depth == 0) {
                tokens.add(current.toString().trim());
                current = new StringBuilder();
            } else {
                current.append(c);
            }
        }
        if (current.length() > 0) {
            tokens.add(current.toString().trim());
        }
        
        for (String token : tokens) {
            int colonIdx = token.indexOf(':');
            if (colonIdx == -1) continue;
            
            String key = token.substring(0, colonIdx).trim();
            String value = token.substring(colonIdx + 1).trim();
            
            if (key.startsWith("\"") && key.endsWith("\"")) {
                key = key.substring(1, key.length() - 1);
            }
            
            if (value.startsWith("\"")) {
                value = value.substring(1, value.length() - 1);
                result.put(key, value);
            } else if (value.equals("null")) {
                result.put(key, null);
            } else if (value.equals("true")) {
                result.put(key, true);
            } else if (value.equals("false")) {
                result.put(key, false);
            } else if (value.startsWith("[")) {
                result.put(key, parseJsonArray(value));
            } else if (value.startsWith("{")) {
                result.put(key, parseJsonObject(value));
            } else {
                try {
                    if (value.contains(".")) {
                        result.put(key, Double.parseDouble(value));
                    } else {
                        result.put(key, Long.parseLong(value));
                    }
                } catch (NumberFormatException e) {
                    result.put(key, value);
                }
            }
        }
        return result;
    }
    
    private static List<Object> parseJsonArray(String json) {
        List<Object> result = new ArrayList<>();
        json = json.trim();
        if (!json.startsWith("[") || !json.endsWith("]")) {
            return result;
        }
        json = json.substring(1, json.length() - 1);
        if (json.trim().isEmpty()) return result;
        
        int depth = 0;
        StringBuilder current = new StringBuilder();
        List<String> tokens = new ArrayList<>();
        
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '{' || c == '[') depth++;
            if (c == '}' || c == ']') depth--;
            if (c == ',' && depth == 0) {
                tokens.add(current.toString().trim());
                current = new StringBuilder();
            } else {
                current.append(c);
            }
        }
        if (current.length() > 0) {
            tokens.add(current.toString().trim());
        }
        
        for (String token : tokens) {
            token = token.trim();
            if (token.startsWith("\"")) {
                result.add(token.substring(1, token.length() - 1));
            } else if (token.equals("null")) {
                result.add(null);
            } else if (token.equals("true")) {
                result.add(true);
            } else if (token.equals("false")) {
                result.add(false);
            } else if (token.startsWith("[")) {
                result.add(parseJsonArray(token));
            } else if (token.startsWith("{")) {
                result.add(parseJsonObject(token));
            } else {
                try {
                    if (token.contains(".")) {
                        result.add(Double.parseDouble(token));
                    } else {
                        result.add(Long.parseLong(token));
                    }
                } catch (NumberFormatException e) {
                    result.add(token);
                }
            }
        }
        return result;
    }
    
    private static void writeMemos(String cwd, List<Memo> memos) throws IOException {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < memos.size(); i++) {
            Memo m = memos.get(i);
            sb.append("{\"id\":").append(m.id)
              .append(",\"ts\":").append(m.ts)
              .append(",\"memo\":\"").append(escapeJson(m.memo)).append("\"");
            if (m.tags != null && !m.tags.isEmpty()) {
                sb.append(",\"tags\":[");
                sb.append(m.tags.stream().map(t -> "\"" + escapeJson(t) + "\"").collect(Collectors.joining(",")));
                sb.append("]");
            }
            sb.append("}");
            if (i < memos.size() - 1) sb.append("\n");
        }
        Files.writeString(Path.of(cwd, ".memo.jsonl"), sb.toString());
    }
    
    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
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
    private static String handleRead(String cwd, String path, int[] range) throws IOException {
        Path file = safeResolveFile(cwd, path);
        String content = Files.readString(file);
        if (range == null) return content;
        String[] lines = content.split("\n");
        int start = Math.max(0, range[0] - 1);
        int end = Math.min(lines.length, range[1]);
        return String.join("\n", Arrays.copyOfRange(lines, start, end));
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
            cmd = append(cmd, pattern, path != null ? path : ".");
        } else if (isWindows && hasFindstr) {
            cmd = new String[]{"findstr", "/r", "/n", pattern, glob != null ? path + "\\" + glob.replace("*", "*") : (path != null ? path : ".")};
        } else {
            cmd = new String[]{"grep", "-rEn"};
            if (glob != null) cmd = append(cmd, "--include", glob);
            cmd = append(cmd, pattern, path != null ? path : ".");
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
            j.process.destroyForcibly();
            return j.id + " stopped";
        }
        
        throw new RuntimeException("bad mode: " + mode);
    }
    
    // --- mcp tool ---
    private static String handleMcp(String cwd, String action, String server, String tool, Map<String, Object> args, String mcpCfgPath) {
        if (action.equals("list")) {
            return "{ \"servers\": [], \"mcpConfigPath\": \"" + (mcpCfgPath != null ? mcpCfgPath : ".mcp.json") + "\" }";
        }
        throw new RuntimeException("MCP tool requires --mcp <path> configuration");
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
        int id = lastMemoId(cwd) + 1;
        Memo m = new Memo(id, System.currentTimeMillis(), memo, tags);
        String line = "{\"id\":" + id + ",\"ts\":" + m.ts + ",\"memo\":\"" + escapeJson(m.memo) + "\"}";
        if (tags != null && !tags.isEmpty()) {
            line = "{\"id\":" + id + ",\"ts\":" + m.ts + ",\"memo\":\"" + escapeJson(m.memo) + "\",\"tags\":[" +
                tags.stream().map(t -> "\"" + escapeJson(t) + "\"").collect(Collectors.joining(",")) + "]}";
        }
        Files.writeString(Path.of(cwd, ".memo.jsonl"), line + "\n", StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        return "remembered #" + id;
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
        }).sorted((a, b) -> b.id - a.id).collect(Collectors.toList());
        
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
            headers.add("Access-Control-Allow-Headers", "Content-Type");
            
            if (exchange.getRequestMethod().equals("OPTIONS")) {
                exchange.sendResponseHeaders(204, -1);
                exchange.close();
                return;
            }
            
            // Token check
            if (token != null) {
                String reqToken = parseQueryParam(exchange.getRequestURI(), "token");
                if (!token.equals(reqToken)) {
                    String response = "{\"error\":\"unauthorized\"}";
                    exchange.sendResponseHeaders(401, response.length());
                    exchange.getResponseBody().write(response.getBytes());
                    exchange.close();
                    return;
                }
            }
            
            String body;
            try (var reader = new BufferedReader(new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
                body = reader.lines().collect(Collectors.joining("\n"));
            }
            
            try {
                Map<String, Object> request = parseJsonObject(body);
                String idStr = request.containsKey("id") ? String.valueOf(request.get("id")) : null;
                String method = (String) request.get("method");
                @SuppressWarnings("unchecked")
                Map<String, Object> params = (Map<String, Object>) request.get("params");
                
                Object result = handleMcpMethod(method, params);
                
                String response;
                if (result instanceof String && ((String) result).startsWith("ERROR")) {
                    response = "{\"jsonrpc\":\"2.0\",\"id\":" + idStr + ",\"error\":{\"code\":-32603,\"message\":" + jsonQuote((String) result) + "}}";
                } else {
                    String resultJson = serializeResult(result);
                    response = "{\"jsonrpc\":\"2.0\",\"id\":" + idStr + ",\"result\":" + resultJson + "}";
                }
                
                headers.add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, response.length());
                exchange.getResponseBody().write(response.getBytes());
            } catch (Exception e) {
                String response = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":" + jsonQuote(e.getMessage()) + "}}";
                headers.add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, response.length());
                exchange.getResponseBody().write(response.getBytes());
            }
            exchange.close();
        }
        
        private String parseQueryParam(URI uri, String param) {
            String query = uri.getQuery();
            if (query == null) return null;
            for (String pair : query.split("&")) {
                String[] kv = pair.split("=", 2);
                if (kv.length == 2 && kv[0].equals(param)) {
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
            return switch (method) {
                case "initialize" -> Map.of(
                    "protocolVersion", "2024-11-05",
                    "capabilities", Map.of("tools", Map.of()),
                    "serverInfo", Map.of("name", "code-mcp", "version", "0.1.0")
                );
                case "tools/list" -> {
                    List<Map<String, Object>> tools = new ArrayList<>();
                    tools.add(makeTool("read", "Read a file. Optional line range [start,end] (1-indexed, inclusive).",
                        List.of(Map.of("name", "cwd", "type", "string"),
                               Map.of("name", "path", "type", "string"),
                               Map.of("name", "range", "type", "array", "items", Map.of("type", "number")))));

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

                    tools.add(makeTool("bash", "Run a bash command. Block until exit, return combined stdout+stderr.",
                        List.of(Map.of("name", "cwd", "type", "string", "required", true),
                               Map.of("name", "command", "type", "string", "required", true),
                               Map.of("name", "timeout_ms", "type", "number"))));

                    tools.add(makeTool("shell", "Run a POSIX sh command.",
                        List.of(Map.of("name", "cwd", "type", "string", "required", true),
                               Map.of("name", "command", "type", "string", "required", true),
                               Map.of("name", "timeout_ms", "type", "number"))));

                    tools.add(makeTool("command", "Run a Windows CMD command.",
                        List.of(Map.of("name", "cwd", "type", "string", "required", true),
                               Map.of("name", "command", "type", "string", "required", true),
                               Map.of("name", "timeout_ms", "type", "number"))));

                    tools.add(makeTool("powershell", "Run a PowerShell command.",
                        List.of(Map.of("name", "cwd", "type", "string", "required", true),
                               Map.of("name", "command", "type", "string", "required", true),
                               Map.of("name", "timeout_ms", "type", "number"))));

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

                    
                    if (mcpConfigPath != null) {
                        tools.add(makeTool("mcp", "Manage MCP servers.",
                            List.of(Map.of("name", "cwd", "type", "string", "required", true),
                                   Map.of("name", "action", "type", "string", "enum", List.of("list", "call", "unload"), "required", true),
                                   Map.of("name", "server", "type", "string"),
                                   Map.of("name", "tool", "type", "string"),
                                   Map.of("name", "args", "type", "object"),
                                   Map.of("name", "mcpConfigPath", "type", "string"))));

                    }
                    
                    if (hasCloudflared) {
                        tools.add(makeTool("preview", "Start a Cloudflare quick tunnel.",
                            List.of(Map.of("name", "url", "type", "string", "required", true))));

                    }
                    
                    if (memoryEnabled) {
                        tools.add(makeTool("remember", "Append a memo to .memo.jsonl.",
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
                    
                    yield Map.of("tools", tools);
                }
                case "tools/call" -> {
                    String name = params != null ? (String) params.get("name") : null;
                    @SuppressWarnings("unchecked")
                    Map<String, Object> args = params != null ? (Map<String, Object>) params.get("arguments") : Map.of();
                    
                    if (name == null) {
                        yield "ERROR: tool name required";
                    }
                    
                    String result;
                    try {
                        result = switch (name) {
                            case "read" -> handleRead(
                                (String) args.get("cwd"),
                                (String) args.get("path"),
                                parseRange(args.get("range")));
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
                default -> "ERROR: unknown method: " + method;
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
            if (range instanceof List) {
                @SuppressWarnings("unchecked")
                List<Number> r = (List<Number>) range;
                if (r.size() >= 2) {
                    return new int[]{r.get(0).intValue(), r.get(1).intValue()};
                }
            }
            return null;
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
                headers.add("Content-Type", "application/json");
                exchange.sendResponseHeaders(401, response.length());
                exchange.getResponseBody().write(response.getBytes());
                exchange.close();
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
            Headers headers = exchange.getResponseHeaders();
            headers.add("Content-Type", "application/json");
            
            try {
                String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
                if (contentType == null || !contentType.contains("multipart/form-data")) {
                    String response = "{\"error\":\"expected multipart/form-data\"}";
                    exchange.sendResponseHeaders(400, response.length());
                    exchange.getResponseBody().write(response.getBytes());
                    exchange.close();
                    return;
                }
                
                byte[] body;
                try ( var baos = new ByteArrayOutputStream()) {
                    exchange.getRequestBody().transferTo(baos);
                    body = baos.toByteArray();
                }
                
                Pattern boundaryPat = Pattern.compile("boundary=(.+?)(?:;|$)");
                Matcher m = boundaryPat.matcher(contentType);
                if (!m.find()) {
                    String response = "{\"error\":\"no boundary\"}";
                    exchange.sendResponseHeaders(400, response.length());
                    exchange.getResponseBody().write(response.getBytes());
                    exchange.close();
                    return;
                }
                String boundary = "--" + m.group(1);
                
                Path uploadDir = Path.of(uploadRoot, sessionId);
                Files.createDirectories(uploadDir);
                
                String bodyStr = new String(body, StandardCharsets.UTF_8);
                String[] parts = bodyStr.split(Pattern.quote(boundary));
                
                String fileName = null;
                byte[] fileContent = null;
                
                for (String part : parts) {
                    if (part.trim().isEmpty() || part.equals("--")) continue;
                    int headerEnd = part.indexOf("\r\n\r\n");
                    if (headerEnd == -1) continue;
                    
                    String partHeader = part.substring(0, headerEnd);
                    String partBody = part.substring(headerEnd + 4);
                    
                    if (partBody.endsWith("\r\n")) {
                        partBody = partBody.substring(0, partBody.length() - 2);
                    }
                    
                    Pattern fnPat = Pattern.compile("filename=\"([^\"]+)\"");
                    if (fnPat.matcher(partHeader).find()) {
                        Matcher fnMatcher = fnPat.matcher(partHeader);
                        if (fnMatcher.find()) {
                            fileName = fnMatcher.group(1);
                            int bodyStart = part.indexOf("\r\n\r\n") + 4;
                            byte[] partBytes = Arrays.copyOfRange(body, bodyStart, body.length);
                            int endMarkerStart = -1;
                            for (int i = 0; i < partBytes.length - boundary.length() - 2; i++) {
                                if (new String(partBytes, i, boundary.length() + 2, StandardCharsets.UTF_8).startsWith(boundary)) {
                                    endMarkerStart = i;
                                    break;
                                }
                            }
                            if (endMarkerStart > 0) {
                                fileContent = Arrays.copyOf(partBytes, endMarkerStart - 2);
                            } else {
                                fileContent = partBytes;
                            }
                        }
                    }
                }
                
                if (fileName == null || fileContent == null) {
                    String response = "{\"error\":\"no file provided\"}";
                    exchange.sendResponseHeaders(400, response.length());
                    exchange.getResponseBody().write(response.getBytes());
                    exchange.close();
                    return;
                }
                
                fileName = fileName.replaceAll("[^A-Za-z0-9._-]", "_");
                
                Path filePath = uploadDir.resolve(fileName);
                Files.write(filePath, fileContent, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                
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
                    jsonQuote(mime)
                );
                
                exchange.sendResponseHeaders(200, response.length());
                exchange.getResponseBody().write(response.getBytes());
            } catch (Exception e) {
                String response = "{\"error\":" + jsonQuote(e.getMessage()) + "}";
                exchange.sendResponseHeaders(500, response.length());
                exchange.getResponseBody().write(response.getBytes());
            }
            exchange.close();
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

    // ===== GATEWAY CLIENT =====
    private static void startGatewayClient(String domain) throws Exception {
        String deviceId = UUID.randomUUID().toString();
        int RECONNECT_DELAY_MS = 3000;
        int MAX_RETRIES = 10;
        int[] retries = {0};

        new Thread(() -> {
            System.err.println("[gateway] starting client for: " + domain);
            while (true) {
                try {
                    String url = domain.startsWith("wss://") || domain.startsWith("https://")
                        ? domain + "/ws"
                        : "wss://" + domain + "/ws";
                    System.err.println("[gateway] connecting to " + url);

                    URI uri = URI.create(url);
                    String host = uri.getHost();
                    int port = uri.getPort() > 0 ? uri.getPort() : 443;

                    SSLSocketFactory sf = SSLContext.getDefault().getSocketFactory();
                    try (SSLSocket sslSocket = (SSLSocket) sf.createSocket(host, port)) {
                        sslSocket.startHandshake();
                        DataOutputStream out = new DataOutputStream(sslSocket.getOutputStream());
                        InputStream in = sslSocket.getInputStream();

                        byte[] keyBytes = new byte[16];
                        new Random().nextBytes(keyBytes);
                        String wsKey = Base64.getEncoder().encodeToString(keyBytes);
                        String request = "GET /ws HTTP/1.1\r\nHost: " + host + ":" + port + "\r\n" +
                                "Upgrade: websocket\r\nConnection: Upgrade\r\n" +
                                "Sec-WebSocket-Key: " + wsKey + "\r\nSec-WebSocket-Version: 13\r\n\r\n";
                        out.writeBytes(request);

                        StringBuilder resp = new StringBuilder();
                        int b;
                        while ((b = in.read()) != -1) {
                            resp.append((char) b);
                            if (resp.toString().contains("\r\n\r\n")) break;
                        }
                        if (!resp.toString().contains("101")) {
                            System.err.println("[gateway] WebSocket upgrade failed");
                            return;
                        }
                        System.err.println("[gateway] connected, sending register...");

                        retries[0] = 0;

                        String register = "{\"type\":\"register\",\"deviceId\":\"" + deviceId + "\"}";
                        sendFrame(out, register.getBytes(StandardCharsets.UTF_8), (byte) 0x81);

                        sslSocket.setSoTimeout(60000);

                        while (true) {
                            int opcode;
                            try {
                                opcode = in.read();
                            } catch (SocketTimeoutException e) {
                                continue;
                            }
                            if (opcode == -1) break;

                            int lenByte = in.read();

                            boolean masked = (lenByte & 0x80) != 0;
                            int len = lenByte & 0x7F;
                            if (len == 126) {
                                len = (in.read() << 8) | in.read();
                            } else if (len == 127) {
                                len = 0;
                                for (int j = 0; j < 8; j++) len = (len << 8) | (in.read() & 0xFF);
                            }

                            byte[] mask = new byte[4];
                            if (masked) {
                                if (in.read(mask) != 4) break;
                            }

                            byte[] payload = new byte[len];
                            int read = 0;
                            while (read < len) {
                                try {
                                    int n = in.read(payload, read, len - read);
                                    if (n == -1) break;
                                    read += n;
                                } catch (SocketTimeoutException e) {
                                    break;
                                }
                            }

                            if (masked) {
                                for (int j = 0; j < len; j++) {
                                    payload[j] = (byte) (payload[j] ^ mask[j % 4]);
                                }
                            }

                            if ((opcode & 0x0F) == 0x01) {
                                String msg = new String(payload, StandardCharsets.UTF_8);
                                System.err.println("[gateway] received: " + msg);
                                if (msg.contains("\"request\"")) {
                                    handleGatewayMessage(out, msg);
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    System.err.println("[gateway] error: " + e.getClass().getName() + ": " + e.getMessage());
                }
                if (++retries[0] > MAX_RETRIES) {
                    System.exit(1);
                }
                try { Thread.sleep(RECONNECT_DELAY_MS); } catch (InterruptedException ignored) {}
            }
        }).start();
    }

    private static void handleGatewayMessage(DataOutputStream out, String data) {
        try {
            Map<String, Object> json = parseJsonObject(data);
            String id = String.valueOf(json.get("id"));
            @SuppressWarnings("unchecked")
            Map<String, Object> req = (Map<String, Object>) json.get("request");
            Object reqId = req.get("id");
            String token = json.containsKey("token") ? String.valueOf(json.get("token")) : null;

            String tokenParam = (token != null && !token.isBlank()) ? "?token=" + token : "";
            String localUrl = "http://localhost:" + port + "/mcp" + tokenParam;

            HttpClient client = HttpClient.newHttpClient();
            HttpRequest httpReq = HttpRequest.newBuilder()
                    .uri(URI.create(localUrl))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(MCPRouteHandler.serializeResult(req)))
                    .build();

            HttpResponse<String> httpRes = client.send(httpReq, HttpResponse.BodyHandlers.ofString());

            Map<String, Object> mcpRes = parseJsonObject(httpRes.body());

            Map<String, Object> tunnelRes = new LinkedHashMap<>();
            tunnelRes.put("id", id);
            tunnelRes.put("response", mcpRes);

            sendFrame(out, MCPRouteHandler.serializeResult(tunnelRes).getBytes(StandardCharsets.UTF_8), (byte) 0x81);
        } catch (Exception e) {
            System.err.println("[gateway] handle error: " + e.getMessage());
        }
    }

    private static void sendFrame(DataOutputStream out, byte[] data, byte opcode) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(0x81);
        if (data.length < 126) {
            baos.write(data.length | 0x80);
        } else if (data.length < 65536) {
            baos.write(126 | 0x80);
            baos.write((data.length >> 8) & 0xFF);
            baos.write(data.length & 0xFF);
        } else {
            baos.write(127 | 0x80);
            for (int i = 7; i >= 0; i--) baos.write((data.length >> (i * 8)) & 0xFF);
        }
        byte[] mask = new byte[4];
        new Random().nextBytes(mask);
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
