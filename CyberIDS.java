import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.time.format.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.*;



public class CyberIDS {

    public static void main(String[] args) {
        System.out.println("╔══════════════════════════════════════╗");
        System.out.println("║   CyberIDS — Cyber Security Detector  ║");
        System.out.println("║   Web UI: http://localhost:8080        ║");
        System.out.println("╚══════════════════════════════════════╝");

        // Start API + Web server
        startApi();

        // Auto-open Chrome after 1.5 seconds
        new Thread(() -> {
            try {
                Thread.sleep(1500);
                new ProcessBuilder("cmd","/c","start","chrome","http://localhost:8080").start();
                System.out.println("[ INFO ] Browser opened at http://localhost:8080");
            } catch (IOException | InterruptedException e) {
                System.out.println("[ INFO ] Open browser: http://localhost:8080");
            }
        }).start();
    }

    private static void startApi() {
        ApiServer api = new ApiServer();
        try {
            api.start();
            Runtime.getRuntime().addShutdownHook(new Thread(api::stop));
        } catch (IOException e) {
            System.err.println("[ ERROR ] ApiServer failed: " + e.getMessage());
        }
    }


    // ══════════════════════════════════════════════════════════════════
    //  1. THREAT ANALYZER
    // ══════════════════════════════════════════════════════════════════
    static class ThreatAnalyzer {

        enum ThreatLevel { SAFE, LOW, MEDIUM, HIGH, CRITICAL }

        static class ScanResult {
            public final ThreatLevel level;
            public final String category;
            public final String detail;
            public final int score;

            ScanResult(ThreatLevel level, String category, String detail, int score) {
                this.level    = level;
                this.category = category;
                this.detail   = detail;
                this.score    = score;
            }

            @Override
            public String toString() {
                return String.format("[%s] %s | %s | Score: %d/100",
                        level, category, detail, score);
            }
        }

        public String analyze(String input) {
            if (input == null || input.isBlank()) return "[SAFE] No input provided.";
            String lower = input.toLowerCase().trim();
            if (lower.startsWith("http://") || lower.startsWith("https://") || lower.contains("www."))
                return analyzeURL(input).toString();
            else if (lower.matches("^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,6}$"))
                return analyzeEmail(input).toString();
            else if (lower.matches(".*\\.(exe|bat|cmd|vbs|ps1|jar|sh|zip|rar)$"))
                return analyzeFile(input).toString();
            else if (lower.matches("^[+\\d\\s\\-()]{7,15}$"))
                return analyzePhone(input).toString();
            else
                return analyzeMessage(input).toString();
        }

        public ScanResult analyzeMessage(String message) {
            String m = message.toLowerCase();
            int score = 0;
            List<String> findings = new ArrayList<>();

            if (m.matches(".*(urgent|immediate|act now|expires today|last chance).*"))
                { score += 25; findings.add("urgency trigger"); }
            if (m.matches(".*(verify account|confirm.*identity|update.*details|login.*now).*"))
                { score += 30; findings.add("phishing pattern"); }
            if (m.matches(".*(lottery|you won|prize|reward|free money|claim now).*"))
                { score += 35; findings.add("lottery/prize scam"); }
            if (m.matches(".*(otp|one.time|passcode|pin|token).*"))
                { score += 30; findings.add("OTP fraud"); }
            if (m.matches(".*(wire transfer|send money|bank account|payment pending).*"))
                { score += 30; findings.add("financial scam"); }
            if (m.contains("bit.ly") || m.contains("tinyurl") || m.contains("t.co"))
                { score += 20; findings.add("shortened URL"); }
            if (m.matches(".*(account blocked|suspended|deactivated|arrested|legal action).*"))
                { score += 25; findings.add("threatening language"); }

            score = Math.min(score, 100);
            String detail = findings.isEmpty() ? "No suspicious patterns found"
                    : "Detected: " + String.join(", ", findings);
            return new ScanResult(getLevel(score), "MESSAGE", detail, score);
        }

        public ScanResult analyzeEmail(String email) {
            String e = email.toLowerCase();
            int score = 0;
            List<String> findings = new ArrayList<>();

            if (!Pattern.matches("^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,6}$", email))
                { score += 40; findings.add("invalid format"); }
            if (e.matches(".*\\.(ru|cn|tk|xyz|top|click|gq|cf|ml)$"))
                { score += 35; findings.add("suspicious TLD"); }
            if (Pattern.compile("(secur|verify|alert|update|account|login|bank|support)").matcher(e).find())
                { score += 25; findings.add("suspicious prefix"); }
            String username = e.contains("@") ? e.substring(0, e.indexOf("@")) : e;
            if (username.chars().filter(Character::isDigit).count() > 5)
                { score += 15; findings.add("number-heavy username"); }

            score = Math.min(score, 100);
            String detail = findings.isEmpty() ? "Valid email format"
                    : "Issues: " + String.join(", ", findings);
            return new ScanResult(getLevel(score), "EMAIL", detail, score);
        }

        public ScanResult analyzeURL(String url) {
            String u = url.toLowerCase();
            int score = 0;
            List<String> findings = new ArrayList<>();

            if (!u.startsWith("https://"))
                { score += 20; findings.add("no HTTPS"); }
            if (u.contains("bit.ly") || u.contains("tinyurl") || u.contains("t.co") || u.contains("goo.gl"))
                { score += 40; findings.add("shortened/masked URL"); }
            if (Pattern.compile("https?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}").matcher(u).find())
                { score += 45; findings.add("IP address hostname"); }
            if (Pattern.compile("(login|verify|secure|account|update|confirm|bank|paypal|amazon)").matcher(u).find())
                { score += 30; findings.add("phishing keywords"); }
            if (u.matches(".*\\.(tk|xyz|top|click|gq|cf|ml|ru|cn)/.*"))
                { score += 30; findings.add("suspicious TLD"); }
            String domain = u.replaceFirst("https?://", "").split("/")[0];
            if (domain.chars().filter(c -> c == '.').count() > 3)
                { score += 20; findings.add("excessive subdomains"); }

            score = Math.min(score, 100);
            String detail = findings.isEmpty() ? "URL appears legitimate"
                    : "Flags: " + String.join(", ", findings);
            return new ScanResult(getLevel(score), "URL", detail, score);
        }

        public ScanResult analyzeFile(String filename) {
            String f = filename.toLowerCase();
            int score = 0;
            List<String> findings = new ArrayList<>();

            if (f.matches(".*\\.(jpg|pdf|doc|txt|png)\\.(exe|bat|cmd|vbs|ps1)$"))
                { score += 80; findings.add("double extension malware"); }
            if (f.endsWith(".exe") || f.endsWith(".bat") || f.endsWith(".cmd"))
                { score += 50; findings.add("executable file"); }
            if (f.endsWith(".vbs") || f.endsWith(".ps1") || f.endsWith(".sh"))
                { score += 45; findings.add("script file"); }
            if (f.endsWith(".zip") || f.endsWith(".rar") || f.endsWith(".7z"))
                { score += 20; findings.add("archive file"); }
            if (f.matches(".*(crack|hack|keygen|patch|loader|cheat|bypass).*"))
                { score += 35; findings.add("suspicious filename"); }

            score = Math.min(score, 100);
            String detail = findings.isEmpty() ? "File appears safe"
                    : "Risk: " + String.join(", ", findings);
            return new ScanResult(getLevel(score), "FILE", detail, score);
        }

        public ScanResult analyzePhone(String phone) {
            String p = phone.replaceAll("[\\s\\-()]", "");
            if (p.matches("^(\\+91|0)?[6-9]\\d{9}$"))
                return new ScanResult(ThreatLevel.SAFE, "PHONE", "Valid Indian mobile number", 0);
            if (p.matches("^\\+1\\d{10}$"))
                return new ScanResult(ThreatLevel.SAFE, "PHONE", "Valid US number", 0);

            int score = 0;
            List<String> findings = new ArrayList<>();
            if (p.length() < 7 || p.length() > 15) { score += 30; findings.add("unusual length"); }
            if (p.matches(".*(.)\\1{5,}.*"))         { score += 50; findings.add("repeated digits - spoofed"); }
            if (p.startsWith("+900") || p.startsWith("900")) { score += 40; findings.add("premium rate number"); }

            score = Math.min(score, 100);
            String detail = findings.isEmpty() ? "Number format unrecognized"
                    : "Issues: " + String.join(", ", findings);
            return new ScanResult(getLevel(score), "PHONE", detail, score);
        }

        private ThreatLevel getLevel(int score) {
            if (score == 0)      return ThreatLevel.SAFE;
            else if (score < 25) return ThreatLevel.LOW;
            else if (score < 50) return ThreatLevel.MEDIUM;
            else if (score < 75) return ThreatLevel.HIGH;
            else                 return ThreatLevel.CRITICAL;
        }
    }


    // ══════════════════════════════════════════════════════════════════
    //  2. LOG MANAGER
    // ══════════════════════════════════════════════════════════════════
    static class LogManager {

        private static final String LOG_FILE = "cyberids_log.txt";
        private final List<String> logBuffer = Collections.synchronizedList(new ArrayList<>());
        private final DateTimeFormatter formatter =
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

        public void log(String level, String message) {
            String timestamp = LocalDateTime.now().format(formatter);
            String entry = String.format("[%s] [%-5s] %s", timestamp, level, message);
            System.out.println(entry);
            logBuffer.add(entry);
            saveToFile(entry);
        }

        private void saveToFile(String entry) {
            try (FileWriter fw = new FileWriter(LOG_FILE, true);
                 BufferedWriter bw = new BufferedWriter(fw)) {
                bw.write(entry);
                bw.newLine();
            } catch (IOException e) {
                System.err.println("[LogManager] File write error: " + e.getMessage());
            }
        }

        public List<String> getAllLogs()         { return Collections.unmodifiableList(logBuffer); }
        public String        getLogFilePath()    { return new File(LOG_FILE).getAbsolutePath(); }

        public List<String> getLastLogs(int count) {
            int size = logBuffer.size();
            int from = Math.max(0, size - count);
            return Collections.unmodifiableList(logBuffer.subList(from, size));
        }

        public void clearLogs() {
            logBuffer.clear();
            log("INFO", "Log buffer cleared.");
        }
    }

    // ══════════════════════════════════════════════════════════════════
    //  6. API SERVER — HTTP (port 8080) + Embedded HTML frontend
    // ══════════════════════════════════════════════════════════════════
    static class ApiServer {

        private static final int API_PORT = 8080;
        private final ThreatAnalyzer analyzer   = new ThreatAnalyzer();
        private final LogManager     logManager = new LogManager();
        private HttpServer           server;

        public void start() throws IOException {
            server = HttpServer.create(new InetSocketAddress(API_PORT), 0);
            server.createContext("/",            new FrontendHandler());
            server.createContext("/api/scan",    new ScanHandler());
            server.createContext("/api/status",  new StatusHandler());
            server.createContext("/api/logs",    new LogsHandler());
            server.setExecutor(null);
            server.start();
            logManager.log("INFO", "ApiServer started on http://localhost:" + API_PORT);
            System.out.println("[ API ] Server running → http://localhost:" + API_PORT);
            System.out.println("[ API ] Open in browser: http://localhost:" + API_PORT);
        }

        public void stop() {
            if (server != null) {
                server.stop(0);
                logManager.log("INFO", "ApiServer stopped.");
            }
        }

        // ── Serve HTML frontend ──────────────────────────────────────
        private class FrontendHandler implements HttpHandler {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                exchange.getResponseHeaders().add("Content-Type", "text/html; charset=UTF-8");
                byte[] bytes = HTML_FRONTEND.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, bytes.length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(bytes); }
            }
        }

        // ── POST /api/scan ───────────────────────────────────────────
        private class ScanHandler implements HttpHandler {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                exchange.getResponseHeaders().add("Access-Control-Allow-Origin",  "*");
                exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "POST, OPTIONS");
                exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type");
                exchange.getResponseHeaders().add("Content-Type", "application/json");

                if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(204, -1);
                    return;
                }
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    sendResponse(exchange, 405, "{\"error\":\"Method not allowed\"}");
                    return;
                }
                try {
                    String body    = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                    String message = extractJson(body, "message");
                    String email   = extractJson(body, "email");
                    String url     = extractJson(body, "url");
                    String file    = extractJson(body, "file");
                    String phone   = extractJson(body, "phone");

                    ThreatAnalyzer.ScanResult msgR   = analyzer.analyzeMessage(message);
                    ThreatAnalyzer.ScanResult emailR = analyzer.analyzeEmail(email);
                    ThreatAnalyzer.ScanResult urlR   = analyzer.analyzeURL(url);
                    ThreatAnalyzer.ScanResult fileR  = analyzer.analyzeFile(file);
                    ThreatAnalyzer.ScanResult phoneR = analyzer.analyzePhone(phone);

                    String json = "{"
                            + "\"message\":"  + resultToJson(msgR)   + ","
                            + "\"email\":"    + resultToJson(emailR) + ","
                            + "\"url\":"      + resultToJson(urlR)   + ","
                            + "\"file\":"     + resultToJson(fileR)  + ","
                            + "\"phone\":"    + resultToJson(phoneR) + ","
                            + "\"timestamp\":\"" + LocalDateTime.now() + "\""
                            + "}";
                    logManager.log("API", "Scan complete.");
                    sendResponse(exchange, 200, json);
                } catch (IOException | RuntimeException e) {
                    logManager.log("ERROR", "Scan failed: " + e.getMessage());
                    sendResponse(exchange, 500, "{\"error\":\"Internal server error\"}");
                }
            }
        }

        // ── GET /api/status ──────────────────────────────────────────
        private class StatusHandler implements HttpHandler {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                String json = "{\"status\":\"online\",\"version\":\"2.0\",\"port\":"
                        + API_PORT + ",\"uptime\":\"" + LocalDateTime.now() + "\"}";
                sendResponse(exchange, 200, json);
            }
        }

        // ── GET /api/logs ────────────────────────────────────────────
        private class LogsHandler implements HttpHandler {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                List<String> logs = logManager.getLastLogs(20);
                StringBuilder sb = new StringBuilder("[");
                for (int i = 0; i < logs.size(); i++) {
                    sb.append("\"").append(logs.get(i).replace("\"", "'")).append("\"");
                    if (i < logs.size() - 1) sb.append(",");
                }
                sb.append("]");
                sendResponse(exchange, 200, sb.toString());
            }
        }

        private void sendResponse(HttpExchange ex, int code, String body) throws IOException {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(code, bytes.length);
            try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
        }

        private String extractJson(String json, String key) {
            String search = "\"" + key + "\":\"";
            int start = json.indexOf(search);
            if (start == -1) return "";
            start += search.length();
            int end = json.indexOf("\"", start);
            return (end == -1) ? "" : json.substring(start, end);
        }

        private String resultToJson(ThreatAnalyzer.ScanResult r) {
            return "{\"level\":\"" + r.level + "\",\"category\":\"" + r.category
                    + "\",\"detail\":\"" + r.detail.replace("\"", "'")
                    + "\",\"score\":" + r.score + "}";
        }
    }

    // ══════════════════════════════════════════════════════════════════
    //  EMBEDDED HTML FRONTEND  (CyberSecurityDetector.html inline)
    // ══════════════════════════════════════════════════════════════════
    private static final String HTML_FRONTEND = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>CyberIDS — Advanced Security Detector</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700;900&display=swap" rel="stylesheet"/>
<style>
  :root {
    --bg-deep:#020c1b;--bg-panel:#0a1628;--bg-card:#0d1f38;--bg-input:#071220;
    --accent:#00e5ff;--accent2:#00ff88;--accent3:#ff3c6e;--accent4:#ffd600;
    --border:rgba(0,229,255,0.18);--border2:rgba(0,229,255,0.35);
    --text:#e0f7ff;--text-dim:#7bafc4;--text-muted:#3a6a82;
    --danger:#ff3c6e;--safe:#00ff88;--warn:#ffd600;
    --font-mono:'Share Tech Mono',monospace;--font-main:'Exo 2',sans-serif;
    --glow:0 0 20px rgba(0,229,255,0.25);
    --glow-safe:0 0 20px rgba(0,255,136,0.3);
    --glow-danger:0 0 20px rgba(255,60,110,0.3);
  }
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  html{scroll-behavior:smooth}
  body{background:var(--bg-deep);color:var(--text);font-family:var(--font-main);min-height:100vh;overflow-x:hidden}
  body::before{content:'';position:fixed;inset:0;z-index:0;background-image:linear-gradient(rgba(0,229,255,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,229,255,0.03) 1px,transparent 1px);background-size:40px 40px;pointer-events:none}
  body::after{content:'';position:fixed;left:0;right:0;top:-100px;height:2px;background:linear-gradient(90deg,transparent,var(--accent),transparent);z-index:1;animation:scanline 6s linear infinite;opacity:0.4;pointer-events:none}
  @keyframes scanline{0%{top:-2px}100%{top:100vh}}
  .wrapper{position:relative;z-index:2;max-width:960px;margin:0 auto;padding:2rem 1.5rem 4rem}
  header{text-align:center;margin-bottom:2.5rem;animation:fadeDown 0.7s ease both}
  .logo-row{display:flex;align-items:center;justify-content:center;gap:14px;margin-bottom:0.4rem}
  .shield-icon{width:48px;height:48px;flex-shrink:0}
  header h1{font-size:clamp(1.8rem,4vw,2.6rem);font-weight:900;letter-spacing:0.08em;color:var(--accent);text-shadow:0 0 30px rgba(0,229,255,0.5);font-family:var(--font-main)}
  header h1 span{color:var(--accent2)}
  .tagline{font-family:var(--font-mono);font-size:0.78rem;color:var(--text-dim);letter-spacing:0.15em;text-transform:uppercase}
  .status-bar{display:flex;align-items:center;gap:12px;flex-wrap:wrap;background:var(--bg-panel);border:1px solid var(--border);border-radius:8px;padding:0.6rem 1.2rem;margin-bottom:1.8rem;font-family:var(--font-mono);font-size:0.75rem;color:var(--text-dim);animation:fadeDown 0.8s 0.1s ease both}
  .status-dot{width:8px;height:8px;border-radius:50%;background:var(--accent2);box-shadow:0 0 8px var(--accent2);animation:pulse-dot 2s infinite;flex-shrink:0}
  .backend-dot{width:8px;height:8px;border-radius:50%;background:var(--warn);flex-shrink:0;transition:background 0.3s}
  @keyframes pulse-dot{0%,100%{opacity:1}50%{opacity:0.4}}
  .status-bar .s-item{color:var(--accent)}
  .threat-meter{background:var(--bg-panel);border:1px solid var(--border);border-radius:12px;padding:1.2rem 1.5rem;margin-bottom:1.8rem;animation:fadeDown 0.8s 0.15s ease both}
  .meter-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:0.8rem}
  .meter-label{font-family:var(--font-mono);font-size:0.72rem;text-transform:uppercase;letter-spacing:0.12em;color:var(--text-dim)}
  .threat-level-badge{font-family:var(--font-mono);font-size:0.8rem;font-weight:700;letter-spacing:0.1em;padding:3px 12px;border-radius:4px;background:rgba(0,255,136,0.12);color:var(--safe);border:1px solid rgba(0,255,136,0.3);transition:all 0.4s}
  .threat-level-badge.medium{background:rgba(255,214,0,0.12);color:var(--warn);border-color:rgba(255,214,0,0.3)}
  .threat-level-badge.high{background:rgba(255,60,110,0.12);color:var(--danger);border-color:rgba(255,60,110,0.3);animation:badge-pulse 0.8s infinite}
  @keyframes badge-pulse{0%,100%{box-shadow:0 0 6px rgba(255,60,110,0.4)}50%{box-shadow:0 0 18px rgba(255,60,110,0.7)}}
  .meter-track{height:8px;background:rgba(255,255,255,0.05);border-radius:4px;overflow:hidden}
  .meter-fill{height:100%;width:0%;border-radius:4px;background:linear-gradient(90deg,var(--safe),var(--warn));transition:width 0.8s cubic-bezier(0.34,1.56,0.64,1),background 0.5s;position:relative}
  .main-grid{display:grid;grid-template-columns:1fr 1fr;gap:1.2rem;margin-bottom:1.2rem;animation:fadeUp 0.8s 0.2s ease both}
  @media(max-width:640px){.main-grid{grid-template-columns:1fr}}
  .input-card{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:1.2rem 1.3rem;transition:border-color 0.3s,box-shadow 0.3s}
  .input-card:hover{border-color:var(--border2);box-shadow:var(--glow)}
  .input-card.full{grid-column:1/-1}
  .card-label{display:flex;align-items:center;gap:8px;font-family:var(--font-mono);font-size:0.7rem;text-transform:uppercase;letter-spacing:0.14em;color:var(--text-dim);margin-bottom:0.7rem}
  input[type="text"],textarea{width:100%;background:var(--bg-input);border:1px solid rgba(0,229,255,0.12);border-radius:6px;color:var(--text);font-family:var(--font-mono);font-size:0.85rem;padding:0.65rem 0.9rem;outline:none;transition:border-color 0.2s,box-shadow 0.2s;resize:none}
  input[type="text"]:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(0,229,255,0.12)}
  textarea{height:80px;line-height:1.5}
  .file-row{display:flex;gap:8px}
  .file-row input{flex:1}
  .browse-btn{background:rgba(0,229,255,0.08);border:1px solid var(--border2);color:var(--accent);font-family:var(--font-mono);font-size:0.75rem;padding:0 14px;border-radius:6px;cursor:pointer;white-space:nowrap;transition:background 0.2s}
  .browse-btn:hover{background:rgba(0,229,255,0.15)}
  .scan-btn-wrap{margin:1.2rem 0;animation:fadeUp 0.8s 0.3s ease both}
  .scan-btn{width:100%;padding:1rem 2rem;background:transparent;border:2px solid var(--accent);border-radius:10px;color:var(--accent);font-family:var(--font-main);font-size:1rem;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;cursor:pointer;position:relative;overflow:hidden;transition:color 0.3s,box-shadow 0.3s}
  .scan-btn::before{content:'';position:absolute;inset:0;background:var(--accent);transform:translateX(-100%);transition:transform 0.35s cubic-bezier(0.4,0,0.2,1);z-index:0}
  .scan-btn:hover::before{transform:translateX(0)}
  .scan-btn:hover{color:var(--bg-deep);box-shadow:0 0 30px rgba(0,229,255,0.4)}
  .scan-btn span{position:relative;z-index:1}
  .results-section{animation:fadeUp 0.8s 0.35s ease both}
  .results-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem}
  .results-title{font-family:var(--font-mono);font-size:0.72rem;text-transform:uppercase;letter-spacing:0.14em;color:var(--text-dim)}
  .mode-badge{font-family:var(--font-mono);font-size:0.65rem;padding:2px 10px;border-radius:3px;letter-spacing:0.08em}
  .mode-backend{background:rgba(0,255,136,0.12);color:var(--safe);border:1px solid rgba(0,255,136,0.3)}
  .mode-local{background:rgba(255,214,0,0.12);color:var(--warn);border:1px solid rgba(255,214,0,0.3)}
  .clear-btn{background:none;border:1px solid var(--border);color:var(--text-muted);font-family:var(--font-mono);font-size:0.68rem;padding:3px 10px;border-radius:4px;cursor:pointer;transition:all 0.2s}
  .result-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:0.9rem;margin-bottom:1.2rem}
  .result-card{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:1rem 1.1rem;position:relative;overflow:hidden;transition:all 0.4s;opacity:0;transform:translateY(10px)}
  .result-card.show{opacity:1;transform:translateY(0)}
  .result-card.status-safe{border-color:rgba(0,255,136,0.3);box-shadow:0 0 12px rgba(0,255,136,0.1)}
  .result-card.status-danger{border-color:rgba(255,60,110,0.4);box-shadow:0 0 15px rgba(255,60,110,0.15)}
  .result-card.status-warn{border-color:rgba(255,214,0,0.35);box-shadow:0 0 12px rgba(255,214,0,0.1)}
  .result-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--accent2);transform:scaleX(0);transform-origin:left;transition:transform 0.5s ease}
  .result-card.status-safe::before{background:var(--safe);transform:scaleX(1)}
  .result-card.status-danger::before{background:var(--danger);transform:scaleX(1)}
  .result-card.status-warn::before{background:var(--warn);transform:scaleX(1)}
  .result-icon{font-size:1.4rem;margin-bottom:0.4rem;display:block}
  .result-name{font-family:var(--font-mono);font-size:0.65rem;text-transform:uppercase;letter-spacing:0.12em;color:var(--text-muted);margin-bottom:0.25rem}
  .result-status{font-size:0.88rem;font-weight:700}
  .result-card.status-safe .result-status{color:var(--safe)}
  .result-card.status-danger .result-status{color:var(--danger)}
  .result-card.status-warn .result-status{color:var(--warn)}
  .result-detail{font-family:var(--font-mono);font-size:0.67rem;color:var(--text-muted);margin-top:0.3rem;line-height:1.4}
  .result-score{font-family:var(--font-mono);font-size:0.62rem;color:var(--text-muted);margin-top:0.4rem}
  .log-terminal{background:var(--bg-input);border:1px solid var(--border);border-radius:10px;overflow:hidden}
  .terminal-bar{display:flex;align-items:center;gap:8px;padding:0.6rem 1rem;background:rgba(0,229,255,0.04);border-bottom:1px solid var(--border)}
  .t-dot{width:10px;height:10px;border-radius:50%}
  .t-dot.red{background:#ff5f57}.t-dot.yellow{background:#ffbd2e}.t-dot.green{background:#28ca41}
  .terminal-title{font-family:var(--font-mono);font-size:0.68rem;color:var(--text-muted);margin-left:4px}
  .terminal-body{padding:1rem 1.2rem;font-family:var(--font-mono);font-size:0.78rem;line-height:1.7;min-height:120px;max-height:260px;overflow-y:auto}
  .log-line.safe{color:var(--safe)}.log-line.danger{color:var(--danger)}.log-line.warn{color:var(--warn)}.log-line.info{color:var(--text-dim)}.log-line.accent{color:var(--accent)}
  .stats-strip{display:grid;grid-template-columns:repeat(4,1fr);gap:0.8rem;margin-top:1.5rem;animation:fadeUp 0.8s 0.45s ease both}
  @media(max-width:500px){.stats-strip{grid-template-columns:repeat(2,1fr)}}
  .stat-box{background:var(--bg-panel);border:1px solid var(--border);border-radius:8px;padding:0.8rem 0.9rem;text-align:center}
  .stat-num{font-size:1.5rem;font-weight:900;color:var(--accent);line-height:1}
  .stat-lbl{font-family:var(--font-mono);font-size:0.62rem;text-transform:uppercase;letter-spacing:0.12em;color:var(--text-muted);margin-top:4px}
  .history-section{margin-top:2rem}
  .history-title{font-family:var(--font-mono);font-size:0.7rem;text-transform:uppercase;letter-spacing:0.14em;color:var(--text-muted);margin-bottom:0.8rem}
  .history-list{display:flex;flex-direction:column;gap:6px;max-height:200px;overflow-y:auto}
  .history-item{display:flex;align-items:center;gap:10px;background:var(--bg-card);border:1px solid var(--border);border-radius:7px;padding:0.55rem 0.9rem;font-family:var(--font-mono);font-size:0.72rem;cursor:pointer;transition:border-color 0.2s}
  .history-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
  .history-text{flex:1;color:var(--text-dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .history-time{color:var(--text-muted)}
  .history-badge{font-size:0.65rem;padding:2px 8px;border-radius:3px;font-weight:600}
  .hb-safe{background:rgba(0,255,136,0.12);color:var(--safe)}
  .hb-danger{background:rgba(255,60,110,0.12);color:var(--danger)}
  .hb-warn{background:rgba(255,214,0,0.12);color:var(--warn)}
  .scan-overlay{position:fixed;inset:0;z-index:100;background:rgba(2,12,27,0.92);display:flex;flex-direction:column;align-items:center;justify-content:center;gap:1.5rem;opacity:0;pointer-events:none;transition:opacity 0.3s}
  .scan-overlay.active{opacity:1;pointer-events:all}
  .scan-ring{width:100px;height:100px;border-radius:50%;border:2px solid var(--border);border-top-color:var(--accent);border-right-color:var(--accent);animation:spin 0.8s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}
  .scan-text{font-family:var(--font-mono);font-size:0.85rem;color:var(--accent);letter-spacing:0.15em;text-transform:uppercase;animation:blink-txt 1s infinite}
  @keyframes blink-txt{0%,100%{opacity:1}50%{opacity:0.5}}
  .scan-progress{width:240px;height:3px;background:var(--border);border-radius:2px;overflow:hidden}
  .scan-bar{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:2px;animation:scan-progress 1.8s ease-in-out forwards}
  @keyframes scan-progress{from{width:0%}to{width:100%}}
  .alert-popup{position:fixed;top:1.5rem;right:1.5rem;z-index:200;max-width:320px;background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:1.1rem 1.3rem;transform:translateX(120%);transition:transform 0.4s cubic-bezier(0.34,1.56,0.64,1);box-shadow:0 20px 60px rgba(0,0,0,0.6)}
  .alert-popup.show{transform:translateX(0)}
  .alert-popup.danger-alert{border-color:rgba(255,60,110,0.5)}
  .alert-popup.safe-alert{border-color:rgba(0,255,136,0.4)}
  .alert-title{font-weight:700;font-size:0.95rem;margin-bottom:0.4rem}
  .danger-alert .alert-title{color:var(--danger)}
  .safe-alert .alert-title{color:var(--safe)}
  .alert-body{font-family:var(--font-mono);font-size:0.73rem;color:var(--text-dim);line-height:1.5}
  #fileInput{display:none}
  @keyframes fadeDown{from{opacity:0;transform:translateY(-16px)}to{opacity:1;transform:translateY(0)}}
  @keyframes fadeUp{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
</style>
</head>
<body>
<div class="scan-overlay" id="scanOverlay">
  <div class="scan-ring"></div>
  <div class="scan-text" id="scanStepText">Initializing scan...</div>
  <div class="scan-progress"><div class="scan-bar" id="scanBar"></div></div>
</div>
<div class="alert-popup" id="alertPopup">
  <div class="alert-title" id="alertTitle">Threat Detected</div>
  <div class="alert-body" id="alertBody"></div>
</div>
<div class="wrapper">
  <header>
    <div class="logo-row">
      <svg class="shield-icon" viewBox="0 0 48 48" fill="none">
        <path d="M24 4L6 12v12c0 11 8 20.7 18 23 10-2.3 18-12 18-23V12L24 4z" stroke="#00e5ff" stroke-width="2" fill="rgba(0,229,255,0.07)"/>
        <path d="M17 24l5 5 9-10" stroke="#00ff88" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <h1>Cyber<span>IDS</span></h1>
    </div>
    <div class="tagline">// Advanced Intrusion Detection System v2.0 — All-in-One //</div>
  </header>
  <div class="status-bar">
    <div class="status-dot"></div>
    <span>System <span class="s-item">ONLINE</span></span>
    <span>|</span>
    <span>Engine <span class="s-item">READY</span></span>
    <span>|</span>
    <span id="clockDisplay"></span>
    <span>|</span>
    <div class="backend-dot" id="backendDot"></div>
    <span id="backendStatus" style="color:var(--warn)">Checking backend...</span>
    <span style="margin-left:auto;">Scans: <span class="s-item" id="scanCount">0</span></span>
  </div>
  <div class="threat-meter">
    <div class="meter-header">
      <span class="meter-label">Threat Level</span>
      <span class="threat-level-badge" id="threatBadge">SAFE</span>
    </div>
    <div class="meter-track"><div class="meter-fill" id="meterFill"></div></div>
  </div>
  <div class="main-grid">
    <div class="input-card full">
      <div class="card-label">Message / SMS Content</div>
      <textarea id="messageInput" placeholder="Paste suspicious message, SMS, or call script here..."></textarea>
    </div>
    <div class="input-card">
      <div class="card-label">Email Address</div>
      <input type="text" id="emailInput" placeholder="suspicious@example.com"/>
    </div>
    <div class="input-card">
      <div class="card-label">URL / Link</div>
      <input type="text" id="urlInput" placeholder="https://suspicious-link.com/verify"/>
    </div>
    <div class="input-card">
      <div class="card-label">Phone Number</div>
      <input type="text" id="phoneInput" placeholder="+91-9999999999"/>
    </div>
    <div class="input-card">
      <div class="card-label">File Name / Path</div>
      <div class="file-row">
        <input type="text" id="fileInput2" placeholder="suspicious_file.exe"/>
        <button class="browse-btn" onclick="document.getElementById('fileInput').click()">Browse</button>
        <input type="file" id="fileInput" onchange="handleFileSelect(event)"/>
      </div>
    </div>
  </div>
  <div class="scan-btn-wrap">
    <button class="scan-btn" id="scanBtn" onclick="runScan()">
      <span id="scanBtnText">⟶ &nbsp;Run Security Scan</span>
    </button>
  </div>
  <div class="results-section">
    <div class="results-header">
      <span class="results-title">// Scan Results</span>
      <span class="mode-badge mode-local" id="modeBadge">LOCAL ENGINE</span>
      <button class="clear-btn" onclick="clearResults()">Clear</button>
    </div>
    <div class="result-cards" id="resultCards"></div>
    <div class="log-terminal">
      <div class="terminal-bar">
        <div class="t-dot red"></div><div class="t-dot yellow"></div><div class="t-dot green"></div>
        <span class="terminal-title">system.log — CyberIDS v2.0 All-in-One</span>
      </div>
      <div class="terminal-body" id="terminalLog">
        <span class="log-line info">[ SYS ] CyberIDS All-in-One engine initialized.</span><br>
        <span class="log-line info">[ SYS ] Java backend running at http://localhost:8080</span><br>
      </div>
    </div>
  </div>
  <div class="stats-strip">
    <div class="stat-box"><div class="stat-num" id="statTotal">0</div><div class="stat-lbl">Total Scans</div></div>
    <div class="stat-box"><div class="stat-num" style="color:var(--danger)" id="statDanger">0</div><div class="stat-lbl">Threats Found</div></div>
    <div class="stat-box"><div class="stat-num" style="color:var(--safe)" id="statSafe">0</div><div class="stat-lbl">Safe Scans</div></div>
    <div class="stat-box"><div class="stat-num" style="color:var(--warn)" id="statWarn">0</div><div class="stat-lbl">Warnings</div></div>
  </div>
  <div class="history-section">
    <div class="history-title">// Scan History</div>
    <div class="history-list" id="historyList">
      <div style="font-family:var(--font-mono);font-size:0.72rem;color:var(--text-muted);padding:0.5rem 0;">No scans yet.</div>
    </div>
  </div>
</div>
<script>
const stats={total:0,danger:0,safe:0,warn:0};
const history=[];
const API_BASE='http://localhost:8080/api';
let backendConnected=false;

async function checkBackend(){
  try{
    const res=await fetch(API_BASE+'/status',{signal:AbortSignal.timeout(2000)});
    if(res.ok){
      backendConnected=true;
      document.getElementById('backendStatus').textContent='JAVA BACKEND ONLINE';
      document.getElementById('backendStatus').style.color='var(--safe)';
      document.getElementById('backendDot').style.background='var(--safe)';
      document.getElementById('modeBadge').textContent='JAVA BACKEND';
      document.getElementById('modeBadge').className='mode-badge mode-backend';
      log('[ API ] Java backend connected','safe');
    }
  }catch{
    backendConnected=false;
    document.getElementById('backendStatus').textContent='OFFLINE (Local Mode)';
    document.getElementById('backendStatus').style.color='var(--warn)';
    log('[ API ] Using built-in local engine','warn');
  }
}

function updateClock(){
  document.getElementById('clockDisplay').textContent=new Date().toLocaleTimeString('en-GB',{hour12:false});
}
setInterval(updateClock,1000);updateClock();

function handleFileSelect(e){
  const f=e.target.files[0];
  if(f)document.getElementById('fileInput2').value=f.name;
}

function log(msg,type='info'){
  const t=document.getElementById('terminalLog');
  const ts=new Date().toLocaleTimeString('en-GB',{hour12:false});
  const s=document.createElement('span');
  s.className='log-line '+type;
  s.textContent='['+ts+'] '+msg;
  t.appendChild(s);t.appendChild(document.createElement('br'));
  t.scrollTop=t.scrollHeight;
}

function clearResults(){
  document.getElementById('resultCards').innerHTML='';
  document.getElementById('terminalLog').innerHTML='<span class="log-line info">[ SYS ] Cleared.</span><br>';
  setMeter(0);
}

function setMeter(pct){
  const fill=document.getElementById('meterFill');
  const badge=document.getElementById('threatBadge');
  fill.style.width=pct+'%';
  if(pct===0){fill.style.background='linear-gradient(90deg,var(--safe),#00c875)';badge.className='threat-level-badge';badge.textContent='SAFE';}
  else if(pct<30){fill.style.background='linear-gradient(90deg,var(--safe),var(--warn))';badge.className='threat-level-badge medium';badge.textContent='LOW RISK';}
  else if(pct<60){fill.style.background='linear-gradient(90deg,var(--warn),#ff8c00)';badge.className='threat-level-badge medium';badge.textContent='MEDIUM';}
  else{fill.style.background='linear-gradient(90deg,#ff8c00,var(--danger))';badge.className='threat-level-badge high';badge.textContent='HIGH RISK';}
}

function showAlert(type,title,body){
  const p=document.getElementById('alertPopup');
  p.className='alert-popup '+(type==='danger'?'danger-alert':'safe-alert');
  document.getElementById('alertTitle').textContent=title;
  document.getElementById('alertBody').textContent=body;
  p.classList.add('show');
  setTimeout(()=>p.classList.remove('show'),4500);
}

function addResultCard(id,icon,label,status,detail,score,delay){
  const cards=document.getElementById('resultCards');
  const card=document.createElement('div');
  card.className='result-card status-'+status;
  const st=status==='safe'?'SAFE':status==='danger'?'THREAT':'WARNING';
  card.innerHTML='<span class="result-icon">'+icon+'</span>'
    +'<div class="result-name">'+label+'</div>'
    +'<div class="result-status">'+st+'</div>'
    +'<div class="result-detail">'+detail+'</div>'
    +(score!==undefined?'<div class="result-score">Score: '+score+'/100</div>':'');
  cards.appendChild(card);
  setTimeout(()=>card.classList.add('show'),delay);
}

// Local engine
function analyzeMessage(msg){
  if(!msg)return{status:'safe',detail:'No message provided',score:0};
  const m=msg.toLowerCase();
  const patterns=[
    {re:/urgent|immediate action|act now|expires today/,label:'urgency trigger',pts:25},
    {re:/lottery|you won|prize|reward/,label:'lottery scam',pts:35},
    {re:/verify account|confirm.*account/,label:'phishing',pts:30},
    {re:/free money|send money|wire transfer/,label:'financial scam',pts:30},
    {re:/otp|one.time.password/,label:'OTP scam',pts:30},
    {re:/bank call|account blocked|suspended/,label:'vishing',pts:25},
  ];
  const hits=patterns.filter(p=>p.re.test(m));
  const score=Math.min(hits.reduce((s,h)=>s+h.pts,0),100);
  if(score>=50)return{status:'danger',detail:'Patterns: '+hits.slice(0,3).map(h=>h.label).join(', '),score};
  if(score>0)return{status:'warn',detail:'Pattern: '+hits[0].label,score};
  return{status:'safe',detail:'No suspicious patterns',score:0};
}
function analyzeEmail(email){
  if(!email)return{status:'safe',detail:'No email provided',score:0};
  if(!/^[a-zA-Z0-9._%+\\-]+@[a-z0-9.\\-]+\\.[a-z]{2,6}$/.test(email))return{status:'danger',detail:'Invalid/spoofed format',score:60};
  if(/(secur|verify|alert|update|account).*@/.test(email.toLowerCase())||/\\.(ru|cn|xyz|top|click|tk)$/.test(email.toLowerCase()))return{status:'warn',detail:'Suspicious domain/prefix',score:35};
  return{status:'safe',detail:'Valid email format',score:0};
}
function analyzeURL(url){
  if(!url)return{status:'safe',detail:'No URL provided',score:0};
  const u=url.toLowerCase();let score=0;const flags=[];
  if(!u.startsWith('https')){score+=20;flags.push('no HTTPS');}
  if(u.includes('bit.ly')||u.includes('tinyurl')||u.includes('t.co')){score+=40;flags.push('shortened URL');}
  if(/https?:\\/\\/\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/.test(u)){score+=45;flags.push('IP hostname');}
  if(/login|verify|secure|account|update|confirm|bank/.test(u)){score+=30;flags.push('phishing keywords');}
  score=Math.min(score,100);
  if(score>=50)return{status:'danger',detail:'Flags: '+flags.join(', '),score};
  if(score>0)return{status:'warn',detail:'Concern: '+flags[0],score};
  return{status:'safe',detail:'URL appears legitimate',score:0};
}
function analyzeFile(fname){
  if(!fname)return{status:'safe',detail:'No file provided',score:0};
  const f=fname.toLowerCase();
  if(/\\.(jpg|pdf|doc|txt|png)\\.(exe|bat|cmd|vbs|ps1)$/.test(f))return{status:'danger',detail:'Double extension — disguised malware',score:90};
  if(f.endsWith('.exe')||f.endsWith('.bat')||f.endsWith('.cmd'))return{status:'danger',detail:'Executable file',score:60};
  if(f.endsWith('.vbs')||f.endsWith('.ps1')||f.endsWith('.sh'))return{status:'danger',detail:'Script file — potential threat',score:55};
  if(f.endsWith('.zip')||f.endsWith('.rar'))return{status:'warn',detail:'Archive — contents unknown',score:20};
  return{status:'safe',detail:'File extension appears safe',score:0};
}
function analyzePhone(phone){
  if(!phone)return{status:'safe',detail:'No number provided',score:0};
  const p=phone.replace(/[\\s\\-()]/g,'');
  if(/^(\\+91|0)?[6-9]\\d{9}$/.test(p))return{status:'safe',detail:'Valid Indian mobile number',score:0};
  if(/^\\+1\\d{10}$/.test(p))return{status:'safe',detail:'Valid US number',score:0};
  if(p.length<7||/(.)\\1{5,}/.test(p))return{status:'danger',detail:'Suspicious/spoofed number',score:55};
  return{status:'warn',detail:'Unrecognized format',score:20};
}

async function scanWithBackend(message,email,url,file,phone){
  const res=await fetch(API_BASE+'/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message,email,url,file,phone}),signal:AbortSignal.timeout(5000)});
  const data=await res.json();
  const conv=(r)=>({status:r.level==='SAFE'?'safe':(r.level==='LOW'||r.level==='MEDIUM')?'warn':'danger',detail:r.detail,score:r.score});
  return{message:conv(data.message),email:conv(data.email),url:conv(data.url),file:conv(data.file),phone:conv(data.phone)};
}

async function runScan(){
  const overlay=document.getElementById('scanOverlay');
  const stepText=document.getElementById('scanStepText');
  overlay.classList.add('active');
  const steps=['Initializing engine...','Scanning patterns...','Validating inputs...','Analyzing threats...','Generating report...'];
  for(const s of steps){stepText.textContent=s;await new Promise(r=>setTimeout(r,250));}
  overlay.classList.remove('active');

  const message=document.getElementById('messageInput').value.trim();
  const email=document.getElementById('emailInput').value.trim();
  const url=document.getElementById('urlInput').value.trim();
  const file=document.getElementById('fileInput2').value.trim();
  const phone=document.getElementById('phoneInput').value.trim();
  document.getElementById('resultCards').innerHTML='';

  let results;
  if(backendConnected){
    try{
      log('[ API ] Sending to Java backend...','accent');
      const d=await scanWithBackend(message,email,url,file,phone);
      results=[{id:'msg',label:'Message',r:d.message},{id:'email',label:'Email',r:d.email},{id:'url',label:'URL',r:d.url},{id:'file',label:'File',r:d.file},{id:'phone',label:'Phone',r:d.phone}];
      log('[ API ] Backend response received','safe');
    }catch(err){
      log('[ API ] Backend error — using local engine','warn');
      backendConnected=false;
      results=buildLocal(message,email,url,file,phone);
    }
  }else{
    results=buildLocal(message,email,url,file,phone);
  }

  const icons={safe:'✔',danger:'✘',warn:'⚠'};
  results.forEach((item,i)=>{
    addResultCard(item.id,icons[item.r.status],item.label,item.r.status,item.r.detail,item.r.score,i*80);
    log('['+item.label.toUpperCase()+'] '+item.r.detail+(item.r.score?' (Score:'+item.r.score+')':''),item.r.status==='safe'?'safe':item.r.status==='danger'?'danger':'warn');
  });

  const dc=results.filter(r=>r.r.status==='danger').length;
  const wc=results.filter(r=>r.r.status==='warn').length;
  setMeter(Math.min(100,dc*22+wc*10));
  stats.total++;
  if(dc>0)stats.danger++;else if(wc>0)stats.warn++;else stats.safe++;
  document.getElementById('statTotal').textContent=stats.total;
  document.getElementById('statDanger').textContent=stats.danger;
  document.getElementById('statSafe').textContent=stats.safe;
  document.getElementById('statWarn').textContent=stats.warn;
  document.getElementById('scanCount').textContent=stats.total;

  if(dc>0)showAlert('danger','⚠ Threat Detected',dc+' threat(s) found.');
  else if(wc>0)showAlert('safe','⚡ Warnings Found',wc+' warning(s) need attention.');
  else showAlert('safe','✔ All Clear','No threats detected.');

  const label=message||email||url||file||phone||'Empty scan';
  const badge=dc>0?'hb-danger':wc>0?'hb-warn':'hb-safe';
  const badgeTxt=dc>0?'THREAT':wc>0?'WARN':'SAFE';
  const dotColor=dc>0?'var(--danger)':wc>0?'var(--warn)':'var(--safe)';
  history.unshift({label,badge,badgeTxt,dotColor,ts:new Date().toLocaleTimeString('en-GB',{hour12:false})});
  renderHistory();
}

function buildLocal(message,email,url,file,phone){
  return[{id:'msg',label:'Message',r:analyzeMessage(message)},{id:'email',label:'Email',r:analyzeEmail(email)},{id:'url',label:'URL',r:analyzeURL(url)},{id:'file',label:'File',r:analyzeFile(file)},{id:'phone',label:'Phone',r:analyzePhone(phone)}];
}

function renderHistory(){
  const list=document.getElementById('historyList');
  if(history.length===0){list.innerHTML='<div style="font-family:var(--font-mono);font-size:0.72rem;color:var(--text-muted);padding:0.5rem 0;">No scans yet.</div>';return;}
  list.innerHTML=history.slice(0,15).map(h=>
    '<div class="history-item"><div class="history-dot" style="background:'+h.dotColor+'"></div>'
    +'<span class="history-text">'+h.label.slice(0,50)+'</span>'
    +'<span class="history-time">'+h.ts+'</span>'
    +'<span class="history-badge '+h.badge+'">'+h.badgeTxt+'</span></div>'
  ).join('');
}

checkBackend();
setInterval(checkBackend,15000);
</script>
</body>
</html>
""";
}