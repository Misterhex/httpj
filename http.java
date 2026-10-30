import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.SecureRandom;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.cert.CertificateFactory;
import java.io.ByteArrayInputStream;
import java.util.Base64;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.security.cert.X509Certificate;

class http {
    record Header(String name, String value) {}

    public static void main(String[] args) {
        try {
            run(args);
        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(2);
        } catch (Exception e) {
            System.err.println("Request failed: " + e.getMessage());
            System.exit(1);
        }
    }

    static void run(String[] args) throws Exception {
        if (args.length == 0 || List.of("--help", "-h").contains(args[0])) {
            usage();
            return;
        }
        if (args.length < 2) throw new IllegalArgumentException("Expected METHOD URL. Use --help.");
        String method = args[0].toUpperCase(Locale.ROOT);
        if (!method.matches("[A-Z]+")) throw new IllegalArgumentException("Invalid HTTP method");
        URI url = URI.create(args[1]);
        requireHttp(url);

        var headers = new ArrayList<Header>();
        String data = null, file = null, cert = null, key = null, cacert = null;
        boolean insecure = false, showHeaders = false, follow = false, raw = false;
        int timeoutSeconds = 30;
        for (int i = 2; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "-H", "--header" -> {
                    String h = next(args, ++i, arg);
                    int colon = h.indexOf(':');
                    if (colon < 1) throw new IllegalArgumentException("Header must be 'Name: value'");
                    headers.add(new Header(h.substring(0, colon).trim(), h.substring(colon + 1).trim()));
                }
                case "-d", "--data" -> data = next(args, ++i, arg);
                case "-f", "--file" -> file = next(args, ++i, arg);
                case "--cert" -> cert = next(args, ++i, arg);
                case "--key" -> key = next(args, ++i, arg);
                case "--cacert" -> cacert = next(args, ++i, arg);
                case "-k", "--insecure" -> insecure = true;
                case "-i", "--include" -> showHeaders = true;
                case "-L", "--location" -> follow = true;
                case "--raw" -> raw = true;
                case "--timeout" -> {
                    try { timeoutSeconds = Integer.parseInt(next(args, ++i, arg)); }
                    catch (NumberFormatException e) { throw new IllegalArgumentException("Timeout must be an integer"); }
                    if (timeoutSeconds <= 0) throw new IllegalArgumentException("Timeout must be positive");
                }
                default -> throw new IllegalArgumentException("Unknown option: " + arg);
            }
        }
        int bodyOptions = (data != null ? 1 : 0) + (file != null ? 1 : 0);
        if (bodyOptions > 1) throw new IllegalArgumentException("Choose only one of -d, -f");

        if ((cert == null) != (key == null)) throw new IllegalArgumentException("--cert and --key must be used together");
        // Must be set before HttpClient is initialized. Only affects this JVM process.
        if (insecure) System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
        HttpClient.Builder builder = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(timeoutSeconds))
                .followRedirects(follow ? HttpClient.Redirect.NORMAL : HttpClient.Redirect.NEVER);
        if (insecure || cert != null || cacert != null) {
            javax.net.ssl.KeyManager[] keyManagers = null;
            if (cert != null) {
                var certificates = certificates(Path.of(cert));
                String pem = Files.readString(Path.of(key));
                PrivateKey privateKey = readKey(pem);
                KeyStore store = KeyStore.getInstance("PKCS12");
                store.load(null, null);
                store.setKeyEntry("client", privateKey, new char[0], certificates);
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(store, new char[0]);
                keyManagers = kmf.getKeyManagers();
            }
            TrustManager[] trustManagers = null;
            if (insecure) {
                trustManagers = new TrustManager[]{new X509TrustManager() {
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                }};
            } else if (cacert != null) {
                KeyStore store = KeyStore.getInstance("PKCS12");
                store.load(null, null);
                int index = 0;
                for (var ca : certificates(Path.of(cacert))) store.setCertificateEntry("ca-" + index++, ca);
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(store);
                trustManagers = tmf.getTrustManagers();
            }
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keyManagers, trustManagers, new SecureRandom());
            builder.sslContext(context);
        }
        try (HttpClient client = builder.build()) {
            byte[] body = null;
            if (data != null) body = data.getBytes(StandardCharsets.UTF_8);
            if (file != null) body = Files.readAllBytes(Path.of(file));
            HttpRequest.Builder request = HttpRequest.newBuilder(url).timeout(Duration.ofSeconds(timeoutSeconds));
            for (Header h : headers) request.header(h.name(), h.value());
            request.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body));
            HttpResponse<byte[]> response = client.send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
            System.err.println("HTTP " + response.statusCode());
            if (showHeaders) response.headers().map().forEach((name, values) ->
                    values.forEach(value -> System.out.println(name + ": " + value)));
            if (showHeaders) System.out.println();
            byte[] bytes = response.body();
            String contentType = response.headers().firstValue("content-type").orElse("").toLowerCase(Locale.ROOT);
            if (!raw && (contentType.contains("json") || looksLikeJson(bytes))) {
                String input = new String(bytes, StandardCharsets.UTF_8);
                try { System.out.println(JsonPretty.format(input)); }
                catch (IllegalArgumentException ex) { System.out.write(bytes); }
            } else {
                System.out.write(bytes);
            }
            System.out.flush();
            if (response.statusCode() >= 400) System.exit(22);
        }
    }

    static X509Certificate[] certificates(Path path) throws Exception {
        var factory = CertificateFactory.getInstance("X.509");
        var parsed = factory.generateCertificates(new ByteArrayInputStream(Files.readAllBytes(path)));
        if (parsed.isEmpty()) throw new IllegalArgumentException("No certificates found: " + path);
        return parsed.stream().map(c -> (X509Certificate)c).toArray(X509Certificate[]::new);
    }

    static PrivateKey readKey(String pem) throws Exception {
        String begin = "-----BEGIN PRIVATE KEY-----";
        String end = "-----END PRIVATE KEY-----";
        int a = pem.indexOf(begin), b = pem.indexOf(end);
        if (a < 0 || b < a) throw new IllegalArgumentException("Private key must be unencrypted PKCS#8 PEM (BEGIN PRIVATE KEY). Convert with openssl pkcs8 -topk8 -nocrypt");
        byte[] bytes = Base64.getMimeDecoder().decode(pem.substring(a + begin.length(), b));
        var spec = new PKCS8EncodedKeySpec(bytes);
        for (String algorithm : List.of("RSA", "EC", "Ed25519", "Ed448")) {
            try { return KeyFactory.getInstance(algorithm).generatePrivate(spec); }
            catch (java.security.spec.InvalidKeySpecException ignored) {}
        }
        throw new IllegalArgumentException("Unsupported PKCS#8 private key algorithm");
    }

    static boolean looksLikeJson(byte[] bytes) {
        String s = new String(bytes, StandardCharsets.UTF_8).stripLeading();
        return s.startsWith("{") || s.startsWith("[");
    }
    static void requireHttp(URI uri) {
        if (uri.getScheme() == null || !(uri.getScheme().equalsIgnoreCase("http") || uri.getScheme().equalsIgnoreCase("https")))
            throw new IllegalArgumentException("Only http:// and https:// URLs are supported");
        if (uri.getHost() == null) throw new IllegalArgumentException("Invalid URL host");
    }
    static String next(String[] args, int index, String option) {
        if (index >= args.length) throw new IllegalArgumentException("Missing value for " + option);
        return args[index];
    }
    static void usage() {
        System.out.println("""
                HTTP CLI for Java 21 (zero dependencies)
                Usage: java http.java METHOD URL [options]
                  -H, --header 'Name: value'   Add request header (repeatable)
                  -d, --data TEXT              Request body as text
                  -f, --file PATH              Request body from local file
                      --cert PATH              Client certificate chain (PEM)
                      --key PATH               Client private key (unencrypted PKCS#8 PEM)
                      --cacert PATH            Trusted server CA certificates (PEM)
                  -k, --insecure               Disable TLS certificate and hostname verification
                  -i, --include                Print response headers
                  -L, --location               Follow redirects
                      --raw                    Disable JSON formatting
                      --timeout SECONDS        Connect/request timeout (default: 30)
                  -h, --help                   Show this help
                Exit codes: 0 success, 1 transport error, 2 usage error, 22 HTTP 4xx/5xx
                """);
    }

    // Minimal strict JSON parser + pretty-printer: no external JSON library.
    static final class JsonPretty {
        private final String s;
        private int pos;
        private final StringBuilder out = new StringBuilder();
        private int depth;
        private JsonPretty(String s) { this.s = s; }
        static String format(String input) {
            JsonPretty p = new JsonPretty(input);
            p.ws(); p.value(); p.ws();
            if (p.pos != input.length()) throw new IllegalArgumentException("Trailing JSON data");
            return p.out.toString();
        }
        void ws() { while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) pos++; }
        char peek() { if (pos >= s.length()) throw new IllegalArgumentException("Unexpected JSON end"); return s.charAt(pos); }
        void expect(char c) { if (peek() != c) throw new IllegalArgumentException("Expected " + c); pos++; }
        void indent() { out.append("  ".repeat(depth)); }
        void value() {
            ws(); char c = peek();
            if (c == '{' || c == '[') { collection(c); return; }
            if (c == '"') { string(); return; }
            if (c == 't') { literal("true"); return; }
            if (c == 'f') { literal("false"); return; }
            if (c == 'n') { literal("null"); return; }
            number();
        }
        void collection(char open) {
            boolean object = open == '{'; char close = object ? '}' : ']';
            expect(open); out.append(open); ws();
            if (peek() == close) { pos++; out.append(close); return; }
            out.append('\n'); depth++;
            while (true) {
                indent();
                if (object) { ws(); string(); ws(); expect(':'); out.append(": "); }
                value(); ws();
                if (peek() == close) { pos++; break; }
                expect(','); out.append(",\n"); ws();
            }
            depth--; out.append('\n'); indent(); out.append(close);
        }
        void string() {
            int start = pos; expect('"');
            while (true) {
                char c = peek(); pos++;
                if (c == '"') break;
                if (c < 0x20) throw new IllegalArgumentException("Invalid JSON string");
                if (c == '\\') {
                    char esc = peek(); pos++;
                    if ("\"\\/bfnrt".indexOf(esc) >= 0) continue;
                    if (esc != 'u' || pos + 4 > s.length()) throw new IllegalArgumentException("Invalid JSON escape");
                    for (int j = 0; j < 4; j++)
                        if (Character.digit(s.charAt(pos++), 16) < 0) throw new IllegalArgumentException("Invalid Unicode escape");
                }
            }
            out.append(s, start, pos);
        }
        void literal(String token) {
            if (!s.startsWith(token, pos)) throw new IllegalArgumentException("Invalid JSON literal");
            pos += token.length(); out.append(token);
        }
        void number() {
            int start = pos;
            if (peek() == '-') pos++;
            if (peek() == '0') pos++;
            else { if (peek() < '1' || peek() > '9') throw new IllegalArgumentException("Invalid JSON number");
                while (pos < s.length() && Character.isDigit(s.charAt(pos))) pos++; }
            if (pos < s.length() && s.charAt(pos) == '.') {
                pos++; int before = pos;
                while (pos < s.length() && Character.isDigit(s.charAt(pos))) pos++;
                if (before == pos) throw new IllegalArgumentException("Invalid decimal");
            }
            if (pos < s.length() && (s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) {
                pos++; if (pos < s.length() && (s.charAt(pos) == '+' || s.charAt(pos) == '-')) pos++;
                int before = pos;
                while (pos < s.length() && Character.isDigit(s.charAt(pos))) pos++;
                if (before == pos) throw new IllegalArgumentException("Invalid exponent");
            }
            out.append(s, start, pos);
        }
    }
}
