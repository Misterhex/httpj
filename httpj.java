import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.InetAddress;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/** Single-file HTTP client entry point: java httpj.java METHOD URL [options]. */
class httpj {
    public static void main(String[] args) {
        if (args.length == 0 || List.of("--help", "-h").contains(args[0])) {
            CliOptions.usage();
            return;
        }

        int exitCode;
        try {
            var options = CliOptions.parse(args);
            var response = HttpExecutor.execute(options);
            ResponsePrinter.print(response, options);
            exitCode = response.statusCode() >= 400 ? 22 : 0;
        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            exitCode = 2;
        } catch (Exception e) {
            System.err.println("Request failed (" + e.getClass().getSimpleName() + "): " + e);
            exitCode = 1;
        }
        if (exitCode != 0) System.exit(exitCode);
    }
}

record Header(String name, String value) {}

/** Immutable command-line configuration and its parsing/validation. */
record CliOptions(
        String method, URI url, List<Header> headers, String data, Path file,
        Path cert, Path key, Path caCert, boolean insecure, boolean showHeaders,
        boolean follow, boolean raw, Duration timeout, ResolveOverride resolve) {

    static CliOptions parse(String[] args) {
        if (args.length < 2) throw new IllegalArgumentException("Expected METHOD URL. Use --help.");
        String method = args[0].toUpperCase(Locale.ROOT);
        if (!method.matches("[A-Z]+")) throw new IllegalArgumentException("Invalid HTTP method");

        URI url = URI.create(args[1]);
        if (url.getScheme() == null ||
                !List.of("http", "https").contains(url.getScheme().toLowerCase(Locale.ROOT)) ||
                url.getHost() == null) {
            throw new IllegalArgumentException("Expected an http:// or https:// URL with a valid host");
        }

        var headers = new ArrayList<Header>();
        String data = null;
        Path file = null, cert = null, key = null, caCert = null;
        ResolveOverride resolve = null;
        boolean insecure = false, showHeaders = false, follow = false, raw = false;
        int timeoutSeconds = 30;

        for (int i = 2; i < args.length; i++) {
            String option = args[i];
            switch (option) {
                case "-H", "--header" -> {
                    String header = value(args, ++i, option);
                    int colon = header.indexOf(':');
                    if (colon < 1) throw new IllegalArgumentException("Header must be 'Name: value'");
                    headers.add(new Header(header.substring(0, colon).trim(), header.substring(colon + 1).trim()));
                }
                case "-d", "--data" -> data = value(args, ++i, option);
                case "-f", "--file" -> file = Path.of(value(args, ++i, option));
                case "--cert" -> cert = Path.of(value(args, ++i, option));
                case "--key" -> key = Path.of(value(args, ++i, option));
                case "--cacert" -> caCert = Path.of(value(args, ++i, option));
                case "--resolve" -> {
                    if (resolve != null) throw new IllegalArgumentException("Only one --resolve is supported");
                    resolve = ResolveOverride.parse(value(args, ++i, option), url);
                }
                case "-k", "--insecure" -> insecure = true;
                case "-i", "--include" -> showHeaders = true;
                case "-L", "--location" -> follow = true;
                case "--raw" -> raw = true;
                case "--timeout" -> {
                    try { timeoutSeconds = Integer.parseInt(value(args, ++i, option)); }
                    catch (NumberFormatException e) { throw new IllegalArgumentException("Timeout must be an integer"); }
                    if (timeoutSeconds <= 0) throw new IllegalArgumentException("Timeout must be positive");
                }
                default -> throw new IllegalArgumentException("Unknown option: " + option);
            }
        }
        if (data != null && file != null) throw new IllegalArgumentException("Choose only one of -d, -f");
        if ((cert == null) != (key == null)) throw new IllegalArgumentException("--cert and --key must be used together");

        return new CliOptions(method, url, List.copyOf(headers), data, file, cert, key,
                caCert, insecure, showHeaders, follow, raw, Duration.ofSeconds(timeoutSeconds), resolve);
    }

    private static String value(String[] args, int index, String option) {
        if (index >= args.length) throw new IllegalArgumentException("Missing value for " + option);
        return args[index];
    }

    static void usage() {
        System.out.println("""
                HTTP CLI for Java 21+ (zero dependencies)
                Usage: java httpj.java METHOD URL [options]
                  -H, --header 'Name: value'   Add request header (repeatable)
                  -d, --data TEXT              Request body as text
                  -f, --file PATH              Request body from local file
                      --cert PATH              Client certificate chain (PEM)
                      --key PATH               Client private key (unencrypted PKCS#8 PEM)
                      --cacert PATH            Trusted server CA certificates (PEM)
                      --resolve HOST:PORT:IP   Connect to IP for the URL hostname (IPv6: [::1])
                  -k, --insecure               Disable TLS certificate and hostname verification
                  -i, --include                Print response headers
                  -L, --location               Follow redirects
                      --raw                    Disable JSON formatting
                      --timeout SECONDS        Connect/request timeout (default: 30)
                  -h, --help                   Show this help
                Exit codes: 0 success, 1 transport error, 2 usage error, 22 HTTP 4xx/5xx
                """);
    }
}

/** Request construction and HTTP transport only. */
final class HttpExecutor {
    private HttpExecutor() {}

    static HttpResponse<byte[]> execute(CliOptions options) throws Exception {
        // jdk.net.hosts.file is a JVM-wide override; scope it to this one-shot invocation.
        try (var dns = ResolveOverride.install(options.resolve())) {
            var builder = HttpClient.newBuilder()
                    .connectTimeout(options.timeout())
                    .followRedirects(options.follow() ? HttpClient.Redirect.NORMAL : HttpClient.Redirect.NEVER);
            TlsSupport.configure(builder, options);

            try (var client = builder.build()) {
                var request = HttpRequest.newBuilder(options.url()).timeout(options.timeout());
                for (var header : options.headers()) request.header(header.name(), header.value());

                HttpRequest.BodyPublisher body = options.file() != null
                        ? HttpRequest.BodyPublishers.ofFile(options.file())
                        : options.data() != null
                            ? HttpRequest.BodyPublishers.ofString(options.data(), StandardCharsets.UTF_8)
                            : HttpRequest.BodyPublishers.noBody();
                return client.send(request.method(options.method(), body).build(),
                        HttpResponse.BodyHandlers.ofByteArray());
            }
        }
    }
}

/** One-shot hostname override. Preserves URI host for TLS verification, SNI, and Host header. */
final class ResolveOverride implements AutoCloseable {
    private static final String PROPERTY = "jdk.net.hosts.file";
    private final String host, address;
    private final Path temporaryFile;
    private final String previous;

    private ResolveOverride(String host, String address, Path temporaryFile, String previous) {
        this.host = host;
        this.address = address;
        this.temporaryFile = temporaryFile;
        this.previous = previous;
    }

    static ResolveOverride parse(String value, URI url) {
        String[] parts = value.split(":", 3);
        if (parts.length != 3 || parts[0].isBlank() || parts[1].isBlank() || parts[2].isBlank()) {
            throw new IllegalArgumentException("--resolve expects HOST:PORT:IP (IPv6: HOST:PORT:[::1])");
        }
        if (!parts[0].equalsIgnoreCase(url.getHost())) {
            throw new IllegalArgumentException("--resolve hostname must match the URL hostname");
        }
        int port;
        try { port = Integer.parseInt(parts[1]); }
        catch (NumberFormatException e) { throw new IllegalArgumentException("Invalid --resolve port"); }
        int targetPort = url.getPort() >= 0 ? url.getPort()
                : url.getScheme().equalsIgnoreCase("https") ? 443 : 80;
        if (port < 1 || port > 65535 || port != targetPort) {
            throw new IllegalArgumentException("--resolve port must match the URL port (" + targetPort + ")");
        }
        String ip = parts[2];
        boolean brackets = ip.startsWith("[") && ip.endsWith("]");
        if (brackets) ip = ip.substring(1, ip.length() - 1);
        boolean ipv4 = ip.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}");
        boolean ipv6 = brackets && ip.contains(":") && ip.matches("[0-9A-Fa-f:.]+");
        if (!ipv4 && !ipv6) throw new IllegalArgumentException("--resolve IP must be an IPv4 literal or bracketed IPv6 literal");
        if (ipv4) {
            for (String octet : ip.split("\\.")) {
                if (Integer.parseInt(octet) > 255)
                    throw new IllegalArgumentException("Invalid --resolve IPv4 address: " + ip);
            }
        }
        // Do not call InetAddress here: JDK reads jdk.net.hosts.file on first resolution.
        return new ResolveOverride(parts[0], ip, null, null);
    }

    static ResolveOverride install(ResolveOverride config) throws IOException {
        if (config == null) return null; // Null is allowed in try-with-resources.
        Path temp = Files.createTempFile("httpj-hosts-", ".txt");
        String previousProperty = System.getProperty(PROPERTY);
        try {
            Files.writeString(temp, config.address + " " + config.host + System.lineSeparator());
            System.setProperty(PROPERTY, temp.toString());
            // Validate the literal *after* selecting the hosts-file resolver.
            InetAddress ip = InetAddress.getByName(config.address);
            boolean ipv6 = config.address.contains(":");
            if (ip.getAddress().length != (ipv6 ? 16 : 4)) {
                throw new IllegalArgumentException("Invalid --resolve IP: " + config.address);
            }
            return new ResolveOverride(config.host, config.address, temp, previousProperty);
        } catch (Exception e) {
            if (config != null) {
                if (previousProperty == null) System.clearProperty(PROPERTY);
                else System.setProperty(PROPERTY, previousProperty);
            }
            Files.deleteIfExists(temp);
            if (e instanceof java.net.UnknownHostException) {
                throw new IllegalArgumentException("Invalid --resolve IP: " + config.address, e);
            }
            throw e;
        }
    }

    @Override public void close() throws IOException {
        if (temporaryFile == null) return;
        if (previous == null) System.clearProperty(PROPERTY);
        else System.setProperty(PROPERTY, previous);
        Files.deleteIfExists(temporaryFile);
    }
}

/** Loads PEM identity/CA certificates and configures TLS. */
final class TlsSupport {
    private TlsSupport() {}

    static void configure(HttpClient.Builder builder, CliOptions options) throws Exception {
        if (!options.insecure() && options.cert() == null && options.caCert() == null) return;

        // JDK HttpClient's implementation-specific option is JVM-wide; this CLI is a one-shot process.
        // Only use -k for testing trusted endpoints, never for production traffic.
        if (options.insecure()) {
            System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
        }

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(clientIdentity(options), serverTrust(options), new SecureRandom());
        builder.sslContext(context);
    }

    private static KeyManager[] clientIdentity(CliOptions options) throws Exception {
        if (options.cert() == null) return null;
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setKeyEntry("client", readKey(options.key()), new char[0], certificates(options.cert()));
        KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(store, new char[0]);
        return factory.getKeyManagers();
    }

    private static TrustManager[] serverTrust(CliOptions options) throws Exception {
        if (options.insecure()) {
            return new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }};
        }
        if (options.caCert() == null) return null; // Use JVM default trust store.

        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        int i = 0;
        for (var ca : certificates(options.caCert())) store.setCertificateEntry("ca-" + i++, ca);
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(store);
        return factory.getTrustManagers();
    }

    private static X509Certificate[] certificates(Path path) throws Exception {
        var factory = CertificateFactory.getInstance("X.509");
        var parsed = factory.generateCertificates(new ByteArrayInputStream(Files.readAllBytes(path)));
        if (parsed.isEmpty()) throw new IllegalArgumentException("No certificates found: " + path);
        return parsed.stream().map(c -> (X509Certificate) c).toArray(X509Certificate[]::new);
    }

    private static PrivateKey readKey(Path path) throws Exception {
        String pem = Files.readString(path);
        String begin = "-----BEGIN PRIVATE KEY-----", end = "-----END PRIVATE KEY-----";
        int from = pem.indexOf(begin), to = pem.indexOf(end);
        if (from < 0 || to <= from) {
            throw new IllegalArgumentException("Private key must be unencrypted PKCS#8 PEM (BEGIN PRIVATE KEY)");
        }
        byte[] bytes = Base64.getMimeDecoder().decode(pem.substring(from + begin.length(), to));
        var spec = new PKCS8EncodedKeySpec(bytes);
        for (String algorithm : List.of("RSA", "EC", "Ed25519", "Ed448")) {
            try { return KeyFactory.getInstance(algorithm).generatePrivate(spec); }
            catch (InvalidKeySpecException ignored) {}
        }
        throw new IllegalArgumentException("Unsupported PKCS#8 private key algorithm");
    }
}

/** Response status, headers, pretty JSON, and binary-safe output. */
final class ResponsePrinter {
    private ResponsePrinter() {}

    static void print(HttpResponse<byte[]> response, CliOptions options) throws IOException {
        System.err.println("HTTP " + response.statusCode());
        if (options.showHeaders()) {
            response.headers().map().forEach((name, values) ->
                    values.forEach(value -> System.out.println(name + ": " + value)));
            System.out.println();
        }

        byte[] bytes = response.body();
        String type = response.headers().firstValue("content-type").orElse("").toLowerCase(Locale.ROOT);
        String text = new String(bytes, StandardCharsets.UTF_8);
        boolean json = type.contains("json") || text.stripLeading().startsWith("{") || text.stripLeading().startsWith("[");
        if (!options.raw() && json) {
            try { System.out.println(JsonPretty.format(text)); }
            catch (IllegalArgumentException e) { System.out.write(bytes); }
        } else {
            System.out.write(bytes);
        }
        System.out.flush();
    }
}

/** Validating JSON pretty-printer without a third-party JSON library. */
final class JsonPretty {
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
