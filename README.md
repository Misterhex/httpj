# httpj

A lightweight, single-file Java alternative to curl, built for Windows. Zero dependencies, JSON pretty-printing, and PEM-based mTLS. **Java 21+.**

No Maven, Gradle, JBang, or installation needed; the JDK runs the source file directly.

## Quick start

Download [http.java](http.java), then:

~~~powershell
java http.java GET https://httpbin.org/get
java http.java POST https://httpbin.org/post -H "Content-Type: application/json" -d '{"name":"httpj"}'
java http.java POST https://httpbin.org/post -H "Content-Type: application/json" -f request.json
~~~

### TLS / mutual TLS

~~~powershell
java http.java GET https://internal.example.com/health --cacert ca.pem
java http.java GET https://internal.example.com/health --cert client.pem --key client-key.pem --cacert ca.pem
java http.java GET https://localhost:8443/health -k
~~~

**Important:** -k disables TLS certificate validation **and** hostname verification. Use it only for trusted test systems, not for production automation. The JDK HTTP client uses a process-wide implementation property for hostname verification; this is acceptable for a one-request-per-process CLI but should not be copied into a long-running application.

Client keys must be **unencrypted PKCS#8 PEM** (BEGIN PRIVATE KEY). Encrypted keys and legacy BEGIN RSA PRIVATE KEY are not supported. Convert legacy keys with OpenSSL:

~~~bash
openssl pkcs8 -topk8 -nocrypt -in legacy.key -out client-key.pem
~~~

## CLI flags

| Flag | Purpose |
| --- | --- |
| -H, --header | Request header; repeatable |
| -d, --data | Inline request body |
| -f, --file | Body from local file |
| --cert | PEM client certificate/chain |
| --key | Unencrypted PKCS#8 PEM private key |
| --cacert | PEM certificates for server trust |
| -k, --insecure | Skip server TLS validation |
| -i, --include | Show response headers |
| -L, --location | Follow redirects |
| --raw | Disable JSON pretty-printing |
| --timeout SECONDS | Connect/request timeout, default 30 |
| -h, --help | Show help |

All HTTP methods are allowed. HTTP status goes to **stderr**; the response body goes to **stdout** (unless -i is used, which also adds headers to stdout). Non-JSON and binary bodies are emitted unchanged. Responses are held in memory before printing.

**Exit codes:** 0 success, 1 transport/runtime failure, 2 usage error, 22 HTTP 4xx/5xx.

## Architecture

Although distributed as just [http.java](http.java), the source contains small, package-private classes:

~~~text
http              CLI entry point / exit codes
CliOptions        Argument parsing and validation
HttpExecutor      HTTP requests and transport
TlsSupport        PEM / SSLContext / mTLS
ResponsePrinter   Response output and JSON detection
JsonPretty        Dependency-free JSON pretty-printer
~~~

## Tests

The Java 21 regression run passed **36/36** local tests covering HTTP methods, bodies, headers, JSON, redirects, error handling, TLS, hostname validation and client-certificate mTLS. See [TEST_REPORT.md](TEST_REPORT.md).

Run the repeatable local suite (requires Python 3, OpenSSL 3 and Java 21+):

~~~bash
python3 tests/test_httpj.py
~~~

The public httpbin smoke test could not complete because outbound networking in the testing environment was unavailable; public-endpoint operation remains unverified there. Native Windows execution has not been tested in that environment.

## License

MIT — see [LICENSE](LICENSE).
