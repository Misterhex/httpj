# HTTPJ — regression test report

**Result:** 36/36 local tests passed after the single-file refactor.

**Runtime:** OpenJDK 21.0.12, Linux test container. The source compiled using javac, and direct execution via java httpj.java was verified.

## Coverage

| Group | Tests | Result |
| --- | --- | --- |
| Java source execution, help and GET | 1–3 | Pass |
| Raw JSON, headers, inline/file bodies | 4–7 | Pass |
| PUT, PATCH, DELETE, response headers | 8–11 | Pass |
| Redirects, HTTP 404 exit, invalid CLI inputs | 12–19 | Pass |
| JSON detection, malformed JSON fallback, binary/empty response, timeout | 20–24 | Pass |
| Untrusted CA rejection, custom CA acceptance, hostname mismatch, insecure TLS | 25–29 | Pass |
| Actual mTLS authentication and -k client-certificate behavior | 30–33 | Pass |
| Missing body file, invalid URL scheme, missing CA file | 34–36 | Pass |

TLS cases used an offline-generated test CA, server certificate, client certificate and HTTPS servers. The mTLS listener required client certificates: without them the request failed, with a valid client PEM keypair and trusted CA it succeeded.

## Public endpoint status

~~~bash
java httpj.java GET https://httpbin.org/get --timeout 8
~~~

**Unverified:** Exit 1, ConnectException in the test container; outbound connectivity/DNS to public sites was unavailable. This is **not** counted as a passing test or confirmed product defect.

## Remaining limitations

- Windows-specific command-line behavior has not yet been verified on a Windows host.
- Encrypted or traditional PEM private key formats are not supported; unencrypted PKCS#8 works.
- Very large response bodies are buffered in memory; streaming and performance have not been load-tested.
- -k uses a JDK HTTP client implementation property to disable hostname verification, which is process-wide.
- Full public-endpoint verification should be done from a network-enabled environment.

No known functional regressions were reproduced in the covered local scenarios.
