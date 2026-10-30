# httpj

A single-file curl alternative for Windows. Java 21+, zero dependencies, JSON pretty-printing, and PEM-based mTLS.

Run with JDK 21+ (no build required):

```sh
java httpj.java GET https://httpbin.org/get
```

## Examples

```sh
# Headers
java httpj.java GET https://httpbin.org/headers -H "Accept: application/json"

# JSON body
java httpj.java POST https://httpbin.org/post -H "Content-Type: application/json" -d '{"name":"httpj"}'

# Body from file
java httpj.java POST https://httpbin.org/post -f payload.json

# Client certificate and CA
java httpj.java GET https://example.com --cert client.pem --key client-key.pem --cacert ca.pem

# Skip TLS verification (insecure)
java httpj.java GET https://localhost:8443 -k

# Response headers, redirects, raw output
java httpj.java GET https://httpbin.org/redirect/1 -i -L --raw
```

Run `java httpj.java --help` for all options. Private keys must be unencrypted PKCS#8 PEM.
