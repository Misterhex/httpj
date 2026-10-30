# httpj

A lightweight curl alternative for Windows in one Java source file. Java 21+, zero dependencies, JSON pretty-printing, and PEM-based mTLS.

## Run

Requires JDK 21 or newer. No installation or build step:

```sh
java httpj.java GET https://httpbin.org/get
```

## Examples

**GET with headers**

```sh
java httpj.java GET https://httpbin.org/headers -H "Accept: application/json" -H "X-Request-ID: 123"
```

**POST JSON**

```sh
java httpj.java POST https://httpbin.org/post -H "Content-Type: application/json" -d '{"name":"httpj"}'
```

**POST body from a file**

```sh
java httpj.java POST https://httpbin.org/post -H "Content-Type: application/json" -f payload.json
```

**Client certificate and custom CA (mTLS)**

```sh
java httpj.java GET https://internal.example.com/api --cert client.pem --key client-key.pem --cacert ca.pem
```

**Skip server certificate and hostname verification (unsafe)**

```sh
java httpj.java GET https://localhost:8443/health -k
```

**Show headers, follow redirects, or disable JSON formatting**

```sh
java httpj.java GET https://httpbin.org/redirect/1 -i -L
java httpj.java GET https://httpbin.org/json --raw
```

**Timeout**

```sh
java httpj.java GET https://httpbin.org/delay/2 --timeout 5
```

Run `java httpj.java --help` for all options. Private keys must use unencrypted PKCS#8 PEM (`BEGIN PRIVATE KEY`). Exit codes: `0` success, `1` transport error, `2` invalid arguments, `22` HTTP 4xx/5xx.
