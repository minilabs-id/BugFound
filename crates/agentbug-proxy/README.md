# agentbug-proxy

Bounded, deterministic HTTP intercepting proxy — the headless analogue of
Burp Suite's Proxy interception decision. No LLM is involved.

## Usage

```sh
agentbug-proxy \
  --listen 127.0.0.1:8080 \
  --scope-in app.example.com \
  --scope-out '*.internal.example.com' \
  --require-ack \
  --max-requests 50 \
  --ca-dir ./agentbug-proxy-ca \
  --out proxy-history.jsonl
```

Configure the browser/client to use `127.0.0.1:8080` as its HTTP proxy.
Only absolute-form HTTP requests are accepted (standard proxy requests).

## Guarantees

- At least one `--scope-in` or `--scope-out` entry is required; an empty scope
  configuration fails closed at startup.
- Every request target is checked with `agentbug_tools::scope_target_allowed`.
  A denied request returns `403` and is recorded as `decision: "drop"`.
- With `--require-ack`, the operator must answer `y` on stdin. EOF, an empty
  answer, or anything else is a fail-closed drop (`operator_declined`).
- `--max-requests` is a hard cap; the listener stops after that many requests.
- Redirects are never followed by the proxy itself; header bytes are bounded,
  hop-by-hop headers are stripped, and one request is handled per connection.

## HTTPS / TLS MITM

HTTPS is supported through operator-controlled MITM. On the first run a
self-signed CA is generated in `--ca-dir` (default `./agentbug-proxy-ca`) and
written as `ca-cert.pem` / `ca-key.pem`. The operator must explicitly trust
`ca-cert.pem` in the client, otherwise HTTPS interception will fail with a
certificate error. Per-host leaf certificates are cached in memory.

`CONNECT` targets pass through the SAME fail-closed scope gate as plain HTTP.
With `--require-ack`, an explicit `y` is required before a tunnel is allowed.
Pass `--no-mitm` to disable HTTPS interception; `CONNECT` then returns 403 with
reason `mitm_disabled`. The private key is never printed or logged.

## Limitations (deliberate)

- Plain HTTP and HTTPS/1.1 are supported; HTTP/2, QUIC/HTTP/3 and HSTS-bypass
  tricks are out of scope. Certificate generation is local and operator-trusted.
- This is an operator-controlled interception point, not an authorization
  bypass. Scope entries still come from the operator/engagement, never from
  the model or a tool flag.
- History is written as JSONL and redacted with `agentbug_tools::redact`.
