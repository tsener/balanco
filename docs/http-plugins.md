# Workload-side HTTP/1.1 header plugins

Set `http1` in a listener's JSON configuration to enable HTTP handling for all of its backends. `examples/http1.json` is a runnable plaintext example. The same setting works with frontend TLS/mTLS and verified backend TLS/mTLS. HTTP parsing happens after frontend TLS termination and writes through the configured backend TCP/TLS connection. A raw TCP listener without `http1` uses the existing bounded relay without HTTP parsing or per-request hooks.

The HTTP path supports persistent HTTP/1.1, ordered pipelined requests, streamed Content-Length and chunked bodies, HEAD, Expect/100-continue and WebSocket Upgrade. After a valid upstream 101 WebSocket response, it switches to a transparent duplex tunnel, retaining any bytes prefetched on either leg. Hooks then stop running on that connection. It does not inspect WebSocket frames.

One backend reservation remains attached to the accepted connection, including its HTTP keep-alive requests and WebSocket lifetime. It does not select another backend per HTTP request, pool upstream connections, or retry application requests. Frontend HTTP/2/3, HTTP/1.0, CONNECT, other upgrade protocols, absolute-form proxy requests and body transformations are unsupported. TLS ALPN is not extended by this plugin.

## Header rules

Rules run in array order, independently for `request` and `response`. Optional `when.method`, `when.path_prefix` and response-only `when.status` conditions must all match. Paths exclude the query string; path-prefix matching is a literal prefix. Each rule has an `action`:

| Operation | Fields | Behavior |
| --- | --- | --- |
| `set` | `name`, `value` | Replace every existing value with one value |
| `add` | `name`, `value` | Append a separate field, preserving duplicates such as Set-Cookie |
| `remove` | `name` | Remove every occurrence |
| `rename` | `from`, `to` | Move every source value, appending to existing destination values |
| `replace` | `name`, `from`, `to` | Replace a nonempty literal substring in each text value |

Names are case-insensitive. Set/add values support `${client_ip}`, `${client_port}`, `${backend}`, `${scheme}`, `${method}`, `${path}` and `${sni}`. Unknown or unterminated variables are rejected. Connection metadata comes from the accepted socket and negotiated TLS session, not client-supplied forwarding headers. SNI is empty on plaintext or no-SNI connections. There is no certificate-subject identity template or scripting engine. Use `set` when supplying a trusted identity or forwarding header; `add` preserves client-supplied values.

For example:

```json
{"phase":"request","when":{"path_prefix":"/devices/"},
 "action":{"op":"set","name":"x-device-gateway","value":"balanco:${client_ip}"}}
```

Host rewriting supports `set` only and must produce exactly one valid authority, for example `workload.internal:9000`. This changes the HTTP Host field; backend TLS SNI and certificate verification still use the backend's configured `server_name`.

The host reserves framing, hop-by-hop, Expect and Sec-WebSocket negotiation headers. It removes hop-by-hop fields and fields nominated by Connection, and rejects invalid Connection nominations. Custom hooks cannot alter the protected fields or reintroduce connection-specific fields. Header changes cannot introduce CR/LF or exceed configured bounds. Request and response trailer fields are discarded, along with Trailer advertisements, so they cannot bypass header removal or trusted identity injection. Applications relying on trailer metadata must use the raw relay or wait for explicit trailer-policy support. Payload bytes stream without whole-body buffering; HTTP chunk boundaries and header casing may change.

## Live management and local CLI

The existing separately authenticated mTLS management listener exposes:

* `GET /v1/http`: enabled state, current HTTP policy and policy generation. Admin and read-only roles may inspect it.
* `PUT /v1/http/rules`: atomically replace the entire rule array. Requires an admin certificate, JSON Content-Type, Content-Length and a matching `expected_generation`.

```sh
curl --cacert ca.pem --cert admin.pem --key admin.key https://localhost:9443/v1/http
# Set expected_generation in rules.json to the generation returned above.
curl --cacert ca.pem --cert admin.pem --key admin.key \
  -X PUT -H 'Content-Type: application/json' --data-binary @rules.json \
  https://localhost:9443/v1/http/rules
```

`examples/http-rules.json` shows the update format. Replies use the existing `{ok,generation,output,data,...}` envelope. Invalid policies return 400, unauthorized roles return 403, and generation conflicts return 409. Failed updates retain the previous policy and generation. Audit logs identify the caller, operation and outcome without printing rule values. A raw TCP listener rejects rule updates; enabling HTTP requires config/reload.

The same operations are available locally:

```sh
balanco --config examples/http1.json -c 'http-show'
balanco --config examples/http1.json -c 'http-rules examples/http-rules.json'
```

The CLI reads the JSON file locally and sends a structured update over the owner-only socket. `/v1/command` and the Unix socket also accept `{"command":"http-show"}` or `{"command":"http-rules","http_rules":{"expected_generation":1,"rules":[]}}`.

Each request captures an immutable rule snapshot and uses it for both its request and response headers. Live updates affect subsequent requests on existing HTTP keep-alive connections as well as new connections. Already upgraded WebSockets continue tunneling. SIGHUP publishes rules from the file, replacing API overrides, and increments the policy generation. Removing `http1` applies to new connections; existing HTTP connections retain HTTP framing and the last policy. API updates are in-memory and reset on restart or file reload. Persist desired rules in the config file.

## Rust API

The library exports `balanco::http_plugin::{HttpPlugin,Context,Phase,HeaderMap,HeaderValue}`. A plugin implements the synchronous `transform` hook; `examples/header_plugin.rs` is a compiled example. Register trusted implementations in the vector passed to `http1::State::new` in `src/main.rs`. Bundled declarative rules run first, followed by custom plugins in registration order. Request and response hooks receive parsed headers, request metadata and, for responses, the status code. All hooks pass through the host's framing/header-limit checks before bytes are forwarded.

This is a Rust source interface for statically linked plugins, not a dynamic library ABI. Implementations must be bounded, nonblocking and free of network or filesystem I/O. They share the process's privileges and memory; there is no sandbox or hard execution-budget enforcement. Hot management changes configure the bundled rule plugin; adding code requires a rebuild. Raw listeners do not call registered hooks.

## Limits and verification

HTTP defaults are 16,384 header bytes (range 8,192–65,536), 64 fields, a 5-second request-header timeout (range 100–60,000 ms) and a 60-second upstream response-start deadline (range 100–3,600,000 ms). The upstream deadline includes uploading the request body; increase `response_timeout_ms` for long streaming uploads. `idle_timeout_ms`, connection admission, backend caps and graceful drain continue to apply, including after WebSocket Upgrade. Connection byte counters include serialized HTTP headers and streamed payloads. Packet dumping continues to use escaped plaintext, as on the raw path.

Policies have at most 128 rules and a 12,288-byte serialized rule budget; individual values/templates are limited to 4,096 bytes. The existing management request limit is 16,384 bytes. HTTP connection settings are captured on acceptance; rules can change per request. Rule/runtime errors terminate the connection and do not trigger request replay.

Run `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked` and `cargo run --locked --example header_plugin`. Inline Rust unit checks remain with their source modules; standalone integration tests and private benchmark tooling are not published. See [the measured HTTP/WebSocket workloads and their limits](benchmarks.md).
