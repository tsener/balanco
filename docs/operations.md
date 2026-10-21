# Operations

## Configuration and sizing

Use `balanco --help` for Balance-style arguments, or `--config FILE` for JSON. Unknown JSON fields are rejected. `--check` validates configuration and loads TLS files without binding the workload listener; it does not verify peer reachability or acceptance of the certificate chain.

| Setting | Default | Purpose |
| --- | --- | --- |
| `workers` | 2 | Tokio worker threads; OS/cgroup controls impose a CPU budget |
| `max_connections` | 10000 | Accepted sessions, including setup |
| `max_handshakes` | 128 | Concurrent setup when either leg uses TLS |
| `buffer_bytes` | 4096 | Raw relay buffer per direction |
| `connect_timeout_ms` | 2000 | Each backend TCP/TLS attempt |
| `handshake_timeout_ms` | 5000 | Frontend TLS setup |
| `establishment_timeout_ms` | 10000 | Total backend setup budget |
| `failure_cooldown_ms` | 1000 | Passive establishment-failure cooldown; zero disables it |
| `drain_timeout_ms` | 30000 | Graceful shutdown deadline |
| `idle_timeout_ms` | absent | Optional application inactivity deadline |

Excess connections/setups are rejected rather than queued inside the application. Ordinarily each session needs two sockets; size file descriptors, TLS state and kernel buffers as well as relay memory. Numeric validation ceilings are not capacity guarantees. JSON backend addresses are numeric; positional CLI names resolve at startup without periodic DNS refresh.

Each backend supports `address`, `weight` (default 1; zero disables assignments), `priority` (smaller values first), and `max_connections` (zero means no additional cap). Set `server_name` on every backend when upstream TLS is enabled. An established session stays with its backend for its lifetime.

Balanco requests a 16,384-entry listener backlog, capped on Linux by `net.core.somaxconn`. The measured reconnect comparison used `somaxconn=16384`, `tcp_max_syn_backlog=16384`, SYN cookies enabled, `max_connections=20000` and `max_handshakes=8192`. These are tested settings, not universal defaults. Monitor setup rejections, SYN cookies, listener drops, retransmissions and memory together. Devices should use reconnect backoff with jitter.

## TLS and certificates

See [two-leg mTLS](../examples/mtls.json). `tls.client_ca` makes device certificates mandatory. Without it, frontend TLS does not require client certificates. Device admission accepts valid chains to that CA; per-device authorization, revocation lists and certificate-subject routing are not implemented.

`upstream_tls.ca` supplies explicit backend trust. `cert` and `key` together authenticate Balanco to workloads. Backend `server_name` controls certificate verification and TLS SNI independently of HTTP Host rewriting. No insecure verification switch is provided.

TLS supports 1.2/1.3 through rustls/AWS-LC. Each TLS block accepts `key_exchange`: `classical`, `hybrid_preferred` (default), or `hybrid_required` (TLS 1.3 only). Hybrid uses X25519 + ML-KEM-768; certificate authentication is still classical. This is hybrid key establishment, not fully post-quantum authentication. Resumption and 0-RTT are disabled.

Add `tls.sni_certificates` entries with `names`, `cert`, `key` for exact names or one-label wildcards such as `*.devices.example`. Top-level `cert`/`key` remain the no-SNI fallback. Unknown SNI also falls back unless `reject_unknown_sni` is true. TLS 1.0/1.1 and automatic OCSP stapling are unavailable.

Certificate paths are relative to the process working directory; prefer absolute paths. Use an external ACME issuer, cert-manager or DNS-01 automation (including Cloudflare tooling) to issue and renew certificates. Balanco has no embedded issuer or provider credentials. Publish a complete versioned bundle atomically, then send SIGHUP. Established sessions keep their previous trust decision.

## Reload and shutdown

```sh
kill -HUP PID   # Validate and publish updated file config and TLS material
kill -TERM PID  # Stop accepting and drain until drain_timeout_ms
```

With positional launch, SIGHUP reloads TLS files only. File reloads may replace data listen endpoints, backends, TLS identities and HTTP configuration. Worker count, admission limits, control socket and management listener settings require a restart; incompatible reloads are rejected. File reload replaces live API overrides. Failed preparation retains active configuration; no automatic file watcher is included.

## Local administration

Match the original listener address/port or use the same config file:

```sh
balanco -b 127.0.0.1 -i 8080
balanco --config examples/tcp.json -c 'show'
balanco --config examples/tcp.json -c 'group 0; disable 1; show'
```

`help` lists commands, including `show`, `group`, `enable`, `disable`, `create`, `maxc`, `weight`, `rr`, `hash`, `reset` and MRTG counters. Newly created channels start disabled. Commands use group-local channel indices. Changes are in memory; persist desired settings in JSON. The control socket and its parent are owner-only and peer credentials are checked. This replaces Balance's shared-memory control mechanism; daemonization is not implemented.

## mTLS management API

[management.json](../examples/management.json) declares a separate HTTPS listener, required client CA, and exact leaf-certificate allowlist with `admin` or `read_only` roles. Give each operator/automation its own identity. A CA-trusted but unlisted client is denied. This is certificate authentication, not MFA or Kerberos.

```sh
curl --cacert management-ca.pem --cert operator.pem --key operator.key \
  https://localhost:9443/v1/status
curl --cacert management-ca.pem --cert operator.pem --key operator.key \
  -H 'Content-Type: application/json' \
  --data '{"group":0,"command":"disable 1"}' \
  https://localhost:9443/v1/command
```

`GET /v1/status` reads backend state. `POST /v1/command` runs a command with role checks. [HTTP plugin management](http-plugins.md) adds `GET /v1/http` and admin-only `PUT /v1/http/rules` with `expected_generation`. Requests have bounded sizes/deadlines and are audited without logging rule values. Keep this listener on a restricted management network.

## Client metadata and observability

`proxy_protocol_v2: true` sends original socket addresses before backend TLS or application bytes. The backend must explicitly support PROXY v2 before its own protocol handshake; an ordinary TCP/TLS listener will fail. Mixed address families are rejected.

Periodic stderr statistics report accepted/rejected/completed/failed sessions. Live administration also exposes per-channel counters. No Prometheus endpoint is included. Avoid `-p`/`packet_dump` in deployments: it prints plaintext application data. Debug logs and captures may contain sensitive metadata.
