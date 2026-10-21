# Architecture and call flow

Balanco is one foreground process with a configurable multithreaded Tokio runtime (two workers by default). It neither forks workers nor embeds Balance's C runtime or shared-memory control protocol. Supervise it with your service manager or container runtime.

## Connection path

1. `main → start` calls `cli::parse`, validates config and loads TLS material. Control commands and `--check` exit without starting the data plane.
2. `run` binds the workload listener and calls `control::start` for the owner-only Unix socket and optional mTLS API. It admits sockets under connection and setup semaphores and spawns `Proxy::handle`.
3. `handle` completes frontend TLS, if configured. `relay` asks `Pool::acquire_for` for an eligible backend reservation and establishes backend TCP/TLS within explicit deadlines.
4. Establishment failure updates passive health and may try a different eligible backend. Retries stop before forwarding application bytes; Balanco never replays a partially forwarded request.
5. `forward` invokes `transport::copy` for raw TCP or `http1::relay` for opt-in HTTP/1.1. The HTTP adapter streams bodies, validates header hooks and switches upgraded WebSockets to byte tunneling.
6. Dropping the backend `Lease` releases its reservation on completion, errors or cancellation. SIGINT/SIGTERM stop acceptance and drain sessions until the configured deadline.

## Shared state and reloads

`scheduler.rs` keeps eligibility, priorities, caps and smooth weighted round-robin under one short mutex, never held over network I/O. Successful establishment clears passive cooldown; health epochs and configuration generations prevent stale failures from disabling a recovered or replaced backend.

SIGHUP loads config/TLS on a blocking task, checks restart-only fields and prepares a replacement listener before publication. Preparation failure retains the previous generation. Established sessions retain their original connection and TLS state. HTTP rules use immutable per-request snapshots; management changes compare policy generations before replacing rules.

`control.rs` routes Unix and HTTPS requests through shared authorization/dispatch functions. Management mTLS requires both a trusted client chain and an exact leaf-certificate allowlist entry with an admin or read-only role.

## Extension boundaries

`http_plugin.rs` is the public Rust header-hook API. Implementations are trusted, synchronous and compiled into the executable; register them in `http1::State::new` from `main.rs`. They must not block or perform I/O. The host protects framing and negotiation headers. Hooks stop after WebSocket Upgrade.

`Scheduler` is an internal compiled extension point. The host filters eligibility and rejects invalid selections. Remote policy engines, a stable dynamic ABI and plugin sandboxing are not implemented.

Optional Linux `reuse_port` allows separately supervised processes to bind the same data address. Each retains independent health, limits and live state; management HTTPS is rejected in that mode. It is not a coordinated prefork deployment.
