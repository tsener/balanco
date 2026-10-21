# Balanco

<p align="center">
  <img src="assets/balanco-logo.png" alt="BALANCO in Hoover Dam-inspired Art Deco lettering" width="720">
</p>

[![Build](https://github.com/tsener/balanco/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/tsener/balanco/actions/workflows/build.yml)
[![License: GPL v3](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)

**A Rust TCP/mTLS load balancer for long-lived IoT connections and WebSockets.** Balance-style commands, bounded connection handling, and optional HTTP header policies in one executable.

## Where it fits

- **Device gateways:** terminate device mTLS, distribute persistent TCP sessions, and optionally authenticate to workloads with upstream mTLS.
- **WebSocket fleets:** retain established sessions while devices reconnect; transform headers during HTTP Upgrade, then tunnel bytes directly.
- **Small proxy deployments:** two runtime workers by default, explicit connection/setup limits, bounded relay buffers, and a raw TCP path that bypasses HTTP parsing.
- **Workload integration:** add trusted forwarding headers, rewrite Host, remove response fields, or compile custom Rust header hooks into the binary.

Smooth weighted round-robin, priority failover and client-IP hashing select backends. Local `-i`/`-c` administration and a separate mTLS management API expose live controls. SNI certificates, PROXY v2, validated SIGHUP reloads and hybrid X25519 + ML-KEM-768 key exchange are supported.

Optional local GeoIP and first-request HTTP/WebSocket metadata steer regional backend selection. A separate Rust controller translates typed Jev/Laya choices into approved weight policies; region/capability restrictions stay under operator control.

## Build and run

Linux or macOS; Rust 1.90+, a C compiler and CMake for AWS-LC. On Debian/Ubuntu, install `build-essential cmake` first.

Inline Rust tests additionally require the OpenSSL command-line tool to generate temporary test certificates; no credentials are bundled in the repository.

```sh
git clone https://github.com/tsener/balanco.git
cd balanco
cargo build --locked --release
./target/release/balanco --config examples/tcp.json --check
./target/release/balanco --config examples/tcp.json
```

The sample forwards port 8080 to your services on ports 9001/9002, with 9003 as fallback. Balance-style launch works too:

```sh
./target/release/balanco -f -b 127.0.0.1 8080 127.0.0.1:9001 127.0.0.1:9002
./target/release/balanco -b 127.0.0.1 -c 'show' 8080
```

Start with [TCP](examples/tcp.json), [two-leg mTLS](examples/mtls.json), [HTTP headers](examples/http1.json) or [management API](examples/management.json). TLS examples contain placeholder paths; supply your own certificates and keys.

## Documentation

- [Operations, TLS, reloads and live administration](docs/operations.md)
- [HTTP header rules and compiled plugin API](docs/http-plugins.md)
- [Architecture and code call flow](docs/architecture.md)
- [Deployment and UML diagrams](docs/diagrams.md)
- [External weight decisions and routing API](docs/routing-api.md)
- [Jev/Laya routing controller](docs/routing-controller.md)

**Status:** early software, not a production-capacity guarantee. TLS 1.2/1.3 only; no TLS 1.0/1.1, HTTP/2/3, OCSP stapling, embedded ACME client or dynamic plugin loader. HTTP hooks act on headers, not WebSocket payloads. CI produces a Linux x86-64 build; static and cross-architecture packaging are separate work.

Licensed under [GPLv3](LICENSE). Inspired by Balance's CLI and routing model; the original C implementation is not included.
