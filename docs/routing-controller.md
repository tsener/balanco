# Jev / Alaya-compatible routing controller

`balanco-controller` is a separate Rust executable built alongside `balanco`. It reads backend telemetry, asks a Jev/Laya-compatible service for a typed choice, and publishes an operator-approved policy through Balanco's mTLS API. The model never chooses arbitrary addresses, parses traffic or runs in the proxy process. Give inference its own CPU budget.

```sh
cargo build --locked --release
target/release/balanco-controller examples/controller.json
# For a single observation, set confirmations to 1 before using --once.
target/release/balanco-controller controller.local.json --once
```

Configure the management CA, admin client certificate/key and approved policy templates in [controller.json](../examples/controller.json). Paths are relative to the working directory. The model endpoint accepts an optional `ca`, `cert`, `key` and `token_file`; token files contain only the bearer token. Management always requires HTTPS/mTLS. Remote model services require HTTPS with an explicit CA and verified server name; plaintext is limited to numeric loopback addresses. No credentials are embedded in the example or executable.

Each cycle fetches `/v1/routing` and `/v1/status`, sends `POST /v1/systemone`, then optionally performs `PUT /v1/routing`. Optional top-level configuration `model_id` pins the service's model by including `model` in the inference request. Omit it to use service-side selection; for reproducible runs, pin a verified model rather than letting backend names influence language detection. The observed Jev/Laya request shape is:

```json
{
  "state": { "observation": "unique-observation", "generation": 1, "backend_generation": 1, "backends": [] },
  "questions": {
    "routing": {
      "type": "choice",
      "instructions": "Select an approved policy for the current backend health and load.",
      "criteria": { "balanced": "Spread load evenly", "prefer-first": "Favor the first backend" }
    }
  }
}
```

The adapter requires `answers.routing.type` to be `choice` and `answers.routing.choice` to name an approved template. Other answer metadata such as probabilities is ignored; it is not treated as a calibrated weight. Each template contains the complete `profiles` and `assignments` policy. Consequently dynamic weights can switch between operator-reviewed distributions without granting the model authority to expand workload pools. Use a deterministic stub or telemetry controller to establish a baseline before evaluating a model.

Consecutive identical choices provide configurable hysteresis. `interval_ms` is 1–60 seconds, per-call `timeout_ms` cannot exceed it, `ttl_ms` must be at least three intervals, and `confirmations` is 1–10. A successful observation can renew the same approved choice. Errors reset pending confirmations and do not renew the policy. There are no automatic retries of old answers or publications: stale generations/topologies are rejected by Balanco and the next cycle starts with fresh state. Answers taking over half the policy TTL are discarded. Observation identifiers become `source_revision` for inspection.

Bodies are bounded to 64 KiB and policy publications fit Balanco's 16 KiB limit. Timeouts, malformed responses, unknown choices, certificate failures and generation conflicts retain the current proxy snapshot until its explicit expiry behavior applies. Existing sessions are unaffected. Run a single controller per management endpoint; generation checks prevent lost writes but do not elect a leader. Publish separately to each instance when sharing a data listener.

The controller does not install or reconfigure a model service, download models or GeoIP data, or send client payloads/headers for inference. Backend addresses, regions, active counts, enabled/cooldown flags and policy generations are disclosed to the configured model endpoint. Verbose policy snapshots and byte counters are omitted to preserve model context for load information. Weight changes use approved templates rather than interpolated scores; weighted rendezvous affinity remains a separate follow-up.
