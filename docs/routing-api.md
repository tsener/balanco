# External routing decisions

Jev, Laya or another controller can publish backend weight policies over the existing mTLS management API. Balanco validates the entire replacement and applies it atomically. No remote inference or network call occurs during backend selection.

## API

| Method and path | Role | Behavior |
| --- | --- | --- |
| `GET /v1/routing` | Admin or read-only | Policy/backend generations, installed policy, expiry and remaining lifetime |
| `PUT /v1/routing` | Admin | Replace all profiles and assignments |
| `DELETE /v1/routing` | Admin | Remove the overlay; JSON body requires `expected_generation` |
| `POST /v1/routing/preview` | Admin or read-only | Resolve supplied metadata to a profile and eligible weighted candidates, without selecting or reserving a backend |

Use the management CA and an explicitly allowlisted client certificate, as in [operations](operations.md). Write requests require `Content-Type: application/json` and `Content-Length`. The existing 16-KiB body limit applies. Replies retain the `{ok,generation,output,data,...}` envelope. Unauthorized roles receive 403, stale generations 409 and invalid policies 400; failures retain the active policy.

```sh
curl --cacert ca.pem --cert operator.pem --key operator.key \
  https://localhost:9443/v1/routing
# Copy data.generation and data.backend_generation into the policy before publishing.
curl --cacert ca.pem --cert operator.pem --key operator.key \
  -X PUT -H 'Content-Type: application/json' \
  --data-binary @examples/routing-policy.json https://localhost:9443/v1/routing
curl --cacert ca.pem --cert operator.pem --key operator.key \
  -H 'Content-Type: application/json' \
  --data '{"client_ip":"127.0.0.5","tls_version":"TLS1.2"}' \
  https://localhost:9443/v1/routing/preview
```

The sample policy references the endpoints in `examples/management.json`; it is not an inference request for Jev/Laya. Their adapter translates typed model answers into this policy contract. The proxy does not host or call those models.

## Policy semantics

See [routing-policy.json](../examples/routing-policy.json). Each profile maps configured numeric backend addresses to integer weights from 0 to 1,000,000. Missing endpoints have zero effective weight in that profile. Profiles require at least one positive weight and a `default` profile. There may be up to 32 profiles and 128 assignments, within the overall request-size bound.

Assignments use ordered first-match semantics. Conditions inside `match` are conjunctive: canonical `source_cidr` (IPv4/IPv6), negotiated `tls_version` (`TLS1.2` or `TLS1.3`), and exact case-insensitive `sni`. An empty or duplicate match is rejected. With no match, use `default`. Plaintext connections have no TLS version or SNI. Metadata comes from the accepted socket and completed TLS handshake; HTTP forwarding headers cannot supply it. SNI is a client-controlled routing hint, not authenticated tenant identity.

Each profile has independent smooth weighted round-robin state. Existing backend priorities, hashing modes, admin disable/zero weights, cooldown and connection caps remain authoritative. In hash groups, the configured IP-hash/failover policy still determines eligible members; increasing a policy weight does not override hashing. The policy cannot invent endpoints, restore an administratively disabled endpoint or bypass health/capacity checks. A profile with no eligible backend rejects establishment rather than escaping to an omitted endpoint.

`expected_generation` compares against the routing generation; `backend_generation` compares against current backend/admin state. File reload and mutating live administration (including counter reset) invalidate the overlay and advance the routing generation. Read-only queries do not. This prevents a policy compiled for older backend state from remaining active. Changes are in memory and reset on restart.

`ttl_ms` is 100–3,600,000 and starts from local monotonic acceptance time. `source_revision` is a bounded identifier for audit/inspection. Expiry must explicitly choose `on_expiry: configured` (restore configured routing) or `reject` (reject new establishments until replacement/clear). Configured fallback can use any otherwise eligible configured endpoint; choose `reject` when that fallback would violate placement requirements. Expired policies remain visible for diagnosis. Existing sessions retain their backend throughout updates, expiry and clear.

Local CLI equivalents use the owner-only socket:

```sh
balanco --config instance.json -c 'routing-show'
balanco --config instance.json -c 'routing-apply examples/routing-policy.json'
balanco --config instance.json -c 'routing-preview client-metadata.json'
balanco --config instance.json -c 'routing-clear 1'
```

GeoIP enrichment, HTTP/WebSocket first-request metadata, per-device identity, rendezvous hashing and a runnable Jev/Laya adapter are not part of this API version. Unknown fields are rejected. The current version supplies atomic decision ingestion and IP/TLS/SNI classification without implying those further data-path features exist.
