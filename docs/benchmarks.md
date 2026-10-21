# Benchmark results

These are development measurements on specific hardware and network paths, not maximum connection counts, production sizing or a universal product ranking. Raw captures, certificates, host addresses and private test scripts are intentionally excluded from this repository.

## HTTP, WebSockets and reconnect storms — 21 October 2026

Final matrix: **48 proxy trials plus two direct-origin calibrations**, three repetitions per supported profile. Each proxy stack had the same **two-core CPU quota/affinity and 3 GiB memory cap** on a ten-vCPU Debian 13 / Linux 6.12 x86-64 VM. The plaintext loopback origin used four other cores; the load generator ran outside the VM on an ARM64 Mac.

Frontend **TLS 1.3 mTLS**, X25519, AES-256-GCM-SHA384, shared P-256 client identity, full handshakes with resumption disabled. This matrix did **not** use hybrid PQ or upstream mTLS. Balanco used two Tokio workers and NGINX two workers. Varnish 7.7 needed Hitch 1.8 for TLS; their CPU and memory are counted together.

| Load | Connections and traffic |
| --- | --- |
| HTTP/1.1 | 512 persistent connections, 64-byte payloads, one outstanding exchange per connection, 15-second window |
| WebSocket | 512 persistent connections, real masked binary frames, 64-byte payloads, 15-second window |
| Reconnect storm | Validate 6,000 sessions; close and simultaneously reconnect 5,000 while 1,000 existing devices send one message/s; probe retained sessions afterward |

Header rules change request and response fields; the origin and generator validate payloads and expected headers. Varnish HTTP uses `return(pass)` to bypass cache. WebSocket pipe mode cannot transform the origin's Upgrade response headers, so its full rules-on WebSocket/storm profile is unsupported.

### Three-run medians

CPU is percentage of the entire two-core allowance: **100% means both cores busy**. Memory is the median of per-trial peak sampled process PSS, including both Hitch and Varnish. p99 is end-to-end client latency. Storm p99 includes full mTLS, Upgrade and first echo, from simultaneous release; burst throughput is not sustained handshake capacity.

| Workload | Stack | Header rules | Throughput | p99 | CPU / two cores | Peak PSS |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| HTTP | Balanco | on | 17,233 req/s | 118.3 ms | 41.3% | 35.9 MiB |
| HTTP | NGINX | on | 15,990 req/s | 118.2 ms | 53.8% | 83.4 MiB |
| HTTP | Hitch + Varnish | on | 7,035 req/s | 179.4 ms | 87.7% | 322.5 MiB |
| WebSocket | Balanco | on | 18,065 msg/s | 114.1 ms | 27.8% | 21.8 MiB |
| WebSocket | NGINX | on | 17,246 msg/s | 115.9 ms | 29.9% | 96.4 MiB |
| WebSocket | Hitch + Varnish | **off** | 15,856 msg/s | 121.6 ms | 63.8% | 121.9 MiB |
| Storm | Balanco | on | 2,516 new conn/s | 1.936 s | 63.7% | 211.5 MiB |
| Storm | NGINX | on | 1,718 new conn/s | 2.905 s | 80.4% | 446.5 MiB |
| Storm | Hitch + Varnish | **off** | 1,457 new conn/s | 3.042 s | 84.9% | 2043.5 MiB |

The Varnish WebSocket/storm rows have a different transformation profile and must not be read as full feature-equivalent comparisons. Its pipe implementation also needed a larger task allowance (8,192 versus 128 for Balanco/NGINX), with two worker pools up to 4,000 each and 8,000 pipe sessions. CPU/memory budgets remained identical.

Across final rules-on/off reconnect trials, **Balanco 30,000/30,000** and **NGINX 30,000/30,000** succeeded. Hitch + Varnish completed **14,996/15,000** (four EOFs in one trial, consistent with Hitch's TLS deadline in a captured flow). Every existing session was retained; no final reconnect resets or proxy OOM kills occurred. Failure counts are separate from successful-operation p99.

Balanco showed the lowest measured CPU and PSS in these profiles, with similar steady latency to NGINX and faster burst completion. This supports its intended role as a compact persistent-session gateway. It does not measure Varnish's caching benefits or the broader feature set of NGINX.

### Reliability work and remaining limits

Earlier diagnostics reproduced resets before application accept, with conflicting SYN-ACK sequence numbers on retransmitted SYNs and active SYN cookies. Enlarging application and Linux listen/SYN queues removed this reset pattern at the tested load. The comparison kept SYN-cookie protection enabled. Increasing the legacy VM NIC rings from 32/16 to 512/512 improved direct-origin latency in single calibrations; those are not repeated causal or capacity proofs.

The final comparison used listener queues and Linux caps of 16,384; Balanco `max_connections=20000`, `max_handshakes=8192`. Default admission limits are lower. All temporary host settings were restored after measurement.

Existing-device storm-message p99 medians were **664.9 ms Balanco**, **1,755.9 ms NGINX**, and **546.7 ms Hitch + Varnish (rules off)**. All exceeded the provisional 250 ms target in the main matrix. A slower TLS completion rate changes pressure on established traffic, so these latency values should be considered together with reconnect throughput.

A separate single-run external Linux-generator diagnostic retained all 1,000 existing sessions and completed all 5,000 reconnects for Balanco and NGINX, with existing-message p99 of 134.3/223.6 ms. That generator saturated its 3.5-core allowance and offered slower handshake pressure; it does not prove the target at the main matrix's load.

The generator network path and legacy virtual NIC constrained interpretation. CPU comes from cgroup deltas and excludes host interrupt work; short-storm alignment is approximate. PSS was sampled roughly every 250 ms and may miss shorter peaks. These 15-second steady windows and bursts are not long soaks. No maximum-capacity search, unique certificate per device, two-leg mTLS performance, HTTP/2, EKS capacity or WebSocket payload transformations were measured here.

## Earlier raw TCP/TLS comparison with Hitch — 20 October 2026

This was a **different, earlier build and workload**, with one repetition at the largest burst. Proxy CPU was again limited to two cores, with an external Mac generator and separately budgeted loopback echo backend. It compared frontend TLS/mTLS and classical/hybrid X25519 + ML-KEM-768 handshakes against both default-buffer and source-tuned Hitch. It predates the final queue/NIC corrections and is not directly comparable to the HTTP table.

At 1,024 concurrent clients, all TLS/mTLS × classical/hybrid profiles completed without errors or backend-establishment failures. Balanco measured 2,257–3,349 connections/s across modes, approximately 20.7–25.2 MiB PSS, and lower proxy CPU than Hitch in those runs.

For a 4,096-client **mTLS + hybrid** burst with a five-second client TLS deadline:

| Stack | Successful connections/s | TLS timeouts | CPU / two cores | PSS |
| --- | ---: | ---: | ---: | ---: |
| Balanco | 2,226 | 74 (0.33% of attempts) | 51.5% | 72.2 MiB |
| Hitch, default buffers | 2,073 | 38 (0.18%) | 82.1% | 313.8 MiB |
| Hitch, tuned buffers | 2,088 | 29 (0.14%) | 80.0% | 147.7 MiB |

Balanco used less CPU/memory but had more timeouts in that historical burst. No backend establishment failures or listener overflow drops were observed; host-wide retransmissions/timeouts increased without definitive attribution. This single sample does not establish a current reliability ranking.

An earlier retained-session test also exercised **20,000 mTLS sessions**, including hybrid mode and paced messages, at about **470 MiB Balanco PSS**, versus roughly **1,203–1,355 MiB** for default Hitch. That is a demonstrated load, not a maximum; it predates later HTTP and reliability work.
