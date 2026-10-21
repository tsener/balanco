# Unikernel clusters and TIPC

Balanco can front a cluster of unikernel workers when their application endpoint speaks TCP, TLS or HTTP/1.1/WebSocket. Its decision API can distribute new connections using worker capacity and external policy. This does not provide a durable work queue, job acknowledgements, message replay or transparent migration of a worker's active sessions.

TIPC (Transparent Inter Process Communication) is a separate cluster protocol. Linux applications use `AF_TIPC` sockets and service addressing. Its inter-node bearer can be raw Ethernet or UDP; using a UDP bearer does not make the service an ordinary TCP endpoint. See the [Linux TIPC documentation](https://www.kernel.org/doc/html/latest/networking/tipc.html).

| Worker interface | Balanco path |
| --- | --- |
| TCP/TLS or HTTP/WebSocket service | Existing relay and routing API |
| Native TIPC service | A new Linux `AF_TIPC` gateway/transport adapter |
| A custom UDP message protocol | A separate datagram module with explicit flow, reply and timeout behavior |

A native TIPC gateway would terminate an application-facing transport, resolve permitted TIPC service names, and preserve the selected TIPC socket semantics. Stream sockets and message-oriented sockets require different relay behavior; multicast, topology subscriptions and service discovery are additional features. A generic UDP load balancer must not distribute TIPC bearer packets to arbitrary workers: that would not preserve peer/link state or cluster addressing.

The specific unikernel must implement TIPC, or speak to a TIPC-capable host gateway. A UDP network stack alone is insufficient. Keeping native TIPC inside Linux cluster nodes and exposing a defined TCP service through a gateway is a possible first deployment, using Balanco's existing data plane. Current TCP mTLS does not secure a newly added datagram transport.

No TIPC or UDP module is implemented here. Choose the worker runtime and application message/acknowledgement semantics before selecting that transport; adding UDP alone would not turn the proxy into a task broker.
