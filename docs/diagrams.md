# Deployment and UML

These diagrams describe the implemented TCP/TLS proxy and decision-ingestion API. GeoIP enrichment, HTTP-based backend selection, the Jev/Laya adapter and TIPC transport are separate planned additions.

## Deployment: shared data listener, independent management

```mermaid
flowchart LR
    Clients["IoT / TCP / WebSocket clients"] --> Shared["Shared data IP:8443<br/>Linux SO_REUSEPORT"]
    Operator["Operator or policy controller"]
    Model["Jev / Laya<br/>optional external inference"]
    Operator -. "model adapter planned" .-> Model
    subgraph Host["Linux host"]
        Shared --> Data1
        Shared --> Data2
        subgraph P1["Balanco process 1"]
            Data1["TLS and TCP/HTTP relay"] --> Pool1["Backend pool + local policy"]
            API1["mTLS API :9441"] --> Pool1
            Unix1["Owner-only instance-1.sock"] --> Pool1
        end
        subgraph P2["Balanco process 2"]
            Data2["TLS and TCP/HTTP relay"] --> Pool2["Backend pool + local policy"]
            API2["mTLS API :9442"] --> Pool2
            Unix2["Owner-only instance-2.sock"] --> Pool2
        end
    end
    Operator -- "mTLS + certificate role" --> API1
    Operator -- "mTLS + certificate role" --> API2
    Pool1 --> Workloads["Configured workload endpoints<br/>TCP or verified TLS/mTLS"]
    Pool2 --> Workloads
```

The kernel chooses a process before TLS/HTTP parsing. Replicas sharing the data port must accept compatible clients and protocols. Management ports and Unix paths are unique; policies, health, limits and counters are independent. Fleet-wide updates require the controller to address each API. External inference does not run on connection acceptance.

## UML: core classes and ownership

```mermaid
classDiagram
    class Proxy {
        +handle()
        +relay()
        +forward()
    }
    class Pool {
        +acquire_for_context()
        +routing()
        +command()
        +reconfigure()
    }
    class SchedulerState
    class RoutingState {
        +apply()
        +selection()
        +clear()
        +status()
    }
    class Scheduler {
        <<interface>>
        +select()
    }
    class WeightedRoundRobin
    class Lease {
        +backend
        +counters
        +drop()
    }
    class HttpState {
        +update()
        +reload()
    }
    class HttpPlugin {
        <<interface>>
        +transform()
    }
    class HeaderRules
    Proxy --> Pool : shared Arc
    Proxy --> HttpState : shared Arc
    Pool *-- SchedulerState : mutex
    SchedulerState *-- RoutingState
    SchedulerState o-- Scheduler
    Scheduler <|.. WeightedRoundRobin
    RoutingState o-- WeightedRoundRobin : per profile
    Pool ..> Lease : reserves backend
    HttpState o-- HttpPlugin : compiled hooks
    HttpPlugin <|.. HeaderRules
```

`SchedulerState` represents `scheduler::State`; `RoutingState` represents `decision::State`; `HttpState` represents `http1::State`. Dropping a lease releases backend capacity on success, errors or cancellation. Scheduler locks never span network I/O.

## UML: connection establishment

```mermaid
sequenceDiagram
    participant C as Client
    participant P as Balanco process
    participant S as Backend pool
    participant B as Workload
    C->>P: TCP connection on shared listener
    P->>P: Admission limits and optional TLS/mTLS
    P->>S: IP / negotiated TLS version / SNI
    S->>S: Match local policy and enforce health/caps
    S-->>P: Backend lease
    P->>B: TCP and optional PROXY v2 / verified TLS
    alt Establishment fails before application bytes
        P->>S: Record failure and try another eligible backend
    else Established
        P->>B: Raw relay or HTTP header hooks
        B-->>P: Workload response
        P-->>C: Forward response
        Note over C,B: HTTP Upgrade switches<br/>to a pinned byte tunnel
    end
    P->>S: Release lease when session ends
```

HTTP header hooks currently run after backend selection; they do not choose another backend per request. Established TCP/WebSocket sessions keep their backend across policy changes.

## UML: external decision publication

```mermaid
sequenceDiagram
    participant A as External controller
    participant M as mTLS management API
    participant S as Backend pool
    A->>M: GET /v1/routing
    M-->>A: Policy and backend generations
    A->>M: PUT /v1/routing with policy, generations and TTL
    M->>M: Verify client certificate and admin role
    M->>S: Validate full policy under pool lock
    alt Invalid input or stale generation
        S-->>A: 400 or 409, active policy retained
    else Accepted
        S->>S: Atomically replace policy and advance generation
        S-->>A: 200 with new state
    end
    Note over M,S: On expiry, use configured fallback<br/>or reject new setup
    Note over A,S: Repeat per instance<br/>Existing sessions are unaffected
```
