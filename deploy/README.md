# Build, publish and deploy

## Distribution

Use [GitHub Container Registry (GHCR)](https://github.com/tsener/balanco/pkgs/container/balanco) for the OCI/Docker image and [GitHub Releases](https://github.com/tsener/balanco/releases) for downloadable binaries. Neither needs Docker Hub credentials. The Build workflow validates both architectures on pull requests, publishes multi-architecture `ghcr.io/tsener/balanco:main` and commit-specific `sha-COMMIT` tags after main checks pass, and publishes version tags on `v*` tag builds. Pin deployments by image-index digest for immutability across architectures. Binary archives, corresponding source and combined SHA-256 checksums are attached to a draft GitHub Release; review it before publishing. The release tag must match `Cargo.toml`, currently `v0.1.1`.

Release targets are Linux AMD64 (`x86_64-unknown-linux-musl`) and ARM64 (`aarch64-unknown-linux-musl`, suitable for Graviton). Each image uses a musl build and a scratch runtime with statically linked `balanco` and `balanco-controller`. No shell, Rust runtime, OpenSSL shared library or DNS-provider credentials are included. Certificate/trust files and optional GeoIP data are supplied at deployment. CI runs unit checks on native AMD64/ARM64 runners, checks each executable's ELF architecture/static linkage, starts the containers and probes local administration before composing a shared manifest. Native macOS release builds are not included.

```sh
docker build -f deploy/container/Dockerfile -t balanco:local .
docker run --rm balanco:local --version
docker run --rm --read-only --cap-drop ALL \
  --tmpfs /run/balanco:uid=65532,gid=65532,mode=0700 \
  -v /absolute/config-directory:/etc/balanco:ro \
  -p 8443:8443 balanco:local --config /etc/balanco/balanco.json
```

Use a config listening on `0.0.0.0:8443` with `control_socket` under `/run/balanco`; mount its certificate paths read-only and make the keys readable by UID/GID 65532. The controller is available with `--entrypoint /bin/balanco-controller`. Application payloads are decrypted in this process; don't enable packet dumping in a deployment.

The local build targets the builder's architecture. For manual multi-architecture publication, use `docker login ghcr.io` and a Buildx builder configured for both platforms:

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  -f deploy/container/Dockerfile -t ghcr.io/YOUR_ACCOUNT/balanco:VERSION --push .
```

Buildx needs native workers or configured emulation for each requested platform; the project CI uses native runners. In GitHub Actions, the repository's `GITHUB_TOKEN` provides package write access. Architecture-specific intermediate tags use `sha-COMMIT-amd64` and `sha-COMMIT-arm64`; shared tags are published only after both pass. After the first push, check the package visibility in GitHub: a public source repository does not automatically make a newly created package public. Docker Hub is an optional second destination requiring its own account/token. Source for the built components is included at `/usr/share/balanco/source.tar.gz` in the image; release assets also contain a repository source archive.

## Kubernetes gateway bundle

For a LAN-accessible single-node lab, follow the [k3s deployment recipe](k3s.md).

`kubernetes/` contains a Kustomize deployment, LoadBalancer Service, ConfigMap and references to a separately supplied TLS Secret. It runs two pods, each limited to two CPUs, as a non-root user with read-only configuration and certificate mounts. Only the image-owned `/run/balanco` directory is writable by that user. The container layer remains writable so the socket directory resets on container restart; a persistent `emptyDir` would retain an uncleanly terminated process's socket, which Balanco deliberately refuses to unlink. No Kubernetes API access or cluster-wide RBAC is required. The configuration is TCP/mTLS forwarding, which also tunnels WebSocket connections; add `http1` configuration for header transformations.

The base `kubernetes/` bundle is a **manually configured edge proxy**. To watch Ingress, Service, EndpointSlice and TLS Secret resources instead, use the [Ingress controller bundle](ingress.md), which requires a build after v0.1.1. Gateway API resources are not reconciled.

Before deployment:

1. Replace the documentation-only backend `192.0.2.10:9000` in `kubernetes/balanco.json` with your backend Service's numeric ClusterIP and port. Balanco does not resolve JSON backend DNS names or track pod churn. A ClusterIP delegates pod selection to Kubernetes; choose separate regional Services to retain regional placement controls.
2. Review the release image index pinned in `deployment.yaml` (v0.1.1), updating it deliberately when upgrading. The base bundle supports Linux AMD64 and ARM64 nodes; for Graviton-only placement use the overlay below.
3. Provide a server certificate/full chain, private key and device client CA as a Secret. Keep the key outside this repository.

```sh
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl -n balanco create secret generic balanco-tls \
  --from-file=tls.crt=/secure/server-fullchain.pem \
  --from-file=tls.key=/secure/server.key \
  --from-file=client-ca.crt=/secure/device-ca.pem
kubectl kustomize deploy/kubernetes
kubectl apply -k deploy/kubernetes
kubectl -n balanco rollout status deployment/balanco
```

The cloud provider must support LoadBalancer Services; for EKS, configure your AWS Load Balancer Controller and NLB **TCP pass-through** so Balanco receives the TLS handshake. Do not terminate TLS at the NLB if Balanco is to verify device certificates. Configure provider-specific annotations and source-IP preservation for your target mode; `externalTrafficPolicy: Local` alone does not guarantee an original client IP through every cloud load balancer. Balanco does not consume inbound PROXY protocol. Management is deliberately not exposed by this example.

Readiness checks the local administration socket, not an unauthenticated TLS probe. It establishes process/control-loop readiness, not backend availability. There is no aggressive liveness probe that would restart a busy proxy during a reconnect storm. A five-second kubelet `preStop.sleep` lets endpoint removal propagate before Balanco stops accepting. The 45-second termination budget includes that pause and the default 30-second drain window; connections still open at the deadline are closed. Clients must reconnect with jitter. The bundle requires a cluster with `PodLifecycleSleepAction` enabled. Kubernetes scheduling and networking still determine capacity; two CPUs is a resource budget, not a throughput guarantee.

For config changes, Kustomize's content hash updates the pod template and triggers a rolling deployment. Mounted Secret updates alone do **not** trigger Balanco reloads. After renewing a Secret, wait for projection and signal HUP using an approved supervisor, or explicitly run `kubectl -n balanco rollout restart deployment/balanco`. The rollout option closes remaining long-lived connections at the drain deadline. Avoid `subPath` certificate mounts because those do not receive Secret updates. For cert-manager, project its server Secret and your separate device CA appropriately; cert-manager does not enroll device identities for Balanco.

## Graviton nodes

Create your ARM64 EKS node group and backend/TLS configuration as above, then deploy the ARM64-only overlay:

```sh
kubectl kustomize deploy/kubernetes-graviton
kubectl apply -k deploy/kubernetes-graviton
kubectl -n balanco rollout status deployment/balanco
kubectl -n balanco get pods -o wide
```

It adds `kubernetes.io/arch: arm64`; containerd selects the ARM64 child from the shared image tag. Pin an image **index** digest, not the AMD64 child digest. Tainted node groups also need matching tolerations supplied by your deployment. The image is built for baseline ARM64 compatibility, not a Graviton-specific CPU generation. Native ARM64 CI execution does not establish EKS/Graviton connection capacity; benchmark on your target instance before sizing production.

## Release checklist

Review the main build and Sonar quality gate, update `Cargo.toml`/`Cargo.lock` if bumping the package version, then create a version tag:

```sh
git tag v0.1.1
git push origin v0.1.1
```

The workflow builds that exact revision, publishes its multi-architecture image tags and creates a draft release containing `balanco-linux-amd64-musl.tar.gz`, `balanco-linux-arm64-musl.tar.gz`, `balanco-source.tar.gz` and `SHA256SUMS`. The combined checksum file covers all three archives; use `sha256sum --check --ignore-missing SHA256SUMS` when downloading only one architecture and source. Verify the assets and publish the draft from GitHub. Tags are not created automatically. Existing release assets are not overwritten. Linux images and binaries still require a compatible host kernel.
