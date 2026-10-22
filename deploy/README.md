# Build, publish and deploy

## Distribution

Use [GitHub Container Registry (GHCR)](https://github.com/tsener/balanco/pkgs/container/balanco) for the OCI/Docker image and [GitHub Releases](https://github.com/tsener/balanco/releases) for downloadable binaries. Neither needs Docker Hub credentials. The Build workflow validates the image on pull requests, publishes `ghcr.io/tsener/balanco:main` plus a commit-specific `sha-COMMIT` tag after main checks pass, and publishes version tags on `v*` tag builds. Pin deployments by image digest for immutability. Binary archives, corresponding source and SHA-256 checksums are attached to a draft GitHub Release; review it before publishing. The first release tag should match `Cargo.toml`, currently `v0.1.0`.

The first release target is Linux x86-64. The image uses a musl build and a scratch runtime with statically linked `balanco` and `balanco-controller`. No shell, Rust runtime, OpenSSL shared library or DNS-provider credentials are included. Certificate/trust files and optional GeoIP data are supplied at deployment. Static ELF checks run during image creation and CI executes the binary outside the image too. ARM64/macOS release builds are not included yet.

```sh
docker build --platform linux/amd64 -f deploy/container/Dockerfile -t balanco:local .
docker run --rm balanco:local --version
docker run --rm --read-only --cap-drop ALL \
  --tmpfs /run/balanco:uid=65532,gid=65532,mode=0700 \
  -v /absolute/config-directory:/etc/balanco:ro \
  -p 8443:8443 balanco:local --config /etc/balanco/balanco.json
```

Use a config listening on `0.0.0.0:8443` with `control_socket` under `/run/balanco`; mount its certificate paths read-only and make the keys readable by UID/GID 65532. The controller is available with `--entrypoint /bin/balanco-controller`. Application payloads are decrypted in this process; don't enable packet dumping in a deployment.

For manual publication, use `docker login ghcr.io`, tag the tested image for your account, and `docker push`. In GitHub Actions, the repository's `GITHUB_TOKEN` provides package write access. After the first push, check the package visibility in GitHub: a public source repository does not automatically make a newly created package public. Docker Hub is an optional second destination requiring its own account/token. Source for the built components is included at `/usr/share/balanco/source.tar.gz` in the image; release assets also contain a repository source archive.

## Kubernetes gateway bundle

`kubernetes/` contains a Kustomize deployment, LoadBalancer Service, ConfigMap and references to a separately supplied TLS Secret. It runs two pods, each limited to two CPUs, as a non-root user with read-only configuration and certificate mounts. Only the image-owned `/run/balanco` directory is writable by that user. The container layer remains writable so the socket directory resets on container restart; a persistent `emptyDir` would retain an uncleanly terminated process's socket, which Balanco deliberately refuses to unlink. No Kubernetes API access or cluster-wide RBAC is required. The configuration is TCP/mTLS forwarding, which also tunnels WebSocket connections; add `http1` configuration for header transformations.

This is a **manually configured edge proxy**, not a Kubernetes Ingress controller. It does not watch Ingress, Gateway API, EndpointSlice, Service or Secret resources. No `IngressClass` is registered. A controller that validates resources, resolves endpoints and publishes configuration is separate implementation work. Packaging the proxy as an image does not add that reconciliation behaviour.

Before deployment:

1. Replace the documentation-only backend `192.0.2.10:9000` in `kubernetes/balanco.json` with your backend Service's numeric ClusterIP and port. Balanco does not resolve JSON backend DNS names or track pod churn. A ClusterIP delegates pod selection to Kubernetes; choose separate regional Services to retain regional placement controls.
2. Set `deployment.yaml` to a verified image tag/digest. `main` is a development convenience, not a reproducible deployment pin. The current published architecture requires x86-64 nodes.
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

Readiness checks the local administration socket, not an unauthenticated TLS probe. It establishes process/control-loop readiness, not backend availability. There is no aggressive liveness probe that would restart a busy proxy during a reconnect storm. The 45-second termination budget exceeds the default 30-second drain window; connections still open at the deadline are closed. Clients must reconnect with jitter. Kubernetes scheduling and networking still determine capacity; two CPUs is a resource budget, not a throughput guarantee.

For config changes, Kustomize's content hash updates the pod template and triggers a rolling deployment. Mounted Secret updates alone do **not** trigger Balanco reloads. After renewing a Secret, wait for projection and signal HUP using an approved supervisor, or explicitly run `kubectl -n balanco rollout restart deployment/balanco`. The rollout option closes remaining long-lived connections at the drain deadline. Avoid `subPath` certificate mounts because those do not receive Secret updates. For cert-manager, project its server Secret and your separate device CA appropriately; cert-manager does not enroll device identities for Balanco.

## Release checklist

Review the main build and Sonar quality gate, update `Cargo.toml`/`Cargo.lock` if bumping the package version, then create a version tag:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The workflow builds that exact revision, publishes its image tags and creates a draft release containing `balanco-linux-amd64-musl.tar.gz`, `balanco-source.tar.gz` and `SHA256SUMS`. Verify the assets and publish the draft from GitHub. Tags are not created automatically. Existing release assets are not overwritten. Linux images and binaries still require a compatible host kernel.
