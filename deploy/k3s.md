# Single-node k3s gateway

This recipe runs Balanco at a Linux node's LAN address on port 443. It uses the
same [Kustomize bundle](kubernetes/) as other Kubernetes deployments. Balanco
terminates device mTLS and forwards to a Service; it does not reconcile Kubernetes
`Ingress` or Gateway API resources. Start with a dedicated lab VM. Two replicas
request four CPUs in total; allow additional capacity for Kubernetes, workloads
and rolling updates. Two replicas on one node do not provide node failure tolerance.

## Install k3s

On the Linux node, download and review the [official installer](https://get.k3s.io),
then install the version validated with this recipe:

```sh
curl -fsSL https://get.k3s.io -o install-k3s.sh
less install-k3s.sh
sudo env INSTALL_K3S_VERSION='v1.37.1+k3s1' \
  INSTALL_K3S_EXEC='server --disable=traefik --flannel-backend=host-gw --write-kubeconfig-mode=600' \
  sh install-k3s.sh
sudo k3s kubectl wait node --all --for=condition=Ready --timeout=120s
sudo k3s kubectl get pods -A
```

Disabling Traefik releases ports 80/443. Keep k3s ServiceLB enabled: it exposes
LoadBalancer Services on the node without a cloud load balancer. The `host-gw`
Flannel backend suffices for this single-node lab; a multi-node deployment needs
an appropriate network design. Check that the default pod `10.42.0.0/16` and Service
`10.43.0.0/16` ranges do not overlap existing networks before installing. See
[k3s networking](https://docs.k3s.io/networking/networking-services) and
[network requirements](https://docs.k3s.io/installation/requirements#networking).
Keep the admin kubeconfig and server token private. Restrict port 6443 to your
administration network; do not disable the host firewall to make this work.

Run the remaining commands on that node from a checkout of this repository.
`sudo k3s kubectl` uses its root-owned kubeconfig; no credentials need copying
into the checkout.

## Supply the workload and TLS identity

Deploy your HTTP/WebSocket workload with a readiness probe and a ClusterIP
Service. Keep it internal; Balanco is the external entry point. Find its address:

```sh
sudo k3s kubectl -n YOUR_WORKLOAD_NAMESPACE get service YOUR_WORKLOAD_SERVICE
```

Prepare a working copy of the gateway manifests outside the checkout:

```sh
mkdir -p "$HOME/balanco-gateway"
cp -R deploy/kubernetes "$HOME/balanco-gateway/"
```

Edit that copy's `balanco.json`: replace `192.0.2.10:9000` with the workload's
numeric ClusterIP and Service port. DNS backend names are not supported. Pod
replacement keeps the Service address stable; deleting and recreating the
Service can change it and requires a configuration update.

The bundle pins the v0.1.1 multi-architecture image index. Supply your server
certificate with the external hostname/IP in its SAN, its private key, and the
CA that issues device client certificates. These are separate from Kubernetes'
own certificates. Obtain and store them through your PKI outside Git:

```sh
sudo k3s kubectl apply -f deploy/kubernetes/namespace.yaml
sudo k3s kubectl -n balanco create secret generic balanco-tls \
  --from-file=tls.crt=/secure/server-fullchain.pem \
  --from-file=tls.key=/secure/server.key \
  --from-file=client-ca.crt=/secure/device-ca.pem
sudo k3s kubectl apply -k "$HOME/balanco-gateway/kubernetes"
sudo k3s kubectl -n balanco rollout status deployment/balanco --timeout=180s
sudo k3s kubectl -n balanco get pods,service -o wide
```

For encryption and authentication toward the workload too, add `upstream_tls`
and each backend's `server_name` as in [the mTLS example](../examples/mtls.json).
Include the workload CA, proxy client certificate and proxy private key in
`balanco-tls` using matching file names and `/etc/balanco/tls/` paths. The workload
must verify that client identity. The base example encrypts only the device leg.

For trusted forwarding headers, add `http1` rules from
[the HTTP example](../examples/http1.json). Overwrite client-supplied
`x-forwarded-for` with `${client_ip}` and `x-forwarded-proto` with `${scheme}`;
backend applications should trust these headers only from the gateway. After a
successful WebSocket Upgrade, Balanco tunnels frames without transforming them.

## Verify from a separate machine

Use a server name covered by the certificate, the issuing server CA, and a
device certificate/key issued by the configured device CA:

```sh
curl --resolve devices.example.test:443:NODE_LAN_IP \
  --cacert /secure/server-ca.pem \
  --cert /secure/device.crt --key /secure/device.key \
  https://devices.example.test/health
```

Repeat without the client certificate and with an untrusted client certificate;
both must fail. Do not use `--insecure`. Exercise the actual device WebSocket
client against `wss://devices.example.test/`, verify echoed message contents,
and check the workload sees the original device IP. The bundle uses
`externalTrafficPolicy: Local`; verify source preservation on your own network.
Keep client generators outside the node when measuring proxy resource usage.

Inspect process readiness and resource usage:

```sh
sudo k3s kubectl -n balanco exec deployment/balanco -- \
  /bin/balanco --config /etc/balanco/config/balanco.json -c show
sudo k3s kubectl -n balanco logs -l app=balanco --prefix --tail=30
sudo k3s kubectl top pods -n balanco
```

The image has no shell or `curl`. Readiness uses Balanco's local CLI and does
not prove backend health. Each pod has its own private administration socket;
`exec deployment/balanco` selects one pod. Address pods individually when changing
live state. The management API is not exposed by this bundle.

## Rotation and failure checks

Replace `balanco-tls` with renewed files, then explicitly restart the deployment.
A mounted Secret change alone does not reload Balanco:

```sh
sudo k3s kubectl -n balanco create secret generic balanco-tls \
  --from-file=tls.crt=/secure/renewed-fullchain.pem \
  --from-file=tls.key=/secure/renewed.key \
  --from-file=client-ca.crt=/secure/device-ca.pem \
  --dry-run=client -o yaml | sudo k3s kubectl apply -f -
sudo k3s kubectl -n balanco rollout restart deployment/balanco
sudo k3s kubectl -n balanco rollout status deployment/balanco --timeout=180s
```

Include **all** upstream TLS files too if configured; replacing a Secret with
an incomplete set breaks new pods. Verify the new certificate fingerprint from
the external client. Existing sessions retain their original TLS connection.
Remaining sessions close at the 30-second drain deadline and clients must
reconnect with backoff and jitter. A five-second kubelet `preStop.sleep` keeps the
listener available while endpoint removal propagates, before that drain begins;
this does not guarantee every load balancer converges within five seconds.
`rollout status` can finish while old pods are
still draining; check `get pods` before declaring the old generation gone.
The pause uses Kubernetes' [native lifecycle sleep action](https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/),
enabled by default from Kubernetes 1.30, so the scratch image needs no shell.

While devices exchange messages, replace one workload pod and roll the Balanco
deployment. Record forced session closures separately from failed reconnects,
verify service recovery, and confirm new connections reach ready workload pods.
Kubernetes does not migrate an established TCP/WebSocket session to another pod.
Changing ConfigMap contents through `apply -k` updates its generated name and
rolls the pods; changing files inside the checkout alone changes nothing live.

## Lab boundaries and cleanup

The recipe has been exercised with the released image on a single-node Linux
k3s cluster: two-leg mTLS, HTTP header rules, WebSocket messaging, reconnects,
source-IP preservation and certificate replacement. It is not an HA, long-soak
or production-capacity qualification. Use real device timing and your network
before sizing a deployment. Test certificates must not become production identities.

Remove just the gateway with `sudo k3s kubectl delete namespace balanco`; this
does not remove workloads in other namespaces or uninstall the cluster. Remove
only your lab workload namespace separately. The k3s uninstaller removes cluster
state and should be used only when the entire lab is no longer needed.
