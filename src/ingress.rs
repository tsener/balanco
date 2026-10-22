//! Namespace-scoped Kubernetes reconciliation; the traffic path reads an atomic snapshot.
use crate::{
    Error,
    config::{Backend, Config},
    decision::HttpMetadata,
    scheduler::Pool,
    tls,
};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::sync::mpsc;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub namespace: String,
    pub class: String,
}
impl Settings {
    pub fn validate(&self) -> Result<(), Error> {
        for (value, max) in [(&self.namespace, 63), (&self.class, 253)] {
            if value.is_empty()
                || value.len() > max
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-.".contains(&b))
                || !value.as_bytes()[0].is_ascii_alphanumeric()
                || !value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
            {
                return Err("invalid ingress namespace or class".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct RoutingError(pub u16);
impl std::fmt::Display for RoutingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ingress routing HTTP {}", self.0)
    }
}
impl std::error::Error for RoutingError {}

struct Route {
    host: String,
    path: String,
    exact: bool,
    fallback: bool,
    identity: String,
    pool: Arc<Pool>,
    addresses: Vec<SocketAddr>,
    server_name: Option<String>,
}
struct Snapshot {
    routes: Vec<Route>,
    tls: Arc<tls::Tls>,
}
pub struct State {
    snapshot: RwLock<Arc<Snapshot>>,
}
impl State {
    pub fn tls(&self) -> Arc<tls::Tls> {
        self.snapshot
            .read()
            .expect("Ingress lock poisoned")
            .tls
            .clone()
    }
    // Called on each HTTP request; no API, DNS, certificate parsing or filesystem I/O here.
    pub fn select(&self, metadata: &HttpMetadata) -> Result<Arc<Pool>, Error> {
        let state = self.snapshot.read().expect("Ingress lock poisoned");
        let route = state.route(metadata).ok_or(RoutingError(404))?;
        if route.addresses.is_empty() {
            return Err(RoutingError(503).into());
        }
        Ok(route.pool.clone())
    }
    pub fn permits(&self, metadata: &HttpMetadata, backend: &Backend) -> bool {
        self.snapshot
            .read()
            .expect("Ingress lock poisoned")
            .route(metadata)
            .is_some_and(|r| {
                r.addresses.contains(&backend.address) && r.server_name == backend.server_name
            })
    }
}
impl Snapshot {
    fn route(&self, metadata: &HttpMetadata) -> Option<&Route> {
        self.routes
            .iter()
            .filter(|r| {
                host_matches(&r.host, &metadata.host)
                    && path_matches(&r.path, r.exact, &metadata.path)
            })
            .max_by_key(|r| {
                (
                    !r.fallback,
                    if r.host.is_empty() {
                        0
                    } else if r.host.starts_with("*.") {
                        1
                    } else {
                        2
                    },
                    r.path.len(),
                    r.exact,
                )
            })
    }
}

pub fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return host
            .strip_suffix(suffix)
            .is_some_and(|label| !label.is_empty() && !label.contains('.'));
    }
    pattern == host
}
fn path_matches(pattern: &str, exact: bool, path: &str) -> bool {
    if exact {
        return path == pattern;
    }
    let pattern = pattern.trim_end_matches('/');
    path.strip_prefix(pattern)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

#[derive(Clone, Default)]
pub struct Cache {
    pub resources: [BTreeMap<String, Value>; 4],
    bytes: [usize; 4],
}
pub enum Event {
    Reset(usize, Vec<Value>),
    Change(usize, Value, bool),
}
impl Cache {
    fn apply(&mut self, event: Event) {
        match event {
            Event::Reset(kind, values) => {
                self.bytes[kind] = values.iter().map(|v| v.to_string().len()).sum();
                self.resources[kind] = values
                    .into_iter()
                    .map(|v| (text(&v, "/metadata/name").to_owned(), v))
                    .collect();
            }
            Event::Change(kind, object, deleted) => {
                let name = text(&object, "/metadata/name").to_owned();
                if deleted {
                    if self.resources[kind].get(&name).is_some_and(|old| {
                        old.pointer("/metadata/uid") == object.pointer("/metadata/uid")
                    }) {
                        self.bytes[kind] -= self.resources[kind]
                            .remove(&name)
                            .expect("existing resource")
                            .to_string()
                            .len();
                    }
                } else {
                    if let Some(old) = self.resources[kind].remove(&name) {
                        self.bytes[kind] -= old.to_string().len();
                    }
                    let size = object.to_string().len();
                    if self.bytes[kind] + size > 8 * 1024 * 1024
                        || self.resources[kind].len() >= 4096
                    {
                        eprintln!(
                            "Kubernetes cache kind={kind} budget exceeded; changed resource withheld"
                        );
                        return;
                    }
                    self.bytes[kind] += size;
                    self.resources[kind].insert(name, object);
                }
            }
        }
    }
}
fn text<'a>(v: &'a Value, path: &str) -> &'a str {
    v.pointer(path).and_then(Value::as_str).unwrap_or("")
}
fn array<'a>(v: &'a Value, path: &str) -> &'a [Value] {
    v.pointer(path)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

// Secret.data uses standard padded base64; reject malformed and oversized inputs before PEM parsing.
fn decode(input: &str) -> Result<Vec<u8>, Error> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if input.len() > 1_048_576 || !input.len().is_multiple_of(4) {
        return Err("invalid Secret encoding or size".into());
    }
    let mut output = Vec::with_capacity(input.len() / 4 * 3);
    for (i, chunk) in input.as_bytes().chunks_exact(4).enumerate() {
        let mut n = 0u32;
        let mut padding = 0;
        for &c in chunk {
            n <<= 6;
            if c == b'=' {
                padding += 1;
            } else {
                if padding != 0 {
                    return Err("invalid Secret padding".into());
                }
                n |= ALPHABET
                    .iter()
                    .position(|x| *x == c)
                    .ok_or("invalid Secret base64")? as u32;
            }
        }
        if padding > 2
            || (padding > 0 && i + 1 != input.len() / 4)
            || (padding == 1 && n & 255 != 0)
            || (padding == 2 && n & 65535 != 0)
        {
            return Err("invalid Secret padding".into());
        }
        output.extend_from_slice(&n.to_be_bytes()[1..4 - padding]);
    }
    Ok(output)
}

fn endpoints(
    cache: &Cache,
    reference: &Value,
    base: &Config,
) -> Result<(String, Vec<Backend>), Error> {
    let name = text(reference, "/service/name");
    let service = cache.resources[1]
        .get(name)
        .ok_or("referenced Service missing")?;
    if text(service, "/spec/type") == "ExternalName" {
        return Err("ExternalName Services are unsupported".into());
    }
    let port_ref = &reference["service"]["port"];
    let port = array(service, "/spec/ports")
        .iter()
        .find(|p| {
            (port_ref["number"].as_u64().is_some() && p["port"] == port_ref["number"])
                || (port_ref["name"].as_str().is_some() && p["name"] == port_ref["name"])
        })
        .ok_or("referenced Service port missing")?;
    if port.get("protocol").is_some_and(|p| p != "TCP") {
        return Err("Ingress requires TCP Service ports".into());
    }
    let server_name = service["metadata"]["annotations"]["balanco.io/backend-server-name"]
        .as_str()
        .map(str::to_owned);
    if base.upstream_tls.is_some() != server_name.is_some() {
        return Err("upstream TLS requires Service backend-server-name annotation".into());
    }
    if let Some(name) = &server_name {
        tokio_rustls::rustls::pki_types::ServerName::try_from(name.clone())?;
    }
    let identity = format!("{name}:{}:{server_name:?}", port["port"]);
    let mut addresses = BTreeSet::new();
    for slice in cache.resources[2]
        .values()
        .filter(|s| s["metadata"]["labels"]["kubernetes.io/service-name"] == name)
    {
        // Ignore slices from a deleted/recreated Service, even when its name is reused.
        let owners = array(slice, "/metadata/ownerReferences");
        if !owners.is_empty()
            && !owners.iter().any(|owner| {
                owner["kind"] == "Service" && owner["uid"] == service["metadata"]["uid"]
            })
        {
            continue;
        }
        if !matches!(text(slice, "/addressType"), "IPv4" | "IPv6") {
            continue;
        }
        let endpoint_port = array(slice, "/ports").iter().find(|p| {
            p["name"].as_str().unwrap_or("") == port["name"].as_str().unwrap_or("")
                && p.get("protocol").is_none_or(|p| p == "TCP")
        });
        let Some(number) = endpoint_port
            .and_then(|p| p["port"].as_u64())
            .filter(|n| (1..=65535).contains(n))
        else {
            continue;
        };
        for endpoint in array(slice, "/endpoints") {
            if endpoint["conditions"]["ready"] == false
                || endpoint["conditions"]["terminating"] == true
            {
                continue;
            }
            for value in array(endpoint, "/addresses") {
                let ip: IpAddr = value.as_str().ok_or("invalid endpoint IP")?.parse()?;
                let link_local = match ip {
                    IpAddr::V4(v) => v.is_link_local(),
                    IpAddr::V6(v) => v.is_unicast_link_local(),
                };
                if ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || link_local
                    || ip.is_ipv4() != (text(slice, "/addressType") == "IPv4")
                {
                    return Err("unsafe endpoint IP".into());
                }
                addresses.insert(SocketAddr::new(ip, number as u16));
            }
        }
    }
    if addresses.len() > 256 {
        return Err("Ingress Service exceeds 256 endpoints".into());
    }
    Ok((
        identity,
        addresses
            .into_iter()
            .map(|address| Backend {
                address,
                server_name: server_name.clone(),
                weight: 1,
                priority: 0,
                max_connections: 0,
                region: None,
                capabilities: vec![],
            })
            .collect(),
    ))
}

fn compile(cache: &Cache, base: &Config, previous: Option<&Snapshot>) -> Result<Snapshot, Error> {
    let settings = base.ingress.as_ref().ok_or("missing Ingress settings")?;
    let mut ingresses: Vec<_> = cache.resources[0]
        .values()
        .filter(|i| {
            text(i, "/spec/ingressClassName") == settings.class
                && i.pointer("/metadata/deletionTimestamp").is_none()
        })
        .collect();
    ingresses.sort_by_key(|i| {
        (
            text(i, "/metadata/creationTimestamp"),
            text(i, "/metadata/name"),
        )
    });
    let mut routes = vec![];
    let mut keys = BTreeSet::new();
    let mut cert_hosts = BTreeSet::new();
    let mut identities = vec![];
    let mut blocked = vec![];
    for ingress in ingresses {
        let mut entries = vec![];
        if let Some(backend) = ingress.pointer("/spec/defaultBackend") {
            entries.push((String::new(), "/".to_owned(), false, true, backend));
        }
        for rule in array(ingress, "/spec/rules") {
            for path in array(rule, "/http/paths") {
                let pattern = text(path, "/path");
                let kind = text(path, "/pathType");
                if !pattern.starts_with('/')
                    || !matches!(kind, "Exact" | "Prefix" | "ImplementationSpecific")
                {
                    continue;
                }
                let normalized = if kind == "Exact" {
                    pattern
                } else {
                    pattern.trim_end_matches('/')
                };
                entries.push((
                    text(rule, "/host").to_ascii_lowercase(),
                    if normalized.is_empty() {
                        "/".to_owned()
                    } else {
                        normalized.to_owned()
                    },
                    kind == "Exact",
                    false,
                    &path["backend"],
                ));
            }
        }
        for (host, path, exact, fallback, reference) in entries {
            if !keys.insert((host.clone(), path.clone(), exact, fallback)) {
                continue;
            }
            let (identity, backends) = match endpoints(cache, reference, base) {
                Ok(result) => result,
                Err(error) => {
                    eprintln!(
                        "Ingress {}/{} backend unavailable: {error}",
                        settings.namespace,
                        text(ingress, "/metadata/name")
                    );
                    (String::new(), vec![])
                }
            };
            let addresses: Vec<_> = backends.iter().map(|b| b.address).collect();
            let server_name = backends.first().and_then(|b| b.server_name.clone());
            let pool = previous
                .and_then(|p| {
                    p.routes
                        .iter()
                        .find(|r| r.identity == identity && r.addresses == addresses)
                })
                .map(|r| r.pool.clone())
                .unwrap_or_else(|| {
                    let mut config = base.clone();
                    config.ingress = None;
                    config.backends = backends;
                    Arc::new(Pool::from_config(&config))
                });
            routes.push(Route {
                host,
                path,
                exact,
                fallback,
                identity,
                pool,
                addresses,
                server_name,
            });
            if routes.len() > 256 {
                return Err("Ingress route limit 256 exceeded".into());
            }
        }
        for entry in array(ingress, "/spec/tls") {
            let hosts: Vec<_> = array(entry, "/hosts")
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_ascii_lowercase)
                .filter(|h| cert_hosts.insert(h.clone()))
                .collect();
            if hosts.is_empty() {
                continue;
            }
            let prepared = (|| -> Result<_, Error> {
                let secret = cache.resources[3]
                    .get(text(entry, "/secretName"))
                    .ok_or("TLS Secret missing")?;
                if text(secret, "/type") != "kubernetes.io/tls" {
                    return Err("Secret must have type kubernetes.io/tls".into());
                }
                let cert = decode(text(secret, "/data/tls.crt"))?;
                let key = decode(text(secret, "/data/tls.key"))?;
                let certified = tls::memory_key(&cert, &key)?;
                for host in &hosts {
                    let probe = host
                        .strip_prefix('*')
                        .map_or_else(|| host.clone(), |suffix| format!("balanco-ingress{suffix}"));
                    tokio_rustls::rustls::server::ResolvesServerCertUsingSni::new()
                        .add(&probe, certified.as_ref().clone())?;
                }
                Ok((hosts.clone(), cert, key))
            })();
            match prepared {
                Ok(identity) => identities.push(identity),
                Err(_) => {
                    eprintln!(
                        "Ingress {}/{} TLS Secret unavailable or invalid; affected SNI hosts denied",
                        settings.namespace,
                        text(ingress, "/metadata/name")
                    );
                    blocked.extend(hosts);
                }
            }
        }
    }
    let mut tls = tls::Tls::load(base)?;
    tls.acceptor = Some(tls::ingress_server(
        base.tls.as_ref().ok_or("Ingress TLS missing")?,
        identities,
        blocked,
    )?);
    Ok(Snapshot {
        routes,
        tls: Arc::new(tls),
    })
}

// Called once by main::run. Readiness starts only after all four caches synchronize.
pub async fn start(base: Config) -> Result<Arc<State>, Error> {
    let settings = base.ingress.as_ref().ok_or("missing Ingress settings")?;
    let api = Arc::new(crate::ingress_api::Api::new().await?);
    let (tx, mut rx) = mpsc::channel(32);
    for (kind, resource) in ["ingresses", "services", "endpointslices", "secrets"]
        .iter()
        .enumerate()
    {
        let prefix = match kind {
            0 => "/apis/networking.k8s.io/v1",
            2 => "/apis/discovery.k8s.io/v1",
            _ => "/api/v1",
        };
        let path = format!("{prefix}/namespaces/{}/{resource}", settings.namespace);
        let api = api.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            api.follow(kind, path, tx).await;
        });
    }
    drop(tx);
    let mut cache = Cache::default();
    let mut ready = [false; 4];
    tokio::time::timeout(Duration::from_secs(45), async {
        while !ready.iter().all(|r| *r) {
            let event = rx.recv().await.ok_or("Kubernetes watchers stopped")?;
            if let Event::Reset(kind, _) = &event {
                ready[*kind] = true;
            }
            cache.apply(event);
        }
        Ok::<_, Error>(())
    })
    .await??;
    let initial_cache = cache.clone();
    let initial_base = base.clone();
    let snapshot =
        tokio::task::spawn_blocking(move || compile(&initial_cache, &initial_base, None)).await??;
    eprintln!(
        "Ingress caches synchronized; routes={}",
        snapshot.routes.len()
    );
    let state = Arc::new(State {
        snapshot: RwLock::new(Arc::new(snapshot)),
    });
    let worker = state.clone();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            cache.apply(event);
            tokio::time::sleep(Duration::from_millis(100)).await;
            while let Ok(event) = rx.try_recv() {
                cache.apply(event);
            }
            let next_cache = cache.clone();
            let next_base = base.clone();
            let old = worker
                .snapshot
                .read()
                .expect("Ingress lock poisoned")
                .clone();
            match tokio::task::spawn_blocking(move || compile(&next_cache, &next_base, Some(&old)))
                .await
            {
                Ok(Ok(snapshot)) => {
                    eprintln!("Ingress snapshot applied; routes={}", snapshot.routes.len());
                    *worker.snapshot.write().expect("Ingress lock poisoned") = Arc::new(snapshot);
                }
                _ => eprintln!("Ingress snapshot rejected; previous generation retained"),
            }
        }
    });
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn route(path: &str, exact: bool, address: SocketAddr) -> Route {
        let config = Config {
            backends: serde_json::from_value(json!([{"address":address}])).unwrap(),
            ..Default::default()
        };
        Route {
            host: "localhost".into(),
            path: path.into(),
            exact,
            fallback: false,
            identity: path.into(),
            pool: Arc::new(Pool::from_config(&config)),
            addresses: vec![address],
            server_name: None,
        }
    }
    fn metadata(path: &str) -> HttpMetadata {
        HttpMetadata {
            host: "localhost".into(),
            path: path.into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn snapshots_select_longest_exact_paths_and_deny_missing_tls_secrets() {
        let fixture = crate::tls::tests::Certificates::new();
        let connector = tls::Tls::load(&fixture.config())
            .unwrap()
            .connector
            .unwrap();
        let mut config = fixture.config();
        config.backends.clear();
        config.management = None;
        config.upstream_tls = None;
        config.http1 = Some(Arc::default());
        config.ingress = Some(Settings {
            namespace: "lab".into(),
            class: "balanco".into(),
        });
        config.validate().unwrap();
        let b64 = |name: &str| {
            String::from_utf8(
                std::process::Command::new("openssl")
                    .args(["base64", "-A", "-in", &fixture.file(name)])
                    .output()
                    .unwrap()
                    .stdout,
            )
            .unwrap()
        };
        let mut cache = Cache::default();
        cache.apply(Event::Reset(0,vec![json!({"metadata":{"name":"edge","uid":"ingress"},"spec":{"ingressClassName":"balanco","tls":[{"hosts":["localhost"],"secretName":"identity"}],"rules":[{"host":"localhost","http":{"paths":[{"path":"/a","pathType":"Prefix","backend":{"service":{"name":"app","port":{"name":"web"}}}}]}}]}})]));
        cache.apply(Event::Reset(1,vec![json!({"metadata":{"name":"app","uid":"svc"},"spec":{"ports":[{"name":"web","port":80}]}})]));
        cache.apply(Event::Reset(2,vec![json!({"metadata":{"name":"slice","uid":"slice","labels":{"kubernetes.io/service-name":"app"}},"addressType":"IPv4","ports":[{"name":"web","port":8080}],"endpoints":[{"addresses":["10.0.0.1"]}]})]));
        cache.apply(Event::Reset(3,vec![json!({"metadata":{"name":"identity","uid":"secret"},"type":"kubernetes.io/tls","data":{"tls.crt":b64("server.pem"),"tls.key":b64("server.key")}})]));
        let old = compile(&cache, &config, None).unwrap();
        let pool = old.route(&metadata("/a/b")).unwrap().pool.clone();
        let next = compile(&cache, &config, Some(&old)).unwrap();
        assert!(Arc::ptr_eq(
            &pool,
            &next.route(&metadata("/a")).unwrap().pool
        ));
        assert!(next.route(&metadata("/ab")).is_none());
        let (server, client) = tokio::io::duplex(65536);
        let (server, client) = tokio::join!(
            next.tls.acceptor.as_ref().unwrap().accept(server),
            connector.connect(
                tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                client
            )
        );
        assert!(server.is_ok() && client.is_ok());
        cache.apply(Event::Change(
            3,
            json!({"metadata":{"name":"identity","uid":"secret"}}),
            true,
        ));
        let missing = compile(&cache, &config, Some(&old)).unwrap();
        let (server, client) = tokio::io::duplex(65536);
        let (server, client) = tokio::join!(
            missing.tls.acceptor.as_ref().unwrap().accept(server),
            connector.connect(
                tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                client
            )
        );
        assert!(server.is_err() && client.is_err());
        cache.resources[0].get_mut("edge").unwrap()["spec"]["ingressClassName"] = "other".into();
        assert!(
            compile(&cache, &config, Some(&old))
                .unwrap()
                .routes
                .is_empty()
        );
        let mut snapshot = old;
        snapshot.routes = vec![
            route("/a", false, "10.0.0.1:80".parse().unwrap()),
            route("/a", true, "10.0.0.2:80".parse().unwrap()),
            route("/a/b", false, "10.0.0.3:80".parse().unwrap()),
        ];
        assert_eq!(
            snapshot.route(&metadata("/a")).unwrap().addresses[0]
                .ip()
                .to_string(),
            "10.0.0.2"
        );
        assert_eq!(
            snapshot.route(&metadata("/a/b/c")).unwrap().addresses[0]
                .ip()
                .to_string(),
            "10.0.0.3"
        );
    }

    #[tokio::test]
    async fn one_http_connection_reroutes_after_path_and_live_snapshot_changes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        async fn head<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
            let mut header = vec![];
            while !header.ends_with(b"\r\n\r\n") {
                let byte = stream.read_u8().await.unwrap();
                header.push(byte);
                assert!(header.len() < 8192);
            }
            header
        }
        async fn backend(value: u8) -> (SocketAddr, tokio::task::JoinHandle<()>) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        loop {
                            if stream.readable().await.is_err() {
                                break;
                            }
                            let mut peek = [0];
                            if stream.peek(&mut peek).await.unwrap_or(0) == 0 {
                                break;
                            }
                            head(&mut stream).await;
                            let mut response =
                                b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n".to_vec();
                            response.push(value);
                            if stream.write_all(&response).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            });
            (address, task)
        }
        let (a, task_a) = backend(b'A').await;
        let (b, task_b) = backend(b'B').await;
        let config: Config = serde_json::from_value(
            json!({"ingress":{"namespace":"lab","class":"balanco"},"http1":{}}),
        )
        .unwrap();
        let tls = Arc::new(tls::Tls::load(&config).unwrap());
        let state = Arc::new(State {
            snapshot: RwLock::new(Arc::new(Snapshot {
                routes: vec![route("/a", false, a), route("/b", false, b)],
                tls: tls.clone(),
            })),
        });
        let proxy = crate::Proxy {
            ingress: Some(state.clone()),
            pool: Arc::new(Pool::from_config(&config)),
            http: Arc::new(crate::http1::State::new(config.http1.clone(), vec![])),
            stats: Default::default(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let relay = tokio::spawn(async move { proxy.handle(&config, stream, None, tls).await });
        for (path, expected) in [("/a", b'A'), ("/a", b'A'), ("/b", b'B'), ("/a", b'B')] {
            if path == "/a" && expected == b'B' {
                let tls = state.tls();
                *state.snapshot.write().unwrap() = Arc::new(Snapshot {
                    routes: vec![route("/a", false, b)],
                    tls,
                });
            }
            client
                .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let header = tokio::time::timeout(Duration::from_secs(2), head(&mut client))
                .await
                .unwrap();
            assert!(header.starts_with(b"HTTP/1.1 200"));
            assert_eq!(client.read_u8().await.unwrap(), expected);
        }
        drop(client);
        tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        task_a.abort();
        task_b.abort();
    }
    #[test]
    fn kubernetes_host_path_and_secret_encoding_rules() {
        assert!(host_matches("*.example.test", "a.example.test"));
        assert!(!host_matches("*.example.test", "a.b.example.test"));
        assert!(!host_matches("*.example.test", "example.test"));
        assert!(path_matches("/foo/", false, "/foo"));
        assert!(path_matches("/foo", false, "/foo/bar"));
        assert!(!path_matches("/foo", false, "/foobar"));
        assert!(!path_matches("/foo", true, "/foo/"));
        assert_eq!(decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(decode("Zg==").unwrap(), b"f");
        for invalid in ["Zg=", "Zg===", "Zg==Zg==", "Zh==", "Zm9=", "====", "Z=g="] {
            assert!(decode(invalid).is_err(), "{invalid}");
        }
    }
    #[test]
    fn endpoints_follow_service_port_uid_and_ready_conditions() {
        let mut cache = Cache::default();
        cache.resources[1].insert("app".into(), json!({"metadata":{"uid":"new"},"spec":{"ports":[{"name":"web","port":80,"targetPort":"http"}]}}));
        cache.resources[2].insert("slice".into(), json!({"metadata":{"labels":{"kubernetes.io/service-name":"app"},"ownerReferences":[{"kind":"Service","uid":"new"}]},"addressType":"IPv4","ports":[{"name":"web","port":8080}],"endpoints":[{"addresses":["10.0.0.1"]},{"addresses":["10.0.0.2"],"conditions":{"ready":false}},{"addresses":["10.0.0.3"],"conditions":{"terminating":true}}]}));
        let reference = json!({"service":{"name":"app","port":{"number":80}}});
        let (_, values) = endpoints(&cache, &reference, &Config::default()).unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].address.to_string(), "10.0.0.1:8080");
        cache.resources[1].get_mut("app").unwrap()["metadata"]["uid"] = "recreated".into();
        assert!(
            endpoints(&cache, &reference, &Config::default())
                .unwrap()
                .1
                .is_empty()
        );
        assert!(
            endpoints(
                &cache,
                &json!({"service":{"name":"app","port":{"number":81}}}),
                &Config::default()
            )
            .is_err()
        );
    }
}
