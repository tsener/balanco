//! Opt-in HTTP framing and header hooks; upgraded WebSockets switch to a raw tunnel.
use crate::{Error, scheduler::Counters};
use balanco::http_plugin::{self, Context, HeaderMap, HttpConfig, HttpPlugin, Phase, Rule};
use hyper::{
    Request,
    body::{Body, Bytes, Frame, Incoming, SizeHint},
    header,
    service::service_fn,
    upgrade::OnUpgrade,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::{Deserialize, Serialize};
use std::{
    io,
    pin::Pin,
    sync::{
        Arc, OnceLock, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Mutex, oneshot},
    time::{Instant, timeout},
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleUpdate {
    pub expected_generation: u64,
    pub rules: Vec<Rule>,
}
struct Snapshot {
    enabled: bool,
    generation: u64,
    policy: Arc<http_plugin::HeaderRules>,
}
pub struct State {
    snapshot: RwLock<Snapshot>,
    plugins: Vec<Arc<dyn HttpPlugin>>,
}
impl State {
    pub fn new(config: Option<Arc<HttpConfig>>, plugins: Vec<Arc<dyn HttpPlugin>>) -> Self {
        Self {
            snapshot: RwLock::new(Snapshot {
                enabled: config.is_some(),
                generation: 1,
                policy: Arc::new(http_plugin::HeaderRules(config.unwrap_or_default())),
            }),
            plugins,
        }
    }
    pub fn reload(&self, config: Option<Arc<HttpConfig>>) {
        let mut state = self.snapshot.write().expect("HTTP policy lock poisoned");
        state.enabled = config.is_some();
        if let Some(config) = config {
            state.policy = Arc::new(http_plugin::HeaderRules(config));
        }
        state.generation += 1;
    }
    pub fn status(&self) -> (u64, serde_json::Value) {
        let state = self.snapshot.read().expect("HTTP policy lock poisoned");
        (
            state.generation,
            serde_json::json!({"enabled":state.enabled,"generation":state.generation,
            "http1": if state.enabled { Some(&state.policy.0) } else { None }}),
        )
    }
    // Called by control::dispatch; compare the generation before replacing the rule snapshot.
    pub fn update(&self, update: RuleUpdate) -> Result<(), Error> {
        let mut next = {
            let state = self.snapshot.read().expect("HTTP policy lock poisoned");
            if !state.enabled {
                return Err("HTTP plugin is not enabled on this listener".into());
            }
            (*state.policy.0).clone()
        };
        next.rules = update.rules;
        next.validate()?;
        let mut state = self.snapshot.write().expect("HTTP policy lock poisoned");
        if state.generation != update.expected_generation {
            return Err("HTTP policy generation conflict; fetch /v1/http and retry".into());
        }
        if !state.enabled {
            return Err("HTTP plugin is not enabled on this listener".into());
        }
        state.policy = Arc::new(http_plugin::HeaderRules(Arc::new(next)));
        state.generation += 1;
        Ok(())
    }
    fn policy(&self) -> Arc<http_plugin::HeaderRules> {
        self.snapshot
            .read()
            .expect("HTTP policy lock poisoned")
            .policy
            .clone()
    }
}

fn token(headers: &HeaderMap, name: &str, value: &str) -> bool {
    headers
        .get_all(name)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .flat_map(|h| h.split(','))
        .any(|h| h.trim().eq_ignore_ascii_case(value))
}
fn websocket(headers: &HeaderMap) -> bool {
    token(headers, "connection", "upgrade") && token(headers, "upgrade", "websocket")
}
fn validate_host(headers: &HeaderMap) -> Result<(), Error> {
    if headers.get_all(header::HOST).iter().count() != 1 {
        return Err("exactly one Host is required".into());
    }
    let value = headers[header::HOST].to_str()?;
    http_plugin::validate_host(value)
}

// Extract classification before any header hook; forwarded identity headers are never trusted.
fn metadata(request: &Request<Incoming>, ws: bool) -> Result<crate::decision::HttpMetadata, Error> {
    let mut protocols = Vec::new();
    if ws {
        if request
            .headers()
            .get_all("sec-websocket-version")
            .iter()
            .count()
            != 1
            || request
                .headers()
                .get("sec-websocket-version")
                .is_none_or(|v| v != "13")
            || request
                .headers()
                .get_all("sec-websocket-key")
                .iter()
                .count()
                != 1
        {
            return Err("invalid WebSocket version or key".into());
        }
        let key = request.headers()["sec-websocket-key"].as_bytes();
        if key.len() != 24
            || &key[22..] != b"=="
            || !b"AQgw".contains(&key[21])
            || !key[..22]
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"+/".contains(b))
        {
            return Err("invalid WebSocket key".into());
        }
        for value in request.headers().get_all("sec-websocket-protocol") {
            for p in value.to_str()?.split(',').map(str::trim) {
                if p.is_empty()
                    || p.len() > 128
                    || !p
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                    || protocols.len() >= 16
                    || protocols.iter().any(|v| v == p)
                {
                    return Err("invalid WebSocket subprotocol offer".into());
                }
                protocols.push(p.to_owned());
            }
        }
    }
    let host = request.headers()[header::HOST]
        .to_str()?
        .parse::<hyper::http::uri::Authority>()?
        .host()
        .to_ascii_lowercase();
    Ok(crate::decision::HttpMetadata {
        host,
        method: request.method().as_str().to_owned(),
        path: request.uri().path().to_owned(),
        version: "HTTP/1.1".into(),
        websocket: ws,
        websocket_protocols: protocols,
    })
}
fn sanitize(headers: &mut HeaderMap, upgrade: bool) -> Result<Vec<header::HeaderName>, Error> {
    let mut nominated = Vec::new();
    for value in headers.get_all(header::CONNECTION) {
        for name in value.to_str()?.split(',') {
            let name = header::HeaderName::from_bytes(name.trim().as_bytes())?;
            if matches!(
                name.as_str(),
                "host" | "content-length" | "transfer-encoding"
            ) || name.as_str().starts_with("sec-websocket-")
            {
                return Err(
                    "Connection cannot nominate framing or WebSocket handshake headers".into(),
                );
            }
            nominated.push(name);
        }
    }
    for name in &nominated {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "upgrade",
    ] {
        headers.remove(name);
    }
    if upgrade {
        headers.insert(
            header::CONNECTION,
            header::HeaderValue::from_static("upgrade"),
        );
        headers.insert(
            header::UPGRADE,
            header::HeaderValue::from_static("websocket"),
        );
    }
    Ok(nominated)
}

/// Run hooks on a copy, then verify that custom plugins did not change framing headers.
fn transform(
    plugin: &dyn HttpPlugin,
    phase: Phase,
    context: &Context<'_>,
    headers: &mut HeaderMap,
    nominated: &[header::HeaderName],
    limit: usize,
) -> Result<(), Error> {
    let before: HeaderMap = headers
        .iter()
        .filter(|(n, _)| http_plugin::protected(n.as_str()))
        .map(|(n, v)| (n.clone(), v.clone()))
        .collect();
    let mut next = headers.clone();
    plugin.transform(phase, context, &mut next)?;
    let after: HeaderMap = next
        .iter()
        .filter(|(n, _)| http_plugin::protected(n.as_str()))
        .map(|(n, v)| (n.clone(), v.clone()))
        .collect();
    if before != after
        || nominated
            .iter()
            .any(|n| !http_plugin::protected(n.as_str()) && next.contains_key(n))
    {
        return Err("HTTP plugin changed a protected or connection-specific header".into());
    }
    http_plugin::check_size(&next, limit)?;
    if phase == Phase::Request {
        validate_host(&next)?;
    }
    *headers = next;
    Ok(())
}

struct Traffic {
    started: Instant,
    track_idle: bool,
    last_ms: AtomicU64,
    up: AtomicU64,
    down: AtomicU64,
    counters: OnceLock<Arc<Counters>>,
}
impl Traffic {
    fn touch(&self) {
        if self.track_idle {
            self.last_ms
                .store(self.started.elapsed().as_millis() as u64, Ordering::Relaxed);
        }
    }
    async fn expire(&self, idle_ms: Option<u64>) {
        let Some(idle_ms) = idle_ms else {
            return std::future::pending().await;
        };
        loop {
            let last = self.last_ms.load(Ordering::Relaxed);
            tokio::time::sleep_until(self.started + Duration::from_millis(last + idle_ms)).await;
            if self.started.elapsed().as_millis()
                >= u128::from(self.last_ms.load(Ordering::Relaxed) + idle_ms)
            {
                return;
            }
        }
    }
}
struct Metered<S> {
    stream: S,
    traffic: Arc<Traffic>,
    upstream: bool,
    dump: Option<&'static str>,
}
impl<S: AsyncRead + Unpin> AsyncRead for Metered<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.traffic.touch();
            if let Some(direction) = self.dump
                && let Err(error) = crate::transport::dump(direction, &buf.filled()[before..])
            {
                return Poll::Ready(Err(error));
            }
        }
        result
    }
}

// Trailer fields must not bypass a header removal or inject a second trusted identity.
struct Payload(Incoming);
impl Body for Payload {
    type Data = Bytes;
    type Error = hyper::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        loop {
            match Pin::new(&mut self.0).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) if frame.is_trailers() => continue,
                other => return other,
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.0.size_hint()
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Metered<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(cx, bytes);
        if let Poll::Ready(Ok(n)) = result {
            if n > 0 {
                self.traffic.touch();
            }
            let local = if self.upstream {
                &self.traffic.up
            } else {
                &self.traffic.down
            };
            local.fetch_add(n as u64, Ordering::Relaxed);
            if let Some(counters) = self.traffic.counters.get() {
                let total = if self.upstream {
                    &counters.up
                } else {
                    &counters.down
                };
                total.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

// Called by Proxy::relay; parse the first headers before establishing an upstream, then stream bodies.
pub async fn relay<A, F, Fut>(
    client: A,
    connection: crate::ClientInfo,
    config: &crate::config::Config,
    state: Arc<State>,
    establish: F,
) -> Result<(u64, u64), Error>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnOnce(crate::decision::HttpMetadata) -> Fut,
    Fut: std::future::Future<Output = Result<(crate::Upstream, crate::scheduler::Lease), Error>>,
{
    let idle_ms = config.idle_timeout_ms;
    let buffer = config.buffer_bytes;
    let packet_dump = config.packet_dump;
    let config = config
        .http1
        .clone()
        .ok_or("HTTP plugin is not configured")?;
    let traffic = Arc::new(Traffic {
        started: Instant::now(),
        track_idle: idle_ms.is_some(),
        last_ms: AtomicU64::new(0),
        up: AtomicU64::new(0),
        down: AtomicU64::new(0),
        counters: OnceLock::new(),
    });
    let client = TokioIo::new(Metered {
        stream: client,
        traffic: traffic.clone(),
        upstream: false,
        dump: packet_dump.then_some("client->backend"),
    });
    let max_header_bytes = config.max_header_bytes;
    let header_timeout = Duration::from_millis(config.header_timeout_ms);
    let run = async {
        let (metadata_tx, metadata_rx) = oneshot::channel();
        let (sender_tx, sender_rx) = oneshot::channel();
        let routing = Arc::new(Mutex::new((Some(metadata_tx), Some(sender_rx))));
        let upstream_traffic = traffic.clone();
        let upstream_config = config.clone();
        let upstream = async move {
            let metadata = match metadata_rx.await {
                Ok(m) => m,
                Err(_) => return Ok(None),
            };
            let (backend, lease) = establish(metadata).await?;
            let _ = upstream_traffic.counters.set(lease.counters.clone());
            let backend = TokioIo::new(Metered {
                stream: backend,
                traffic: upstream_traffic,
                upstream: true,
                dump: packet_dump.then_some("backend->client"),
            });
            let (sender, driver) = hyper::client::conn::http1::Builder::new()
                .max_headers(64)
                .max_buf_size(upstream_config.max_header_bytes)
                .handshake::<_, Payload>(backend)
                .await?;
            sender_tx
                .send((sender, lease))
                .map_err(|_| "HTTP frontend closed before backend setup")?;
            driver.with_upgrades().await?;
            Ok::<_, Error>(None::<()>)
        };
        let sender = Arc::new(Mutex::new(None));
        let retained_lease = Arc::new(Mutex::new(None));
        let service_lease = retained_lease.clone();
        let (upgrade_tx, upgrade_rx) = oneshot::channel::<(OnUpgrade, OnUpgrade)>();
        let upgrade_tx = Arc::new(Mutex::new(Some(upgrade_tx)));
        let service = service_fn(move |mut request: Request<Incoming>| {
            let sender = sender.clone();
            let routing = routing.clone();
            let retained_lease = service_lease.clone();
            let state = state.clone();
            let upgrade_tx = upgrade_tx.clone();
            let sni = connection.sni.clone();
            let config = config.clone();
            let mut routing_info = connection.clone();
            async move {
                let result = async {
                    if request.version() != hyper::Version::HTTP_11
                        || request.method() == hyper::Method::CONNECT
                        || !request.uri().path().starts_with('/')
                        || request.uri().scheme().is_some()
                        || request.uri().authority().is_some()
                    {
                        return Err::<_, Error>(
                            "HTTP plugin requires origin-form HTTP/1.1; CONNECT is unsupported"
                                .into(),
                        );
                    }
                    validate_host(request.headers())?;
                    let ws = websocket(request.headers());
                    if request.headers().contains_key(header::UPGRADE) && !ws {
                        return Err("only WebSocket upgrades are supported".into());
                    }
                    if ws
                        && (request.method() != hyper::Method::GET
                            || request.headers().contains_key(header::TRANSFER_ENCODING)
                            || request
                                .headers()
                                .get(header::CONTENT_LENGTH)
                                .is_some_and(|v| v != "0"))
                    {
                        return Err("WebSocket upgrade requires GET without a request body".into());
                    }
                    let method = request.method().as_str().to_owned();
                    let path = request.uri().path().to_owned();
                    let metadata = metadata(&request, ws)?;
                    routing_info.metadata.http = Some(metadata.clone());
                    let mut sender = sender.lock().await;
                    if sender.is_none() {
                        let mut init = routing.lock().await;
                        init.0
                            .take()
                            .ok_or("missing HTTP routing request")?
                            .send(metadata)
                            .map_err(|_| "backend setup closed")?;
                        let (ready, lease) =
                            init.1.take().ok_or("missing backend setup result")?.await?;
                        *retained_lease.lock().await = Some(lease);
                        *sender = Some(ready);
                    }
                    let lease = retained_lease.lock().await;
                    let lease = lease.as_ref().ok_or("missing backend lease")?;
                    if !lease.routing_guard.permits(routing_info.context()) {
                        return Err("HTTP keep-alive request changed routing class".into());
                    }
                    let mut context = Context {
                        peer: connection.peer,
                        backend: lease.backend.address,
                        scheme: if routing_info.tls_version.is_some() {
                            "https"
                        } else {
                            "http"
                        },
                        method: &method,
                        path: &path,
                        sni: sni.as_deref(),
                        status: None,
                    };
                    let policy = state.policy();
                    let nominated = sanitize(request.headers_mut(), ws)?;
                    transform(
                        policy.as_ref(),
                        Phase::Request,
                        &context,
                        request.headers_mut(),
                        &nominated,
                        config.max_header_bytes,
                    )?;
                    for plugin in &state.plugins {
                        transform(
                            plugin.as_ref(),
                            Phase::Request,
                            &context,
                            request.headers_mut(),
                            &nominated,
                            config.max_header_bytes,
                        )?;
                    }
                    let client_upgrade = if ws {
                        Some(hyper::upgrade::on(&mut request))
                    } else {
                        None
                    };
                    let sender = sender.as_mut().ok_or("missing HTTP backend sender")?;
                    let mut response =
                        timeout(Duration::from_millis(config.response_timeout_ms), async {
                            sender.ready().await?;
                            sender.send_request(request.map(Payload)).await
                        })
                        .await??;
                    let switching = response.status() == hyper::StatusCode::SWITCHING_PROTOCOLS;
                    if switching && (!ws || !websocket(response.headers())) {
                        return Err("unexpected or invalid upstream upgrade".into());
                    }
                    let status = response.status();
                    let has_body = method != "HEAD"
                        && !status.is_informational()
                        && status != hyper::StatusCode::NO_CONTENT
                        && status != hyper::StatusCode::NOT_MODIFIED;
                    let close = token(response.headers(), "connection", "close")
                        || (has_body
                            && !response.headers().contains_key(header::CONTENT_LENGTH)
                            && !token(response.headers(), "transfer-encoding", "chunked"));
                    let nominated = sanitize(response.headers_mut(), switching)?;
                    if close {
                        response.headers_mut().insert(
                            header::CONNECTION,
                            header::HeaderValue::from_static("close"),
                        );
                    }
                    context.status = Some(response.status().as_u16());
                    transform(
                        policy.as_ref(),
                        Phase::Response,
                        &context,
                        response.headers_mut(),
                        &nominated,
                        config.max_header_bytes,
                    )?;
                    for plugin in &state.plugins {
                        transform(
                            plugin.as_ref(),
                            Phase::Response,
                            &context,
                            response.headers_mut(),
                            &nominated,
                            config.max_header_bytes,
                        )?;
                    }
                    if switching {
                        let upstream_upgrade = hyper::upgrade::on(&mut response);
                        upgrade_tx
                            .lock()
                            .await
                            .take()
                            .ok_or("multiple HTTP upgrades")?
                            .send((
                                client_upgrade.ok_or("missing client upgrade")?,
                                upstream_upgrade,
                            ))
                            .map_err(|_| "HTTP upgrade receiver closed")?;
                    }
                    Ok(response.map(Payload))
                }
                .await;
                result.map_err(io::Error::other)
            }
        });
        let mut builder = hyper::server::conn::http1::Builder::new();
        // The connection's limits stay fixed; request/response policy snapshots can change live.
        builder
            .timer(TokioTimer::new())
            .half_close(true)
            .max_headers(64)
            .max_buf_size(max_header_bytes)
            .max_header_size(max_header_bytes)
            .header_read_timeout(header_timeout);
        let frontend = builder.serve_connection(client, service).with_upgrades();
        tokio::try_join!(async { frontend.await.map_err(Error::from) }, upstream)?;
        if let Ok((client, backend)) = upgrade_rx.await {
            let (client, backend) = timeout(Duration::from_secs(5), async {
                tokio::try_join!(client, backend)
            })
            .await??;
            tokio::io::copy_bidirectional_with_sizes(
                &mut TokioIo::new(client),
                &mut TokioIo::new(backend),
                buffer,
                buffer,
            )
            .await?;
        }
        Ok::<_, Error>(())
    };
    tokio::select! {
        result = run => result?,
        _ = traffic.expire(idle_ms) => return Err("connection idle timeout".into()),
    }
    Ok((
        traffic.up.load(Ordering::Relaxed),
        traffic.down.load(Ordering::Relaxed),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn first_request_selects_backend_and_keep_alive_cannot_cross_classes() {
        use crate::{Proxy, config::Config, decision::Operation, scheduler::Pool};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        async fn headers<S: AsyncRead + Unpin>(s: &mut S) -> Vec<u8> {
            let mut b = Vec::new();
            while !b.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                if s.read(&mut byte).await.unwrap() == 0 {
                    break;
                }
                b.push(byte[0]);
                assert!(b.len() < 8192);
            }
            b
        }
        for ws in [false, true] {
            let unused = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let selected = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let config:Config=serde_json::from_value(serde_json::json!({"backends":[
                {"address":unused.local_addr().unwrap(),"region":"us"},
                {"address":selected.local_addr().unwrap(),"region":"eu","capabilities":["devices"]}],"http1":{},
                "routing_constraints":[{"match":{"path_prefix":"/devices"},"regions":["eu"],"capabilities":["devices"]}]
            })).unwrap();
            config.validate().unwrap();
            let pool = Arc::new(Pool::from_config(&config));
            let policy=serde_json::from_value(serde_json::json!({"expected_generation":0,"backend_generation":0,"ttl_ms":60000,"source_revision":"http-test","on_expiry":"reject",
                "profiles":{"default":{"weights":{unused.local_addr().unwrap().to_string():1}},"devices":{"weights":{selected.local_addr().unwrap().to_string():1}}},
                "assignments":[{"match":{"host":"edge.example","method":"GET","path_prefix":"/devices","http_version":"HTTP/1.1","websocket":ws},"profile":"devices"}]})).unwrap();
            pool.routing(&Operation::Apply(policy)).unwrap();
            let tls = Arc::new(crate::tls::Tls::load(&config).unwrap());
            let proxy = Proxy {
                pool: pool.clone(),
                http: Arc::new(State::new(config.http1.clone(), vec![])),
                stats: Default::default(),
            };
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let forward = async {
                let (s, _) = listener.accept().await.unwrap();
                proxy.handle(&config, s, None, tls).await
            };
            let workload = async {
                let (mut s, _) = selected.accept().await.unwrap();
                let request = headers(&mut s).await;
                assert!(
                    String::from_utf8(request)
                        .unwrap()
                        .starts_with("GET /devices?not-classified=1 HTTP/1.1")
                );
                if ws {
                    s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\nready").await.unwrap();
                    let mut message = [0; 4];
                    s.read_exact(&mut message).await.unwrap();
                    assert_eq!(&message, b"ping");
                    s.write_all(b"pong").await.unwrap();
                } else {
                    s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await
                        .unwrap();
                    assert!(headers(&mut s).await.is_empty());
                }
                s.shutdown().await.unwrap();
            };
            let client = async {
                let mut s = tokio::net::TcpStream::connect(address).await.unwrap();
                // Neither backend is touched while waiting for the first valid request.
                assert!(
                    timeout(Duration::from_millis(20), unused.accept())
                        .await
                        .is_err()
                );
                assert!(
                    timeout(Duration::from_millis(20), selected.accept())
                        .await
                        .is_err()
                );
                let upgrade = if ws {
                    "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: mqtt\r\n"
                } else {
                    ""
                };
                s.write_all(format!("GET /devices?not-classified=1 HTTP/1.1\r\nHost: EDGE.EXAMPLE:8080\r\n{upgrade}\r\n").as_bytes()).await.unwrap();
                let response = headers(&mut s).await;
                assert!(!response.is_empty());
                if ws {
                    let mut ready = [0; 5];
                    s.read_exact(&mut ready).await.unwrap();
                    assert_eq!(&ready, b"ready");
                    // Publication/expiry does not move an established WebSocket.
                    pool.routing(&Operation::Clear {
                        expected_generation: 1,
                    })
                    .unwrap();
                    s.write_all(b"ping").await.unwrap();
                    let mut pong = [0; 4];
                    s.read_exact(&mut pong).await.unwrap();
                    assert_eq!(&pong, b"pong");
                } else {
                    let mut ok = [0; 2];
                    s.read_exact(&mut ok).await.unwrap();
                    assert_eq!(&ok, b"ok");
                    s.write_all(b"GET /other HTTP/1.1\r\nHost: edge.example\r\n\r\n")
                        .await
                        .unwrap();
                    assert!(headers(&mut s).await.is_empty());
                }
                s.shutdown().await.unwrap();
            };
            let (result, (), ()) = timeout(Duration::from_secs(3), async {
                tokio::join!(forward, workload, client)
            })
            .await
            .unwrap();
            if ws {
                result.unwrap();
            } else {
                assert!(result.is_err());
            }
            assert!(
                timeout(Duration::from_millis(20), unused.accept())
                    .await
                    .is_err()
            );
            assert_eq!(
                pool.command(0, &["show"], None).unwrap().data["channels"][1]["active"],
                0
            );
        }
    }
    #[test]
    fn updates_are_validated_and_compare_generation_atomically() {
        let state = State::new(Some(Arc::new(HttpConfig::default())), vec![]);
        state
            .update(RuleUpdate {
                expected_generation: 1,
                rules: vec![],
            })
            .unwrap();
        assert!(
            state
                .update(RuleUpdate {
                    expected_generation: 1,
                    rules: vec![]
                })
                .is_err()
        );
        assert_eq!(state.status().0, 2);
        state.reload(None);
        assert!(
            state
                .update(RuleUpdate {
                    expected_generation: 3,
                    rules: vec![]
                })
                .is_err()
        );
    }
    #[test]
    fn host_rejects_framing_changes_from_custom_plugins() {
        struct Bad;
        impl HttpPlugin for Bad {
            fn transform(
                &self,
                _: Phase,
                _: &Context<'_>,
                headers: &mut HeaderMap,
            ) -> Result<(), Error> {
                headers.insert(
                    header::CONTENT_LENGTH,
                    header::HeaderValue::from_static("999"),
                );
                Ok(())
            }
        }
        let mut headers = HeaderMap::new();
        let context = Context {
            peer: "127.0.0.1:1".parse().unwrap(),
            backend: "127.0.0.1:2".parse().unwrap(),
            scheme: "http",
            method: "GET",
            path: "/",
            sni: None,
            status: None,
        };
        assert!(transform(&Bad, Phase::Request, &context, &mut headers, &[], 16_384).is_err());
        assert!(headers.is_empty());
    }
}
