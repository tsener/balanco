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
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, RwLock,
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

pub struct Connection {
    pub peer: SocketAddr,
    pub backend: SocketAddr,
    pub tls: bool,
    pub sni: Option<String>,
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
    counters: Arc<Counters>,
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
            let (local, total) = if self.upstream {
                (&self.traffic.up, &self.traffic.counters.up)
            } else {
                (&self.traffic.down, &self.traffic.counters.down)
            };
            local.fetch_add(n as u64, Ordering::Relaxed);
            total.fetch_add(n as u64, Ordering::Relaxed);
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

// Called by Proxy::forward for HTTP-enabled listeners; stream rather than buffer bodies.
pub async fn relay<A, B>(
    client: A,
    backend: B,
    connection: Connection,
    config: &crate::config::Config,
    state: Arc<State>,
    counters: Arc<Counters>,
) -> Result<(u64, u64), Error>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
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
        counters,
    });
    let client = TokioIo::new(Metered {
        stream: client,
        traffic: traffic.clone(),
        upstream: false,
        dump: packet_dump.then_some("client->backend"),
    });
    let backend = TokioIo::new(Metered {
        stream: backend,
        traffic: traffic.clone(),
        upstream: true,
        dump: packet_dump.then_some("backend->client"),
    });
    let max_header_bytes = config.max_header_bytes;
    let header_timeout = Duration::from_millis(config.header_timeout_ms);
    let run = async {
        let (sender, upstream) = hyper::client::conn::http1::Builder::new()
            .max_headers(64)
            .max_buf_size(config.max_header_bytes)
            .handshake::<_, Payload>(backend)
            .await?;
        let sender = Arc::new(Mutex::new(sender));
        let (upgrade_tx, upgrade_rx) = oneshot::channel::<(OnUpgrade, OnUpgrade)>();
        let upgrade_tx = Arc::new(Mutex::new(Some(upgrade_tx)));
        let service = service_fn(move |mut request: Request<Incoming>| {
            let sender = sender.clone();
            let state = state.clone();
            let upgrade_tx = upgrade_tx.clone();
            let sni = connection.sni.clone();
            let config = config.clone();
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
                    let mut context = Context {
                        peer: connection.peer,
                        backend: connection.backend,
                        scheme: if connection.tls { "https" } else { "http" },
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
                    let mut sender = sender.lock().await;
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
        tokio::try_join!(frontend, upstream.with_upgrades())?;
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
