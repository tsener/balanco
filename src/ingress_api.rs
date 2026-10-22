//! Small HTTPS LIST/WATCH client with projected-token rotation and bounded bodies.
use crate::{Error, ingress::Event};
use hyper::{
    Request, Response,
    body::{Body, Bytes, Frame, Incoming, SizeHint},
};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use std::{
    io::Read,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{net::TcpStream, sync::mpsc, task::JoinHandle};
use tokio_rustls::{
    TlsConnector,
    rustls::{
        self,
        pki_types::{CertificateDer, ServerName, pem::PemObject},
    },
};

const SERVICE_ACCOUNT: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
const LIMIT: usize = 8 * 1024 * 1024;
struct Empty;
impl Body for Empty {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Poll::Ready(None)
    }
    fn is_end_stream(&self) -> bool {
        true
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(0)
    }
}
struct Driver(JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct Exchange {
    response: Response<Incoming>,
    _driver: Driver,
}
impl Exchange {
    async fn data(&mut self) -> Result<Option<Bytes>, Error> {
        while let Some(frame) =
            std::future::poll_fn(|cx| Pin::new(self.response.body_mut()).poll_frame(cx)).await
        {
            if let Ok(data) = frame?.into_data() {
                return Ok(Some(data));
            }
        }
        Ok(None)
    }
}

pub struct Api {
    tls: TlsConnector,
    authority: hyper::http::uri::Authority,
    token_file: std::path::PathBuf,
}
impl Api {
    pub async fn new() -> Result<Self, Error> {
        tokio::task::spawn_blocking(|| {
            let mut roots = rustls::RootCertStore::empty();
            for cert in CertificateDer::pem_file_iter(format!("{SERVICE_ACCOUNT}/ca.crt"))? {
                roots.add(cert?)?;
            }
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
            Ok(Self {
                tls: TlsConnector::from(Arc::new(config)),
                authority: "kubernetes.default.svc:443".parse()?,
                token_file: format!("{SERVICE_ACCOUNT}/token").into(),
            })
        })
        .await?
    }
    async fn open(&self, path: &str) -> Result<Exchange, Error> {
        tokio::time::timeout(Duration::from_secs(10), async {
            // Kubelet rotates the projected token; read it again for every reconnect.
            let token_file = self.token_file.clone();
            let token = tokio::task::spawn_blocking(move || -> Result<_, Error> {
                let mut token = String::new();
                std::fs::File::open(token_file)?
                    .take(16385)
                    .read_to_string(&mut token)?;
                if token.len() > 16384 || token.trim().is_empty() {
                    return Err("invalid projected service-account token".into());
                }
                let mut value =
                    hyper::header::HeaderValue::from_str(&format!("Bearer {}", token.trim()))?;
                value.set_sensitive(true);
                Ok(value)
            })
            .await??;
            let host = self.authority.host().trim_matches(['[', ']']);
            let stream =
                TcpStream::connect((host, self.authority.port_u16().unwrap_or(443))).await?;
            let stream = self
                .tls
                .connect(ServerName::try_from(host.to_owned())?, stream)
                .await?;
            let (mut sender, driver) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
            let driver = Driver(tokio::spawn(async move {
                let _ = driver.await;
            }));
            let request = Request::builder()
                .uri(path)
                .header("host", self.authority.as_str())
                .header("authorization", token)
                .header("accept", "application/json")
                .header("connection", "close")
                .body(Empty)?;
            let response = sender.send_request(request).await?;
            Ok::<_, Error>(Exchange {
                response,
                _driver: driver,
            })
        })
        .await?
    }
    async fn list(&self, path: &str) -> Result<(Vec<Value>, String), Error> {
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut values = vec![];
            let mut continuation = String::new();
            let mut version = String::new();
            let mut total = 0;
            loop {
                let mut exchange = self
                    .open(&format!(
                        "{path}?limit=200&continue={}",
                        encode(&continuation)
                    ))
                    .await?;
                if !exchange.response.status().is_success() {
                    return Err(
                        format!("Kubernetes LIST HTTP {}", exchange.response.status()).into(),
                    );
                }
                let mut bytes = vec![];
                while let Some(data) = exchange.data().await? {
                    total += data.len();
                    if total > LIMIT {
                        return Err("Kubernetes list exceeds 8 MiB".into());
                    }
                    bytes.extend_from_slice(&data);
                }
                let page: Value = serde_json::from_slice(&bytes)?;
                let rv = page["metadata"]["resourceVersion"]
                    .as_str()
                    .ok_or("LIST resourceVersion missing")?;
                if !version.is_empty() && version != rv {
                    return Err("inconsistent paginated resourceVersion".into());
                }
                version = rv.to_owned();
                values.extend(
                    page["items"]
                        .as_array()
                        .ok_or("LIST items missing")?
                        .iter()
                        .cloned(),
                );
                if values.len() > 4096 {
                    return Err("Kubernetes object limit 4096 exceeded".into());
                }
                continuation = page["metadata"]["continue"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned();
                if continuation.is_empty() {
                    return Ok((values, version));
                }
            }
        })
        .await?
    }
    async fn watch(
        &self,
        kind: usize,
        path: &str,
        rv: &mut String,
        tx: &mpsc::Sender<Event>,
    ) -> Result<bool, Error> {
        let url = format!(
            "{path}?watch=true&allowWatchBookmarks=true&timeoutSeconds=60&resourceVersion={}",
            encode(rv)
        );
        let mut exchange = self.open(&url).await?;
        if exchange.response.status() == hyper::StatusCode::GONE {
            return Ok(true);
        }
        if !exchange.response.status().is_success() {
            return Err(format!("Kubernetes WATCH HTTP {}", exchange.response.status()).into());
        }
        let mut buffer = vec![];
        while let Some(data) =
            tokio::time::timeout(Duration::from_secs(75), exchange.data()).await??
        {
            for part in data.split_inclusive(|b| *b == b'\n') {
                if buffer.len() + part.len() > LIMIT {
                    return Err("Kubernetes watch event exceeds 8 MiB".into());
                }
                buffer.extend_from_slice(part);
                if !buffer.ends_with(b"\n") {
                    continue;
                }
                if buffer.iter().all(u8::is_ascii_whitespace) {
                    buffer.clear();
                    continue;
                }
                let event: Value = serde_json::from_slice(&buffer)?;
                buffer.clear();
                let object = &event["object"];
                match event["type"].as_str().ok_or("watch type missing")? {
                    "ERROR" if object["code"] == 410 => return Ok(true),
                    "ERROR" => return Err("Kubernetes watch ERROR event".into()),
                    "BOOKMARK" => {}
                    "ADDED" | "MODIFIED" | "DELETED" => {
                        tx.send(Event::Change(
                            kind,
                            object.clone(),
                            event["type"] == "DELETED",
                        ))
                        .await?;
                    }
                    _ => return Err("unsupported Kubernetes watch event".into()),
                }
                *rv = object["metadata"]["resourceVersion"]
                    .as_str()
                    .ok_or("watch resourceVersion missing")?
                    .to_owned();
            }
        }
        if !buffer.is_empty() {
            return Err("truncated Kubernetes watch event".into());
        }
        Ok(false)
    }
    // Each kind has its own RV. A 410 relists that cache; other failures retry without dropping routes.
    pub async fn follow(&self, kind: usize, path: String, tx: mpsc::Sender<Event>) {
        let mut rv = None;
        let mut delay = 1;
        while !tx.is_closed() {
            let result = async {
                if rv.is_none() {
                    let (objects, version) = self.list(&path).await?;
                    tx.send(Event::Reset(kind, objects)).await?;
                    rv = Some(version);
                }
                let expired = self
                    .watch(kind, &path, rv.as_mut().expect("listed RV"), &tx)
                    .await?;
                if expired {
                    rv = None;
                }
                Ok::<_, Error>(())
            }
            .await;
            match result {
                Ok(()) => {
                    delay = 1;
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(error) => {
                    eprintln!(
                        "Kubernetes watch kind={kind} unavailable: {error}; retry in {delay}s"
                    );
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                    delay = (delay * 2).min(30);
                }
            }
        }
    }
}
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct Chunks(VecDeque<Bytes>);
    impl Body for Chunks {
        type Data = Bytes;
        type Error = std::convert::Infallible;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            Poll::Ready(self.0.pop_front().map(|b| Ok(Frame::data(b))))
        }
    }

    #[tokio::test]
    async fn https_lists_paginate_watches_decode_expiry_and_rotate_bearer_tokens() {
        use serde_json::json;
        let fixture = crate::tls::tests::Certificates::new();
        let mut config = fixture.config();
        config.tls.as_mut().unwrap().client_ca = None;
        let tls = crate::tls::Tls::load(&config).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_file_iter(fixture.file("ca.pem")).unwrap() {
            roots.add(cert.unwrap()).unwrap();
        }
        let client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let token_file = std::path::PathBuf::from(fixture.file("token"));
        std::fs::write(&token_file, "token-a\n").unwrap();
        let api = Api {
            tls: TlsConnector::from(Arc::new(client)),
            authority: format!("localhost:{}", listener.local_addr().unwrap().port())
                .parse()
                .unwrap(),
            token_file: token_file.clone(),
        };
        let responses = Arc::new(std::sync::Mutex::new(VecDeque::from([
            (200, json!({"metadata":{"resourceVersion":"42","continue":"opaque+/="},"items":[{"metadata":{"name":"first"}}]}).to_string()),
            (200, json!({"metadata":{"resourceVersion":"42"},"items":[{"metadata":{"name":"second"}}]}).to_string()),
            (200, concat!("{\"type\":\"BOOKMARK\",\"object\":{\"metadata\":{\"resourceVersion\":\"43\"}}}\n",
                "{\"type\":\"ADDED\",\"object\":{\"metadata\":{\"name\":\"new\",\"uid\":\"uid\",\"resourceVersion\":\"44\"}}}\n",
                "{\"type\":\"DELETED\",\"object\":{\"metadata\":{\"name\":\"new\",\"uid\":\"uid\",\"resourceVersion\":\"45\"}}}\n",
                "{\"type\":\"ERROR\",\"object\":{\"code\":410}}\n").to_owned()),
            (410, String::new()), (403, "sensitive-body-must-not-be-logged".into()),
            (200, "{\"type\":\"ADDED\",\"object\":{}".into()),
            (200, "{\"metadata\":{\"resourceVersion\":\"46\"}}".into()),
        ])));
        let observed = Arc::new(std::sync::Mutex::new(vec![]));
        let server_observed = observed.clone();
        let server = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let stream = tls.acceptor.as_ref().unwrap().accept(tcp).await.unwrap();
                let responses = responses.clone();
                let observed = server_observed.clone();
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                        observed.lock().unwrap().push((
                            request.uri().to_string(),
                            request.headers()["authorization"]
                                .to_str()
                                .unwrap()
                                .to_owned(),
                        ));
                        let (status, body) = responses
                            .lock()
                            .unwrap()
                            .pop_front()
                            .expect("scripted response");
                        async move {
                            let parts = body
                                .as_bytes()
                                .chunks(7)
                                .map(Bytes::copy_from_slice)
                                .collect();
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(status)
                                    .body(Chunks(parts))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        let (items, mut rv) = api.list("/resources").await.unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(rv, "42");
        std::fs::write(&token_file, "token-b").unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        assert!(api.watch(0, "/resources", &mut rv, &tx).await.unwrap());
        assert_eq!(rv, "45");
        assert!(matches!(
            rx.recv().await.unwrap(),
            Event::Change(0, _, false)
        ));
        assert!(matches!(
            rx.recv().await.unwrap(),
            Event::Change(0, _, true)
        ));
        assert!(api.watch(0, "/resources", &mut rv, &tx).await.unwrap());
        let error = api
            .watch(0, "/resources", &mut rv, &tx)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("403") && !error.contains("sensitive"));
        assert!(
            api.watch(0, "/resources", &mut rv, &tx)
                .await
                .unwrap_err()
                .to_string()
                .contains("truncated")
        );
        assert!(api.list("/resources").await.is_err());
        let requests = observed.lock().unwrap();
        assert!(requests[1].0.contains("continue=opaque%2B%2F%3D"));
        assert_eq!(requests[0].1, "Bearer token-a");
        assert_eq!(requests[2].1, "Bearer token-b");
        assert!(requests[2].0.contains("resourceVersion=42"));
        server.abort();
    }
    #[test]
    fn opaque_resource_versions_cannot_inject_query_parameters() {
        assert_eq!(super::encode("12345"), "12345");
        assert_eq!(super::encode("opaque+/=&"), "opaque%2B%2F%3D%26");
    }
}
