//! A separate control-plane client: model choices select only operator-approved policies.
use crate::Error;
use hyper::{
    Request,
    body::{Body, Bytes, Frame, SizeHint},
};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::Read,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub url: String,
    pub ca: Option<String>,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub token_file: Option<String>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub description: String,
    pub profiles: BTreeMap<String, Weights>,
    #[serde(default)]
    pub assignments: Vec<Value>,
}
#[derive(Clone, Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Weights {
    pub weights: BTreeMap<std::net::SocketAddr, u32>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub management: Endpoint,
    pub model: Endpoint,
    pub model_id: Option<String>,
    pub policies: BTreeMap<String, Policy>,
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub ttl_ms: u64,
    pub on_expiry: String,
    pub confirmations: u8,
}
impl Config {
    pub fn validate(&self) -> Result<(), Error> {
        if self.model_id.as_ref().is_some_and(|s| {
            s.is_empty() || s.len() > 128 || s.bytes().any(|b| b.is_ascii_control())
        }) {
            return Err("invalid model_id".into());
        }
        if !(1000..=60000).contains(&self.interval_ms)
            || self.timeout_ms == 0
            || self.timeout_ms > self.interval_ms
            || self.ttl_ms < 3 * self.interval_ms
            || self.ttl_ms > 3_600_000
            || !(1..=10).contains(&self.confirmations)
            || !matches!(self.on_expiry.as_str(), "configured" | "reject")
            || self.policies.len() < 2
            || self.policies.len() > 16
        {
            return Err("invalid adapter cadence, TTL, confirmations or policy count".into());
        }
        for (name, p) in &self.policies {
            if name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                || p.description.is_empty()
                || p.description.len() > 2048
                || p.profiles.is_empty()
                || p.profiles.len() > 32
                || !p.profiles.contains_key("default")
                || p.assignments.len() > 128
            {
                return Err("invalid approved policy".into());
            }
            for weights in p.profiles.values() {
                if weights.weights.is_empty()
                    || weights.weights.len() > 256
                    || !weights.weights.values().any(|w| *w > 0)
                    || weights.weights.values().any(|w| *w > 1_000_000)
                {
                    return Err("invalid approved weights".into());
                }
            }
            if serde_json::to_vec(&json!({"profiles":p.profiles,"assignments":p.assignments}))?
                .len()
                > 14000
            {
                return Err("approved policy exceeds management request budget".into());
            }
        }
        Ok(())
    }
}

struct Payload(Option<Bytes>);
impl Body for Payload {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Poll::Ready(self.0.take().map(|b| Ok(Frame::data(b))))
    }
    fn is_end_stream(&self) -> bool {
        self.0.is_none()
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.0.as_ref().map_or(0, |b| b.len() as u64))
    }
}
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub struct Client {
    authority: hyper::http::uri::Authority,
    tls: Option<tokio_rustls::TlsConnector>,
    token: Option<hyper::header::HeaderValue>,
    timeout: Duration,
}
impl Client {
    // Called before starting the runtime: read credentials once, never on the proxy accept path.
    pub fn new(endpoint: Endpoint, timeout_ms: u64, management: bool) -> Result<Self, Error> {
        let uri: hyper::Uri = endpoint.url.parse()?;
        let authority = uri
            .authority()
            .ok_or("endpoint requires an authority")?
            .clone();
        if authority.as_str().contains('@')
            || uri.path_and_query().is_some_and(|p| p.as_str() != "/")
        {
            return Err("endpoint must be a base URL without credentials, path or query".into());
        }
        let encrypted = uri.scheme_str() == Some("https");
        if !encrypted && uri.scheme_str() != Some("http") {
            return Err("endpoint requires HTTP or HTTPS".into());
        }
        if management && (!encrypted || endpoint.cert.is_none() || endpoint.key.is_none()) {
            return Err("management endpoint requires HTTPS and client cert/key".into());
        }
        if !encrypted
            && !authority
                .host()
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        {
            return Err(
                "plaintext model endpoint is restricted to numeric loopback; use HTTPS remotely"
                    .into(),
            );
        }
        let tls = if encrypted {
            let mut roots = rustls::RootCertStore::empty();
            for cert in CertificateDer::pem_file_iter(
                endpoint.ca.as_ref().ok_or("HTTPS endpoint requires ca")?,
            )? {
                roots.add(cert?)?;
            }
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let builder = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots);
            let config = match (&endpoint.cert, &endpoint.key) {
                (Some(cert), Some(key)) => builder.with_client_auth_cert(
                    CertificateDer::pem_file_iter(cert)?.collect::<Result<Vec<_>, _>>()?,
                    PrivateKeyDer::from_pem_file(key)?,
                )?,
                (None, None) => builder.with_no_client_auth(),
                _ => return Err("endpoint cert/key mismatch".into()),
            };
            Some(tokio_rustls::TlsConnector::from(Arc::new(config)))
        } else {
            if endpoint.cert.is_some() || endpoint.key.is_some() || endpoint.ca.is_some() {
                return Err("TLS credentials on plaintext endpoint".into());
            }
            None
        };
        let token = endpoint
            .token_file
            .as_ref()
            .map(|p| -> Result<_, Error> {
                let mut value = String::new();
                std::fs::File::open(p)?
                    .take(4097)
                    .read_to_string(&mut value)?;
                if value.trim().is_empty() || value.len() > 4096 {
                    return Err("invalid model bearer token".into());
                }
                let mut header =
                    hyper::header::HeaderValue::from_str(&format!("Bearer {}", value.trim()))?;
                header.set_sensitive(true);
                Ok(header)
            })
            .transpose()?;
        Ok(Self {
            authority,
            tls,
            token,
            timeout: Duration::from_millis(timeout_ms),
        })
    }
    pub async fn json(
        &self,
        method: hyper::Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, Error> {
        tokio::time::timeout(self.timeout, async {
            let host = self.authority.host().trim_matches(['[', ']']);
            let tcp = tokio::net::TcpStream::connect((
                host,
                self.authority
                    .port_u16()
                    .unwrap_or(if self.tls.is_some() { 443 } else { 80 }),
            ))
            .await?;
            let stream: Box<dyn Io> = if let Some(tls) = &self.tls {
                Box::new(
                    tls.connect(ServerName::try_from(host.to_owned())?, tcp)
                        .await?,
                )
            } else {
                Box::new(tcp)
            };
            let (mut sender, driver) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
            let exchange = async {
                let bytes = body
                    .map(serde_json::to_vec)
                    .transpose()?
                    .unwrap_or_default();
                if bytes.len() > 65536 {
                    return Err("adapter request too large".into());
                }
                let mut request = Request::builder()
                    .method(method)
                    .uri(path)
                    .header("Host", self.authority.as_str())
                    .header("Content-Type", "application/json")
                    .header("Cache-Control", "no-store")
                    .header("Connection", "close");
                if let Some(token) = &self.token {
                    request = request.header("Authorization", token);
                }
                let mut response = sender
                    .send_request(request.body(Payload(Some(Bytes::from(bytes))))?)
                    .await?;
                if !response.status().is_success() {
                    return Err(format!("endpoint returned HTTP {}", response.status()).into());
                }
                let mut bytes = Vec::new();
                while let Some(frame) =
                    std::future::poll_fn(|cx| Pin::new(response.body_mut()).poll_frame(cx)).await
                {
                    if let Ok(data) = frame?.into_data() {
                        if bytes.len() + data.len() > 65536 {
                            return Err("adapter response exceeds 64 KiB".into());
                        }
                        bytes.extend_from_slice(&data);
                    }
                }
                Ok::<_, Error>(serde_json::from_slice(&bytes)?)
            };
            tokio::pin!(driver);
            tokio::pin!(exchange);
            tokio::select! {
                result=&mut exchange => result,
                result=&mut driver => { result?; exchange.await },
            }
        })
        .await?
    }
}

#[derive(Default)]
pub struct Controller {
    candidate: Option<String>,
    count: u8,
    sequence: u64,
}
impl Controller {
    pub fn question(config: &Config, state: Value) -> Value {
        let criteria: BTreeMap<_, _> = config
            .policies
            .iter()
            .map(|(k, p)| (k.clone(), p.description.clone()))
            .collect();
        let mut request = json!({"state":state,"questions":{"routing":{"type":"choice","instructions":"Select the approved routing policy best suited to current backend health and load. Never invent a policy.","criteria":criteria}}});
        if let Some(model) = &config.model_id {
            request["model"] = model.clone().into();
        }
        request
    }
    fn choose(&mut self, config: &Config, answer: &Value) -> Result<Option<String>, Error> {
        let a = &answer["answers"]["routing"];
        let choice = a["choice"]
            .as_str()
            .ok_or("model omitted typed routing choice")?;
        if a["type"] != "choice" || !config.policies.contains_key(choice) {
            return Err("model selected an unapproved policy".into());
        }
        if self.candidate.as_deref() == Some(choice) {
            self.count = self.count.saturating_add(1);
        } else {
            self.candidate = Some(choice.into());
            self.count = 1;
        }
        Ok((self.count >= config.confirmations).then(|| choice.to_owned()))
    }
    pub fn failed(&mut self) {
        self.candidate = None;
        self.count = 0;
    }
    pub async fn tick(
        &mut self,
        config: &Config,
        management: &Client,
        model: &Client,
    ) -> Result<(), Error> {
        let started = tokio::time::Instant::now();
        let routing = management
            .json(hyper::Method::GET, "/v1/routing", None)
            .await?;
        let status = management
            .json(hyper::Method::GET, "/v1/status", None)
            .await?;
        let generation = routing["data"]["generation"]
            .as_u64()
            .ok_or("missing routing generation")?;
        let backend_generation = routing["data"]["backend_generation"]
            .as_u64()
            .ok_or("missing backend generation")?;
        self.sequence += 1;
        let observation = format!(
            "adapter-{}-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
            self.sequence
        );
        // Keep counters ahead of verbose policy data so bounded-context models see the actual load.
        let channels = status["data"]["channels"]
            .as_array()
            .ok_or("missing backend telemetry")?;
        let backends:Vec<_>=channels.iter().map(|c|json!({"address":c["address"],"active":c["active"],"enabled":c["enabled"],"cooling_down":c["cooling_down"],"region":c["region"]})).collect();
        let request = Self::question(
            config,
            json!({"observation":observation,"generation":generation,"backend_generation":backend_generation,"backends":backends}),
        );
        let answer = model
            .json(hyper::Method::POST, "/v1/systemone", Some(&request))
            .await?;
        if started.elapsed() > Duration::from_millis(config.ttl_ms / 2) {
            return Err("model answer is too old to publish".into());
        }
        let Some(choice) = self.choose(config, &answer)? else {
            return Ok(());
        };
        let p = &config.policies[&choice];
        let update = json!({"expected_generation":generation,"backend_generation":backend_generation,"source_revision":observation,
            "ttl_ms":config.ttl_ms,"on_expiry":config.on_expiry,"profiles":p.profiles,"assignments":p.assignments});
        management
            .json(hyper::Method::PUT, "/v1/routing", Some(&update))
            .await?;
        eprintln!("routing published choice={choice} base_generation={generation}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture_config() -> Config {
        serde_json::from_value(json!({
            "management":{"url":"https://localhost:9443","ca":"ca.pem","cert":"operator.pem","key":"operator.key"},
            "model":{"url":"http://127.0.0.1:8772"},"interval_ms":1000,"timeout_ms":500,"ttl_ms":6000,"on_expiry":"reject","confirmations":2,
            "policies":{
                "balanced":{"description":"Spread new sessions evenly","profiles":{"default":{"weights":{"127.0.0.1:9000":1,"127.0.0.1:9001":1}}}},
                "prefer-a":{"description":"Prefer backend A","profiles":{"default":{"weights":{"127.0.0.1:9000":3,"127.0.0.1:9001":1}}}}
            }
        })).unwrap()
    }
    #[test]
    fn approved_choices_are_bounded_confirmed_and_reset_on_failure() {
        let mut config = fixture_config();
        config.validate().unwrap();
        config.model_id = Some("multilingual".into());
        config.validate().unwrap();
        assert_eq!(
            Controller::question(&config, json!({}))["model"],
            "multilingual"
        );
        let mut controller = Controller::default();
        let answer =
            json!({"answers":{"routing":{"type":"choice","choice":"prefer-a","confidence":0.9}}});
        assert!(controller.choose(&config, &answer).unwrap().is_none());
        assert_eq!(
            controller.choose(&config, &answer).unwrap().as_deref(),
            Some("prefer-a")
        );
        controller.failed();
        assert!(controller.choose(&config, &answer).unwrap().is_none());
        for bad in [
            json!({}),
            json!({"answers":{"routing":{"type":"score","choice":"prefer-a"}}}),
            json!({"answers":{"routing":{"type":"choice","choice":"invented"}}}),
        ] {
            assert!(controller.choose(&config, &bad).is_err());
        }
        assert_eq!(
            Controller::question(&config, json!({}))["questions"]["routing"]["type"],
            "choice"
        );
        let question = Controller::question(&config, json!({}));
        assert!(question["questions"]["routing"]["instructions"].is_string());
        assert_eq!(
            question["questions"]["routing"]["criteria"]
                .as_object()
                .unwrap()
                .len(),
            2
        );
        config.ttl_ms = 100;
        assert!(config.validate().is_err());
        config = fixture_config();
        config
            .policies
            .get_mut("balanced")
            .unwrap()
            .profiles
            .get_mut("default")
            .unwrap()
            .weights
            .insert("127.0.0.1:9000".parse().unwrap(), 1_000_001);
        assert!(config.validate().is_err());
    }
    #[test]
    fn client_refuses_insecure_management_and_untrusted_remote_model_endpoints() {
        let config = fixture_config();
        assert!(Client::new(config.management.clone(), 100, true).is_err());
        assert!(Client::new(config.model.clone(), 100, true).is_err());
        for url in [
            "http://example.com",
            "ftp://127.0.0.1",
            "http://user@127.0.0.1",
            "http://127.0.0.1/path",
            "http://127.0.0.1/?secret=x",
        ] {
            let mut endpoint = config.model.clone();
            endpoint.url = url.into();
            assert!(Client::new(endpoint, 100, false).is_err());
        }
        let mut endpoint = config.model.clone();
        endpoint.ca = Some("unused".into());
        assert!(Client::new(endpoint, 100, false).is_err());
    }
    #[tokio::test]
    async fn deterministic_model_publishes_cas_policy_and_transport_failures_stay_bounded() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let endpoint = Endpoint {
            url,
            ca: None,
            cert: None,
            key: None,
            token_file: None,
        };
        // Only the test bypasses production's mandatory management mTLS constructor flag.
        let management = Client::new(endpoint.clone(), 500, false).unwrap();
        let model = Client::new(endpoint, 500, false).unwrap();
        let mut config = fixture_config();
        config.confirmations = 1;
        let server = async {
            let mut published = false;
            for _ in 0..7 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let (path, length, end) = loop {
                    let mut b = [0; 2048];
                    let n = stream.read(&mut b).await.unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&b[..n]);
                    let mut headers = [httparse::EMPTY_HEADER; 16];
                    let mut request = httparse::Request::new(&mut headers);
                    if let httparse::Status::Complete(end) = request.parse(&bytes).unwrap() {
                        let length = request
                            .headers
                            .iter()
                            .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                            .map_or(0, |h| {
                                std::str::from_utf8(h.value)
                                    .unwrap()
                                    .parse::<usize>()
                                    .unwrap()
                            });
                        break (request.path.unwrap().to_owned(), length, end);
                    }
                };
                while bytes.len() < end + length {
                    let mut b = [0; 2048];
                    let n = stream.read(&mut b).await.unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&b[..n]);
                }
                let (code, body) = match path.as_str() {
                    "/v1/status" => (
                        200,
                        json!({"data":{"channels":[{"address":"127.0.0.1:9000","active":12}]}})
                            .to_string(),
                    ),
                    "/v1/systemone" => {
                        let request: Value =
                            serde_json::from_slice(&bytes[end..end + length]).unwrap();
                        assert!(request["state"]["observation"].is_string());
                        assert_eq!(request["questions"]["routing"]["type"], "choice");
                        assert!(request["questions"]["routing"].get("t").is_none());
                        assert!(request["state"].get("routing").is_none());
                        assert_eq!(request["state"]["backends"][0]["active"], 12);
                        (
                            200,
                            json!({"answers":{"routing":{"type":"choice","choice":"prefer-a"}}})
                                .to_string(),
                        )
                    }
                    "/v1/routing" if length > 0 => {
                        let update: Value =
                            serde_json::from_slice(&bytes[end..end + length]).unwrap();
                        assert_eq!(update["expected_generation"], 4);
                        assert_eq!(update["backend_generation"], 2);
                        assert_eq!(
                            update["profiles"]["default"]["weights"]["127.0.0.1:9000"],
                            3
                        );
                        assert_eq!(update["on_expiry"], "reject");
                        published = true;
                        (200, json!({"ok":true}).to_string())
                    }
                    "/v1/routing" => (
                        200,
                        json!({"data":{"generation":4,"backend_generation":2}}).to_string(),
                    ),
                    "/conflict" => (409, "{}".into()),
                    "/oversized" => (200, "x".repeat(65537)),
                    _ => (200, "not-json".into()),
                };
                stream.write_all(format!("HTTP/1.1 {code} Result\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
            }
            assert!(published);
        };
        let exercise = async {
            Controller::default()
                .tick(&config, &management, &model)
                .await
                .unwrap();
            for path in ["/conflict", "/oversized", "/bad-json"] {
                assert!(model.json(hyper::Method::GET, path, None).await.is_err());
            }
        };
        tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(server, exercise)
        })
        .await
        .unwrap();
        let stalled = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = Endpoint {
            url: format!("http://{}", stalled.local_addr().unwrap()),
            ca: None,
            cert: None,
            key: None,
            token_file: None,
        };
        assert!(
            Client::new(endpoint, 20, false)
                .unwrap()
                .json(hyper::Method::GET, "/", None)
                .await
                .is_err()
        );
    }
}
