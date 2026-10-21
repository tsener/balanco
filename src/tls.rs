//! Prepare verified frontend, upstream and management TLS before publication.
use crate::{
    Error,
    config::{Config, KeyExchange, Role, ServerTls},
};
use std::{collections::HashMap, sync::Arc};
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
    },
};

pub struct Tls {
    pub geoip: Arc<crate::geoip::GeoIp>,
    pub acceptor: Option<TlsAcceptor>,
    pub connector: Option<TlsConnector>,
    pub management: Option<ManagementTls>,
}
pub struct ManagementTls {
    pub acceptor: TlsAcceptor,
    pub clients: Vec<(CertificateDer<'static>, String, Role)>,
}
// Used by both TLS builders; each leg has an explicit key-exchange policy.
fn provider(policy: KeyExchange) -> Arc<rustls::crypto::CryptoProvider> {
    use rustls::crypto::aws_lc_rs::{default_provider, kx_group};
    let mut provider = default_provider();
    provider.kx_groups = match policy {
        KeyExchange::Classical => vec![kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1],
        KeyExchange::HybridPreferred => vec![
            kx_group::X25519MLKEM768,
            kx_group::X25519,
            kx_group::SECP256R1,
            kx_group::SECP384R1,
        ],
        KeyExchange::HybridRequired => vec![kx_group::X25519MLKEM768],
    };
    Arc::new(provider)
}
fn versions(policy: KeyExchange) -> &'static [&'static rustls::SupportedProtocolVersion] {
    static TLS13_ONLY: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS13];
    if policy == KeyExchange::HybridRequired {
        &TLS13_ONLY
    } else {
        rustls::DEFAULT_VERSIONS
    }
}
#[derive(Debug)]
struct CertificateResolver {
    fallback: Arc<rustls::sign::CertifiedKey>,
    exact: HashMap<String, Arc<rustls::sign::CertifiedKey>>,
    wildcard: Vec<(String, Arc<rustls::sign::CertifiedKey>)>,
    reject_unknown: bool,
}
impl rustls::server::ResolvesServerCert for CertificateResolver {
    // Called by rustls on ClientHello; prefer exact SNI, then a one-label wildcard.
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let Some(name) = hello.server_name() else {
            return Some(self.fallback.clone());
        };
        let name = name.to_ascii_lowercase();
        if let Some(cert) = self.exact.get(&name) {
            return Some(cert.clone());
        }
        self.wildcard
            .iter()
            .find(|(suffix, _)| {
                name.strip_suffix(suffix)
                    .is_some_and(|prefix| !prefix.is_empty() && !prefix.contains('.'))
            })
            .map(|(_, cert)| cert.clone())
            .or_else(|| (!self.reject_unknown).then(|| self.fallback.clone()))
    }
}

fn certified_key(cert: &str, key: &str) -> Result<Arc<rustls::sign::CertifiedKey>, Error> {
    let chain = certs(cert)?;
    let private_key = PrivateKeyDer::from_pem_file(key)?;
    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&private_key)?;
    let certified = rustls::sign::CertifiedKey::new(chain, signing_key);
    certified.keys_match()?;
    Ok(Arc::new(certified))
}

fn server(tls: &ServerTls) -> Result<TlsAcceptor, Error> {
    let provider = provider(tls.key_exchange);
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions(tls.key_exchange))?;
    let builder = match &tls.client_ca {
        Some(ca) => builder.with_client_cert_verifier(
            rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots(ca)?),
                provider,
            )
            .build()?,
        ),
        None => builder.with_no_client_auth(),
    };
    let fallback = certified_key(&tls.cert, &tls.key)?;
    let mut exact = HashMap::new();
    let mut wildcard = Vec::new();
    for identity in &tls.sni_certificates {
        let key = certified_key(&identity.cert, &identity.key)?;
        for name in &identity.names {
            let name = name.to_ascii_lowercase();
            if let Some(suffix) = name.strip_prefix("*") {
                let probe = format!("balanco-sni-check{suffix}");
                rustls::server::ResolvesServerCertUsingSni::new()
                    .add(&probe, key.as_ref().clone())?;
                wildcard.push((suffix.to_owned(), key.clone()));
            } else {
                rustls::server::ResolvesServerCertUsingSni::new()
                    .add(&name, key.as_ref().clone())?;
                exact.insert(name, key.clone());
            }
        }
    }
    wildcard.sort_by_key(|(suffix, _)| std::cmp::Reverse(suffix.len()));
    let resolver = Arc::new(CertificateResolver {
        fallback,
        exact,
        wildcard,
        reject_unknown: tls.reject_unknown_sni,
    });
    let mut server = builder.with_cert_resolver(resolver);
    server.max_early_data_size = 0;
    server.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    server.send_tls13_tickets = 0;
    Ok(TlsAcceptor::from(Arc::new(server)))
}
fn certs(path: &str) -> Result<Vec<CertificateDer<'static>>, Error> {
    let certs: Vec<_> = CertificateDer::pem_file_iter(path)?.collect::<Result<_, _>>()?;
    if certs.is_empty() {
        return Err(format!("no certificates in {path}").into());
    }
    Ok(certs)
}
fn roots(path: &str) -> Result<rustls::RootCertStore, Error> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs(path)? {
        roots.add(cert)?;
    }
    Ok(roots)
}
impl Tls {
    // Called by startup and reload preparation; failure leaves active TLS unchanged.
    pub fn load(config: &Config) -> Result<Self, Error> {
        let acceptor = config.tls.as_ref().map(server).transpose()?;
        let connector = config
            .upstream_tls
            .as_ref()
            .map(|tls| -> Result<_, Error> {
                let builder =
                    rustls::ClientConfig::builder_with_provider(provider(tls.key_exchange))
                        .with_protocol_versions(versions(tls.key_exchange))?
                        .with_root_certificates(roots(&tls.ca)?);
                let mut client = match (&tls.cert, &tls.key) {
                    (Some(cert), Some(key)) => builder
                        .with_client_auth_cert(certs(cert)?, PrivateKeyDer::from_pem_file(key)?)?,
                    (None, None) => builder.with_no_client_auth(),
                    _ => return Err("upstream TLS cert/key mismatch".into()),
                };
                client.resumption = rustls::client::Resumption::disabled();
                Ok(TlsConnector::from(Arc::new(client)))
            })
            .transpose()?;
        for backend in &config.backends {
            if let Some(name) = &backend.server_name {
                ServerName::try_from(name.clone())?;
            }
        }
        let management = config
            .management
            .as_ref()
            .map(|m| -> Result<_, Error> {
                let acceptor = server(&m.tls)?;
                let mut clients = Vec::new();
                for client in &m.clients {
                    let chain = certs(&client.cert)?;
                    if chain.len() != 1 {
                        return Err(
                            "management allowlist files must contain exactly one leaf certificate"
                                .into(),
                        );
                    }
                    let cert = chain.into_iter().next().unwrap();
                    if clients.iter().any(|(c, _, _)| *c == cert) {
                        return Err("duplicate management client certificate".into());
                    }
                    clients.push((cert, client.name.clone(), client.role));
                }
                Ok(ManagementTls { acceptor, clients })
            })
            .transpose()?;
        Ok(Self {
            geoip: Arc::new(crate::geoip::GeoIp::load(config.geoip.as_ref())?),
            acceptor,
            connector,
            management,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::DirBuilderExt,
        path::PathBuf,
        process::{Command, Stdio},
    };

    struct Certificates(PathBuf);
    impl Certificates {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "balanco-tls-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            let fixture = Self(path);
            fixture.openssl(&[
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-keyout",
                "ca.key",
                "-out",
                "ca.pem",
                "-days",
                "1",
                "-subj",
                "/CN=TestCA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ]);
            for (name, usage) in [
                ("server", "serverAuth"),
                ("client", "clientAuth"),
                ("reader", "clientAuth"),
            ] {
                fixture.openssl(&[
                    "req",
                    "-new",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-nodes",
                    "-keyout",
                    &format!("{name}.key"),
                    "-out",
                    &format!("{name}.csr"),
                    "-subj",
                    &format!("/CN={name}"),
                ]);
                fs::write(fixture.0.join(format!("{name}.ext")),format!("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={usage}\nsubjectAltName=DNS:localhost,DNS:*.devices.test\n")).unwrap();
                fixture.openssl(&[
                    "x509",
                    "-req",
                    "-in",
                    &format!("{name}.csr"),
                    "-CA",
                    "ca.pem",
                    "-CAkey",
                    "ca.key",
                    "-CAcreateserial",
                    "-out",
                    &format!("{name}.pem"),
                    "-days",
                    "1",
                    "-extfile",
                    &format!("{name}.ext"),
                ]);
            }
            fixture
        }
        fn openssl(&self, args: &[&str]) {
            assert!(
                Command::new("openssl")
                    .args(args)
                    .current_dir(&self.0)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .expect("OpenSSL is required for TLS tests")
                    .success()
            );
        }
        fn file(&self, name: &str) -> String {
            self.0.join(name).to_str().unwrap().into()
        }
        fn config(&self) -> Config {
            let server = serde_json::json!({"cert":self.file("server.pem"),"key":self.file("server.key"),"client_ca":self.file("ca.pem"),
                "sni_certificates":[{"names":["localhost","*.devices.test"],"cert":self.file("server.pem"),"key":self.file("server.key")}],"reject_unknown_sni":true});
            let config:Config=serde_json::from_value(serde_json::json!({"backends":[{"address":"127.0.0.1:9001","server_name":"localhost"}],
                "tls":server,"upstream_tls":{"ca":self.file("ca.pem"),"cert":self.file("client.pem"),"key":self.file("client.key")},
                "management":{"listen":"127.0.0.1:0","tls":server,"clients":[
                    {"name":"operator","cert":self.file("client.pem"),"role":"admin"},
                    {"name":"observer","cert":self.file("reader.pem"),"role":"read_only"}]}})).unwrap();
            config.validate().unwrap();
            config
        }
    }
    impl Drop for Certificates {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn mutual_tls_negotiates_all_policies_and_selects_exact_and_wildcard_sni() {
        let fixture = Certificates::new();
        let mut sessions = Vec::new();
        for policy in [
            KeyExchange::Classical,
            KeyExchange::HybridPreferred,
            KeyExchange::HybridRequired,
        ] {
            let mut config = fixture.config();
            config.tls.as_mut().unwrap().key_exchange = policy;
            config.upstream_tls.as_mut().unwrap().key_exchange = policy;
            sessions.push(Tls::load(&config).unwrap());
        }
        let fallback = Tls::load(&fixture.config()).unwrap();
        let mut no_sni =
            rustls::ClientConfig::builder_with_provider(provider(KeyExchange::Classical))
                .with_protocol_versions(&[&rustls::version::TLS12])
                .unwrap()
                .with_root_certificates(roots(&fixture.file("ca.pem")).unwrap())
                .with_client_auth_cert(
                    certs(&fixture.file("client.pem")).unwrap(),
                    PrivateKeyDer::from_pem_file(fixture.file("client.key")).unwrap(),
                )
                .unwrap();
        no_sni.enable_sni = false;
        let no_sni = TlsConnector::from(Arc::new(no_sni));
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                for tls in sessions {
                    assert_eq!(tls.management.as_ref().unwrap().clients.len(), 2);
                    for name in ["localhost", "sensor.devices.test"] {
                        let (server, client) = tokio::io::duplex(65536);
                        let (server, client) =
                            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                                tokio::join!(
                                    tls.acceptor.as_ref().unwrap().accept(server),
                                    tls.connector
                                        .as_ref()
                                        .unwrap()
                                        .connect(ServerName::try_from(name).unwrap(), client)
                                )
                            })
                            .await
                            .unwrap();
                        let server = server.unwrap();
                        let client = client.unwrap();
                        assert_eq!(server.get_ref().1.peer_certificates().unwrap().len(), 1);
                        assert_eq!(
                            client.get_ref().1.protocol_version(),
                            Some(rustls::ProtocolVersion::TLSv1_3)
                        );
                    }
                }
                let (server, client) = tokio::io::duplex(65536);
                let (server, client) = tokio::join!(
                    fallback.acceptor.as_ref().unwrap().accept(server),
                    no_sni.connect(ServerName::try_from("localhost").unwrap(), client)
                );
                assert!(server.unwrap().get_ref().1.server_name().is_none());
                assert_eq!(
                    client.unwrap().get_ref().1.protocol_version(),
                    Some(rustls::ProtocolVersion::TLSv1_2)
                );
                let (server, client) = tokio::io::duplex(65536);
                let (server, client) =
                    tokio::time::timeout(std::time::Duration::from_secs(5), async {
                        tokio::join!(
                            fallback.acceptor.as_ref().unwrap().accept(server),
                            fallback
                                .connector
                                .as_ref()
                                .unwrap()
                                .connect(ServerName::try_from("unknown.test").unwrap(), client)
                        )
                    })
                    .await
                    .unwrap();
                assert!(server.is_err());
                assert!(client.is_err());
            });
    }

    #[test]
    fn invalid_keys_trust_and_management_pins_fail_before_publication() {
        let fixture = Certificates::new();
        let baseline = fixture.config();
        let mut bad = baseline.clone();
        bad.tls.as_mut().unwrap().key = fixture.file("client.key");
        assert!(Tls::load(&bad).is_err());
        let mut bad = baseline.clone();
        bad.upstream_tls.as_mut().unwrap().key = None;
        assert!(Tls::load(&bad).is_err());
        let mut bad = baseline.clone();
        bad.backends[0].server_name = Some("invalid name!".into());
        assert!(Tls::load(&bad).is_err());
        let mut bad = baseline.clone();
        bad.management.as_mut().unwrap().clients[1].cert = fixture.file("client.pem");
        assert!(Tls::load(&bad).is_err());
        let bundle = [
            fs::read(fixture.file("client.pem")).unwrap(),
            fs::read(fixture.file("ca.pem")).unwrap(),
        ]
        .concat();
        fs::write(fixture.file("bundle.pem"), bundle).unwrap();
        let mut bad = baseline.clone();
        bad.management.as_mut().unwrap().clients[0].cert = fixture.file("bundle.pem");
        assert!(Tls::load(&bad).is_err());
        fs::write(fixture.file("empty.pem"), b"").unwrap();
        let mut bad = baseline;
        bad.upstream_tls.as_mut().unwrap().ca = fixture.file("empty.pem");
        assert!(Tls::load(&bad).is_err());
        assert!(roots(&fixture.file("missing.pem")).is_err());
    }

    #[test]
    fn proxy_relays_tcp_two_leg_mtls_and_transformed_http() {
        use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
        async fn origin<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, http: bool) {
            if http {
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    assert!(headers.len() < 16384);
                    headers.push(stream.read_u8().await.unwrap());
                }
                assert!(
                    String::from_utf8(headers)
                        .unwrap()
                        .to_ascii_lowercase()
                        .contains("x-gateway: balanco:localhost\r\n")
                );
            }
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"ping");
            let reply: &[u8] = if http {
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nServer: origin\r\nConnection: close\r\n\r\npong"
            } else {
                b"pong"
            };
            stream.write_all(reply).await.unwrap();
            stream.shutdown().await.unwrap();
        }
        async fn client<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, http: bool) {
            let payload: &[u8] = if http {
                b"POST /devices HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nConnection: close\r\n\r\nping"
            } else {
                b"ping"
            };
            stream.write_all(payload).await.unwrap();
            if http {
                let mut reply = String::new();
                stream.read_to_string(&mut reply).await.unwrap();
                assert!(reply.starts_with("HTTP/1.1 200 OK"));
                assert!(reply.ends_with("pong"));
                assert!(reply.to_ascii_lowercase().contains("x-proxy: balanco\r\n"));
                assert!(!reply.to_ascii_lowercase().contains("\r\nserver:"));
            } else {
                let mut reply = [0; 4];
                stream.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"pong");
            }
            stream.shutdown().await.unwrap();
        }
        let fixture = Certificates::new();
        let mut cases = Vec::new();
        for (encrypted, http) in [(false, false), (true, false), (true, true)] {
            let mut config = fixture.config();
            config.management = None;
            if !encrypted {
                config.tls = None;
                config.upstream_tls = None;
                config.backends[0].server_name = None;
            }
            if http {
                config.http1=Some(Arc::new(serde_json::from_value(serde_json::json!({"rules":[
                    {"phase":"request","action":{"op":"set","name":"x-gateway","value":"balanco:${sni}"}},
                    {"phase":"response","action":{"op":"remove","name":"server"}},
                    {"phase":"response","action":{"op":"set","name":"x-proxy","value":"balanco"}}]})).unwrap()));
            }
            let tls = Tls::load(&config).unwrap();
            cases.push((config, tls, encrypted, http));
        }
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            for (mut config,tls,encrypted,http) in cases {
                let backend=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                config.backends[0].address=backend.local_addr().unwrap();
                let frontend=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address=frontend.local_addr().unwrap();
                let acceptor=tls.acceptor.clone(); let connector=tls.connector.clone();
                let proxy=crate::Proxy{pool:Arc::new(crate::scheduler::Pool::from_config(&config)),
                    http:Arc::new(crate::http1::State::new(config.http1.clone(),vec![])),stats:Default::default()};
                let workload=async {
                    let (stream,_)=backend.accept().await.unwrap();
                    if encrypted {origin(acceptor.unwrap().accept(stream).await.unwrap(),http).await;}
                    else {origin(stream,http).await;}
                };
                let forwarding=async {
                    let (stream,_)=frontend.accept().await.unwrap();
                    proxy.handle(&config,stream,None,Arc::new(tls)).await.unwrap();
                };
                let exchange=async {
                    let stream=tokio::net::TcpStream::connect(address).await.unwrap();
                    if encrypted {client(connector.unwrap().connect(ServerName::try_from("localhost").unwrap(),stream).await.unwrap(),http).await;}
                    else {client(stream,http).await;}
                };
                tokio::time::timeout(std::time::Duration::from_secs(5),async {tokio::join!(workload,forwarding,exchange)}).await.unwrap();
                assert_eq!(proxy.pool.command(0,&["show"],None).unwrap().data["channels"][0]["active"],0);
            }
        });
    }
}
