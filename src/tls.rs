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
            acceptor,
            connector,
            management,
        })
    }
}
