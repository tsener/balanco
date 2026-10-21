//! Shared configuration schema and bounds for startup and reload validation.
use serde::Deserialize;
use std::{
    collections::HashSet,
    fs::File,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::Path,
};

use crate::Error;

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub backends: Vec<Backend>,
    pub workers: usize,
    pub reuse_port: bool,
    pub max_connections: usize,
    pub max_handshakes: usize,
    pub buffer_bytes: usize,
    pub connect_timeout_ms: u64,
    pub handshake_timeout_ms: u64,
    pub establishment_timeout_ms: u64,
    pub failure_cooldown_ms: u64,
    pub drain_timeout_ms: u64,
    pub tls: Option<ServerTls>,
    #[serde(default)]
    pub proxy_protocol_v2: bool,
    pub upstream_tls: Option<ClientTls>,
    pub outbound_bind: Option<IpAddr>,
    pub idle_timeout_ms: Option<u64>,
    pub autodisable: bool,
    pub hash_groups: Vec<u16>,
    pub hash_failover: bool,
    pub debug: bool,
    pub packet_dump: bool,
    pub control_socket: Option<std::path::PathBuf>,
    pub management: Option<Management>,
    pub http1: Option<std::sync::Arc<balanco::http_plugin::HttpConfig>>,
    #[serde(skip)]
    pub config_file: Option<std::path::PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080".parse().unwrap(),
            backends: vec![],
            workers: 2,
            reuse_port: false,
            max_connections: 10_000,
            max_handshakes: 128,
            buffer_bytes: 4096,
            connect_timeout_ms: 2000,
            handshake_timeout_ms: 5000,
            establishment_timeout_ms: 10_000,
            failure_cooldown_ms: 1000,
            drain_timeout_ms: 30_000,
            tls: None,
            proxy_protocol_v2: false,
            upstream_tls: None,
            outbound_bind: None,
            idle_timeout_ms: None,
            autodisable: false,
            hash_groups: vec![],
            hash_failover: false,
            debug: false,
            packet_dump: false,
            control_socket: None,
            management: None,
            http1: None,
            config_file: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    // shortcut: numeric endpoints only; add bounded DNS refresh when service discovery is implemented.
    pub address: SocketAddr,
    #[serde(default = "one")]
    pub weight: u32,
    #[serde(default)]
    pub priority: u16,
    #[serde(default)]
    pub max_connections: usize,
    pub server_name: Option<String>,
}
fn one() -> u32 {
    1
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerTls {
    pub cert: String,
    pub key: String,
    pub client_ca: Option<String>,
    #[serde(default)]
    pub sni_certificates: Vec<SniCertificate>,
    #[serde(default)]
    pub reject_unknown_sni: bool,
    #[serde(default)]
    pub key_exchange: KeyExchange,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SniCertificate {
    pub names: Vec<String>,
    pub cert: String,
    pub key: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientTls {
    pub ca: String,
    pub cert: Option<String>,
    pub key: Option<String>,
    #[serde(default)]
    pub key_exchange: KeyExchange,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum KeyExchange {
    Classical,
    #[default]
    HybridPreferred,
    HybridRequired,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    ReadOnly,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementClient {
    pub name: String,
    pub cert: String,
    pub role: Role,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Management {
    pub listen: SocketAddr,
    pub tls: ServerTls,
    pub clients: Vec<ManagementClient>,
    #[serde(default = "management_limit")]
    pub max_connections: usize,
    #[serde(default = "management_timeout")]
    pub request_timeout_ms: u64,
}
fn management_limit() -> usize {
    16
}
fn management_timeout() -> u64 {
    5000
}

impl Config {
    // Used by CLI startup and SIGHUP preparation; both apply the same validation.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let mut bytes = Vec::new();
        File::open(path)?.take(1_048_577).read_to_end(&mut bytes)?;
        if bytes.len() > 1_048_576 {
            return Err("config exceeds 1 MiB".into());
        }
        let mut config: Self = serde_json::from_slice(&bytes)?;
        config.config_file = Some(path.canonicalize()?);
        config.validate()?;
        Ok(config)
    }

    // Called by load and positional CLI parsing; reject inconsistent settings before use.
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(http) = &self.http1 {
            http.validate()?;
        }
        if self.reuse_port && self.control_socket.is_none() {
            return Err("reuse_port workers require a unique control_socket".into());
        }
        if let Some(tls) = &self.tls {
            let mut names = HashSet::new();
            for identity in &tls.sni_certificates {
                if identity.names.is_empty() || identity.names.len() > 256 {
                    return Err("each SNI identity needs 1..=256 names".into());
                }
                for name in &identity.names {
                    let normalized = name.to_ascii_lowercase();
                    let host = normalized.strip_prefix("*.").unwrap_or(&normalized);
                    if host.is_empty()
                        || host.len() > 253
                        || !host.split('.').all(|label| {
                            !label.is_empty()
                                && label.len() <= 63
                                && label.as_bytes()[0].is_ascii_alphanumeric()
                                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                                && label
                                    .bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                        })
                        || (normalized.contains('*') && !normalized.starts_with("*."))
                        || !names.insert(normalized)
                    {
                        return Err(format!("invalid or duplicate SNI name {name}").into());
                    }
                }
            }
        }
        if let Some(m) = &self.management {
            if m.tls.client_ca.is_none() || m.clients.is_empty() || m.clients.len() > 256 {
                return Err("management requires a client CA and 1..=256 explicitly authorized client certificates".into());
            }
            if !(1..=128).contains(&m.max_connections)
                || !(100..=60_000).contains(&m.request_timeout_ms)
            {
                return Err("invalid management connection limit or request timeout".into());
            }
            let mut names = HashSet::new();
            for client in &m.clients {
                if client.name.is_empty()
                    || client.name.len() > 64
                    || !client
                        .name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                    || !names.insert(&client.name)
                {
                    return Err("management client names must be unique ASCII identifiers of 1..=64 characters".into());
                }
            }
        }
        if !(1..=256).contains(&self.backends.len()) {
            return Err("need 1..=256 backends".into());
        }
        if !(1..=256).contains(&self.workers) {
            return Err("workers must be 1..=256".into());
        }
        if !(1..=10_000_000).contains(&self.max_connections)
            || !(1..=self.max_connections).contains(&self.max_handshakes)
        {
            return Err("require 1 <= max_handshakes <= max_connections <= 10000000".into());
        }
        if !(1024..=65536).contains(&self.buffer_bytes) {
            return Err("buffer_bytes must be 1024..=65536".into());
        }
        for value in [
            self.connect_timeout_ms,
            self.handshake_timeout_ms,
            self.establishment_timeout_ms,
            self.drain_timeout_ms,
        ] {
            if !(1..=3_600_000).contains(&value) {
                return Err("timeouts must be 1..=3600000 ms".into());
            }
        }
        if self.failure_cooldown_ms > 3_600_000
            || self
                .idle_timeout_ms
                .is_some_and(|t| !(1..=3_600_000).contains(&t))
        {
            return Err("invalid cooldown or idle timeout".into());
        }
        if self
            .hash_groups
            .iter()
            .any(|g| !self.backends.iter().any(|b| b.priority == *g))
        {
            return Err("hash_groups references a nonexistent priority group".into());
        }
        let mut addresses = HashSet::new();
        for backend in &self.backends {
            if self
                .outbound_bind
                .is_some_and(|ip| ip.is_ipv4() != backend.address.is_ipv4())
            {
                return Err(
                    "outbound_bind and all backend addresses must use the same IP family".into(),
                );
            }
            if backend.address.port() == 0 || backend.address.ip().is_unspecified() {
                return Err("backend must have a concrete address and nonzero port".into());
            }
            if !addresses.insert(backend.address) {
                return Err("duplicate backend address".into());
            }
            if backend.weight > 1_000_000 {
                return Err("backend weight exceeds 1000000".into());
            }
            if self.upstream_tls.is_some() != backend.server_name.is_some() {
                return Err("server_name is required exactly when upstream_tls is enabled".into());
            }
        }
        if !self.backends.iter().any(|b| b.weight > 0) {
            return Err("at least one backend needs positive weight".into());
        }
        if self
            .upstream_tls
            .as_ref()
            .is_some_and(|tls| tls.cert.is_some() != tls.key.is_some())
        {
            return Err("upstream TLS cert and key must be supplied together".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boundaries() {
        let good = r#"{"backends":[{"address":"127.0.0.1:9000"}]}"#;
        let mut config: Config = serde_json::from_str(good).unwrap();
        config.validate().unwrap();
        config.backends.push(config.backends[0].clone());
        assert!(config.validate().is_err());
        config.backends.pop();
        config.backends[0].weight = 0;
        assert!(config.validate().is_err());
        config.backends[0].weight = 1;
        config.max_handshakes = config.max_connections + 1;
        assert!(config.validate().is_err());
        assert!(serde_json::from_str::<Config>(r#"{"typo":true}"#).is_err());
    }

    #[test]
    fn sni_names_accept_exact_and_one_label_wildcards_only_once() {
        let mut config: Config = serde_json::from_str(
            r#"{"backends":[{"address":"127.0.0.1:9000"}],"tls":{"cert":"fallback.pem","key":"fallback.key","sni_certificates":[{"names":["api.example.test","*.devices.test"],"cert":"devices.pem","key":"devices.key"}]}}"#,
        ).unwrap();
        config.validate().unwrap();
        config.tls.as_mut().unwrap().sni_certificates[0]
            .names
            .push("API.EXAMPLE.TEST".into());
        assert!(config.validate().is_err());
        config.tls.as_mut().unwrap().sni_certificates[0].names = vec!["*a.devices.test".into()];
        assert!(config.validate().is_err());
    }
}
