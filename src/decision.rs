//! Bounded decision snapshots; the scheduler applies them without external calls.
use crate::{
    Error,
    config::Backend,
    scheduler::{Scheduler, WeightedRoundRobin},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub weights: BTreeMap<SocketAddr, u32>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Match {
    pub source_cidr: Option<String>,
    pub tls_version: Option<String>,
    pub sni: Option<String>,
    #[serde(default)]
    pub country_codes: Vec<String>,
    pub country_unknown: Option<bool>,
    pub tls_cipher: Option<String>,
    pub alpn: Option<String>,
    pub client_verified: Option<bool>,
    pub host: Option<String>,
    pub method: Option<String>,
    pub path_prefix: Option<String>,
    pub http_version: Option<String>,
    pub websocket: Option<bool>,
    pub websocket_protocol: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct HttpMetadata {
    pub host: String,
    pub method: String,
    pub path: String,
    pub version: String,
    pub websocket: bool,
    pub websocket_protocols: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Metadata {
    pub country: Option<String>,
    pub tls_cipher: Option<String>,
    pub alpn: Option<String>,
    pub client_verified: bool,
    pub http: Option<HttpMetadata>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Constraint {
    #[serde(rename = "match")]
    pub matcher: Match,
    #[serde(default)]
    pub regions: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub reject: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    #[serde(rename = "match")]
    pub matcher: Match,
    pub profile: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OnExpiry {
    Configured,
    Reject,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Update {
    pub expected_generation: u64,
    pub backend_generation: u64,
    pub ttl_ms: u64,
    pub source_revision: String,
    pub on_expiry: OnExpiry,
    pub profiles: BTreeMap<String, Profile>,
    #[serde(default)]
    pub assignments: Vec<Assignment>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Preview {
    pub client_ip: IpAddr,
    pub tls_version: Option<String>,
    pub sni: Option<String>,
    #[serde(default)]
    pub metadata: Metadata,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Show,
    Apply(Update),
    Clear { expected_generation: u64 },
    Preview(Preview),
}
impl Operation {
    pub fn writes(&self) -> bool {
        matches!(self, Self::Apply(_) | Self::Clear { .. })
    }
}

#[derive(Clone, Copy)]
pub struct Client<'a> {
    pub ip: IpAddr,
    pub tls_version: Option<&'a str>,
    pub sni: Option<&'a str>,
    pub metadata: Option<&'a Metadata>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selection {
    Configured,
    Profile(usize),
    Reject,
}

#[derive(Clone)]
struct Rule {
    network: Option<(IpAddr, u8)>,
    matcher: Match,
    profile: usize,
}
struct CompiledProfile {
    name: String,
    weights: Vec<u32>,
    scheduler: WeightedRoundRobin,
}
struct Snapshot {
    update: Update,
    expires: Instant,
    profiles: Vec<CompiledProfile>,
    classifier: Arc<Classifier>,
}

#[derive(Clone)]
pub struct Classifier {
    rules: Vec<Rule>,
    default: usize,
}
impl Classifier {
    pub fn class(&self, client: Client<'_>) -> usize {
        self.rules
            .iter()
            .find(|r| matches(&r.matcher, r.network, client))
            .map_or(self.default, |r| r.profile)
    }
}

// A lease pins classification semantics even if a controller publishes another policy.
pub struct Guard {
    classifier: Option<(Arc<Classifier>, usize)>,
    constraints: Arc<Vec<Constraint>>,
    selected: [bool; 128],
}
impl Guard {
    pub fn permits(&self, client: Client<'_>) -> bool {
        self.classifier
            .as_ref()
            .is_none_or(|(c, class)| c.class(client) == *class)
            && self.constraints.iter().enumerate().all(|(i, c)| {
                let m = &c.matcher;
                matches(
                    m,
                    m.source_cidr.as_deref().and_then(|n| network(n).ok()),
                    client,
                ) == self.selected[i]
            })
    }
}

fn matches(m: &Match, network: Option<(IpAddr, u8)>, client: Client<'_>) -> bool {
    let empty = Metadata::default();
    let data = client.metadata.unwrap_or(&empty);
    let http = data.http.as_ref();
    network.is_none_or(|n| contains(n, client.ip))
        && m.tls_version
            .as_deref()
            .is_none_or(|v| Some(v) == client.tls_version)
        && m.sni
            .as_deref()
            .is_none_or(|v| client.sni.is_some_and(|n| n.eq_ignore_ascii_case(v)))
        && (m.country_codes.is_empty()
            || data
                .country
                .as_ref()
                .is_some_and(|c| m.country_codes.contains(c)))
        && m.country_unknown
            .is_none_or(|unknown| unknown == data.country.is_none())
        && m.tls_cipher
            .as_deref()
            .is_none_or(|v| data.tls_cipher.as_deref() == Some(v))
        && m.alpn
            .as_deref()
            .is_none_or(|v| data.alpn.as_deref() == Some(v))
        && m.client_verified.is_none_or(|v| data.client_verified == v)
        && m.host
            .as_deref()
            .is_none_or(|v| http.is_some_and(|h| h.host.eq_ignore_ascii_case(v)))
        && m.method
            .as_deref()
            .is_none_or(|v| http.is_some_and(|h| h.method == v))
        && m.path_prefix
            .as_deref()
            .is_none_or(|v| http.is_some_and(|h| h.path.starts_with(v)))
        && m.http_version
            .as_deref()
            .is_none_or(|v| http.is_some_and(|h| h.version == v))
        && m.websocket
            .is_none_or(|v| http.is_some_and(|h| h.websocket == v))
        && m.websocket_protocol.as_deref().is_none_or(|v| {
            http.is_some_and(|h| h.websocket && h.websocket_protocols.iter().any(|p| p == v))
        })
}

pub fn validate_match(m: &Match) -> Result<(), Error> {
    validate_metadata(m.tls_version.as_deref(), m.sni.as_deref())?;
    if let Some(cidr) = &m.source_cidr {
        network(cidr)?;
    }
    if m.country_codes.len() > 250
        || m.country_codes
            .iter()
            .any(|c| c.len() != 2 || !c.bytes().all(|b| b.is_ascii_uppercase()))
        || (m.country_unknown == Some(true) && !m.country_codes.is_empty())
    {
        return Err("invalid country match".into());
    }
    for value in [
        &m.tls_cipher,
        &m.alpn,
        &m.host,
        &m.method,
        &m.path_prefix,
        &m.websocket_protocol,
    ]
    .into_iter()
    .flatten()
    {
        if value.is_empty() || value.len() > 2048 || value.bytes().any(|b| b.is_ascii_control()) {
            return Err("routing metadata is empty, oversized or contains control bytes".into());
        }
    }
    if m.http_version.as_deref().is_some_and(|v| v != "HTTP/1.1")
        || m.path_prefix
            .as_deref()
            .is_some_and(|v| !v.starts_with('/') || v.contains('?'))
        || m.websocket_protocol.is_some() && m.websocket == Some(false)
    {
        return Err("invalid HTTP routing match".into());
    }
    if let Some(host) = &m.host {
        balanco::http_plugin::validate_host(host)?;
        if host
            .parse::<hyper::http::uri::Authority>()?
            .port()
            .is_some()
        {
            return Err("routing host must omit the port".into());
        }
    }
    if let Some(method) = &m.method {
        hyper::Method::from_bytes(method.as_bytes())?;
    }
    if m.alpn.as_ref().is_some_and(|s| s.len() > 255)
        || m.websocket_protocol.as_ref().is_some_and(|s| {
            s.len() > 128 || hyper::header::HeaderName::from_bytes(s.as_bytes()).is_err()
        })
    {
        return Err("invalid protocol metadata".into());
    }
    Ok(())
}

pub fn permitted(constraints: &[Constraint], backend: &Backend, client: Client<'_>) -> bool {
    constraints.iter().all(|c| {
        !matches(
            &c.matcher,
            c.matcher
                .source_cidr
                .as_deref()
                .and_then(|n| network(n).ok()),
            client,
        ) || (!c.reject
            && (c.regions.is_empty()
                || backend
                    .region
                    .as_ref()
                    .is_some_and(|r| c.regions.contains(r)))
            && c.capabilities
                .iter()
                .all(|v| backend.capabilities.contains(v)))
    })
}

#[derive(Default)]
pub struct State {
    pub generation: u64,
    snapshot: Option<Snapshot>,
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}

fn network(value: &str) -> Result<(IpAddr, u8), Error> {
    let (ip, prefix) = value
        .split_once('/')
        .ok_or("source_cidr requires a prefix length")?;
    let ip: IpAddr = ip.parse()?;
    let prefix: u8 = prefix.parse()?;
    let width = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > width {
        return Err("source_cidr prefix out of range".into());
    }
    let bits = match ip {
        IpAddr::V4(ip) => u128::from(u32::from(ip)),
        IpAddr::V6(ip) => u128::from(ip),
    };
    let host_bits = width - prefix;
    let mask = if host_bits == 128 {
        u128::MAX
    } else {
        (1u128 << host_bits) - 1
    };
    if bits & mask != 0 {
        return Err("source_cidr must use a canonical network address".into());
    }
    Ok((ip, prefix))
}

fn contains(network: (IpAddr, u8), ip: IpAddr) -> bool {
    match (network, ip) {
        ((IpAddr::V4(net), prefix), IpAddr::V4(ip)) => {
            prefix == 0 || u32::from(net) >> (32 - prefix) == u32::from(ip) >> (32 - prefix)
        }
        ((IpAddr::V6(net), prefix), IpAddr::V6(ip)) => {
            prefix == 0 || u128::from(net) >> (128 - prefix) == u128::from(ip) >> (128 - prefix)
        }
        _ => false,
    }
}

fn validate_metadata(tls: Option<&str>, sni: Option<&str>) -> Result<(), Error> {
    if tls.is_some_and(|v| !matches!(v, "TLS1.2" | "TLS1.3")) {
        return Err("tls_version must be TLS1.2 or TLS1.3".into());
    }
    if let Some(sni) = sni
        && (sni.len() > 253
            || sni.is_empty()
            || sni.contains('*')
            || tokio_rustls::rustls::pki_types::ServerName::try_from(sni.to_owned()).is_err())
    {
        return Err("sni must be an exact valid server name".into());
    }
    Ok(())
}

impl State {
    // Called under the pool lock; validate the whole replacement before changing state.
    pub fn apply(
        &mut self,
        update: Update,
        backend_generation: u64,
        backends: &[Backend],
        now: Instant,
    ) -> Result<(), Error> {
        if update.expected_generation != self.generation
            || update.backend_generation != backend_generation
        {
            return Err("routing generation conflict; fetch /v1/routing and retry".into());
        }
        if !(100..=3_600_000).contains(&update.ttl_ms)
            || !identifier(&update.source_revision)
            || update.profiles.is_empty()
            || update.profiles.len() > 32
            || update.assignments.len() > 128
        {
            return Err("invalid routing TTL, revision or profile/assignment count".into());
        }
        let mut profiles = Vec::new();
        for (name, profile) in &update.profiles {
            if !identifier(name)
                || profile.weights.is_empty()
                || !profile.weights.values().any(|w| *w > 0)
                || profile.weights.iter().any(|(address, weight)| {
                    *weight > 1_000_000 || !backends.iter().any(|b| b.address == *address)
                })
            {
                return Err("invalid routing profile or unknown backend".into());
            }
            profiles.push(CompiledProfile {
                name: name.clone(),
                weights: backends
                    .iter()
                    .map(|b| profile.weights.get(&b.address).copied().unwrap_or(0))
                    .collect(),
                scheduler: WeightedRoundRobin::new(backends.len()),
            });
        }
        let lookup = |name: &str| {
            profiles
                .iter()
                .position(|p| p.name == name)
                .ok_or("unknown routing profile")
        };
        let default = lookup("default")?;
        let mut rules: Vec<Rule> = Vec::new();
        for assignment in &update.assignments {
            let mut matcher = assignment.matcher.clone();
            validate_match(&matcher)?;
            matcher.sni = matcher.sni.map(|name| name.to_ascii_lowercase());
            matcher.host = matcher.host.map(|name| name.to_ascii_lowercase());
            matcher.country_codes.sort();
            matcher.country_codes.dedup();
            let network = matcher.source_cidr.as_deref().map(network).transpose()?;
            matcher.source_cidr = network.map(|(ip, prefix)| format!("{ip}/{prefix}"));
            if matcher == Match::default() || rules.iter().any(|r| r.matcher == matcher) {
                return Err("empty or duplicate routing match".into());
            }
            rules.push(Rule {
                network,
                matcher,
                profile: lookup(&assignment.profile)?,
            });
        }
        let expires = now + Duration::from_millis(update.ttl_ms);
        self.snapshot = Some(Snapshot {
            update,
            expires,
            profiles,
            classifier: Arc::new(Classifier { rules, default }),
        });
        self.generation += 1;
        Ok(())
    }

    pub fn clear(&mut self, expected: u64) -> Result<(), Error> {
        if expected != self.generation {
            return Err("routing generation conflict; fetch /v1/routing and retry".into());
        }
        self.invalidate();
        Ok(())
    }

    // Reload and local administrative changes must not leave stale compiled backend indices.
    pub fn invalidate(&mut self) {
        self.snapshot = None;
        self.generation += 1;
    }

    pub fn status(&self, now: Instant) -> serde_json::Value {
        serde_json::json!({"generation":self.generation,"policy":self.snapshot.as_ref().map(|s| &s.update),
            "expired":self.snapshot.as_ref().is_some_and(|s| now >= s.expires),
            "remaining_ms":self.snapshot.as_ref().map(|s| s.expires.saturating_duration_since(now).as_millis() as u64)})
    }

    // Called once per selection attempt; match only bounded, already collected metadata.
    pub fn selection(&self, client: Client<'_>, now: Instant) -> Selection {
        let Some(s) = &self.snapshot else {
            return Selection::Configured;
        };
        if now >= s.expires {
            return if s.update.on_expiry == OnExpiry::Reject {
                Selection::Reject
            } else {
                Selection::Configured
            };
        }
        let profile = s.classifier.class(client);
        Selection::Profile(profile)
    }

    pub fn guard(
        &self,
        selection: Selection,
        constraints: Arc<Vec<Constraint>>,
        client: Client<'_>,
    ) -> Guard {
        let mut selected = [false; 128];
        for (i, c) in constraints.iter().enumerate() {
            selected[i] = matches(
                &c.matcher,
                c.matcher
                    .source_cidr
                    .as_deref()
                    .and_then(|n| network(n).ok()),
                client,
            );
        }
        Guard {
            classifier: match selection {
                Selection::Profile(index) => self
                    .snapshot
                    .as_ref()
                    .map(|s| (s.classifier.clone(), index)),
                _ => None,
            },
            constraints,
            selected,
        }
    }

    pub fn weights(&self, selection: Selection, base: &[u32], out: &mut [u32; 256]) {
        let weights = match selection {
            Selection::Configured => base,
            Selection::Profile(index) => &self.snapshot.as_ref().unwrap().profiles[index].weights,
            Selection::Reject => return,
        };
        out[..weights.len()].copy_from_slice(weights);
    }

    pub fn select(&mut self, index: usize, weights: &[u32], eligible: &[bool]) -> Option<usize> {
        self.snapshot.as_mut()?.profiles[index]
            .scheduler
            .select(weights, eligible)
    }

    pub fn profile_name(&self, selection: Selection) -> Option<&str> {
        match selection {
            Selection::Profile(i) => Some(&self.snapshot.as_ref()?.profiles[i].name),
            _ => None,
        }
    }

    pub fn validate_preview(preview: &Preview) -> Result<(), Error> {
        validate_metadata(preview.tls_version.as_deref(), preview.sni.as_deref())?;
        let data = &preview.metadata;
        let mut matcher = Match {
            country_codes: data.country.iter().cloned().collect(),
            tls_cipher: data.tls_cipher.clone(),
            alpn: data.alpn.clone(),
            ..Default::default()
        };
        if let Some(http) = &data.http {
            matcher.host = Some(http.host.clone());
            matcher.method = Some(http.method.clone());
            matcher.path_prefix = Some(http.path.clone());
            matcher.http_version = Some(http.version.clone());
            if http.websocket_protocols.len() > 16 {
                return Err("too many preview WebSocket protocols".into());
            }
            for p in &http.websocket_protocols {
                matcher.websocket_protocol = Some(p.clone());
                validate_match(&matcher)?;
            }
        }
        validate_match(&matcher)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn backend() -> Backend {
        Backend {
            address: "127.0.0.1:9000".parse().unwrap(),
            weight: 1,
            priority: 0,
            max_connections: 0,
            server_name: None,
            region: None,
            capabilities: vec![],
        }
    }
    fn update() -> Update {
        serde_json::from_value(serde_json::json!({"expected_generation":0,"backend_generation":0,"ttl_ms":100,
        "source_revision":"test-1","on_expiry":"configured","profiles":{"default":{"weights":{"127.0.0.1:9000":1}}}})).unwrap()
    }

    #[test]
    fn metadata_rules_and_placement_remain_pinned_across_policy_changes() {
        let mut u = update();
        u.profiles
            .insert("devices".into(), u.profiles["default"].clone());
        let matcher: Match = serde_json::from_value(serde_json::json!({
            "country_codes":["BG"],"tls_cipher":"TLS13_AES_128_GCM_SHA256","alpn":"http/1.1","client_verified":true,
            "host":"EDGE.EXAMPLE","method":"GET","path_prefix":"/devices","http_version":"HTTP/1.1","websocket":true,"websocket_protocol":"mqtt"
        })).unwrap();
        u.assignments.push(Assignment {
            matcher,
            profile: "devices".into(),
        });
        let mut state = State::default();
        let now = Instant::now();
        let mut backend = backend();
        backend.region = Some("eu".into());
        backend.capabilities = vec!["mqtt".into()];
        state
            .apply(u, 0, std::slice::from_ref(&backend), now)
            .unwrap();
        let mut data = Metadata {
            country: Some("BG".into()),
            tls_cipher: Some("TLS13_AES_128_GCM_SHA256".into()),
            alpn: Some("http/1.1".into()),
            client_verified: true,
            http: Some(HttpMetadata {
                host: "edge.example".into(),
                method: "GET".into(),
                path: "/devices/ws".into(),
                version: "HTTP/1.1".into(),
                websocket: true,
                websocket_protocols: vec!["mqtt".into()],
            }),
        };
        fn client(data: &Metadata) -> Client<'_> {
            Client {
                ip: "8.8.8.8".parse().unwrap(),
                tls_version: Some("TLS1.3"),
                sni: None,
                metadata: Some(data),
            }
        }
        let selected = state.selection(client(&data), now);
        assert_eq!(state.profile_name(selected), Some("devices"));
        let constraints: Vec<Constraint> = serde_json::from_value(serde_json::json!([
            {"match":{"path_prefix":"/devices"},"regions":["eu"],"capabilities":["mqtt"]},
            {"match":{"country_unknown":true},"reject":true}
        ]))
        .unwrap();
        let guard = state.guard(selected, Arc::new(constraints.clone()), client(&data));
        assert!(permitted(&constraints, &backend, client(&data)));
        backend.region = Some("us".into());
        assert!(!permitted(&constraints, &backend, client(&data)));
        state.invalidate();
        assert!(guard.permits(client(&data)));
        data.http.as_mut().unwrap().path = "/other".into();
        assert!(!guard.permits(client(&data)));
        data.country = None;
        assert!(!permitted(&constraints, &backend, client(&data)));
        for m in [
            serde_json::json!({"country_codes":["bg"]}),
            serde_json::json!({"path_prefix":"/path?secret"}),
            serde_json::json!({"http_version":"HTTP/2"}),
            serde_json::json!({"country_unknown":true,"country_codes":["BG"]}),
            serde_json::json!({"websocket":false,"websocket_protocol":"mqtt"}),
        ] {
            assert!(validate_match(&serde_json::from_value(m).unwrap()).is_err());
        }
    }

    #[test]
    fn generations_validation_and_expiry_do_not_partially_publish() {
        let mut state = State::default();
        let now = Instant::now();
        let b = backend();
        state
            .apply(update(), 0, std::slice::from_ref(&b), now)
            .unwrap();
        let client = Client {
            ip: "127.0.0.1".parse().unwrap(),
            tls_version: None,
            sni: None,
            metadata: None,
        };
        assert_eq!(state.selection(client, now), Selection::Profile(0));
        assert!(
            state
                .apply(update(), 0, std::slice::from_ref(&b), now)
                .is_err()
        );
        let mut bad = update();
        bad.expected_generation = 1;
        bad.profiles
            .get_mut("default")
            .unwrap()
            .weights
            .insert("127.0.0.1:9999".parse().unwrap(), 1);
        assert!(state.apply(bad, 0, std::slice::from_ref(&b), now).is_err());
        assert_eq!(state.generation, 1);
        assert_eq!(
            state.selection(client, now + Duration::from_millis(100)),
            Selection::Configured
        );
        let mut strict = update();
        strict.expected_generation = 1;
        strict.on_expiry = OnExpiry::Reject;
        state.apply(strict, 0, &[b], now).unwrap();
        assert_eq!(
            state.selection(client, now + Duration::from_millis(100)),
            Selection::Reject
        );
        assert!(state.clear(1).is_err());
        state.clear(2).unwrap();
        assert_eq!(state.selection(client, now), Selection::Configured);
    }

    #[test]
    fn cidr_and_tls_rules_require_all_conditions() {
        let mut u = update();
        u.profiles
            .insert("special".into(), u.profiles["default"].clone());
        u.assignments.push(Assignment {
            matcher: Match {
                source_cidr: Some("127.0.0.0/8".into()),
                tls_version: Some("TLS1.3".into()),
                sni: Some("EDGE.EXAMPLE".into()),
                ..Match::default()
            },
            profile: "special".into(),
        });
        let mut state = State::default();
        let now = Instant::now();
        state.apply(u, 0, &[backend()], now).unwrap();
        let client = Client {
            ip: "127.0.0.2".parse().unwrap(),
            tls_version: Some("TLS1.3"),
            sni: Some("edge.example"),
            metadata: None,
        };
        assert_eq!(
            state.profile_name(state.selection(client, now)),
            Some("special")
        );
        assert_eq!(
            state.profile_name(state.selection(
                Client {
                    tls_version: None,
                    ..client
                },
                now
            )),
            Some("default")
        );
        assert!(network("127.0.0.1/8").is_err());
        assert!(network("::/129").is_err());
        assert!(contains(
            network("::/0").unwrap(),
            "2001:db8::1".parse().unwrap()
        ));
        assert!(!contains(
            network("::/0").unwrap(),
            "127.0.0.1".parse().unwrap()
        ));
    }
}
