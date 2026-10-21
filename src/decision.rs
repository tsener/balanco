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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selection {
    Configured,
    Profile(usize),
    Reject,
}

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
    rules: Vec<Rule>,
    default: usize,
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
            validate_metadata(matcher.tls_version.as_deref(), matcher.sni.as_deref())?;
            matcher.sni = matcher.sni.map(|name| name.to_ascii_lowercase());
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
            rules,
            default,
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
        let profile = s
            .rules
            .iter()
            .find(|r| {
                r.network.is_none_or(|n| contains(n, client.ip))
                    && r.matcher
                        .tls_version
                        .as_deref()
                        .is_none_or(|v| Some(v) == client.tls_version)
                    && r.matcher
                        .sni
                        .as_deref()
                        .is_none_or(|v| client.sni.is_some_and(|n| n.eq_ignore_ascii_case(v)))
            })
            .map_or(s.default, |r| r.profile);
        Selection::Profile(profile)
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
        validate_metadata(preview.tls_version.as_deref(), preview.sni.as_deref())
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
        }
    }
    fn update() -> Update {
        serde_json::from_value(serde_json::json!({"expected_generation":0,"backend_generation":0,"ttl_ms":100,
        "source_revision":"test-1","on_expiry":"configured","profiles":{"default":{"weights":{"127.0.0.1:9000":1}}}})).unwrap()
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
