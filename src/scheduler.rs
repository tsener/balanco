//! Backend eligibility, reservations and live controls; locks never span network I/O.
use crate::config::Backend;
use std::{
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

/// Compiled plugins choose only among the host's eligible backends. Never perform I/O here.
pub trait Scheduler: Send {
    fn select(&mut self, weights: &[u32], eligible: &[bool]) -> Option<usize>;
}

pub struct WeightedRoundRobin {
    current: Vec<i64>,
}
impl WeightedRoundRobin {
    pub fn new(count: usize) -> Self {
        Self {
            current: vec![0; count],
        }
    }
}
impl Scheduler for WeightedRoundRobin {
    fn select(&mut self, weights: &[u32], eligible: &[bool]) -> Option<usize> {
        self.current.resize(weights.len(), 0);
        let mut best = None;
        let mut total = 0;
        for (i, &weight) in weights.iter().enumerate() {
            if !eligible[i] || weight == 0 {
                self.current[i] = 0;
                continue;
            }
            total += i64::from(weight);
            self.current[i] += i64::from(weight);
            if best.is_none_or(|b| self.current[i] > self.current[b]) {
                best = Some(i);
            }
        }
        if let Some(best) = best {
            self.current[best] -= total;
        }
        best
    }
}

#[derive(Default)]
pub struct Counters {
    pub active: AtomicUsize,
    pub total: std::sync::atomic::AtomicU64,
    pub up: std::sync::atomic::AtomicU64,
    pub down: std::sync::atomic::AtomicU64,
}
struct Channel {
    backend: Backend,
    counters: Arc<Counters>,
    failed_until: Instant,
    disabled: bool,
    health_epoch: u64,
    config_generation: u64,
}
struct State {
    constraints: Arc<Vec<crate::decision::Constraint>>,
    routing: crate::decision::State,
    channels: Vec<Channel>,
    weights: Vec<u32>,
    hash_groups: Vec<u16>,
    scheduler: Box<dyn Scheduler>,
    generation: u64,
    cooldown: Duration,
    autodisable: bool,
    hash_failover: bool,
    outbound_bind: Option<IpAddr>,
    upstream_tls: bool,
}
pub struct Pool {
    state: Mutex<State>,
    pub geoip: std::sync::RwLock<Arc<crate::geoip::GeoIp>>,
}
pub struct Lease {
    pub routing_guard: crate::decision::Guard,
    pub index: usize,
    pub backend: Backend,
    pub counters: Arc<Counters>,
    pub health_epoch: u64,
    pub config_generation: u64,
}
impl Drop for Lease {
    // Relay tasks own leases; cancellation and error exits also release backend capacity.
    fn drop(&mut self) {
        self.counters.active.fetch_sub(1, Ordering::Relaxed);
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Reply {
    pub ok: bool,
    pub group: u16,
    pub generation: u64,
    pub output: String,
    pub data: serde_json::Value,
    pub quit: bool,
    #[serde(skip)]
    pub shutdown: bool,
}
impl Reply {
    pub fn error(group: u16, error: impl std::fmt::Display) -> Self {
        Self {
            ok: false,
            group,
            generation: 0,
            output: error.to_string(),
            data: serde_json::Value::Null,
            quit: false,
            shutdown: false,
        }
    }
}
impl Pool {
    pub fn from_config(config: &crate::config::Config) -> Self {
        let mut pool = Self::new(
            config.backends.clone(),
            Duration::from_millis(config.failure_cooldown_ms),
            Box::new(WeightedRoundRobin::new(config.backends.len())),
        );
        let state = pool.state.get_mut().unwrap();
        state.autodisable = config.autodisable;
        state.hash_groups = config.hash_groups.clone();
        state.hash_failover = config.hash_failover;
        state.outbound_bind = config.outbound_bind;
        state.upstream_tls = config.upstream_tls.is_some();
        state.constraints = Arc::new(config.routing_constraints.clone());
        pool
    }
    pub fn new(backends: Vec<Backend>, cooldown: Duration, scheduler: Box<dyn Scheduler>) -> Self {
        Self {
            geoip: std::sync::RwLock::new(Arc::default()),
            state: Mutex::new(State {
                constraints: Arc::default(),
                routing: crate::decision::State::default(),
                scheduler,
                weights: backends.iter().map(|b| b.weight).collect(),
                channels: backends
                    .into_iter()
                    .map(|backend| Channel {
                        backend,
                        counters: Arc::default(),
                        failed_until: Instant::now(),
                        disabled: false,
                        health_epoch: 0,
                        config_generation: 0,
                    })
                    .collect(),
                hash_groups: vec![],
                generation: 0,
                cooldown,
                autodisable: false,
                hash_failover: false,
                outbound_bind: None,
                upstream_tls: false,
            }),
        }
    }
    // Called after reload preparation; generations discard old establishment results.
    pub fn reconfigure(&self, config: &crate::config::Config) {
        let mut state = self.state.lock().expect("scheduler panicked");
        state.routing.invalidate();
        state.constraints = Arc::new(config.routing_constraints.clone());
        let old_counters: std::collections::HashMap<_, _> = state
            .channels
            .iter()
            .map(|channel| (channel.backend.address, channel.counters.clone()))
            .collect();
        let generation = state.generation.wrapping_add(1);
        state.channels = config
            .backends
            .iter()
            .cloned()
            .map(|backend| Channel {
                counters: old_counters
                    .get(&backend.address)
                    .cloned()
                    .unwrap_or_default(),
                backend,
                failed_until: Instant::now(),
                disabled: false,
                health_epoch: generation,
                config_generation: generation,
            })
            .collect();
        state.weights = config
            .backends
            .iter()
            .map(|backend| backend.weight)
            .collect();
        state.hash_groups.clone_from(&config.hash_groups);
        state.scheduler = Box::new(WeightedRoundRobin::new(config.backends.len()));
        state.cooldown = Duration::from_millis(config.failure_cooldown_ms);
        state.autodisable = config.autodisable;
        state.hash_failover = config.hash_failover;
        state.outbound_bind = config.outbound_bind;
        state.upstream_tls = config.upstream_tls.is_some();
        state.generation = generation;
    }
    #[cfg(test)]
    pub fn acquire(&self, attempted: &[bool]) -> Option<Lease> {
        self.acquire_for(attempted, "127.0.0.1".parse().unwrap())
    }
    #[cfg(test)]
    pub fn acquire_for(&self, attempted: &[bool], peer: IpAddr) -> Option<Lease> {
        self.acquire_for_context(
            attempted,
            crate::decision::Client {
                ip: peer,
                tls_version: None,
                sni: None,
                metadata: None,
            },
        )
    }
    // Called by Proxy::relay; reserve an eligible backend before starting network I/O.
    pub fn acquire_for_context(
        &self,
        attempted: &[bool],
        client: crate::decision::Client<'_>,
    ) -> Option<Lease> {
        let mut state = self.state.lock().expect("scheduler panicked");
        let now = Instant::now();
        let (weights, eligible, selection) = state.candidates(attempted, client, now);
        let count = state.channels.len();
        let index = match selection {
            crate::decision::Selection::Profile(profile) => {
                state
                    .routing
                    .select(profile, &weights[..count], &eligible[..count])
            }
            crate::decision::Selection::Configured => state
                .scheduler
                .select(&weights[..count], &eligible[..count]),
            crate::decision::Selection::Reject => None,
        }?;
        if index >= count || !eligible[index] {
            return None;
        }
        let channel = &state.channels[index];
        channel.counters.active.fetch_add(1, Ordering::Relaxed);
        channel.counters.total.fetch_add(1, Ordering::Relaxed);
        Some(Lease {
            routing_guard: state
                .routing
                .guard(selection, state.constraints.clone(), client),
            index,
            backend: channel.backend.clone(),
            counters: channel.counters.clone(),
            health_epoch: channel.health_epoch,
            config_generation: channel.config_generation,
        })
    }

    // Shared by HTTPS and Unix control; publication and backend selection share one lock.
    pub fn routing(&self, operation: &crate::decision::Operation) -> Result<Reply, crate::Error> {
        use crate::decision::{Client, Operation};
        let mut state = self.state.lock().expect("scheduler panicked");
        let now = Instant::now();
        match operation {
            Operation::Apply(update) => {
                let backends: Vec<_> = state.channels.iter().map(|c| c.backend.clone()).collect();
                let generation = state.generation;
                state
                    .routing
                    .apply(update.clone(), generation, &backends, now)?;
            }
            Operation::Clear {
                expected_generation,
            } => state.routing.clear(*expected_generation)?,
            Operation::Show | Operation::Preview(_) => (),
        }
        let mut data = state.routing.status(now);
        data["backend_generation"] = state.generation.into();
        data["geoip"] = self.geoip.read().expect("GeoIP lock poisoned").status();
        if let Operation::Preview(preview) = operation {
            crate::decision::State::validate_preview(preview)?;
            let client = Client {
                ip: preview.client_ip,
                tls_version: preview.tls_version.as_deref(),
                sni: preview.sni.as_deref(),
                metadata: Some(&preview.metadata),
            };
            let (weights, eligible, selection) = state.candidates(&[false; 256], client, now);
            data["profile"] = serde_json::json!(state.routing.profile_name(selection));
            data["candidates"] = serde_json::json!(state.channels.iter().enumerate().map(|(i,c)|
                serde_json::json!({"address":c.backend.address,"effective_weight":weights[i],"eligible":eligible[i]})).collect::<Vec<_>>());
        }
        Ok(Reply {
            ok: true,
            group: 0,
            generation: state.routing.generation,
            output: serde_json::to_string_pretty(&data)?,
            data,
            quit: false,
            shutdown: false,
        })
    }
    // Called on establishment failure; stale attempts cannot reapply a cleared cooldown.
    pub fn failed(&self, index: usize, config_generation: u64, health_epoch: u64) {
        let mut state = self.state.lock().expect("scheduler panicked");
        let failed_until = Instant::now() + state.cooldown;
        let autodisable = state.autodisable;
        let channel = &mut state.channels[index];
        if channel.config_generation != config_generation || channel.health_epoch != health_epoch {
            return;
        }
        channel.failed_until = failed_until;
        channel.disabled |= autodisable;
        channel.health_epoch = channel.health_epoch.wrapping_add(1);
    }
    pub fn succeeded(&self, index: usize, config_generation: u64) {
        let mut state = self.state.lock().expect("scheduler panicked");
        let channel = &mut state.channels[index];
        if channel.config_generation != config_generation {
            return;
        }
        if !channel.disabled {
            channel.failed_until = Instant::now();
            channel.health_epoch = channel.health_epoch.wrapping_add(1);
        }
    }

    pub fn uses_tls(&self) -> bool {
        self.state.lock().expect("scheduler panicked").upstream_tls
    }
}

impl State {
    fn candidates(
        &self,
        attempted: &[bool],
        client: crate::decision::Client<'_>,
        now: Instant,
    ) -> ([u32; 256], [bool; 256], crate::decision::Selection) {
        let state = self;
        let peer = client.ip;
        let selection = state.routing.selection(client, now);
        let mut weights = [0; 256];
        state
            .routing
            .weights(selection, &state.weights, &mut weights);
        // Fixed arrays avoid heap allocation on each selection; config caps backend count at 256.
        let mut eligible = [false; 256];
        for (i, channel) in state.channels.iter().enumerate() {
            let b = &channel.backend;
            eligible[i] = crate::decision::permitted(&state.constraints, b, client)
                && b.weight > 0
                && weights[i] > 0
                && !channel.disabled
                && !attempted[i]
                && channel.failed_until <= now
                && (b.max_connections == 0
                    || channel.counters.active.load(Ordering::Relaxed) < b.max_connections);
        }
        for group in &state.hash_groups {
            let mut members = [0; 256];
            let mut count = 0;
            for (i, channel) in state.channels.iter().enumerate() {
                let b = &channel.backend;
                if b.priority == *group {
                    members[count] = i;
                    count += 1;
                }
            }
            if count == 0 {
                continue;
            }
            let first = ip_hash(peer) as usize % count;
            let selected = (0..if state.hash_failover { count } else { 1 })
                .map(|offset| members[(first + offset) % count])
                .find(|&i| eligible[i]);
            for &i in &members[..count] {
                eligible[i] &= Some(i) == selected;
            }
        }
        let priority = state
            .channels
            .iter()
            .enumerate()
            .filter(|(i, _)| eligible[*i])
            .map(|(_, b)| b.backend.priority)
            .min();
        for (i, b) in state.channels.iter().enumerate() {
            eligible[i] &= Some(b.backend.priority) == priority;
        }
        (weights, eligible, selection)
    }
}

impl Pool {
    // Called by control::execute; administrative changes invalidate external decisions.
    pub fn command(
        &self,
        mut group: u16,
        args: &[&str],
        created: Option<Backend>,
    ) -> Result<Reply, crate::Error> {
        use serde_json::json;
        let mut state = self.state.lock().expect("scheduler panicked");
        let mut data = serde_json::Value::Null;
        let mut changed = false;
        let mut quit = false;
        let mut shutdown = false;
        let index = |state: &State, group: u16, n: &str| -> Result<usize, crate::Error> {
            let n: usize = n.parse()?;
            state
                .channels
                .iter()
                .enumerate()
                .filter(|(_, c)| c.backend.priority == group)
                .nth(n)
                .map(|(i, _)| i)
                .ok_or_else(|| "unknown channel".into())
        };
        let output = match args {
            ["help" | "?"] => "show; group N; create HOST PORT [TLS_NAME]; enable N; disable N; maxc N LIMIT; weight N VALUE; rr; hash; reset N; mrtg-bytes G N; mrtg-conns G N; http-show; http-rules FILE; routing-show; routing-apply FILE; routing-preview FILE; routing-clear GENERATION; version; quit; kill".into(),
            ["version"] => format!("balanco {}; MAXCHANNELS=256 total; group IDs 0..65535", env!("CARGO_PKG_VERSION")),
            ["quit"] => { quit = true; "bye".into() }
            ["kill"] => { shutdown = true; changed = true; "draining connections".into() }
            ["group", n] => { group = n.parse()?; format!("group {group}") }
            ["show"] => {
                let mut rows = Vec::new();
                let mut numbers = std::collections::BTreeMap::<u16, usize>::new();
                for c in &state.channels {
                    let b = &c.backend;
                    let n = numbers.entry(b.priority).or_default();
                    rows.push(json!({"group":b.priority,"channel":*n,"address":b.address,"server_name":b.server_name,"region":b.region,"capabilities":b.capabilities,"enabled":!c.disabled,"weight":b.weight,"maxc":b.max_connections,"active":c.counters.active.load(Ordering::Relaxed),"connections":c.counters.total.load(Ordering::Relaxed),"bytes_up":c.counters.up.load(Ordering::Relaxed),"bytes_down":c.counters.down.load(Ordering::Relaxed),"mode":if state.hash_groups.contains(&b.priority){"hash"}else{"rr"},"cooling_down":c.failed_until>Instant::now()}));
                    *n += 1;
                }
                rows.sort_by_key(|r| (r["group"].as_u64(),r["channel"].as_u64()));
                let mut out = "group channel mode enabled address active maxc weight connections bytes_up bytes_down\n".to_owned();
                for r in &rows { out.push_str(&format!("{} {} {} {} {} {} {} {} {} {} {}\n",r["group"],r["channel"],r["mode"].as_str().unwrap(),r["enabled"],r["address"].as_str().unwrap(),r["active"],r["maxc"],r["weight"],r["connections"],r["bytes_up"],r["bytes_down"])); }
                data = json!({"channels":rows});
                out
            }
            ["create", ..] if created.is_some() => {
                let backend = created.unwrap();
                if state.channels.len() >= 256 || state.channels.iter().any(|c| c.backend.address == backend.address) { return Err("channel limit reached or duplicate backend".into()); }
                if backend.address.port() == 0 || backend.address.ip().is_unspecified() || state.outbound_bind.is_some_and(|ip| ip.is_ipv4() != backend.address.is_ipv4()) { return Err("invalid backend address or source-bind family".into()); }
                if state.upstream_tls != backend.server_name.is_some() { return Err("TLS backend requires a server name".into()); }
                if let Some(name) = &backend.server_name { tokio_rustls::rustls::pki_types::ServerName::try_from(name.clone())?; }
                let n = state.channels.iter().filter(|c| c.backend.priority == group).count();
                state.weights.push(backend.weight);
                let config_generation = state.generation;
                state.channels.push(Channel { backend, counters: Arc::default(), failed_until: Instant::now(), disabled: true, health_epoch: 0, config_generation });
                changed = true;
                format!("channel {n} created disabled in group {group}; enable it explicitly")
            }
            [op @ ("enable" | "disable" | "reset"), n] => {
                let i = index(&state,group,n)?;
                let c = &mut state.channels[i];
                match *op {
                    "enable" => { c.disabled = false; c.failed_until = Instant::now(); c.health_epoch = c.health_epoch.wrapping_add(1); }
                    "disable" => { c.disabled = true; c.health_epoch = c.health_epoch.wrapping_add(1); }
                    _ => { c.counters.up.store(0, Ordering::Relaxed); c.counters.down.store(0, Ordering::Relaxed); c.counters.total.store(0, Ordering::Relaxed); }
                }
                changed = true;
                format!("{op} channel {n} in group {group}")
            }
            [op @ ("maxc" | "weight"), n, value] => {
                let i = index(&state,group,n)?;
                let value: usize = value.parse()?;
                if (*op == "weight" && value > 1_000_000) || value > 10_000_000 { return Err("value out of range".into()); }
                if *op == "maxc" { state.channels[i].backend.max_connections = value; }
                else { state.channels[i].backend.weight = value as u32; state.weights[i] = value as u32; }
                changed = true;
                format!("{op} channel {n} = {value}")
            }
            [op @ ("rr" | "hash")] => {
                if !state.channels.iter().any(|c| c.backend.priority == group) { return Err("group has no channels".into()); }
                state.hash_groups.retain(|g| *g != group);
                if *op == "hash" { state.hash_groups.push(group); }
                changed = true;
                format!("group {group} set to {op}")
            }
            [op @ ("mrtg-bytes" | "mrtg-conns"), g, n] => {
                let g = g.parse()?;
                let c = &state.channels[index(&state,g,n)?].counters;
                if *op == "mrtg-bytes" { format!("{}\n{}\nUNKNOWN\ngroup {g} channel {n}",c.up.load(Ordering::Relaxed),c.down.load(Ordering::Relaxed)) }
                else { format!("{}\nUNKNOWN\nUNKNOWN\ngroup {g} channel {n}",c.total.load(Ordering::Relaxed)) }
            }
            _ => return Err("invalid command or arguments; use help".into()),
        };
        if changed {
            state.routing.invalidate();
            state.generation += 1;
        }
        Ok(Reply {
            ok: true,
            group,
            generation: state.generation,
            output,
            data,
            quit,
            shutdown,
        })
    }
}

// Match Balance's IPv4 polynomial on platforms with signed char; extend the same rule to IPv6.
fn ip_hash(ip: IpAddr) -> u32 {
    let fold = |bytes: &[u8]| {
        bytes.iter().fold(0u32, |hash, byte| {
            hash.wrapping_mul(31)
                .wrapping_add(i32::from(*byte as i8) as u32)
        })
    };
    match ip {
        IpAddr::V4(ip) => fold(&ip.octets()),
        IpAddr::V6(ip) => fold(&ip.octets()),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn placement_constraints_survive_external_expiry_and_backend_failover() {
        use crate::{
            config::Config,
            decision::{Client, Metadata, Operation},
        };
        let config: Config = serde_json::from_value(serde_json::json!({"backends":[
            {"address":"127.0.0.1:9001","region":"eu","capabilities":["devices"]},
            {"address":"127.0.0.1:9002","region":"us","capabilities":["devices"]}],
            "routing_constraints":[{"match":{},"regions":["eu"],"capabilities":["devices"]},
                {"match":{"country_unknown":true},"reject":true}]
        }))
        .unwrap();
        config.validate().unwrap();
        let pool = Pool::from_config(&config);
        let data = Metadata {
            country: Some("BG".into()),
            ..Default::default()
        };
        let client = Client {
            ip: "8.8.8.8".parse().unwrap(),
            tls_version: None,
            sni: None,
            metadata: Some(&data),
        };
        assert!(
            pool.acquire_for_context(
                &[false; 2],
                Client {
                    metadata: None,
                    ..client
                }
            )
            .is_none()
        );
        let update=serde_json::from_value(serde_json::json!({"expected_generation":0,"backend_generation":0,"ttl_ms":100,"source_revision":"placement","on_expiry":"configured",
            "profiles":{"default":{"weights":{"127.0.0.1:9002":1000}}}})).unwrap();
        pool.routing(&Operation::Apply(update)).unwrap();
        assert!(pool.acquire_for_context(&[false; 2], client).is_none());
        // Expire the snapshot without wall-clock sleeps, then verify configured fallback stays in-region.
        let mut state = pool.state.lock().unwrap();
        let (_, eligible, _) = state.candidates(
            &[false; 2],
            client,
            Instant::now() + Duration::from_millis(101),
        );
        assert_eq!(&eligible[..2], &[true, false]);
        state.routing.invalidate();
        drop(state);
        let lease = pool.acquire_for_context(&[false; 2], client).unwrap();
        assert_eq!(lease.index, 0);
        pool.failed(0, lease.config_generation, lease.health_epoch);
        drop(lease);
        assert!(pool.acquire_for_context(&[false; 2], client).is_none());
    }
    use super::*;
    #[test]
    fn hash_affinity_and_failover_policy() {
        let mut config: crate::config::Config = serde_json::from_str(r#"{
            "backends":[{"address":"127.0.0.1:1"},{"address":"127.0.0.1:2"},{"address":"127.0.0.1:3","priority":1}],
            "hash_groups":[0]
        }"#).unwrap();
        let pool = Pool::from_config(&config);
        assert_eq!(
            pool.acquire_for(&[false; 3], "127.0.0.1".parse().unwrap())
                .unwrap()
                .index,
            0
        );
        assert_eq!(
            pool.acquire_for(&[false; 3], "127.0.0.2".parse().unwrap())
                .unwrap()
                .index,
            1
        );
        assert_eq!(pool.acquire(&[true, false, false]).unwrap().index, 2);
        config.hash_failover = true;
        assert_eq!(
            Pool::from_config(&config)
                .acquire(&[true, false, false])
                .unwrap()
                .index,
            1
        );
        config.autodisable = true;
        config.failure_cooldown_ms = 0;
        let pool = Pool::from_config(&config);
        let failed = pool.acquire(&[false; 3]).unwrap();
        pool.failed(0, failed.config_generation, failed.health_epoch);
        assert_eq!(pool.acquire(&[false; 3]).unwrap().index, 1);
    }
    #[test]
    fn weighted_distribution_and_ineligible_reset() {
        let mut rr = WeightedRoundRobin::new(3);
        let mut counts = [0; 3];
        for _ in 0..400 {
            counts[rr.select(&[3, 1, 0], &[true, true, true]).unwrap()] += 1;
        }
        assert_eq!(counts, [300, 100, 0]);
        for _ in 0..100 {
            assert_eq!(rr.select(&[3, 1, 0], &[false, true, true]), Some(1));
        }
        assert_eq!(rr.select(&[3, 1, 0], &[false, false, true]), None);
    }
    #[test]
    fn tiers_caps_failures_and_raii() {
        let backends = serde_json::from_str::<Vec<Backend>>(
            r#"[
            {"address":"127.0.0.1:1","max_connections":1},
            {"address":"127.0.0.1:2","priority":1}
        ]"#,
        )
        .unwrap();
        let pool = Pool::new(
            backends,
            Duration::from_secs(60),
            Box::new(WeightedRoundRobin::new(2)),
        );
        let first = pool.acquire(&[false, false]).unwrap();
        assert_eq!(first.index, 0);
        assert_eq!(pool.acquire(&[false, false]).unwrap().index, 1);
        drop(first);
        assert_eq!(pool.acquire(&[false, false]).unwrap().index, 0);
        let failed = pool.acquire(&[false, false]).unwrap();
        pool.failed(0, failed.config_generation, failed.health_epoch);
        assert_eq!(pool.acquire(&[false, false]).unwrap().index, 1);
        assert!(pool.acquire(&[false, true]).is_none());
    }

    #[test]
    fn successful_concurrent_attempt_clears_cooldown_and_stales_failures() {
        let backends =
            serde_json::from_str::<Vec<Backend>>(r#"[{"address":"127.0.0.1:1"}]"#).unwrap();
        let pool = Pool::new(
            backends,
            Duration::from_secs(60),
            Box::new(WeightedRoundRobin::new(1)),
        );
        let failed_attempt = pool.acquire(&[false]).unwrap();
        let successful_attempt = pool.acquire(&[false]).unwrap();

        pool.failed(
            failed_attempt.index,
            failed_attempt.config_generation,
            failed_attempt.health_epoch,
        );
        assert!(pool.acquire(&[false]).is_none());

        pool.succeeded(
            successful_attempt.index,
            successful_attempt.config_generation,
        );
        assert!(pool.acquire(&[false]).is_some());

        pool.failed(
            failed_attempt.index,
            failed_attempt.config_generation,
            failed_attempt.health_epoch,
        );
        assert!(pool.acquire(&[false]).is_some());
    }

    #[test]
    fn reconfiguration_ignores_establishment_results_from_old_generation() {
        let backends =
            serde_json::from_str::<Vec<Backend>>(r#"[{"address":"127.0.0.1:9000"}]"#).unwrap();
        let pool = Pool::new(
            backends,
            Duration::from_secs(60),
            Box::new(WeightedRoundRobin::new(1)),
        );
        let old = pool.acquire(&[false]).unwrap();
        let next = crate::config::Config {
            backends: serde_json::from_str(r#"[{"address":"127.0.0.1:9001"}]"#).unwrap(),
            ..crate::config::Config::default()
        };
        pool.reconfigure(&next);
        pool.failed(old.index, old.config_generation, old.health_epoch);
        let selected = pool.acquire(&[false]).unwrap();
        assert_eq!(selected.backend.address.port(), 9001);
    }

    #[test]
    fn concurrent_reservations_respect_cap() {
        let backends = serde_json::from_str::<Vec<Backend>>(
            r#"[{"address":"127.0.0.1:1","max_connections":1}]"#,
        )
        .unwrap();
        let pool = Arc::new(Pool::new(
            backends,
            Duration::from_secs(1),
            Box::new(WeightedRoundRobin::new(1)),
        ));
        let observed = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (pool, observed, barrier) = (pool.clone(), observed.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..1000 {
                        if let Some(lease) = pool.acquire(&[false]) {
                            assert_eq!(observed.fetch_add(1, Ordering::SeqCst), 0);
                            std::thread::yield_now();
                            assert_eq!(observed.fetch_sub(1, Ordering::SeqCst), 1);
                            drop(lease);
                        }
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert!(pool.acquire(&[false]).is_some());
    }

    #[test]
    fn plugin_cannot_select_ineligible_or_out_of_range_backend() {
        struct BadPlugin(usize);
        impl Scheduler for BadPlugin {
            fn select(&mut self, _: &[u32], _: &[bool]) -> Option<usize> {
                Some(self.0)
            }
        }
        for index in [0, 256] {
            let backends =
                serde_json::from_str::<Vec<Backend>>(r#"[{"address":"127.0.0.1:1"}]"#).unwrap();
            let pool = Pool::new(backends, Duration::from_secs(1), Box::new(BadPlugin(index)));
            assert!(pool.acquire(&[true]).is_none());
        }
    }

    #[test]
    fn routing_cannot_override_admin_health_or_capacity_and_reload_invalidates_it() {
        use crate::decision::{Operation, Preview};
        let config: crate::config::Config = serde_json::from_value(serde_json::json!({"backends":[
            {"address":"127.0.0.1:1","weight":0}, {"address":"127.0.0.1:2","max_connections":1}]}))
        .unwrap();
        let pool = Pool::from_config(&config);
        let update=serde_json::from_value(serde_json::json!({"expected_generation":0,"backend_generation":0,"ttl_ms":10000,
            "source_revision":"unit-1","on_expiry":"reject","profiles":{"default":{"weights":{"127.0.0.1:1":100,"127.0.0.1:2":1}}}})).unwrap();
        pool.routing(&Operation::Apply(update)).unwrap();
        let preview = Operation::Preview(Preview {
            client_ip: "127.0.0.1".parse().unwrap(),
            tls_version: None,
            sni: None,
            metadata: Default::default(),
        });
        let before = pool.routing(&preview).unwrap();
        assert_eq!(before.data["candidates"][0]["eligible"], false);
        assert_eq!(before.data["candidates"][1]["eligible"], true);
        let lease = pool.acquire(&[false; 2]).unwrap();
        assert_eq!(lease.index, 1);
        assert!(pool.acquire(&[false; 2]).is_none());
        pool.failed(1, lease.config_generation, lease.health_epoch);
        drop(lease);
        assert!(pool.acquire(&[false; 2]).is_none());
        pool.succeeded(1, 0);
        assert_eq!(pool.acquire(&[false; 2]).unwrap().index, 1);
        pool.reconfigure(&config);
        let after = pool.routing(&Operation::Show).unwrap();
        assert!(after.data["policy"].is_null());
        assert_eq!(after.data["generation"], 2);
        assert_eq!(after.data["backend_generation"], 1);
    }
}
