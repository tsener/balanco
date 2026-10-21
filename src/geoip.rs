//! Immutable owned MMDB snapshots, prepared with TLS/config reload off the accept path.
use crate::Error;
use serde::Deserialize;
use std::{
    io::Read,
    net::IpAddr,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub database: String,
    pub max_age_days: u32,
}
#[derive(Default)]
pub struct GeoIp {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
    max_age_seconds: u64,
    lookups: AtomicU64,
    unknown: AtomicU64,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// Private, documentation, multicast and translation ranges must not acquire invented locations.
fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, c, _] = v.octets();
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_documentation()
                || a == 0
                || a >= 224
                || a == 100 && (64..=127).contains(&b)
                || a == 198 && (b == 18 || b == 19)
                || a == 192 && b == 0 && c == 0
                || a == 192 && b == 88 && c == 99)
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && (s[1] <= 0x1ff || s[1] == 0xdb8))
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && s[1] <= 0x0fff)
        }
    }
}
impl GeoIp {
    pub fn load(config: Option<&Config>) -> Result<Self, Error> {
        let Some(config) = config else {
            return Ok(Self::default());
        };
        if !(1..=3650).contains(&config.max_age_days) {
            return Err("GeoIP max_age_days must be 1..=3650".into());
        }
        let mut bytes = Vec::new();
        std::fs::File::open(&config.database)?
            .take(134_217_729)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 134_217_728 {
            return Err("GeoIP database exceeds 128 MiB".into());
        }
        let reader = maxminddb::Reader::from_source(bytes)?;
        reader.verify()?;
        if !reader.metadata().database_type.contains("Country")
            && !reader.metadata().database_type.contains("City")
        {
            return Err("GeoIP requires a Country or City database".into());
        }
        if reader.metadata().build_epoch > now() + 86400 {
            return Err("GeoIP database has a future revision".into());
        }
        Ok(Self {
            reader: Some(reader),
            max_age_seconds: u64::from(config.max_age_days) * 86400,
            ..Self::default()
        })
    }
    fn stale(&self) -> bool {
        self.reader
            .as_ref()
            .is_some_and(|r| now().saturating_sub(r.metadata().build_epoch) > self.max_age_seconds)
    }
    pub fn country(&self, ip: IpAddr) -> Option<String> {
        self.lookups.fetch_add(1, Ordering::Relaxed);
        let country = (|| {
            if !public(ip) || self.stale() {
                return None;
            }
            let result = self.reader.as_ref()?.lookup(ip).ok()?;
            let code: Option<String> = result
                .decode_path(&maxminddb::path!["country", "iso_code"])
                .ok()?;
            code.filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()))
        })();
        if country.is_none() {
            self.unknown.fetch_add(1, Ordering::Relaxed);
        }
        country
    }
    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({"enabled":self.reader.is_some(),"build_epoch":self.reader.as_ref().map(|r|r.metadata().build_epoch),
            "stale":self.stale(),"lookups":self.lookups.load(Ordering::Relaxed),"unknown":self.unknown.load(Ordering::Relaxed)})
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    // A one-node MMDB covers both address families; no downloaded data or license is needed.
    fn database(country: &str, epoch: u64, kind: &str) -> Vec<u8> {
        fn string(out: &mut Vec<u8>, s: &str) {
            assert!(s.len() < 29);
            out.push(0x40 + s.len() as u8);
            out.extend_from_slice(s.as_bytes());
        }
        let mut bytes = vec![0, 0, 17, 0, 0, 17];
        bytes.extend_from_slice(&[0; 16]);
        bytes.push(0xe1);
        string(&mut bytes, "country");
        bytes.push(0xe1);
        string(&mut bytes, "iso_code");
        string(&mut bytes, country);
        bytes.extend_from_slice(b"\xab\xcd\xefMaxMind.com");
        bytes.push(0xe9);
        string(&mut bytes, "description");
        bytes.push(0xe1);
        string(&mut bytes, "en");
        string(&mut bytes, "Synthetic country fixture");
        string(&mut bytes, "languages");
        bytes.extend_from_slice(&[1, 4]);
        string(&mut bytes, "en");
        string(&mut bytes, "node_count");
        bytes.extend_from_slice(&[0xc1, 1]);
        for (k, v) in [
            ("record_size", 24),
            ("ip_version", 6),
            ("binary_format_major_version", 2),
            ("binary_format_minor_version", 0),
        ] {
            string(&mut bytes, k);
            bytes.extend_from_slice(&[0xa1, v]);
        }
        string(&mut bytes, "database_type");
        string(&mut bytes, kind);
        string(&mut bytes, "build_epoch");
        bytes.extend_from_slice(&[8, 2]);
        bytes.extend_from_slice(&epoch.to_be_bytes());
        bytes
    }
    #[test]
    fn owned_database_reload_staleness_and_corruption_are_explicit() {
        let dir =
            std::env::temp_dir().join(format!("balanco-geoip-{}-{}", std::process::id(), now()));
        std::fs::create_dir(&dir).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        let path = dir.join("country.mmdb");
        let config = Config {
            database: path.to_string_lossy().into_owned(),
            max_age_days: 1,
        };
        std::fs::write(&path, database("BG", now(), "Balanco-Country")).unwrap();
        let old = GeoIp::load(Some(&config)).unwrap();
        assert_eq!(
            old.country("8.8.8.8".parse().unwrap()).as_deref(),
            Some("BG")
        );
        assert_eq!(
            old.country("2606:4700::1111".parse().unwrap()).as_deref(),
            Some("BG")
        );
        assert_eq!(old.country("127.0.0.1".parse().unwrap()), None);
        std::fs::write(&path, database("US", now(), "Balanco-Country")).unwrap();
        let new = GeoIp::load(Some(&config)).unwrap();
        assert_eq!(
            new.country("8.8.8.8".parse().unwrap()).as_deref(),
            Some("US")
        );
        assert_eq!(
            old.country("8.8.8.8".parse().unwrap()).as_deref(),
            Some("BG")
        );
        std::fs::write(&path, database("US", now() - 172800, "Balanco-Country")).unwrap();
        let stale = GeoIp::load(Some(&config)).unwrap();
        assert_eq!(stale.status()["stale"], true);
        assert!(stale.country("8.8.8.8".parse().unwrap()).is_none());
        for bytes in [
            database("BG", now() + 172800, "Balanco-Country"),
            database("BG", now(), "ASN"),
            vec![1, 2, 3],
        ] {
            std::fs::write(&path, bytes).unwrap();
            assert!(GeoIp::load(Some(&config)).is_err());
        }
        assert_eq!(
            old.country("8.8.8.8".parse().unwrap()).as_deref(),
            Some("BG")
        );
    }
    #[test]
    fn reserved_and_unknown_addresses_are_never_geolocated() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "100.64.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "224.0.0.1",
            "::1",
            "::ffff:8.8.8.8",
            "2001:db8::1",
            "fc00::1",
        ] {
            assert!(!public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "2606:4700::1111"] {
            assert!(public(ip.parse().unwrap()));
        }
        let geo = GeoIp::load(None).unwrap();
        assert_eq!(geo.country("8.8.8.8".parse().unwrap()), None);
        assert_eq!(geo.status()["unknown"], 1);
        assert!(
            GeoIp::load(Some(&Config {
                database: "missing".into(),
                max_age_days: 0
            }))
            .is_err()
        );
    }
}
