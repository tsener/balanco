//! Header hooks run synchronously: implementations must be bounded and must not perform I/O.
use crate::Error;
pub use hyper::http::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Request,
    Response,
}

/// Metadata comes from the accepted connection and parsed request, never forwarded headers.
pub struct Context<'a> {
    pub peer: SocketAddr,
    pub backend: SocketAddr,
    pub scheme: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub sni: Option<&'a str>,
    pub status: Option<u16>,
}

pub trait HttpPlugin: Send + Sync {
    fn transform(
        &self,
        phase: Phase,
        context: &Context<'_>,
        headers: &mut HeaderMap,
    ) -> Result<(), Error>;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpConfig {
    pub max_header_bytes: usize,
    pub header_timeout_ms: u64,
    pub response_timeout_ms: u64,
    pub rules: Vec<Rule>,
}
impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            max_header_bytes: 16_384,
            header_timeout_ms: 5000,
            response_timeout_ms: 60_000,
            rules: vec![],
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub phase: Phase,
    #[serde(default)]
    pub when: Match,
    pub action: Action,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Match {
    pub method: Option<String>,
    pub path_prefix: Option<String>,
    pub status: Option<u16>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Set {
        name: String,
        value: String,
    },
    Add {
        name: String,
        value: String,
    },
    Remove {
        name: String,
    },
    Rename {
        from: String,
        to: String,
    },
    Replace {
        name: String,
        from: String,
        to: String,
    },
}

/// HTTP framing, connection state and WebSocket negotiation belong to the host.
pub fn protected(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "content-length"
            | "transfer-encoding"
            | "connection"
            | "upgrade"
            | "keep-alive"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "expect"
            | "proxy-authenticate"
            | "proxy-authorization"
    ) || name.to_ascii_lowercase().starts_with("sec-websocket-")
}
pub fn validate_host(value: &str) -> Result<(), Error> {
    let authority: hyper::http::uri::Authority = value.parse()?;
    if authority.host().is_empty() || value.contains('@') {
        return Err("invalid Host authority".into());
    }
    Ok(())
}

impl HttpConfig {
    pub fn validate(&self) -> Result<(), Error> {
        if !(8192..=65_536).contains(&self.max_header_bytes)
            || !(100..=60_000).contains(&self.header_timeout_ms)
            || !(100..=3_600_000).contains(&self.response_timeout_ms)
            || self.rules.len() > 128
        {
            return Err("HTTP requires 8192..=65536 header bytes, 100..=60000 ms header timeout, and at most 128 rules".into());
        }
        if serde_json::to_vec(&self.rules)?.len() > 12_288 {
            return Err("HTTP rules exceed the 12288-byte policy budget".into());
        }
        let name = |s: &str| -> Result<(), Error> {
            HeaderName::from_bytes(s.as_bytes())?;
            if protected(s) {
                return Err(format!("header {s} is reserved for HTTP framing/negotiation").into());
            }
            Ok(())
        };
        let text = |s: &str| -> Result<(), Error> {
            if s.len() > 4096 || s.bytes().any(|b| b < 0x20 && b != b'\t' || b == 0x7f) {
                return Err(
                    "header rule text must be at most 4096 bytes without control characters".into(),
                );
            }
            Ok(())
        };
        for rule in &self.rules {
            match &rule.action {
                Action::Set { .. } => (),
                Action::Add { name, .. }
                | Action::Remove { name }
                | Action::Replace { name, .. }
                    if name.eq_ignore_ascii_case("host") =>
                {
                    return Err("Host supports set only".into());
                }
                Action::Rename { from, to }
                    if from.eq_ignore_ascii_case("host") || to.eq_ignore_ascii_case("host") =>
                {
                    return Err("Host supports set only".into());
                }
                _ => (),
            }
            if rule
                .when
                .method
                .as_ref()
                .is_some_and(|s| s.len() > 32 || hyper::Method::from_bytes(s.as_bytes()).is_err())
                || rule.when.path_prefix.as_ref().is_some_and(|s| {
                    s.len() > 4096
                        || !s.starts_with('/')
                        || s.bytes().any(|b| b <= 0x20 || b == 0x7f)
                })
                || rule
                    .when
                    .status
                    .is_some_and(|s| !(100..=599).contains(&s) || rule.phase == Phase::Request)
            {
                return Err("invalid HTTP rule match".into());
            }
            match &rule.action {
                Action::Set { name: n, value } | Action::Add { name: n, value } => {
                    name(n)?;
                    text(value)?;
                    validate_template(value)?;
                    if n.eq_ignore_ascii_case("host") && !value.contains("${") {
                        validate_host(value)?;
                    }
                }
                Action::Remove { name: n } => name(n)?,
                Action::Rename { from, to } => {
                    name(from)?;
                    name(to)?;
                }
                Action::Replace { name: n, from, to } => {
                    name(n)?;
                    text(from)?;
                    text(to)?;
                    if from.is_empty() {
                        return Err("replace requires a nonempty literal search value".into());
                    }
                }
            }
        }
        Ok(())
    }
}

fn validate_template(value: &str) -> Result<(), Error> {
    expand(
        value,
        &Context {
            peer: "127.0.0.1:1".parse()?,
            backend: "127.0.0.1:2".parse()?,
            scheme: "https",
            method: "GET",
            path: "/",
            sni: None,
            status: None,
        },
    )
    .map(|_| ())
}
fn expand(template: &str, context: &Context<'_>) -> Result<String, Error> {
    let mut result = String::new();
    let mut rest = template;
    while let Some(start) = rest.find("${") {
        result.push_str(&rest[..start]);
        let tail = &rest[start + 2..];
        let end = tail.find('}').ok_or("unterminated HTTP header template")?;
        let value = match &tail[..end] {
            "client_ip" => context.peer.ip().to_string(),
            "client_port" => context.peer.port().to_string(),
            "backend" => context.backend.to_string(),
            "scheme" => context.scheme.to_owned(),
            "method" => context.method.to_owned(),
            "path" => context.path.to_owned(),
            "sni" => context.sni.unwrap_or("").to_owned(),
            _ => return Err("unknown HTTP header template variable".into()),
        };
        result.push_str(&value);
        if result.len() > 4096 {
            return Err("expanded HTTP header exceeds 4096 bytes".into());
        }
        rest = &tail[end + 1..];
    }
    result.push_str(rest);
    if result.len() > 4096 {
        return Err("expanded HTTP header exceeds 4096 bytes".into());
    }
    Ok(result)
}

/// The bundled plugin. Custom plugins can implement HttpPlugin and be compiled into the host.
pub struct HeaderRules(pub Arc<HttpConfig>);
impl HttpPlugin for HeaderRules {
    fn transform(
        &self,
        phase: Phase,
        context: &Context<'_>,
        headers: &mut HeaderMap,
    ) -> Result<(), Error> {
        for rule in &self.0.rules {
            if rule.phase != phase
                || rule
                    .when
                    .method
                    .as_deref()
                    .is_some_and(|v| v != context.method)
                || rule
                    .when
                    .path_prefix
                    .as_deref()
                    .is_some_and(|v| !context.path.starts_with(v))
                || rule.when.status.is_some_and(|v| Some(v) != context.status)
            {
                continue;
            }
            match &rule.action {
                Action::Set { name, value } | Action::Add { name, value } => {
                    let name = HeaderName::from_bytes(name.as_bytes())?;
                    let value = HeaderValue::from_str(&expand(value, context)?)?;
                    if matches!(rule.action, Action::Set { .. }) {
                        headers.insert(name, value);
                    } else {
                        headers.append(name, value);
                    }
                }
                Action::Remove { name } => {
                    headers.remove(name);
                }
                Action::Rename { from, to } => {
                    let values: Vec<_> = headers.get_all(from).iter().cloned().collect();
                    headers.remove(from);
                    let to = HeaderName::from_bytes(to.as_bytes())?;
                    for value in values {
                        headers.append(to.clone(), value);
                    }
                }
                Action::Replace { name, from, to } => {
                    let mut values = Vec::new();
                    for value in headers.get_all(name) {
                        let value = value.to_str()?;
                        let count = value.matches(from).count();
                        let size = value
                            .len()
                            .saturating_sub(count.saturating_mul(from.len()))
                            .saturating_add(count.saturating_mul(to.len()));
                        if size > 4096 {
                            return Err("replaced HTTP header exceeds 4096 bytes".into());
                        }
                        values.push(HeaderValue::from_str(&value.replace(from, to))?);
                    }
                    headers.remove(name);
                    let name = HeaderName::from_bytes(name.as_bytes())?;
                    for value in values {
                        headers.append(name.clone(), value);
                    }
                }
            }
            check_size(headers, self.0.max_header_bytes)?;
        }
        Ok(())
    }
}

pub fn check_size(headers: &HeaderMap, limit: usize) -> Result<(), Error> {
    let size: usize = headers
        .iter()
        .map(|(n, v)| n.as_str().len() + v.as_bytes().len() + 4)
        .sum();
    if headers.len() > 64 || size > limit {
        return Err("transformed HTTP headers exceed configured limits".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> Context<'static> {
        Context {
            peer: "192.0.2.4:3210".parse().unwrap(),
            backend: "127.0.0.1:9000".parse().unwrap(),
            scheme: "https",
            method: "GET",
            path: "/devices/a",
            sni: Some("devices.test"),
            status: None,
        }
    }
    #[test]
    fn ordered_rules_keep_duplicate_values_and_match_metadata() {
        let config: HttpConfig = serde_json::from_value(serde_json::json!({"rules":[
            {"phase":"request","action":{"op":"set","name":"x-peer","value":"${client_ip}:${client_port}"}},
            {"phase":"request","when":{"path_prefix":"/devices/","method":"GET"},"action":{"op":"rename","from":"x-old","to":"x-new"}},
            {"phase":"request","action":{"op":"replace","name":"x-new","from":"old","to":"new"}},
            {"phase":"response","action":{"op":"remove","name":"x-peer"}}
        ]})).unwrap();
        config.validate().unwrap();
        let mut headers = HeaderMap::new();
        headers.append("x-old", HeaderValue::from_static("old-a"));
        headers.append("x-old", HeaderValue::from_static("old-b"));
        HeaderRules(Arc::new(config))
            .transform(Phase::Request, &context(), &mut headers)
            .unwrap();
        assert_eq!(headers["x-peer"], "192.0.2.4:3210");
        assert!(!headers.contains_key("x-old"));
        assert_eq!(
            headers
                .get_all("x-new")
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["new-a", "new-b"]
        );
    }
    #[test]
    fn configuration_rejects_injection_reserved_headers_and_bad_templates() {
        for (name, value) in [
            ("Content-Length", "0"),
            ("sec-websocket-key", "anything"),
            ("connection", "close"),
            ("Host", ""),
            ("Host", "user@host"),
            ("bad name", "x"),
            ("x-test", "hello\r\ninjected: value"),
            ("x-test", "${unknown}"),
            ("x-test", "${client_ip"),
        ] {
            let config = HttpConfig {
                rules: vec![Rule {
                    phase: Phase::Request,
                    when: Match::default(),
                    action: Action::Set {
                        name: name.into(),
                        value: value.into(),
                    },
                }],
                ..Default::default()
            };
            assert!(config.validate().is_err(), "{name}: {value:?}");
        }
    }
    #[test]
    fn expansion_and_replacement_cannot_exceed_value_budget() {
        let mut ctx = context();
        let path = "/".repeat(4097);
        ctx.path = &path;
        assert!(expand("${path}", &ctx).is_err());
        let config = HttpConfig {
            rules: vec![Rule {
                phase: Phase::Request,
                when: Match::default(),
                action: Action::Replace {
                    name: "x-test".into(),
                    from: "a".into(),
                    to: "b".repeat(4096),
                },
            }],
            ..Default::default()
        };
        let mut headers = HeaderMap::new();
        headers.insert("x-test", HeaderValue::from_static("aa"));
        assert!(
            HeaderRules(Arc::new(config))
                .transform(Phase::Request, &context(), &mut headers)
                .is_err()
        );
    }
}
