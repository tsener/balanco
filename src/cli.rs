//! Balance-style launch and local-control argument parsing.
use crate::{
    Error,
    config::{Backend, Config},
};
use std::{
    collections::HashSet,
    fs,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::Path,
};

pub const HELP: &str = "balanco [options] port host[:port[:maxc]] [!|%] ...\n\
balanco --config FILE [--check]\n\n\
balanco [-b addr] [-i | -c 'command'] port\n\
  -i            Interactive live administration over the local Unix socket\n\
  -c command    Run live commands; semicolons sequence commands in one session\n\
  --control-socket PATH  Explicit owner-only local control socket\n\
  -b addr       Listen address (positional mode defaults to 0.0.0.0)\n\
  -B addr       Source address for backend connections\n\
  -t seconds    Backend connect/TLS timeout (positional default: 5)\n\
  -T seconds    Application I/O idle timeout (default: disabled)\n\
  -a            Disable a backend after establishment failure until enabled\n\
  -H            Try other channels within a hash group on failure\n\
  -f, -F        Foreground (always the default)\n\
  -d            Log every connection outcome\n\
  -p            Dump plaintext application data to stdout (debugging only)\n\
  --workers N   Runtime worker threads (default: 2)\n\
  --check       Validate startup configuration and TLS files, then exit\n\
  --help        Show help (-h); --version shows version (-V)\n\n\
! ends a round-robin group; % ends a client-IP hash group. Quote these in shells.\n\
Use [IPv6]:port:maxc for IPv6 backends. Omitted backend ports inherit port.\n\
Hostnames and /etc/services names resolve at startup. SIGHUP reloads --config files and TLS material.\n\
SIGINT/SIGTERM drain connections. No background fork or shared-memory IPC.\n";

pub enum Action {
    Run(Box<Config>, bool),
    Help,
    Version,
    Control(std::path::PathBuf, Option<String>),
}

// Called by main::start; resolve and validate arguments before opening listeners.
pub fn parse(args: Vec<String>) -> Result<Action, Error> {
    let mut config = Config {
        listen: "0.0.0.0:0".parse()?,
        connect_timeout_ms: 5000,
        failure_cooldown_ms: 0,
        ..Config::default()
    };
    let mut file = None;
    let mut admin = None;
    let mut control_socket = None;
    let mut check = false;
    let mut routing_flags = false;
    let mut workers = None;
    let mut debug = false;
    let mut packet_dump = false;
    let mut seen = HashSet::new();
    let mut positionals = Vec::new();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--" {
            positionals.extend(args);
            break;
        }
        if !arg.starts_with('-') {
            positionals.push(arg);
            positionals.extend(args);
            break;
        }
        if arg.starts_with("--") || arg == "-h" || arg == "-V" {
            if !seen.insert(arg.clone()) {
                return Err(format!("repeated option {arg}").into());
            }
            match arg.as_str() {
                "--help" | "-h" => return Ok(Action::Help),
                "--version" | "-V" => return Ok(Action::Version),
                "--config" => file = Some(args.next().ok_or("--config requires a file")?),
                "--control-socket" => {
                    control_socket = Some(std::path::PathBuf::from(
                        args.next().ok_or("--control-socket requires a path")?,
                    ))
                }
                "--check" => check = true,
                "--workers" => {
                    workers = Some(args.next().ok_or("--workers requires a count")?.parse()?)
                }
                _ => return Err(format!("unknown option {arg}").into()),
            }
            continue;
        }
        for (offset, flag) in arg[1..].char_indices() {
            if !seen.insert(format!("-{flag}")) {
                return Err(format!("repeated option -{flag}").into());
            }
            match flag {
                'f' | 'F' => (),
                'd' => debug = true,
                'p' => packet_dump = true,
                'a' => { config.autodisable = true; routing_flags = true; }
                'H' => { config.hash_failover = true; routing_flags = true; }
                'b' | 'B' | 't' | 'T' => {
                    let rest = &arg[1 + offset + flag.len_utf8()..];
                    let value = if rest.is_empty() { args.next().ok_or_else(|| format!("-{flag} requires a value"))? } else { rest.to_owned() };
                    match flag {
                        'b' => config.listen.set_ip(resolve_ip(&value)?),
                        'B' => config.outbound_bind = Some(resolve_ip(&value)?),
                        't' => config.connect_timeout_ms = seconds(&value)?,
                        'T' => config.idle_timeout_ms = Some(seconds(&value)?),
                        _ => unreachable!(),
                    }
                    routing_flags = true;
                    break;
                }
                'i' => {
                    if admin.is_some() { return Err("choose -i or -c, not both".into()); }
                    admin = Some(None);
                }
                'c' => {
                    if admin.is_some() { return Err("choose -i or -c, not both".into()); }
                    let rest = &arg[1 + offset + flag.len_utf8()..];
                    admin = Some(Some(if rest.is_empty() { args.next().ok_or("-c requires a command")? } else { rest.to_owned() }));
                    break;
                }
                'M' => return Err("-M selects Balance's memory-mapped IPC; Balanco has no shared-memory control interface".into()),
                _ => return Err(format!("unknown option -{flag}").into()),
            }
        }
    }
    if let Some(command) = admin {
        if check
            || workers.is_some()
            || packet_dump
            || ["-B", "-t", "-T", "-a", "-H"]
                .iter()
                .any(|f| seen.contains(*f))
        {
            return Err("startup routing options cannot accompany -i/-c".into());
        }
        if let Some(file) = file {
            if !positionals.is_empty() || routing_flags {
                return Err("use either --config or -b/port to identify the instance".into());
            }
            config = Config::load(Path::new(&file))?;
        } else if positionals.len() == 1 {
            config.listen.set_port(service_port(&positionals[0])?);
        } else if !positionals.is_empty() || control_socket.is_none() {
            return Err("-i/-c needs a port, --config, or --control-socket".into());
        }
        let path = control_socket.or(config.control_socket).unwrap_or_else(|| {
            config
                .config_file
                .as_deref()
                .map(crate::control::default_config_path)
                .unwrap_or_else(|| crate::control::default_path(config.listen))
        });
        return Ok(Action::Control(path, command));
    }
    if let Some(file) = file {
        if !positionals.is_empty() || routing_flags {
            return Err(
                "--config cannot be combined with positional backends or routing flags".into(),
            );
        }
        config = Config::load(Path::new(&file))?;
    } else {
        if positionals.len() < 2 {
            return Err(HELP.into());
        }
        let port = service_port(&positionals[0])?;
        config.listen.set_port(port);
        let mut group = 0;
        let mut members = 0;
        for token in &positionals[1..] {
            if token == "!" || token == "%" {
                if members == 0 {
                    return Err("empty channel group".into());
                }
                if token == "%" {
                    config.hash_groups.push(group);
                }
                group += 1;
                members = 0;
            } else {
                config.backends.push(channel(token, port, group)?);
                members += 1;
                if config.backends.len() > 256 {
                    return Err("at most 256 backends are supported".into());
                }
            }
        }
        // A trailing % is how Balance marks the final group as hash-based.
        config.establishment_timeout_ms =
            (config.connect_timeout_ms * config.backends.len() as u64).min(3_600_000);
    }
    if let Some(workers) = workers {
        config.workers = workers;
    }
    config.debug |= debug;
    config.packet_dump |= packet_dump;
    if control_socket.is_some() {
        config.control_socket = control_socket;
    }
    config.validate()?;
    Ok(Action::Run(Box::new(config), check))
}

fn seconds(value: &str) -> Result<u64, Error> {
    let seconds: u64 = value.parse()?;
    if !(1..=3600).contains(&seconds) {
        return Err("timeout must be 1..=3600 seconds".into());
    }
    Ok(seconds * 1000)
}

pub fn service_port(value: &str) -> Result<u16, Error> {
    if let Ok(port) = value.parse::<u16>() {
        if port > 0 {
            return Ok(port);
        }
        return Err("port must be nonzero".into());
    }
    let services = fs::read_to_string("/etc/services")?;
    for line in services.lines() {
        let words: Vec<_> = line
            .split('#')
            .next()
            .unwrap_or("")
            .split_whitespace()
            .collect();
        if words.len() >= 2
            && (words[0] == value || words[2..].contains(&value))
            && let Some(port) = words[1].strip_suffix("/tcp")
        {
            return Ok(port.parse()?);
        }
    }
    Err(format!("unknown TCP service or invalid port: {value}").into())
}

fn resolve_ip(host: &str) -> Result<IpAddr, Error> {
    if let Ok(ip) = host.parse() {
        return Ok(ip);
    }
    let addresses: Vec<_> = (host, 0).to_socket_addrs()?.collect();
    addresses
        .iter()
        .find(|a| a.is_ipv4())
        .or(addresses.first())
        .map(SocketAddr::ip)
        .ok_or_else(|| format!("no address for {host}").into())
}

fn channel(token: &str, default_port: u16, priority: u16) -> Result<Backend, Error> {
    let (host, tail) = if let Some(bracketed) = token.strip_prefix('[') {
        let (host, tail) = bracketed
            .split_once(']')
            .ok_or("missing closing IPv6 bracket")?;
        if !tail.is_empty() && !tail.starts_with(':') {
            return Err("invalid bracketed backend".into());
        }
        (host, tail.strip_prefix(':'))
    } else {
        let (host, tail) = token
            .split_once(':')
            .map_or((token, None), |(h, t)| (h, Some(t)));
        (host, tail)
    };
    if host.is_empty() {
        return Err("backend host must not be empty".into());
    }
    let fields: Vec<_> = tail.map(|s| s.split(':').collect()).unwrap_or_default();
    if fields.len() > 2 {
        return Err("use [IPv6]:port:maxc for IPv6 backends".into());
    }
    let port = match fields.first() {
        Some(p) if !p.is_empty() => service_port(p)?,
        _ => default_port,
    };
    let max_connections = match fields.get(1) {
        Some(n) if !n.is_empty() => n.parse()?,
        Some(_) => return Err("empty maxc".into()),
        None => 0,
    };
    Ok(Backend {
        address: SocketAddr::new(resolve_ip(host)?, port),
        weight: 1,
        priority,
        max_connections,
        server_name: None,
        region: None,
        capabilities: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(args: &[&str]) -> Config {
        match parse(args.iter().map(|s| s.to_string()).collect()).unwrap() {
            Action::Run(c, _) => *c,
            _ => panic!("expected startup"),
        }
    }
    #[test]
    fn balance_channels_groups_and_flags() {
        let c = config(&[
            "-fdH",
            "-b127.0.0.1",
            "-B",
            "127.0.0.2",
            "-t",
            "3",
            "-T4",
            "8080",
            "127.0.0.1::16",
            "%",
            "127.0.0.2:9000",
            "!",
        ]);
        assert_eq!(c.listen, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(c.backends[0].max_connections, 16);
        assert_eq!(c.backends[0].address.port(), 8080);
        assert_eq!(c.backends[1].priority, 1);
        assert_eq!(c.hash_groups, [0]);
        assert!(c.hash_failover && c.debug);
        assert_eq!(c.connect_timeout_ms, 3000);
        assert_eq!(c.idle_timeout_ms, Some(4000));
    }
    #[test]
    fn services_ipv6_and_validation() {
        let c = config(&["--check", "http", "[::1]::2"]);
        assert_eq!(c.listen.port(), 80);
        assert_eq!(c.backends[0].address, "[::1]:80".parse().unwrap());
        for args in [
            vec!["80", "!", "localhost"],
            vec!["-t", "0", "80", "localhost"],
            vec!["--config", "x", "80", "localhost"],
            vec!["80", "::1"],
            vec!["-z", "80", "localhost"],
        ] {
            assert!(parse(args.into_iter().map(String::from).collect()).is_err());
        }
    }
}
