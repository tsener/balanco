//! Owner-only Unix control and certificate-authorized HTTPS share command handlers.
use crate::{
    Error,
    config::{Backend, Config, Role},
    scheduler::{Pool, Reply},
    tls::Tls,
};
use serde::Deserialize;
use std::{
    fs,
    io::{self, BufRead, IsTerminal, Read, Write},
    net::SocketAddr,
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixStream as BlockingUnixStream,
    },
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, UnixListener},
    sync::{Notify, Semaphore, watch},
    task::JoinSet,
    time::timeout,
};

const REQUEST_LIMIT: usize = 16_384;
const RESPONSE_LIMIT: u64 = 262_144;
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    #[serde(default)]
    pub group: u16,
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_rules: Option<crate::http1::RuleUpdate>,
}

fn uid() -> u32 {
    // SAFETY: geteuid has no arguments or memory preconditions.
    unsafe { libc::geteuid() }
}
pub fn default_path(address: SocketAddr) -> PathBuf {
    PathBuf::from(format!(
        "/tmp/balanco-{}/{}-{}.sock",
        uid(),
        address.ip().to_string().replace(':', "_"),
        address.port()
    ))
}
pub fn default_config_path(config_file: &Path) -> PathBuf {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    config_file.hash(&mut hasher);
    PathBuf::from(format!(
        "/tmp/balanco-{}/config-{:016x}.sock",
        uid(),
        hasher.finish()
    ))
}
fn directory(path: &Path, create: bool) -> Result<(), Error> {
    let parent = path
        .parent()
        .ok_or("control socket needs a parent directory")?;
    if create {
        match fs::DirBuilder::new().mode(0o700).create(parent) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e.into()),
        }
    }
    let meta = fs::symlink_metadata(parent)?;
    if !meta.is_dir() || meta.uid() != uid() || meta.mode() & 0o077 != 0 {
        return Err("control socket parent must be an owner-only directory (0700), owned by the process user, not a symlink".into());
    }
    Ok(())
}
struct SocketGuard {
    path: PathBuf,
    inode: u64,
}
impl Drop for SocketGuard {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.ino() == self.inode && m.file_type().is_socket())
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}
pub struct Controls {
    pub tasks: JoinSet<()>,
    _socket: SocketGuard,
}
impl Drop for Controls {
    fn drop(&mut self) {
        self.tasks.abort_all();
    }
}

// Called by main::run; bind control listeners separately from workload traffic.
pub async fn start(
    config: &Config,
    address: SocketAddr,
    pool: Arc<Pool>,
    tls: watch::Receiver<Arc<Tls>>,
    shutdown: Arc<Notify>,
    http: Arc<crate::http1::State>,
) -> Result<Controls, Error> {
    let path = config.control_socket.clone().unwrap_or_else(|| {
        config
            .config_file
            .as_deref()
            .map(default_config_path)
            .unwrap_or_else(|| default_path(address))
    });
    directory(&path, true)?;
    // Never unlink an existing socket: it may belong to a live instance.
    let local = UnixListener::bind(&path)?;
    let guard = SocketGuard {
        inode: fs::symlink_metadata(&path)?.ino(),
        path: path.clone(),
    };
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let remote = match &config.management {
        Some(m) => Some((TcpListener::bind(m.listen).await?, m.clone())),
        None => None,
    };
    let mut tasks = JoinSet::new();
    eprintln!("control_socket={}", path.display());
    let local_pool = pool.clone();
    let local_shutdown = shutdown.clone();
    let local_http = http.clone();
    tasks.spawn(async move {
        let capacity = Arc::new(Semaphore::new(16));
        let mut requests = JoinSet::new();
        loop {
            while requests.try_join_next().is_some() {}
            tokio::select! {
                Some(_) = requests.join_next(), if !requests.is_empty() => (),
                accepted = local.accept() => {
                    let Ok((mut stream,_)) = accepted else { tokio::time::sleep(Duration::from_millis(100)).await; continue; };
                    if !stream.peer_cred().is_ok_and(|c| c.uid() == uid()) { continue; }
                    let Ok(permit) = capacity.clone().try_acquire_owned() else { continue; };
                    let pool = local_pool.clone(); let shutdown = local_shutdown.clone();
                    let http = local_http.clone();
                    requests.spawn(async move {
                        let _permit = permit;
                        let _ = timeout(Duration::from_secs(5), async {
                            let input = line(&mut stream, REQUEST_LIMIT).await?;
                            let request: Request = serde_json::from_slice(&input)?;
                            let (reply, _) = dispatch(&pool, &http, &request, Role::Admin).await;
                            audit("unix", "owner", &request, &reply);
                            let mut bytes = serde_json::to_vec(&reply)?; bytes.push(b'\n');
                            stream.write_all(&bytes).await?;
                            if reply.shutdown { shutdown.notify_one(); }
                            Ok::<_, Error>(())
                        }).await;
                    });
                }
            }
        }
    });
    if let Some((listener, management)) = remote {
        eprintln!("management_listening={}", listener.local_addr()?);
        tasks.spawn(async move {
            let capacity = Arc::new(Semaphore::new(management.max_connections));
            let mut requests = JoinSet::new();
            loop {
                while requests.try_join_next().is_some() {}
                tokio::select! {
                    Some(_) = requests.join_next(), if !requests.is_empty() => (),
                    accepted = listener.accept() => {
                        let Ok((stream,_)) = accepted else { tokio::time::sleep(Duration::from_millis(100)).await; continue; };
                        let Ok(permit) = capacity.clone().try_acquire_owned() else { continue; };
                        let snapshot = tls.borrow().clone(); let pool = pool.clone(); let shutdown = shutdown.clone();
                        let http = http.clone();
                        requests.spawn(async move {
                            let _permit = permit;
                            let _ = timeout(Duration::from_millis(management.request_timeout_ms), async {
                                let management = snapshot.management.as_ref().ok_or("management TLS unavailable")?;
                                let mut stream = management.acceptor.accept(stream).await?;
                                let certificate = stream.get_ref().1.peer_certificates().and_then(|c| c.first());
                                let identity = management.clients.iter().find(|(c,_,_)| Some(c) == certificate);
                                let Some((_,name,role)) = identity else {
                                    return respond(&mut stream,403,&Reply::error(0,"client certificate is not authorized")).await;
                                };
                                let request = match http_request(&mut stream).await {
                                    Ok(request) => request,
                                    Err(error) => return respond(&mut stream,400,&Reply::error(0,error)).await,
                                };
                                let (reply, status) = dispatch(&pool,&http,&request,*role).await;
                                audit("mtls",name,&request,&reply);
                                respond(&mut stream,status,&reply).await?;
                                if reply.shutdown { shutdown.notify_one(); }
                                Ok::<_, Error>(())
                            }).await;
                        });
                    }
                }
            }
        });
    }
    Ok(Controls {
        tasks,
        _socket: guard,
    })
}

async fn line<S: AsyncRead + Unpin>(stream: &mut S, limit: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    loop {
        let byte = stream.read_u8().await?;
        if byte == b'\n' {
            return Ok(out);
        }
        if out.len() == limit {
            return Err("request too large".into());
        }
        out.push(byte);
    }
}
async fn http_request<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Request, Error> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() == 8192 {
            return Err("headers exceed 8192 bytes".into());
        }
        bytes.push(stream.read_u8().await?);
    }
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    if !request.parse(&bytes)?.is_complete() || request.version != Some(1) {
        return Err("HTTP/1.1 required".into());
    }
    let mut length = None;
    let mut hosts = 0;
    let mut json = false;
    for h in request.headers.iter() {
        if h.name.eq_ignore_ascii_case("transfer-encoding") || h.name.eq_ignore_ascii_case("expect")
        {
            return Err("Transfer-Encoding and Expect are not supported".into());
        }
        if h.name.eq_ignore_ascii_case("content-length") {
            if length.is_some() || h.value.is_empty() || !h.value.iter().all(u8::is_ascii_digit) {
                return Err("invalid or duplicate Content-Length".into());
            }
            length = Some(std::str::from_utf8(h.value)?.parse::<usize>()?);
        }
        if h.name.eq_ignore_ascii_case("host") {
            hosts += 1;
            if h.value.is_empty() {
                return Err("empty Host".into());
            }
        }
        if h.name.eq_ignore_ascii_case("content-type") {
            json = std::str::from_utf8(h.value)?
                .split(';')
                .next()
                .is_some_and(|s| s.trim().eq_ignore_ascii_case("application/json"));
        }
    }
    if hosts != 1 {
        return Err("exactly one Host header is required".into());
    }
    match (request.method, request.path) {
        (Some("GET"), Some("/v1/status")) if length.unwrap_or(0) == 0 => Ok(Request {
            group: 0,
            command: "show".into(),
            http_rules: None,
        }),
        (Some("GET"), Some("/v1/http")) if length.unwrap_or(0) == 0 => Ok(Request {
            group: 0, command: "http-show".into(), http_rules: None,
        }),
        (Some("POST"), Some("/v1/command")) | (Some("PUT"), Some("/v1/http/rules")) if json => {
            let length = length.ok_or("Content-Length required")?;
            if length > REQUEST_LIMIT {
                return Err("body exceeds 16384 bytes".into());
            }
            let mut body = vec![0; length];
            stream.read_exact(&mut body).await?;
            if request.method == Some("PUT") {
                Ok(Request {group:0,command:"http-rules".into(),http_rules:Some(serde_json::from_slice(&body)?)})
            } else { Ok(serde_json::from_slice(&body)?) }
        }
        _ => Err("use GET /v1/status, GET /v1/http, POST /v1/command or PUT /v1/http/rules with application/json".into()),
    }
}
async fn respond<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    reply: &Reply,
) -> Result<(), Error> {
    let body = serde_json::to_vec(reply)?;
    let reason = match status {
        200 => "OK",
        403 => "Forbidden",
        409 => "Conflict",
        _ => "Bad Request",
    };
    let headers = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;
    stream.shutdown().await?;
    Ok(())
}
fn audit(transport: &str, identity: &str, request: &Request, reply: &Reply) {
    eprintln!(
        "audit transport={transport} identity={identity} group={} command={:?} ok={} generation={}",
        request.group,
        request.command.split_whitespace().next().unwrap_or(""),
        reply.ok,
        reply.generation
    );
}
// Shared by Unix and HTTPS handlers; check roles before changing policy or backends.
async fn dispatch(
    pool: &Pool,
    http: &crate::http1::State,
    request: &Request,
    role: Role,
) -> (Reply, u16) {
    if !matches!(request.command.as_str(), "http-show" | "http-rules") {
        if request.http_rules.is_some() {
            return (
                Reply::error(request.group, "http_rules requires the http-rules command"),
                400,
            );
        }
        return execute(pool, request, role).await;
    }
    let result = match request.command.as_str() {
        "http-show" if request.http_rules.is_none() => Ok(()),
        "http-rules" if role != Role::Admin => Err("permission denied: admin role required".into()),
        "http-rules" => match request.http_rules.clone() {
            Some(update) => http.update(update),
            None => Err("http-rules requires a structured http_rules update".into()),
        },
        _ => Err("http-show does not accept a rule update".into()),
    };
    let (reply, status) = match result {
        Ok(()) => {
            let (generation, data) = http.status();
            (
                Reply {
                    ok: true,
                    group: request.group,
                    generation,
                    output: serde_json::to_string_pretty(&data).unwrap_or_default(),
                    data,
                    quit: false,
                    shutdown: false,
                },
                200,
            )
        }
        Err(error) => {
            let message = error.to_string();
            let status = if message.starts_with("permission denied") {
                403
            } else if message.starts_with("HTTP policy generation conflict") {
                409
            } else {
                400
            };
            (Reply::error(request.group, error), status)
        }
    };
    (reply, status)
}
// Called by dispatch; resolve new backend addresses outside the scheduler mutex.
pub async fn execute(pool: &Pool, request: &Request, role: Role) -> (Reply, u16) {
    let result = async {
        if request.command.len() > 4096 || request.command.contains(['\n', '\r', ';']) {
            return Err("one command of at most 4096 bytes is required".into());
        }
        let args: Vec<_> = request.command.split_whitespace().collect();
        if role == Role::ReadOnly
            && !matches!(
                args.first(),
                Some(
                    &("show"
                        | "help"
                        | "?"
                        | "version"
                        | "quit"
                        | "group"
                        | "mrtg-bytes"
                        | "mrtg-conns")
                )
            )
        {
            return Err("permission denied: admin role required".into());
        }
        let created = if args.first() == Some(&"create") {
            if !(3..=4).contains(&args.len()) {
                return Err("create HOST PORT [TLS_NAME]".into());
            }
            let port = crate::cli::service_port(args[2])?;
            let host = args[1].trim_start_matches('[').trim_end_matches(']');
            let addresses: Vec<_> = tokio::net::lookup_host((host, port)).await?.collect();
            let address = *addresses
                .iter()
                .find(|a| a.is_ipv4())
                .or(addresses.first())
                .ok_or("host has no addresses")?;
            let server_name = if pool.uses_tls() {
                Some(args.get(3).copied().unwrap_or(host).to_owned())
            } else {
                if args.len() == 4 {
                    return Err("TLS_NAME requires upstream TLS".into());
                }
                None
            };
            Some(Backend {
                address,
                weight: 1,
                priority: request.group,
                max_connections: 0,
                server_name,
            })
        } else {
            None
        };
        pool.command(request.group, &args, created)
    }
    .await;
    match result {
        Ok(reply) => (reply, 200),
        Err(error) => {
            let status = if error.to_string().starts_with("permission denied") {
                403
            } else {
                400
            };
            (Reply::error(request.group, error), status)
        }
    }
}

fn call(path: &Path, group: u16, command: &str) -> Result<Reply, Error> {
    directory(path, false)?;
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_socket() || meta.uid() != uid() || meta.mode() & 0o077 != 0 {
        return Err("control socket must be owner-only and owned by this user".into());
    }
    let mut stream = BlockingUnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut request = Request {
        group,
        command: command.to_owned(),
        http_rules: None,
    };
    if let Some(path) = command.strip_prefix("http-rules ") {
        let mut input = Vec::new();
        fs::File::open(path.trim())?
            .take(REQUEST_LIMIT as u64 + 1)
            .read_to_end(&mut input)?;
        if input.len() > REQUEST_LIMIT {
            return Err("HTTP rule update exceeds 16384 bytes".into());
        }
        request.command = "http-rules".into();
        request.http_rules = Some(serde_json::from_slice(&input)?);
    }
    let mut bytes = serde_json::to_vec(&request)?;
    if bytes.len() > REQUEST_LIMIT {
        return Err("control request exceeds 16384 bytes".into());
    }
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    let mut response = String::new();
    io::BufReader::new(stream)
        .take(RESPONSE_LIMIT + 1)
        .read_line(&mut response)?;
    if response.len() as u64 > RESPONSE_LIMIT {
        return Err("control response too large".into());
    }
    Ok(serde_json::from_str(&response)?)
}
// Called by CLI control actions; interactive and one-shot modes share the Unix protocol.
pub fn client(path: PathBuf, command: Option<String>) -> Result<(), Error> {
    let mut group = 0;
    let mut run = |line: &str| -> Result<bool, Error> {
        if line.len() > 4096 {
            return Err("command exceeds 4096 bytes".into());
        }
        for command in line.split(';').map(str::trim).filter(|s| !s.is_empty()) {
            let reply = call(&path, group, command)?;
            if !reply.ok {
                return Err(reply.output.into());
            }
            group = reply.group;
            println!("{}", reply.output.trim_end());
            if reply.quit || command == "kill" {
                return Ok(true);
            }
        }
        Ok(false)
    };
    if let Some(command) = command {
        run(&command)?;
        return Ok(());
    }
    let stdin = io::stdin();
    let terminal = stdin.is_terminal();
    let mut input = stdin.lock();
    loop {
        if terminal {
            print!("balanco> ");
            io::stdout().flush()?;
        }
        let mut line = String::new();
        if input.by_ref().take(4097).read_line(&mut line)? == 0 {
            break;
        }
        match run(line.trim_end()) {
            Ok(true) => break,
            Ok(false) => (),
            Err(e) => eprintln!("balanco: {e}"),
        }
        if line.len() > 4096 {
            return Err("input line too long".into());
        }
    }
    Ok(())
}
