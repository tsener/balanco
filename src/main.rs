//! Entrypoint: parse commands, then supervise listeners and connection tasks.
mod cli;
mod config;
mod control;
mod decision;
mod geoip;
mod http1;
mod scheduler;
mod tls;
mod transport;

use config::Config;
use scheduler::Pool;
use std::{
    env,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
    sync::{Notify, OwnedSemaphorePermit, Semaphore, watch},
    task::JoinSet,
    time::{Instant, timeout, timeout_at},
};
type Error = Box<dyn std::error::Error + Send + Sync>;

fn main() {
    if let Err(error) = start() {
        eprintln!("balanco: {error}");
        std::process::exit(1);
    }
}
// Called by main; control and validation commands exit before starting the runtime.
fn start() -> Result<(), Error> {
    let args = env::args_os()
        .skip(1)
        .map(|s| s.into_string().map_err(|_| "arguments must be valid UTF-8"))
        .collect::<Result<Vec<_>, _>>()?;
    let (config, check) = match cli::parse(args)? {
        cli::Action::Help => {
            print!("{}", cli::HELP);
            return Ok(());
        }
        cli::Action::Version => {
            println!("balanco {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        cli::Action::Run(config, check) => (*config, check),
        cli::Action::Control(path, command) => return control::client(path, command),
    };
    let tls = tls::Tls::load(&config)?;
    if check {
        println!("configuration valid");
        return Ok(());
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.workers)
        .enable_all()
        .build()?
        .block_on(run(config, tls))
}

#[derive(Default)]
struct Stats {
    accepted: AtomicU64,
    rejected: AtomicU64,
    completed: AtomicU64,
    failed: AtomicU64,
    up: AtomicU64,
    down: AtomicU64,
}
impl Stats {
    fn report(&self, active: usize) {
        eprintln!(
            "stats active={active} accepted={} rejected={} completed={} failed={} bytes_up={} bytes_down={}",
            self.accepted.load(Ordering::Relaxed),
            self.rejected.load(Ordering::Relaxed),
            self.completed.load(Ordering::Relaxed),
            self.failed.load(Ordering::Relaxed),
            self.up.load(Ordering::Relaxed),
            self.down.load(Ordering::Relaxed)
        );
    }
}
struct Proxy {
    pool: Arc<Pool>,
    http: Arc<http1::State>,
    stats: Stats,
}
#[derive(Clone)]
struct ClientInfo {
    peer: std::net::SocketAddr,
    destination: std::net::SocketAddr,
    sni: Option<String>,
    tls_version: Option<&'static str>,
    metadata: decision::Metadata,
}
impl ClientInfo {
    fn context(&self) -> decision::Client<'_> {
        decision::Client {
            ip: self.peer.ip().to_canonical(),
            tls_version: self.tls_version,
            sni: self.sni.as_deref(),
            metadata: Some(&self.metadata),
        }
    }
}
impl Proxy {
    // Spawned by run; complete frontend TLS before selecting a backend.
    async fn handle(
        &self,
        config: &Config,
        stream: TcpStream,
        handshakes: Option<Arc<Semaphore>>,
        tls: Arc<tls::Tls>,
    ) -> Result<(), Error> {
        let deadline = Instant::now() + Duration::from_millis(config.handshake_timeout_ms);
        // Queue under the connection cap; the same deadline also bounds frontend TLS.
        let setup = match handshakes {
            Some(slots) => Some(
                timeout_at(deadline, slots.acquire_owned())
                    .await
                    .map_err(|_| "TLS setup admission deadline elapsed")??,
            ),
            None => None,
        };
        let peer = stream.peer_addr()?;
        let destination = stream.local_addr()?;
        let mut info = ClientInfo {
            peer,
            destination,
            sni: None,
            tls_version: None,
            metadata: decision::Metadata {
                country: tls.geoip.country(peer.ip()),
                ..Default::default()
            },
        };
        stream.set_nodelay(true)?;
        match &tls.acceptor {
            Some(acceptor) => {
                let stream = timeout_at(deadline, acceptor.accept(stream)).await??;
                info.sni = stream.get_ref().1.server_name().map(str::to_owned);
                info.metadata.tls_cipher = stream
                    .get_ref()
                    .1
                    .negotiated_cipher_suite()
                    .map(|s| format!("{:?}", s.suite()));
                info.metadata.alpn = stream
                    .get_ref()
                    .1
                    .alpn_protocol()
                    .map(|v| String::from_utf8_lossy(v).into_owned());
                info.metadata.client_verified = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .is_some_and(|c| !c.is_empty());
                info.tls_version = match stream.get_ref().1.protocol_version() {
                    Some(tokio_rustls::rustls::ProtocolVersion::TLSv1_2) => Some("TLS1.2"),
                    Some(tokio_rustls::rustls::ProtocolVersion::TLSv1_3) => Some("TLS1.3"),
                    _ => None,
                };
                self.relay(config, stream, setup, &tls, info).await
            }
            None => self.relay(config, stream, setup, &tls, info).await,
        }
    }
    // Called by handle; retry establishment only, before forwarding application bytes.
    async fn relay<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        &self,
        config: &Config,
        client: S,
        setup: Option<OwnedSemaphorePermit>,
        tls: &tls::Tls,
        info: ClientInfo,
    ) -> Result<(), Error> {
        if config.http1.is_some() {
            let (up, down) = http1::relay(
                client,
                info.clone(),
                config,
                self.http.clone(),
                |metadata| async move {
                    let mut info = info;
                    info.metadata.http = Some(metadata);
                    let result = self.establish(config, tls, &info).await;
                    drop(setup);
                    result
                },
            )
            .await?;
            self.stats.up.fetch_add(up, Ordering::Relaxed);
            self.stats.down.fetch_add(down, Ordering::Relaxed);
            return Ok(());
        }
        let (upstream, lease) = self.establish(config, tls, &info).await?;
        drop(setup);
        let result = self.forward(config, client, upstream, &lease).await;
        drop(lease);
        result
    }

    async fn establish(
        &self,
        config: &Config,
        tls: &tls::Tls,
        info: &ClientInfo,
    ) -> Result<(Upstream, scheduler::Lease), Error> {
        let peer = info.peer;
        let mut attempted = [false; 256];
        let deadline =
            tokio::time::Instant::now() + Duration::from_millis(config.establishment_timeout_ms);
        let mut last_error: Error = "no eligible backend".into();
        while let Some(lease) = self.pool.acquire_for_context(&attempted, info.context()) {
            let i = lease.index;
            attempted[i] = true;
            let attempt_deadline = deadline.min(
                tokio::time::Instant::now() + Duration::from_millis(config.connect_timeout_ms),
            );
            let attempt_started = tokio::time::Instant::now();
            let mut failure_phase = "backend_tcp_connect";
            let connection = tokio::time::timeout_at(attempt_deadline, async {
                let address = lease.backend.address;
                let mut stream = if let Some(ip) = config.outbound_bind {
                    let socket = if address.is_ipv4() {
                        TcpSocket::new_v4()?
                    } else {
                        TcpSocket::new_v6()?
                    };
                    socket.bind(std::net::SocketAddr::new(ip, 0))?;
                    socket.connect(address).await?
                } else {
                    TcpStream::connect(address).await?
                };
                stream.set_nodelay(true)?;
                if config.proxy_protocol_v2 {
                    failure_phase = "proxy_v2_write";
                    stream
                        .write_all(&proxy_v2_header(peer, info.destination)?)
                        .await?;
                }
                match &tls.connector {
                    Some(connector) => {
                        failure_phase = "upstream_tls_handshake";
                        Ok::<_, Error>(Upstream::Tls(Box::new(
                            connector
                                .connect(
                                    tokio_rustls::rustls::pki_types::ServerName::try_from(
                                        lease
                                            .backend
                                            .server_name
                                            .clone()
                                            .ok_or("missing backend TLS name")?,
                                    )?,
                                    stream,
                                )
                                .await?,
                        )))
                    }
                    None => Ok(Upstream::Tcp(stream)),
                }
            })
            .await;
            match connection {
                Ok(Ok(upstream)) => {
                    self.pool.succeeded(i, lease.config_generation);
                    if config.debug {
                        eprintln!("client {peer} connected to {}", lease.backend.address);
                    }
                    return Ok((upstream, lease));
                }
                Ok(Err(error)) => last_error = format!("{failure_phase}: {error}").into(),
                Err(error) => last_error = format!("{failure_phase}: {error}").into(),
            }
            if config.debug {
                eprintln!(
                    "backend {} failed phase={} elapsed_ms={} error={last_error}",
                    lease.backend.address,
                    failure_phase,
                    attempt_started.elapsed().as_millis()
                );
            }
            self.pool
                .failed(i, lease.config_generation, lease.health_epoch);
            if tokio::time::Instant::now() >= deadline {
                break;
            }
        }
        Err(last_error)
    }
    // Called by relay for non-HTTP listeners; retain the backend lease through the raw transfer.
    async fn forward<
        A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    >(
        &self,
        config: &Config,
        mut a: A,
        mut b: B,
        lease: &scheduler::Lease,
    ) -> Result<(), Error> {
        let (up, down) = transport::copy(
            &mut a,
            &mut b,
            config.buffer_bytes,
            config.idle_timeout_ms,
            config.packet_dump,
            &lease.counters,
        )
        .await?;
        self.stats.up.fetch_add(up, Ordering::Relaxed);
        self.stats.down.fetch_add(down, Ordering::Relaxed);
        Ok(())
    }
}

fn proxy_v2_header(
    source: std::net::SocketAddr,
    destination: std::net::SocketAddr,
) -> Result<Vec<u8>, Error> {
    const SIGNATURE: [u8; 12] = [
        b'\r', b'\n', b'\r', b'\n', 0, b'\r', b'\n', b'Q', b'U', b'I', b'T', b'\n',
    ];
    let mut header = Vec::with_capacity(36);
    header.extend_from_slice(&SIGNATURE);
    header.push(0x21); // version 2, PROXY command
    match (source, destination) {
        (std::net::SocketAddr::V4(src), std::net::SocketAddr::V4(dst)) => {
            header.push(0x11); // INET, STREAM
            header.extend_from_slice(&12u16.to_be_bytes());
            header.extend_from_slice(&src.ip().octets());
            header.extend_from_slice(&dst.ip().octets());
            header.extend_from_slice(&src.port().to_be_bytes());
            header.extend_from_slice(&dst.port().to_be_bytes());
        }
        (std::net::SocketAddr::V6(src), std::net::SocketAddr::V6(dst)) => {
            header.push(0x21); // INET6, STREAM
            header.extend_from_slice(&36u16.to_be_bytes());
            header.extend_from_slice(&src.ip().octets());
            header.extend_from_slice(&dst.ip().octets());
            header.extend_from_slice(&src.port().to_be_bytes());
            header.extend_from_slice(&dst.port().to_be_bytes());
        }
        _ => return Err("PROXY v2 cannot encode mixed IPv4/IPv6 endpoints".into()),
    }
    Ok(header)
}
// These variants keep TLS optional without a per-read dynamic dispatch boundary.
enum Upstream {
    Tcp(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}
impl AsyncRead for Upstream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}
impl AsyncWrite for Upstream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            Self::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

// Called by start; supervise admission, reload publication and graceful drain.
async fn run(config: Config, tls: tls::Tls) -> Result<(), Error> {
    let config = Arc::new(std::sync::RwLock::new(config));
    let initial = config.read().expect("config lock poisoned").clone();
    let mut listener = bind_listener(initial.listen, initial.reuse_port)?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut reload = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let capacity = Arc::new(Semaphore::new(initial.max_connections));
    let handshakes = Arc::new(Semaphore::new(initial.max_handshakes));
    let pool = Arc::new(Pool::from_config(&initial));
    *pool.geoip.write().expect("GeoIP lock poisoned") = tls.geoip.clone();
    // Register trusted, compiled HttpPlugin implementations after the bundled header rules.
    let http = Arc::new(http1::State::new(initial.http1.clone(), vec![]));
    let shutdown = Arc::new(Notify::new());
    let mut tls = Arc::new(tls);
    let (tls_updates, tls_receiver) = watch::channel(tls.clone());
    let mut controls = control::start(
        &initial,
        listener.local_addr()?,
        pool.clone(),
        tls_receiver,
        shutdown.clone(),
        http.clone(),
    )
    .await?;
    eprintln!(
        "listening={} workers={} reuse_port={} max_connections={} relay_buffer_bytes_per_connection={} tls={} upstream_tls={}",
        listener.local_addr()?,
        initial.workers,
        initial.reuse_port,
        initial.max_connections,
        2 * initial.buffer_bytes,
        tls.acceptor.is_some(),
        tls.connector.is_some()
    );
    let proxy = Arc::new(Proxy {
        pool,
        http,
        stats: Stats::default(),
    });
    let mut reloading: Option<tokio::task::JoinHandle<Result<(Config, tls::Tls), Error>>> = None;
    let mut tasks = JoinSet::new();
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    loop {
        while let Some(result) = tasks.try_join_next() {
            if let Err(error) = result {
                eprintln!("connection task failed: {error}");
            }
        }
        tokio::select! {
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
            _ = shutdown.notified() => break,
            result = controls.tasks.join_next() => {
                return Err(format!("control listener stopped unexpectedly: {result:?}").into());
            }
            _ = reload.recv(), if reloading.is_none() => {
                let current = config.read().expect("config lock poisoned").clone();
                reloading = Some(tokio::task::spawn_blocking(move || {
                    let next = match &current.config_file {
                        Some(path) => Config::load(path)?,
                        None => current,
                    };
                    let tls = tls::Tls::load(&next)?;
                    Ok((next, tls))
                }));
            }
            result = async { reloading.as_mut().expect("reload in progress").await }, if reloading.is_some() => {
                match result {
                    Ok(Ok((next_config, next_tls))) => {
                        let active = config.read().expect("config lock poisoned").clone();
                        if let Err(error) = reload_compatible(&active, &next_config) {
                            eprintln!("configuration reload rejected; previous configuration retained: {error}");
                        } else {
                            match bind_listener_if_changed(&listener, next_config.listen, next_config.reuse_port) {
                                Ok(next_listener) => {
                                    proxy.pool.reconfigure(&next_config);
                                    *proxy.pool.geoip.write().expect("GeoIP lock poisoned") = next_tls.geoip.clone();
                                    proxy.http.reload(next_config.http1.clone());
                                    *config.write().expect("config lock poisoned") = next_config;
                                    tls = Arc::new(next_tls);
                                    tls_updates.send_replace(tls.clone());
                                    if let Some(next_listener) = next_listener {
                                        listener = next_listener;
                                    }
                                    eprintln!("configuration generation reloaded for new connections");
                                }
                                Err(error) => eprintln!("configuration reload rejected; previous configuration retained: {error}"),
                            }
                        }
                    }
                    Ok(Err(error)) => eprintln!("configuration reload rejected; previous configuration retained: {error}"),
                    Err(error) => eprintln!("configuration reload task failed: {error}"),
                }
                reloading = None;
            }
            _ = interval.tick() => {
                let config = config.read().expect("config lock poisoned");
                proxy.stats.report(config.max_connections - capacity.available_permits());
            }
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = result {
                    eprintln!("connection task failed: {error}");
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(value) => value,
                    Err(error) => {
                        eprintln!("accept failed: {error}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                proxy.stats.accepted.fetch_add(1, Ordering::Relaxed);
                let Ok(permit) = capacity.clone().try_acquire_owned() else {
                    proxy.stats.rejected.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                let current = config.read().expect("config lock poisoned").clone();
                let current_uses_tls = current.tls.is_some() || current.upstream_tls.is_some();
                let setup = current_uses_tls.then(|| handshakes.clone());
                let proxy = proxy.clone();
                let tls = tls.clone();
                tasks.spawn(async move {
                    let result = proxy.handle(&current, stream, setup, tls).await;
                    match result {
                        Err(error) => {
                            let failed = proxy.stats.failed.fetch_add(1, Ordering::Relaxed) + 1;
                            if current.debug || failed == 1 || failed.is_multiple_of(1024) {
                                eprintln!("connection failed (sample {failed}): {error}");
                            }
                        }
                        Ok(()) => {
                            proxy.stats.completed.fetch_add(1, Ordering::Relaxed);
                            if current.debug { eprintln!("connection completed"); }
                        }
                    }
                    drop(permit);
                });
            }
        }
    }
    drop(listener);
    drop(controls);
    eprintln!("draining connections");
    let drain_timeout = config
        .read()
        .expect("config lock poisoned")
        .drain_timeout_ms;
    if timeout(Duration::from_millis(drain_timeout), async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        eprintln!("drain deadline reached; closing remaining connections");
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    let config = config.read().expect("config lock poisoned");
    proxy
        .stats
        .report(config.max_connections - capacity.available_permits());
    Ok(())
}

// Used at startup and reload; the kernel may cap the requested burst backlog.
fn bind_listener(
    address: std::net::SocketAddr,
    reuse_port: bool,
) -> Result<tokio::net::TcpListener, Error> {
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    if reuse_port {
        use std::os::fd::AsRawFd;
        let enabled: libc::c_int = 1;
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                &enabled as *const _ as *const libc::c_void,
                std::mem::size_of_val(&enabled) as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    socket.bind(address)?;
    // Leave room for device boot storms; Linux also caps this at net.core.somaxconn.
    Ok(socket.listen(16384)?)
}

fn bind_listener_if_changed(
    active: &tokio::net::TcpListener,
    address: std::net::SocketAddr,
    reuse_port: bool,
) -> Result<Option<tokio::net::TcpListener>, Error> {
    if active.local_addr()? == address
        || (address.port() == 0 && active.local_addr()?.ip() == address.ip())
    {
        Ok(None)
    } else {
        Ok(Some(bind_listener(address, reuse_port)?))
    }
}

// Called before publishing a reload; reject settings whose resources require a restart.
fn reload_compatible(active: &Config, next: &Config) -> Result<(), Error> {
    if active.workers != next.workers
        || active.reuse_port != next.reuse_port
        || active.max_connections != next.max_connections
        || active.max_handshakes != next.max_handshakes
        || active.control_socket != next.control_socket
        || active
            .management
            .as_ref()
            .map(|m| (m.listen, m.max_connections, m.request_timeout_ms))
            != next
                .management
                .as_ref()
                .map(|m| (m.listen, m.max_connections, m.request_timeout_ms))
    {
        return Err("workers, reuse_port, admission limits, control socket, and management listener settings require restart".into());
    }
    Ok(())
}

#[cfg(test)]
mod proxy_protocol_tests {
    use super::proxy_v2_header;
    use std::net::SocketAddr;

    #[test]
    fn mapped_peers_have_canonical_routing_identity() {
        let info = super::ClientInfo {
            peer: "[::ffff:192.0.2.1]:1234".parse().unwrap(),
            destination: "[::]:443".parse().unwrap(),
            sni: None,
            tls_version: None,
            metadata: Default::default(),
        };
        assert_eq!(
            info.context().ip,
            "192.0.2.1".parse::<std::net::IpAddr>().unwrap()
        );
        assert!(info.peer.is_ipv6()); // Transport metadata remains intact for PROXY v2.
    }

    #[test]
    fn proxy_v2_encodes_ipv4_addresses_ports_and_signature() {
        let src: SocketAddr = "192.0.2.1:1234".parse().unwrap();
        let dst: SocketAddr = "198.51.100.2:443".parse().unwrap();
        let header = proxy_v2_header(src, dst).unwrap();
        assert_eq!(&header[..12], b"\r\n\r\n\0\r\nQUIT\n");
        assert_eq!(&header[12..16], &[0x21, 0x11, 0, 12]);
        assert_eq!(&header[16..24], &[192, 0, 2, 1, 198, 51, 100, 2]);
        assert_eq!(&header[24..28], &[4, 210, 1, 187]);
    }

    #[test]
    fn proxy_v2_rejects_mixed_address_families() {
        let src: SocketAddr = "192.0.2.1:1234".parse().unwrap();
        let dst: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert!(proxy_v2_header(src, dst).is_err());
    }

    #[test]
    fn proxy_v2_encodes_ipv6_address_family_and_length() {
        let src: SocketAddr = "[2001:db8::1]:1234".parse().unwrap();
        let dst: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
        let header = proxy_v2_header(src, dst).unwrap();
        assert_eq!(&header[12..16], &[0x21, 0x21, 0, 36]);
        assert_eq!(header.len(), 52);
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use std::future::Future;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn queued_setup_resumes_and_releases_its_slot_before_streaming() {
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config: Config = serde_json::from_value(serde_json::json!({
            "backends": [{"address": origin.local_addr().unwrap()}]
        }))
        .unwrap();
        let proxy = Proxy {
            pool: Arc::new(Pool::from_config(&config)),
            http: Arc::new(http1::State::new(config.http1.clone(), vec![])),
            stats: Stats::default(),
        };
        let tls = Arc::new(tls::Tls::load(&config).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let slots = Arc::new(Semaphore::new(0));
        let mut forward = Box::pin(proxy.handle(&config, stream, Some(slots.clone()), tls));
        assert!(
            std::future::poll_fn(|cx| {
                std::task::Poll::Ready(forward.as_mut().poll(cx).is_pending())
            })
            .await
        );
        slots.add_permits(1);
        let device = async {
            client.write_all(b"ping").await.unwrap();
            let mut reply = [0; 4];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"ping");
            assert_eq!(slots.available_permits(), 1);
            client.shutdown().await.unwrap();
        };
        let workload = async {
            let (mut stream, _) = origin.accept().await.unwrap();
            let mut message = [0; 4];
            stream.read_exact(&mut message).await.unwrap();
            stream.write_all(&message).await.unwrap();
            stream.shutdown().await.unwrap();
        };
        let (result, (), ()) = timeout(Duration::from_secs(1), async {
            tokio::join!(forward, device, workload)
        })
        .await
        .unwrap();
        result.unwrap();
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn queued_setup_expires_without_consuming_a_later_slot() {
        let config = Config {
            handshake_timeout_ms: 10,
            ..Config::default()
        };
        let proxy = Proxy {
            pool: Arc::new(Pool::from_config(&config)),
            http: Arc::new(http1::State::new(config.http1.clone(), vec![])),
            stats: Stats::default(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let slots = Arc::new(Semaphore::new(0));
        let error = timeout(
            Duration::from_secs(1),
            proxy.handle(
                &config,
                stream,
                Some(slots.clone()),
                Arc::new(tls::Tls::load(&config).unwrap()),
            ),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(error.to_string(), "TLS setup admission deadline elapsed");
        slots.add_permits(1);
        assert_eq!(slots.available_permits(), 1);
        let mut byte = [0];
        assert_eq!(client.read(&mut byte).await.unwrap(), 0);
    }
}

#[cfg(test)]
mod reuse_port_tests {
    use super::bind_listener;

    #[tokio::test]
    async fn multiple_process_listeners_can_share_a_port() {
        let first = bind_listener("127.0.0.1:0".parse().unwrap(), true).unwrap();
        let address = first.local_addr().unwrap();
        let second = bind_listener(address, true).unwrap();
        assert_eq!(second.local_addr().unwrap(), address);
    }
}
