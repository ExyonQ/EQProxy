//! TCP proxy: accept, connect to the backend and pump bytes with timeouts.
//!
//! Semantics (documented and tested):
//! - `maxconn` per listener: when full, the connection is **refused** (close
//!   immediately + counter); there are never unbounded queues (SPEC §7.3).
//! - `connect_timeout`: maximum to establish the backend connection
//!   (includes the TLS handshake to it).
//! - `idle_timeout`: per direction; with no bytes in that direction during
//!   the window, it closes with EOF towards its peer and `idle_timeouts`
//!   counts it.
//! - Graceful shutdown: stops accepting, live connections finish within
//!   `grace`; on expiry the process exits and the rest are closed.
//! - `bind` is "all or nothing": when a listener cannot open, the
//!   others close and an error returns (resource preparation before
//!   activation, SPEC §7.2).
//!
//! Phase 2b: TLS termination (A11, handshake in the client phase), TLS to
//! backends (A12), weighted RR balancing (B1/B7) with TCP health checks
//! (B11) and PROXY protocol v1 send (A9). With no servers available:
//! HTTP → 503, TCP → close (counted in `no_available_server`).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

use eqproxy_core::{Metrics, Shutdown};

use crate::balancer::{Balancer, ResolvedServer};
use crate::health::{self, HealthCheck};
use crate::http1;
use crate::pool::Pool;
use crate::proxy_proto::{self, ProxyProtocolMode};
use crate::tls::{self, ClientTls};

/// Per-direction buffer (SPEC §7.3: 16 KiB).
pub const READ_BUF: usize = 16 * 1024;

/// Reader of an already-split stream half (TCP or TLS).
pub type BoxRead = Box<dyn AsyncRead + Unpin + Send>;
/// Writer of an already-split stream half (TCP or TLS).
pub type BoxWrite = Box<dyn AsyncWrite + Unpin + Send>;

/// Modo de proxy de un listener (A1 `Tcp`, A2 `Http`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyMode {
    /// TCP tunnel without interpretation.
    #[default]
    Tcp,
    /// Proxy HTTP/1.1 con framing estricto.
    Http,
}

/// Backend resuelto: servidores, balanceo, TLS y PROXY protocol.
///
/// Shared across listeners referencing the same backend (a single
/// [`Balancer`] and a single health machine per backend).
#[derive(Debug)]
pub struct ResolvedBackend {
    pub name: String,
    pub servers: Vec<ResolvedServer>,
    pub proxy_protocol: ProxyProtocolMode,
    pub tls: Option<ClientTls>,
    pub health_check: Option<HealthCheck>,
    pub balancer: Arc<Balancer>,
    /// Per-backend keep-alive pool (A16), shared across listeners.
    pub pool: Pool,
}

impl ResolvedBackend {
    /// Single-server backend with default settings (compat 0.1.0).
    #[must_use]
    pub fn single(name: impl Into<String>, server: SocketAddr) -> Self {
        Self::new(
            name,
            vec![ResolvedServer {
                addr: server,
                weight: 1,
            }],
            3,
            2,
        )
    }

    /// Backend con servidores ponderados y umbrales `fall`/`rise` (B11).
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        servers: Vec<ResolvedServer>,
        fall: u32,
        rise: u32,
    ) -> Self {
        Self {
            name: name.into(),
            balancer: Arc::new(Balancer::new(servers.clone(), fall, rise)),
            servers,
            proxy_protocol: ProxyProtocolMode::None,
            tls: None,
            health_check: None,
            pool: Pool::with_defaults(),
        }
    }

    /// PROXY protocol v1 send to the servers (A9).
    #[must_use]
    pub fn with_proxy_protocol(mut self, mode: ProxyProtocolMode) -> Self {
        self.proxy_protocol = mode;
        self
    }

    /// TLS to the servers (A12).
    #[must_use]
    pub fn with_tls(mut self, tls: ClientTls) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Health check TCP activo (B11).
    #[must_use]
    pub fn with_health_check(mut self, check: HealthCheck) -> Self {
        self.health_check = Some(check);
        self
    }
}

/// Resolved listener (already-validated config: parsed addresses, sound refs).
///
/// `#[non_exhaustive]`: adding fields is not a breaking change for
/// consumers (ADR-0004 semver policy). Built with [`Self::new`].
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ResolvedListener {
    pub name: String,
    pub listen: SocketAddr,
    pub backend_name: String,
    /// Backend destino (servidores + balanceo + TLS + PROXY).
    pub backend: Arc<ResolvedBackend>,
    pub mode: ProxyMode,
    pub maxconn: u32,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    /// Client phase (`http` only): request head. Also covers the
    /// handshake TLS del cliente (A11).
    pub client_header_timeout: Duration,
    /// Server phase (`http` only): response head.
    pub server_header_timeout: Duration,
    /// TLS termination at this listener (A11). `None` = plain TCP.
    pub server_tls: Option<tls::ServerTls>,
}

impl ResolvedListener {
    /// Builds a listener with a single-server backend (compat 0.1.0).
    /// Use [`Self::with_backend`] for balancing/TLS/PROXY and
    /// [`Self::with_server_tls`] for TLS termination.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        listen: SocketAddr,
        backend_name: impl Into<String>,
        server: SocketAddr,
        mode: ProxyMode,
        maxconn: u32,
        connect_timeout: Duration,
        idle_timeout: Duration,
        client_header_timeout: Duration,
        server_header_timeout: Duration,
    ) -> Self {
        let backend_name = backend_name.into();
        Self {
            name: name.into(),
            listen,
            backend: Arc::new(ResolvedBackend::single(backend_name.clone(), server)),
            backend_name,
            mode,
            maxconn,
            connect_timeout,
            idle_timeout,
            client_header_timeout,
            server_header_timeout,
            server_tls: None,
        }
    }

    /// Sustituye el backend por uno completo (multi-servidor, TLS, PROXY, …).
    #[must_use]
    pub fn with_backend(mut self, backend: Arc<ResolvedBackend>) -> Self {
        self.backend_name = backend.name.clone();
        self.backend = backend;
        self
    }

    /// Activa TLS termination en el listener (A11).
    #[must_use]
    pub fn with_server_tls(mut self, server_tls: tls::ServerTls) -> Self {
        self.server_tls = Some(server_tls);
        self
    }
}

/// Error de arranque del dataplane.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("no se pudo escuchar en {addr} (listener «{name}»): {source}")]
    Bind {
        name: String,
        addr: SocketAddr,
        source: io::Error,
    },
}

/// Why the stream to the backend could not open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundError {
    /// All servers are down or drained (HTTP → 503, TCP → close).
    NoServer,
    /// The chosen server refused the connection/handshake (HTTP → 502).
    Connect,
}

#[derive(Debug)]
struct BoundListener {
    cfg: ResolvedListener,
    listener: TcpListener,
}

/// Dataplane with all sockets already open (activation pending).
#[derive(Debug)]
pub struct BoundProxy {
    listeners: Vec<BoundListener>,
    metrics: Arc<Metrics>,
}

/// Opens all listeners. Fails whole when any one cannot open.
pub async fn bind(
    listeners: Vec<ResolvedListener>,
    metrics: Arc<Metrics>,
) -> Result<BoundProxy, ProxyError> {
    let mut bound = Vec::with_capacity(listeners.len());
    for cfg in listeners {
        match TcpListener::bind(cfg.listen).await {
            Ok(listener) => bound.push(BoundListener { cfg, listener }),
            Err(source) => {
                return Err(ProxyError::Bind {
                    name: cfg.name,
                    addr: cfg.listen,
                    source,
                });
            }
        }
    }
    Ok(BoundProxy {
        listeners: bound,
        metrics,
    })
}

impl BoundProxy {
    /// Real addresses after bind (port 0 resolves an ephemeral one).
    #[must_use]
    pub fn local_addrs(&self) -> Vec<(String, SocketAddr)> {
        self.listeners
            .iter()
            .map(|b| {
                let addr = b.listener.local_addr().unwrap_or(b.cfg.listen);
                (b.cfg.name.clone(), addr)
            })
            .collect()
    }

    /// Serves until the shutdown signal; then drains until `grace`.
    pub async fn serve(self, mut shutdown: Shutdown, grace: Duration) -> Result<(), ProxyError> {
        // Health checks (B11): un task por backend con checks configurados,
        // shared across the listeners of the same backend (same Arc).
        let mut health_tasks = JoinSet::new();
        let mut seen: Vec<Arc<Balancer>> = Vec::new();
        for bound in &self.listeners {
            let backend = &bound.cfg.backend;
            let Some(check) = backend.health_check else {
                continue;
            };
            let balancer = Arc::clone(&backend.balancer);
            if seen.iter().any(|s| Arc::ptr_eq(s, &balancer)) {
                continue;
            }
            seen.push(Arc::clone(&balancer));
            health_tasks.spawn(health::run(balancer, check, shutdown.clone()));
        }

        let mut acceptors = JoinSet::new();
        for bound in self.listeners {
            let metrics = Arc::clone(&self.metrics);
            let signal = shutdown.clone();
            acceptors.spawn(async move { accept_loop(bound, metrics, signal).await });
        }

        shutdown.wait().await;

        // Accept loops return instantly on the triggered signal.
        let _ = tokio::time::timeout(grace, async {
            while acceptors.join_next().await.is_some() {}
        })
        .await;
        acceptors.abort_all();
        health_tasks.abort_all();

        // Draining: live connections may finish within the window.
        let deadline = tokio::time::Instant::now() + grace;
        while self.metrics.connections_active.load(Ordering::Acquire) > 0 {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(())
    }
}

async fn accept_loop(bound: BoundListener, metrics: Arc<Metrics>, mut shutdown: Shutdown) {
    loop {
        tokio::select! {
            _ = shutdown.wait() => break,
            accepted = bound.listener.accept() => {
                let (socket, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        // Error transitorio (EMFILE, etc.): registrar y continuar,
                        // with a small breather to avoid saturating the CPU.
                        eprintln!("ERROR [{}] accept failed: {err}", bound.cfg.name);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                if !metrics.try_acquire_connection(bound.cfg.maxconn) {
                    metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                    // Explicit refusal: immediate close, no queue.
                    drop(socket);
                    continue;
                }
                metrics.connections_accepted.fetch_add(1, Ordering::Relaxed);
                let cfg = bound.cfg.clone();
                let task_metrics = Arc::clone(&metrics);
                tokio::spawn(async move {
                    handle_connection(socket, peer, cfg, task_metrics).await;
                });
            }
        }
    }
}

/// RAII guard: releases the connection slot no matter what.
struct ConnectionGuard {
    metrics: Arc<Metrics>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.metrics.release_connection();
    }
}

/// Conecta al backend elegido por el balancer: TCP + TLS opcional (A12) +
/// optional PROXY v1 header (A9). Returns the halves ready to pump.
pub async fn connect_backend(
    cfg: &ResolvedListener,
    peer: SocketAddr,
    local: SocketAddr,
    metrics: &Metrics,
) -> Result<(BoxRead, BoxWrite), OutboundError> {
    let backend = &cfg.backend;
    let addr = backend.balancer.pick().ok_or_else(|| {
        metrics.no_available_server.fetch_add(1, Ordering::Relaxed);
        OutboundError::NoServer
    })?;
    connect_backend_to(cfg, addr, peer, local, metrics).await
}

/// Stream to the backend with its origin: reused from the pool (A16) or
/// freshly dialed. `reused` feeds `backend_connections_reused`.
pub struct BackendConn {
    /// Balancer-chosen server (pool key).
    pub addr: SocketAddr,
    /// Read half (ready for `read_head`: message-aligned).
    pub read: BufReader<BoxRead>,
    /// Write half.
    pub write: BoxWrite,
    /// `true` when from the pool (no dial, handshake or PROXY again).
    pub reused: bool,
}

/// Reuses an idle pool connection or dials a new one to the
/// balancer-chosen server. With no servers available: `NoServer` (503).
pub async fn checkout_or_connect(
    cfg: &ResolvedListener,
    peer: SocketAddr,
    local: SocketAddr,
    metrics: &Metrics,
) -> Result<BackendConn, OutboundError> {
    let backend = &cfg.backend;
    let addr = backend.balancer.pick().ok_or_else(|| {
        metrics.no_available_server.fetch_add(1, Ordering::Relaxed);
        OutboundError::NoServer
    })?;
    let now = Instant::now();
    if let Some((read, write)) = backend.pool.checkout(&addr, now) {
        metrics
            .backend_connections_reused
            .fetch_add(1, Ordering::Relaxed);
        return Ok(BackendConn {
            addr,
            read,
            write,
            reused: true,
        });
    }
    let (read, write) = connect_backend_to(cfg, addr, peer, local, metrics).await?;
    metrics
        .backend_connections_opened
        .fetch_add(1, Ordering::Relaxed);
    Ok(BackendConn {
        addr,
        read: BufReader::new(read),
        write,
        reused: false,
    })
}

/// Variant of [`connect_backend`] against an already-chosen server (the pool
/// needs the address before deciding between reuse and dial).
///
/// The PROXY v1 header (A9) is written once per connection: pool-reused
/// connections already carry it from their first use.
async fn connect_backend_to(
    cfg: &ResolvedListener,
    addr: SocketAddr,
    peer: SocketAddr,
    local: SocketAddr,
    metrics: &Metrics,
) -> Result<(BoxRead, BoxWrite), OutboundError> {
    let backend = &cfg.backend;

    let socket = match tokio::time::timeout(cfg.connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(socket)) => socket,
        Ok(Err(err)) => {
            metrics.connect_failures.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "ERROR [{}] no se pudo conectar a {} (par {peer}): {err}",
                cfg.name, addr
            );
            return Err(OutboundError::Connect);
        }
        Err(_elapsed) => {
            metrics.connect_failures.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "ERROR [{}] connect timeout to {} (peer {peer}) after {:?}",
                cfg.name, addr, cfg.connect_timeout
            );
            return Err(OutboundError::Connect);
        }
    };
    let _ = socket.set_nodelay(true);

    if let Some(client_tls) = &backend.tls {
        let name = tls::server_name_for(client_tls, addr);
        let handshake = tokio::time::timeout(
            cfg.connect_timeout,
            client_tls.connector.connect(name, socket),
        );
        let mut stream = match handshake.await {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
                metrics
                    .tls_handshake_failures
                    .fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "ERROR [{}] failed TLS handshake to {} (peer {peer}): {err}",
                    cfg.name, addr
                );
                return Err(OutboundError::Connect);
            }
            Err(_elapsed) => {
                metrics
                    .tls_handshake_failures
                    .fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "ERROR [{}] TLS handshake timeout to {} (peer {peer}) after {:?}",
                    cfg.name, addr, cfg.connect_timeout
                );
                return Err(OutboundError::Connect);
            }
        };
        if backend.proxy_protocol == ProxyProtocolMode::V1
            && proxy_proto::write_v1(&mut stream, peer, local)
                .await
                .is_err()
        {
            metrics.connect_failures.fetch_add(1, Ordering::Relaxed);
            return Err(OutboundError::Connect);
        }
        let (read, write) = tokio::io::split(stream);
        Ok((Box::new(read), Box::new(write)))
    } else {
        let mut socket = socket;
        if backend.proxy_protocol == ProxyProtocolMode::V1
            && proxy_proto::write_v1(&mut socket, peer, local)
                .await
                .is_err()
        {
            metrics.connect_failures.fetch_add(1, Ordering::Relaxed);
            return Err(OutboundError::Connect);
        }
        let (read, write) = socket.into_split();
        Ok((Box::new(read), Box::new(write)))
    }
}

async fn handle_connection(
    client: TcpStream,
    peer: SocketAddr,
    cfg: ResolvedListener,
    metrics: Arc<Metrics>,
) {
    let _guard = ConnectionGuard {
        metrics: Arc::clone(&metrics),
    };
    let _ = client.set_nodelay(true);
    let local = client.local_addr().unwrap_or(cfg.listen);

    // TLS termination (A11): el handshake vive en la fase cliente.
    let (client_read, client_write): (BoxRead, BoxWrite) = if let Some(server_tls) = &cfg.server_tls
    {
        let handshake = tokio::time::timeout(
            cfg.client_header_timeout,
            server_tls.acceptor.accept(client),
        );
        let stream = match handshake.await {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
                metrics
                    .tls_handshake_failures
                    .fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "ERROR [{}] handshake TLS de cliente fallido (par {peer}): {err}",
                    cfg.name
                );
                return;
            }
            Err(_elapsed) => {
                metrics
                    .tls_handshake_failures
                    .fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "ERROR [{}] client TLS handshake timeout (peer {peer}) after {:?}",
                    cfg.name, cfg.client_header_timeout
                );
                return;
            }
        };
        let (read, write) = tokio::io::split(stream);
        (Box::new(read), Box::new(write))
    } else {
        let (read, write) = client.into_split();
        (Box::new(read), Box::new(write))
    };

    if cfg.mode == ProxyMode::Http {
        http1::serve_http(client_read, client_write, peer, local, &cfg, metrics).await;
        return;
    }

    match connect_backend(&cfg, peer, local, &metrics).await {
        Ok((server_read, server_write)) => {
            pump(
                (client_read, client_write),
                (server_read, server_write),
                cfg.idle_timeout,
                &metrics,
            )
            .await;
        }
        Err(OutboundError::NoServer) => {
            eprintln!(
                "ERROR [{}] no servers available (peer {peer}): connection closed",
                cfg.name
            );
        }
        Err(OutboundError::Connect) => {}
    }
}

/// Independent bidirectional pump per direction.
async fn pump(
    client: (BoxRead, BoxWrite),
    server: (BoxRead, BoxWrite),
    idle: Duration,
    metrics: &Metrics,
) {
    let (client_read, client_write) = client;
    let (server_read, server_write) = server;

    let c2b = copy_dir(
        client_read,
        server_write,
        idle,
        &metrics.bytes_client_to_backend,
        &metrics.idle_timeouts,
    );
    let b2c = copy_dir(
        server_read,
        client_write,
        idle,
        &metrics.bytes_backend_to_client,
        &metrics.idle_timeouts,
    );
    // join!: each direction has its own timeout, so the set finishes in
    // bounded time even when a peer is silent.
    let (c2b_result, b2c_result) = tokio::join!(c2b, b2c);
    for result in [c2b_result, b2c_result] {
        // The inactivity timeout is already counted and closed in copy_dir;
        // real I/O errors are logged for diagnosis.
        if let Err(err) = result
            && err.kind() != io::ErrorKind::TimedOut
        {
            eprintln!("ERROR in the TCP tunnel: {err}");
        }
    }
}

/// Copia `reader → writer` con timeout de inactividad por lectura.
///
/// On EOF (or timeout) the writer gets `shutdown()` to propagate the
/// half-close towards the peer. Returns `TimedOut` when the timeout expired.
async fn copy_dir<R, W>(
    mut reader: R,
    mut writer: W,
    idle: Duration,
    counter: &AtomicU64,
    idle_counter: &AtomicU64,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; READ_BUF];
    let mut total = 0u64;
    loop {
        let read = match tokio::time::timeout(idle, reader.read(&mut buf)).await {
            Err(_elapsed) => {
                idle_counter.fetch_add(1, Ordering::Relaxed);
                let _ = writer.shutdown().await;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "inactivity timeout in one tunnel direction",
                ));
            }
            Ok(result) => result,
        };
        match read {
            Ok(0) => {
                let _ = writer.shutdown().await;
                return Ok(total);
            }
            Ok(n) => {
                writer.write_all(&buf[..n]).await?;
                total += n as u64;
                counter.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(err) => {
                let _ = writer.shutdown().await;
                return Err(err);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use tokio::io::AsyncWriteExt;

    /// Runs a future on a single-thread runtime **without IO driver**
    /// (mio/kqueue): tests only use timers and in-memory duplex, so they
    /// also run under miri, which does not emulate that OS FFI.
    fn sin_driver_io<F: Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime tokio")
            .block_on(fut)
    }

    #[test]
    fn copy_dir_moves_bytes_and_propagates_eof() {
        sin_driver_io(async {
            let (mut client, server) = tokio::io::duplex(64);
            let bytes = Arc::new(AtomicU64::new(0));
            let idles = Arc::new(AtomicU64::new(0));
            let task_bytes = Arc::clone(&bytes);
            let task_idles = Arc::clone(&idles);

            let copier = tokio::spawn(async move {
                copy_dir(
                    server,
                    tokio::io::sink(),
                    Duration::from_secs(5),
                    &task_bytes,
                    &task_idles,
                )
                .await
            });
            client.write_all(b"hola").await.expect("write");
            drop(client); // EOF
            let copied = tokio::time::timeout(Duration::from_secs(2), copier)
                .await
                .expect("the copier must finish")
                .expect("join")
                .expect("sin error en EOF");
            assert_eq!(copied, 4);
            assert_eq!(bytes.load(Ordering::Relaxed), 4);
            assert_eq!(idles.load(Ordering::Relaxed), 0);
        })
    }

    #[test]
    fn copy_dir_times_out_when_reader_is_silent() {
        sin_driver_io(async {
            let (_client, server) = tokio::io::duplex(64);
            let bytes = AtomicU64::new(0);
            let idles = AtomicU64::new(0);
            let result = copy_dir(
                server,
                tokio::io::sink(),
                Duration::from_millis(50),
                &bytes,
                &idles,
            )
            .await;
            let err = result.expect_err("must expire on inactivity");
            assert_eq!(err.kind(), io::ErrorKind::TimedOut);
            assert_eq!(idles.load(Ordering::Relaxed), 1);
        })
    }
}
