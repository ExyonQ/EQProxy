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
//! - Hot reload (S-CFG-01): `serve_with_reloads` swaps the listeners of a
//!   validated config while serving. Fail-closed (bind before mutate),
//!   established connections drain with the config they were accepted
//!   with and the counters never reset (PP-03).
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

use eqproxy_core::{Metrics, Shutdown, ShutdownHandle};

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

/// Proxy mode of a listener (A1 `Tcp`, A2 `Http`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyMode {
    /// TCP tunnel without interpretation.
    #[default]
    Tcp,
    /// HTTP/1.1 proxy with strict framing.
    Http,
}

/// Resolved backend: servers, balancing, TLS and PROXY protocol.
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
    /// Bounded wait queue when no server is up (B-H7). `None` = reject now.
    pub queue: Option<WaitQueue>,
    /// Connect-phase retry policy (B-H7).
    pub retries: RetryPolicy,
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

    /// Backend with weighted servers and `fall`/`rise` thresholds (B11).
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
            queue: None,
            retries: RetryPolicy::default(),
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

    /// Active TCP health check (B11).
    #[must_use]
    pub fn with_health_check(mut self, check: HealthCheck) -> Self {
        self.health_check = Some(check);
        self
    }

    /// Bounded wait queue when no server is up (B-H7).
    #[must_use]
    pub fn with_queue(mut self, settings: QueueSettings) -> Self {
        self.queue = Some(WaitQueue::new(settings));
        self
    }

    /// Connect-phase retry policy (B-H7).
    #[must_use]
    pub fn with_retries(mut self, retries: RetryPolicy) -> Self {
        self.retries = retries;
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
    /// Destination backend (servers + balancing + TLS + PROXY).
    pub backend: Arc<ResolvedBackend>,
    pub mode: ProxyMode,
    pub maxconn: u32,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    /// Client phase (`http` only): request head. Also covers the
    /// client TLS handshake (A11).
    pub client_header_timeout: Duration,
    /// Server phase (`http` only): response head.
    pub server_header_timeout: Duration,
    /// TLS termination at this listener (A11). `None` = plain TCP.
    pub server_tls: Option<tls::ServerTls>,
    /// PROXY v1 reception with origin allowlist (B-H9/B-E10): strict
    /// front door — every connection must come from an allowlisted
    /// origin and carry a valid PROXY v1 line.
    pub proxy_receive: Option<eqproxy_core::expectation::IpAllowlist>,
    /// `X-Forwarded-For`/`X-Real-IP` handling (B-N4).
    pub forwarded_headers: ForwardedMode,
    /// Custom response for the "no server available" class (C9).
    pub local_response: Option<LocalResponse>,
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
            proxy_receive: None,
            forwarded_headers: ForwardedMode::Off,
            local_response: None,
        }
    }

    /// Replaces the backend with a full one (multi-server, TLS, PROXY, …).
    #[must_use]
    pub fn with_backend(mut self, backend: Arc<ResolvedBackend>) -> Self {
        self.backend_name = backend.name.clone();
        self.backend = backend;
        self
    }

    /// Enables TLS termination on the listener (A11).
    #[must_use]
    pub fn with_server_tls(mut self, server_tls: tls::ServerTls) -> Self {
        self.server_tls = Some(server_tls);
        self
    }

    /// PROXY v1 reception with origin allowlist (B-H9/B-E10).
    #[must_use]
    pub fn with_proxy_receive(mut self, allowlist: eqproxy_core::expectation::IpAllowlist) -> Self {
        self.proxy_receive = Some(allowlist);
        self
    }

    /// `X-Forwarded-For`/`X-Real-IP` handling (B-N4).
    #[must_use]
    pub fn with_forwarded_headers(mut self, mode: ForwardedMode) -> Self {
        self.forwarded_headers = mode;
        self
    }

    /// Custom "no server available" response (C9).
    #[must_use]
    pub fn with_local_response(mut self, local: LocalResponse) -> Self {
        self.local_response = Some(local);
        self
    }
}

/// Dataplane activation error (startup or hot swap).
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("could not listen on {addr} (listener \"{name}\"): {source}")]
    Bind {
        name: String,
        addr: SocketAddr,
        source: io::Error,
    },
    #[error("listener \"{name}\" uses {addr}, already used by another listener")]
    DuplicateListener { name: String, addr: SocketAddr },
}

/// Why the stream to the backend could not open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundError {
    /// All servers are down or drained (HTTP → 503, TCP → close).
    NoServer,
    /// The chosen server refused the connection/handshake (HTTP → 502).
    Connect,
    /// The bounded backend queue is full (B-H7): explicit rejection
    /// (HTTP → 503, TCP → close; counted in `queue_full`).
    QueueFull,
    /// The bounded backend queue wait expired (B-H7; HTTP → 503).
    QueueTimeout,
}

/// Bounded wait queue settings (B-H7): wait for a server when none is up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueSettings {
    /// Maximum waiters (`MAX_QUEUE` budget); admission is capped.
    pub maxqueue: u32,
    /// Maximum wait in the queue.
    pub timeout: Duration,
}

/// Bounded wait queue (B-H7): never more than `maxqueue` waiters, never
/// unbounded waits (SPEC §7.3). Full queue = explicit rejection.
#[derive(Debug)]
pub struct WaitQueue {
    /// Settings (rendered in `config plan`).
    pub settings: QueueSettings,
    slots: Arc<tokio::sync::Semaphore>,
}

impl WaitQueue {
    #[must_use]
    pub fn new(settings: QueueSettings) -> Self {
        Self {
            settings,
            slots: Arc::new(tokio::sync::Semaphore::new(settings.maxqueue as usize)),
        }
    }

    /// Admission for one waiter; `None` when the queue is full.
    fn enter(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.slots.clone().try_acquire_owned().ok()
    }
}

/// Connect-phase retry policy (B-H7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RetryPolicy {
    /// Extra dials after the first failure (0 = disabled; max 5).
    pub max: u32,
    /// Non-idempotent exchanges may retry (explicit opt-in).
    pub non_idempotent: bool,
}

impl RetryPolicy {
    /// Is a redial allowed for this exchange?
    ///
    /// Documented rule (B-H7): only idempotent exchanges unless
    /// `non_idempotent` opts in. v0.5 retries cover connect-phase
    /// failures only (nothing was sent to any backend yet).
    #[must_use]
    pub fn allows(self, idempotent: bool) -> bool {
        self.max > 0 && (idempotent || self.non_idempotent)
    }
}

/// What the caller knows about the exchange for retry safety (B-H7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RetryContext {
    /// The exchange is safe to replay (idempotent request).
    pub idempotent: bool,
}

impl RetryContext {
    /// Idempotent exchange (RFC 9110 method).
    #[must_use]
    pub const fn idempotent() -> Self {
        Self { idempotent: true }
    }

    /// Non-idempotent exchange (or protocol without replay safety).
    #[must_use]
    pub const fn non_idempotent() -> Self {
        Self { idempotent: false }
    }
}

/// `X-Forwarded-For`/`X-Real-IP` handling (B-N4 first step).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ForwardedMode {
    /// No forwarded headers (default; explicit opt-in).
    #[default]
    Off,
    /// Append the client address to `X-Forwarded-For` (creating it when
    /// absent); `X-Real-IP` only when absent.
    Append,
    /// Replace `X-Forwarded-For` and `X-Real-IP` with the client address.
    Replace,
}

/// Custom response for the "no server available" class (C9 minimal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalResponse {
    /// Status code (400-599).
    pub status: u16,
    /// Content-Type of the body.
    pub content_type: String,
    /// Response body (bounded by config validation).
    pub body: String,
}

/// Current configuration of one listener, shared between its accept loop
/// (read per accept) and the hot swap (write). Established connections
/// keep the `ResolvedListener` they were accepted with (drain).
type SharedCfg = Arc<RwLock<Arc<ResolvedListener>>>;

/// The config in force right now (poison-recovered lock).
fn current_cfg(shared: &SharedCfg) -> Arc<ResolvedListener> {
    Arc::clone(
        &shared
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
}

/// One live listener: socket + accept loop + the config that new
/// connections see. Dropping it stops the accept loop (RAII).
struct Entry {
    /// Config address (swap key together with the name; `:0` keeps its
    /// resolved ephemeral socket across reloads).
    listen: SocketAddr,
    /// Real bound address (after `:0` resolution).
    local: SocketAddr,
    cfg: SharedCfg,
    stop: ShutdownHandle,
    task: JoinHandle<()>,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.stop.trigger();
    }
}

/// What a hot swap changed (logged; rendering unit-tested).
/// A rebind (same name, new address) counts as removed + added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapSummary {
    /// Kept socket (same name and address): only the config changed.
    pub kept: usize,
    /// Listeners started.
    pub added: usize,
    /// Listeners stopped.
    pub removed: usize,
}

impl std::fmt::Display for SwapSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "listeners kept={} added={} removed={}",
            self.kept, self.added, self.removed
        )
    }
}

/// Dataplane with all sockets open and their accept loops running.
pub struct BoundProxy {
    entries: Vec<Entry>,
    metrics: Arc<Metrics>,
    health_tasks: JoinSet<()>,
    health_stop: ShutdownHandle,
}

impl std::fmt::Debug for BoundProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundProxy")
            .field("listeners", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// Opens all listeners and starts their accept loops. Fails whole when
/// any one cannot open (SPEC §7.2): the already-opened ones close and an
/// error returns — never partially started.
pub async fn bind(
    listeners: Vec<ResolvedListener>,
    metrics: Arc<Metrics>,
) -> Result<BoundProxy, ProxyError> {
    let mut entries = Vec::with_capacity(listeners.len());
    for cfg in listeners {
        let name = cfg.name.clone();
        let addr = cfg.listen;
        // On error `entries` drops: its Drop impls stop the loops opened
        // so far (all-or-nothing).
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|source| ProxyError::Bind { name, addr, source })?;
        entries.push(make_entry(cfg, listener, Arc::clone(&metrics)));
    }
    let (health_stop, _health_shutdown) = eqproxy_core::shutdown::channel();
    let mut proxy = BoundProxy {
        entries,
        metrics,
        health_tasks: JoinSet::new(),
        health_stop,
    };
    proxy.spawn_health();
    Ok(proxy)
}

/// One entry: socket + shared config + its accept loop task.
fn make_entry(cfg: ResolvedListener, listener: TcpListener, metrics: Arc<Metrics>) -> Entry {
    let listen = cfg.listen;
    let local = listener.local_addr().unwrap_or(listen);
    let name = cfg.name.clone();
    let listener = Arc::new(listener);
    let shared: SharedCfg = Arc::new(RwLock::new(Arc::new(cfg)));
    let (stop, shutdown) = eqproxy_core::shutdown::channel();
    let task = tokio::spawn(accept_loop(
        Arc::clone(&listener),
        Arc::clone(&shared),
        name,
        metrics,
        shutdown,
    ));
    Entry {
        listen,
        local,
        cfg: shared,
        stop,
        task,
    }
}

impl BoundProxy {
    /// Real addresses after bind (port 0 resolves an ephemeral one).
    #[must_use]
    pub fn local_addrs(&self) -> Vec<(String, SocketAddr)> {
        self.entries
            .iter()
            .map(|e| (current_cfg(&e.cfg).name.clone(), e.local))
            .collect()
    }

    /// Hot swap (S-CFG-01): applies a new listener set while serving.
    ///
    /// Matching is by listener name (unique in the config):
    /// - same name + same address → the socket is **kept** (no rejection
    ///   window): only the config of new connections changes;
    /// - same name + different address → stop + rebind;
    /// - new name → start; missing name → stop.
    ///
    /// Fail-closed (SPEC §7.2): every needed address is bound **before**
    /// anything mutates, so a rejected swap leaves the running config
    /// untouched. Established connections drain with the config they
    /// were accepted with. Known edge: renaming a listener while keeping
    /// its exact address is rejected (the socket is still held); keep the
    /// name to keep the socket.
    pub async fn apply(
        &mut self,
        listeners: Vec<ResolvedListener>,
    ) -> Result<SwapSummary, ProxyError> {
        if let Some((name, addr)) = find_duplicate_addr(&listeners) {
            return Err(ProxyError::DuplicateListener { name, addr });
        }

        // Phase 1 — prepare resources: bind what we do not hold yet.
        // `None` = the socket is kept. On failure nothing has mutated.
        let mut prepared: Vec<(ResolvedListener, Option<TcpListener>)> = Vec::new();
        for cfg in listeners {
            let kept = self
                .entries
                .iter()
                .any(|e| e.listen == cfg.listen && current_cfg(&e.cfg).name == cfg.name);
            if kept {
                prepared.push((cfg, None));
                continue;
            }
            let name = cfg.name.clone();
            let addr = cfg.listen;
            match TcpListener::bind(addr).await {
                Ok(listener) => prepared.push((cfg, Some(listener))),
                Err(source) => return Err(ProxyError::Bind { name, addr, source }),
            }
        }

        // Phase 2 — commit: only infallible steps from here on.
        let mut summary = SwapSummary {
            kept: 0,
            added: 0,
            removed: 0,
        };
        // Stop what is not kept (the Drop impl stops the accept loop).
        self.entries.retain(|e| {
            let kept = prepared.iter().any(|(cfg, fresh)| {
                fresh.is_none() && cfg.listen == e.listen && cfg.name == current_cfg(&e.cfg).name
            });
            if kept {
                true
            } else {
                summary.removed += 1;
                false
            }
        });
        for (cfg, fresh) in prepared {
            let name = cfg.name.clone();
            match fresh {
                None => {
                    // Kept socket: swap the config new connections see.
                    let entry = self
                        .entries
                        .iter_mut()
                        .find(|e| e.listen == cfg.listen && current_cfg(&e.cfg).name == name)
                        .expect("kept entry present (phase 1 matched it)");
                    *entry
                        .cfg
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(cfg);
                    summary.kept += 1;
                }
                Some(listener) => {
                    self.entries
                        .push(make_entry(cfg, listener, Arc::clone(&self.metrics)));
                    summary.added += 1;
                }
            }
        }
        self.spawn_health();
        Ok(summary)
    }

    /// (Re)starts the health tasks (B11) for the current config: one per
    /// backend with configured checks, shared across listeners that share
    /// the backend (same [`Balancer`] Arc).
    fn spawn_health(&mut self) {
        self.health_stop.trigger();
        self.health_tasks.abort_all();
        let (stop, shutdown) = eqproxy_core::shutdown::channel();
        self.health_stop = stop;
        let mut seen: Vec<Arc<Balancer>> = Vec::new();
        for entry in &self.entries {
            let cfg = current_cfg(&entry.cfg);
            let backend = &cfg.backend;
            let Some(check) = backend.health_check.clone() else {
                continue;
            };
            let balancer = Arc::clone(&backend.balancer);
            if seen.iter().any(|s| Arc::ptr_eq(s, &balancer)) {
                continue;
            }
            seen.push(Arc::clone(&balancer));
            self.health_tasks
                .spawn(health::run(balancer, check, shutdown.clone()));
        }
    }

    /// Serves until the shutdown signal; then drains until `grace`.
    pub async fn serve(self, shutdown: Shutdown, grace: Duration) -> Result<(), ProxyError> {
        // No reload source: the channel stays silent for the whole life
        // of the dataplane.
        let (_reload_tx, reload_rx) = tokio::sync::mpsc::channel(1);
        self.serve_with_reloads(shutdown, grace, reload_rx).await
    }

    /// Serves until the shutdown signal, applying the validated config
    /// swaps that arrive through `reloads` (S-CFG-01). A rejected swap
    /// keeps serving the running config; a closed channel only disables
    /// the reloads.
    pub async fn serve_with_reloads(
        mut self,
        mut shutdown: Shutdown,
        grace: Duration,
        mut reloads: tokio::sync::mpsc::Receiver<Vec<ResolvedListener>>,
    ) -> Result<(), ProxyError> {
        loop {
            tokio::select! {
                _ = shutdown.wait() => break,
                // `Some(..)`: when the channel closes, this branch is
                // disabled and only shutdown is left.
                Some(listeners) = reloads.recv() => {
                    // The swap latency is measured (PP-04/05), not assumed.
                    let started = std::time::Instant::now();
                    match self.apply(listeners).await {
                        Ok(summary) => {
                            let elapsed = started.elapsed();
                            self.metrics.config_reloads.fetch_add(1, Ordering::Relaxed);
                            self.metrics.config_reload_duration_us.store(
                                u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
                                Ordering::Relaxed,
                            );
                            eprintln!("INFO config reload applied: {summary} in {elapsed:?}");
                        }
                        Err(err) => {
                            self.metrics.config_reload_failures.fetch_add(1, Ordering::Relaxed);
                            eprintln!("ERROR config reload rejected: {err}");
                        }
                    }
                }
            }
        }

        // Accept loops return instantly on the triggered signal.
        for entry in &self.entries {
            entry.stop.trigger();
        }
        self.health_stop.trigger();
        let _ = tokio::time::timeout(grace, async {
            for entry in &mut self.entries {
                let _ = (&mut entry.task).await;
            }
        })
        .await;
        for entry in &mut self.entries {
            entry.task.abort();
        }
        self.health_tasks.abort_all();

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

/// First duplicate explicit listen address (two listeners sharing one
/// address can never both bind; startup fails the same way). Port 0 is
/// exempt: each resolves its own ephemeral port. Pure (unit-tested).
fn find_duplicate_addr(listeners: &[ResolvedListener]) -> Option<(String, SocketAddr)> {
    let mut seen: Vec<SocketAddr> = Vec::new();
    for cfg in listeners {
        if cfg.listen.port() == 0 {
            continue;
        }
        if seen.contains(&cfg.listen) {
            return Some((cfg.name.clone(), cfg.listen));
        }
        seen.push(cfg.listen);
    }
    None
}

async fn accept_loop(
    listener: Arc<TcpListener>,
    shared: SharedCfg,
    name: String,
    metrics: Arc<Metrics>,
    mut shutdown: Shutdown,
) {
    loop {
        tokio::select! {
            _ = shutdown.wait() => break,
            accepted = listener.accept() => {
                let (socket, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        // Transient error (EMFILE, etc.): log and continue,
                        // with a small breather to avoid saturating the CPU.
                        eprintln!("ERROR [{name}] accept failed: {err}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                // Config in force at accept time (S-CFG-01): established
                // connections keep it until they drain.
                let cfg = (*current_cfg(&shared)).clone();
                if !metrics.try_acquire_connection(cfg.maxconn) {
                    metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                    // Explicit refusal: immediate close, no queue.
                    drop(socket);
                    continue;
                }
                metrics.connections_accepted.fetch_add(1, Ordering::Relaxed);
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

/// Picks a server honoring active health state (B11) and excluding servers
/// that already failed this exchange (B-H7: `pick_except`).
///
/// Pure selection: `NoServer` when everything is down/drained or already
/// tried. Counting `no_available_server` is the caller's job (once per
/// rejected exchange, never per queue poll).
fn select_server(
    cfg: &ResolvedListener,
    exclude: &[SocketAddr],
) -> Result<SocketAddr, OutboundError> {
    let backend = &cfg.backend;
    if exclude.is_empty() {
        backend.balancer.pick()
    } else {
        backend.balancer.pick_except(exclude)
    }
    .ok_or(OutboundError::NoServer)
}

/// Passive health (B12/B-N10): a connect-phase failure feeds the balancer's
/// fall counter (same threshold as the active checker), so a dead server is
/// not hammered in a loop. **Opt-in + safe-restart rule:** only when the
/// backend sets `passive = true` AND an active checker exists that can bring
/// the server back (its `rise` transition clears the mark) — without a
/// checker a passive DOWN would be permanent.
fn report_passive(cfg: &ResolvedListener, addr: SocketAddr) {
    let backend = &cfg.backend;
    if backend
        .health_check
        .as_ref()
        .is_some_and(|check| check.passive)
    {
        backend.balancer.report_fail(addr);
    }
}

/// Connects to the balancer-chosen backend: TCP + optional TLS (A12) +
/// optional PROXY v1 header (A9), with B-H7 retry/queue semantics.
///
/// Retry rule: connect-phase failures only (nothing was sent to any backend
/// yet), idempotent exchanges unless the explicit opt-in; the failed server
/// is excluded from redials. With no server up: bounded wait in the backend
/// queue (or explicit rejection when configured/off).
///
/// `use_pool` enables A16 reuse (HTTP keep-alive); the pool checkout runs
/// on the very pick that would be dialed — a separate pick would steal the
/// round-robin turn of another server and silently starve it.
async fn dial_with_retries(
    cfg: &ResolvedListener,
    peer: SocketAddr,
    local: SocketAddr,
    metrics: &Metrics,
    ctx: RetryContext,
    use_pool: bool,
) -> Result<BackendConn, OutboundError> {
    let backend = &cfg.backend;
    let max_attempts = if backend.retries.allows(ctx.idempotent) {
        backend.retries.max
    } else {
        0
    };
    let mut tried: Vec<SocketAddr> = Vec::new();
    loop {
        // --- Server selection (B11 active state; B-H7 exclusion) ---
        let addr = match select_server(cfg, &tried) {
            Ok(addr) => addr,
            Err(OutboundError::NoServer) if !tried.is_empty() => {
                // Every candidate already failed this exchange: the class is
                // "the chosen server failed" (HTTP → 502), not "nothing up".
                return Err(OutboundError::Connect);
            }
            Err(OutboundError::NoServer) => {
                // Nothing up/drained now: bounded queue (B-H7) or reject.
                let Some(queue) = &backend.queue else {
                    metrics.no_available_server.fetch_add(1, Ordering::Relaxed);
                    return Err(OutboundError::NoServer);
                };
                let Some(_permit) = queue.enter() else {
                    metrics.queue_full.fetch_add(1, Ordering::Relaxed);
                    return Err(OutboundError::QueueFull);
                };
                let deadline = tokio::time::Instant::now() + queue.settings.timeout;
                let result = tokio::time::timeout_at(deadline, async {
                    loop {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        if let Ok(addr) = select_server(cfg, &[]) {
                            return addr;
                        }
                    }
                })
                .await;
                match result {
                    Ok(addr) => addr,
                    Err(_) => {
                        metrics.queue_timeout.fetch_add(1, Ordering::Relaxed);
                        return Err(OutboundError::QueueTimeout);
                    }
                }
            }
            Err(err) => return Err(err),
        };

        // --- Pool reuse first (A16), first attempt only ---
        if use_pool
            && tried.is_empty()
            && let Some((read, write)) = backend.pool.checkout(&addr, Instant::now())
        {
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

        // --- Dial the chosen server ---
        match connect_backend_to(cfg, addr, peer, local, metrics).await {
            Ok((read, write)) => {
                metrics
                    .backend_connections_opened
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(BackendConn {
                    addr,
                    read: BufReader::new(read),
                    write,
                    reused: false,
                });
            }
            Err(OutboundError::Connect) => {
                tried.push(addr);
                // Passive mark (when safe to restart) + exclusion.
                report_passive(cfg, addr);
                if tried.len() as u32 > max_attempts {
                    // Retry budget spent: final error.
                    return Err(OutboundError::Connect);
                }
                metrics.retry_attempts.fetch_add(1, Ordering::Relaxed);
            }
            Err(err) => return Err(err),
        }
    }
}

/// Connects to the balancer-chosen backend (TCP/TLS + PROXY send).
pub async fn connect_backend(
    cfg: &ResolvedListener,
    peer: SocketAddr,
    local: SocketAddr,
    metrics: &Metrics,
) -> Result<(BoxRead, BoxWrite), OutboundError> {
    // TCP has no replay-safety knowledge: conservative non-idempotent,
    // and no pooling (streams have no message boundaries).
    let conn = dial_with_retries(
        cfg,
        peer,
        local,
        metrics,
        RetryContext::non_idempotent(),
        false,
    )
    .await?;
    Ok((Box::new(conn.read), conn.write))
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
/// balancer-chosen server, with B-H7 retry/queue semantics.
///
/// `ctx` decides retry safety (idempotent unless explicit opt-in).
pub async fn checkout_or_connect(
    cfg: &ResolvedListener,
    peer: SocketAddr,
    local: SocketAddr,
    metrics: &Metrics,
    ctx: RetryContext,
) -> Result<BackendConn, OutboundError> {
    // Pool checkout runs on the very pick that would be dialed (inside
    // `dial_with_retries`): one request, one pick, one connection (B-H7).
    dial_with_retries(cfg, peer, local, metrics, ctx, true).await
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
                "ERROR [{}] could not connect to {} (peer {peer}): {err}",
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
    mut client: TcpStream,
    peer: SocketAddr,
    cfg: ResolvedListener,
    metrics: Arc<Metrics>,
) {
    let _guard = ConnectionGuard {
        metrics: Arc::clone(&metrics),
    };
    let _ = client.set_nodelay(true);
    let local = client.local_addr().unwrap_or(cfg.listen);

    // PROXY v1 reception (B-H9/B-E10): strict front door — only
    // allowlisted origins, only valid lines, always bounded. The claimed
    // address becomes the peer for XFF, logs and PROXY send.
    let peer = if let Some(allowlist) = &cfg.proxy_receive {
        match proxy_proto::read_v1(&mut client, peer, allowlist, cfg.client_header_timeout).await {
            Ok(claimed) => claimed,
            Err(err) => {
                match err {
                    proxy_proto::ProxyReceiveError::Denied => {
                        metrics
                            .proxy_protocol_denied
                            .fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "WARN [{}] PROXY v1 from non-allowlisted origin {peer}: connection rejected",
                            cfg.name
                        );
                    }
                    proxy_proto::ProxyReceiveError::Invalid => {
                        metrics
                            .proxy_protocol_invalid
                            .fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "WARN [{}] invalid PROXY v1 header from {peer}: connection rejected",
                            cfg.name
                        );
                    }
                    proxy_proto::ProxyReceiveError::Timeout => {
                        metrics
                            .proxy_protocol_invalid
                            .fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "WARN [{}] PROXY v1 header from {peer} timed out after {:?}: connection rejected",
                            cfg.name, cfg.client_header_timeout
                        );
                    }
                }
                return;
            }
        }
    } else {
        peer
    };

    // TLS termination (A11): the handshake lives in the client phase.
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
                    "ERROR [{}] failed client TLS handshake (peer {peer}): {err}",
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
        Err(OutboundError::NoServer | OutboundError::QueueFull | OutboundError::QueueTimeout) => {
            // TCP mode has no response channel: explicit close (logged).
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

/// Copies `reader → writer` with a per-read inactivity timeout.
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
            client.write_all(b"hello").await.expect("write");
            drop(client); // EOF
            let copied = tokio::time::timeout(Duration::from_secs(2), copier)
                .await
                .expect("the copier must finish")
                .expect("join")
                .expect("no error on EOF");
            assert_eq!(copied, 5);
            assert_eq!(bytes.load(Ordering::Relaxed), 5);
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

    #[test]
    fn swap_summary_renders_the_three_counts() {
        let summary = SwapSummary {
            kept: 1,
            added: 2,
            removed: 3,
        };
        assert_eq!(summary.to_string(), "listeners kept=1 added=2 removed=3");
    }

    /// Builds a listener without sockets (pure: miri-safe).
    fn listener(name: &str, listen: &str) -> ResolvedListener {
        ResolvedListener::new(
            name,
            listen.parse().expect("listen"),
            "backend",
            "127.0.0.1:9000".parse().expect("server"),
            ProxyMode::Tcp,
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
    }

    #[test]
    fn duplicate_explicit_addresses_are_detected_and_port_zero_is_exempt() {
        let a = listener("a", "127.0.0.1:8080");
        let b = listener("b", "127.0.0.1:8080");
        let z1 = listener("z1", "127.0.0.1:0");
        let z2 = listener("z2", "127.0.0.1:0");
        let addr: SocketAddr = "127.0.0.1:8080".parse().expect("addr");

        assert_eq!(
            find_duplicate_addr(&[a.clone(), b.clone()]),
            Some(("b".to_owned(), addr))
        );
        // Two ephemeral listeners are legal: each gets its own port.
        assert_eq!(find_duplicate_addr(&[z1, z2]), None);
        assert_eq!(find_duplicate_addr(&[a]), None);
        assert_eq!(find_duplicate_addr(&[]), None);
    }
}
