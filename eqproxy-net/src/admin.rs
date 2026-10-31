//! Administration plane (v0.8, D6): read API, Prometheus metrics and the
//! first write path — per-server administration state (ADR-0018).
//!
//! Scope: `GET /api/v1/status`, `GET /metrics`, the per-server state write
//! (`PUT /api/v1/backends/{backend}/servers/{target}/state` with
//! `{"state":"ready"|"drain"}`, ADR-0018), the configuration writes
//! (`PUT /api/v1/backends/{name}` and `PUT /api/v1/listeners/{name}`, ADR-0019)
//! and the certificate renewal action
//! (`POST /api/v1/certificates/reload`, ADR-0025).
//! The read token opens the two `GET`s; the write token is required for every
//! `PUT` and the renewal (and may also read). Without a write token the whole
//! plane stays read-only and every write is `403 write_disabled` — absent
//! means off, never an implicit grant.
//!
//! Authorization is per route (RBAC with two roles), and every write leaves
//! one `AUDIT` JSON line on stderr with its method, outcome, peer and the
//! transition it caused. The token never appears in a response or a log line.
//!
//! CSRF does not apply to a bearer-token JSON API (there is no cookie the
//! browser would attach), but a browser page can still reach a loopback
//! socket (DNS rebinding): a request carrying `Origin` is refused, and the
//! write requires a declared media type, which a cross-origin simple request
//! cannot send without a preflight — and no CORS headers are served. A
//! server-state write is a declared-state `PUT`, so it needs no `If-Match`;
//! a configuration write replaces a live table and therefore **does** require
//! `If-Match` with the revision from `GET /api/v1/status` (no lost update).
//!
//! Isolation (SPEC §9: the panel is not required to operate the proxy): the
//! plane is a separate socket and accept loop, spawned as a task the
//! dataplane never awaits. If it dies or refuses connections, proxied traffic
//! is untouched; `AdminHandle` only exists so the CLI can stop it on shutdown.
//!
//! Secrets: both tokens are compared in constant time and never appear in a
//! response, a log line or an error body. Loopback is the default TCP bind and
//! a non-loopback one is rejected by validation unless `allow_remote` is set,
//! because this slice has no TLS on the plane. The alternative endpoint is a
//! Unix domain socket with mode `0600` (ADR-0021): the filesystem gates who
//! can connect, the same bearer token still gates every route, a live socket
//! is never stolen, a stale one from a crash is replaced, and a clean
//! shutdown removes only the file this process created. The socket's mode,
//! owning group and peer-uid allowlist are **hot**: a SIGHUP applies them to
//! the socket already bound (ADR-0022), with the previous policy restored
//! when the new one cannot be written.

use std::fmt;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, RwLock, RwLockReadGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};

use eqproxy_core::{Metrics, Shutdown, shutdown};

use crate::balancer::{ServerMode, ServerModes};
use crate::proxy::ResolvedBackend;

/// Maximum request head accepted (request line + headers). Larger heads are
/// refused with `431`, never buffered.
pub const MAX_ADMIN_HEAD_BYTES: usize = 8 * 1024;

/// Maximum body accepted by the per-server state route. The only body there
/// is `{"state":"drain"}` (17 bytes); anything larger is refused with `413`.
pub const MAX_ADMIN_BODY_BYTES: usize = 1024;

/// Maximum body accepted by the configuration routes (`PUT` of a backend or
/// listener table, in TOML). A whole `[backend.*]` table is small; 64 KiB is
/// generous and still a hard bound.
pub const MAX_CONFIG_BODY_BYTES: usize = 64 * 1024;

/// Deadline of one admin exchange (read of the head and body, write of the
/// answer).
pub const ADMIN_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Concurrent admin connections kept open. Above it a new connection is
/// closed immediately: the plane is bounded like every other resource.
pub const MAX_ADMIN_CONNECTIONS: usize = 64;

/// Where the admin plane listens (ADR-0021).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminEndpoint {
    /// TCP address, loopback unless validation allowed otherwise.
    Tcp(SocketAddr),
    /// Unix domain socket created with mode `0600`.
    Unix(PathBuf),
}

impl fmt::Display for AdminEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(addr) => write!(formatter, "{addr}"),
            Self::Unix(path) => write!(formatter, "unix:{}", path.display()),
        }
    }
}

/// Unix socket policy (ADR-0021/0022/0023). `mode` is `0o600` by default;
/// `0o660` requires `gid`, the group that will own the file. A non-empty
/// `allow_uids` is checked against the kernel's peer credentials before any
/// HTTP byte is read; an unknown uid is refused, never allowed by default.
/// `acl_uids` are **named users in the file's POSIX ACL** (Linux): the kernel
/// admits them at `connect`, in addition to the owning group, without
/// widening that group.
#[derive(Clone, Debug)]
pub struct UnixSocketOptions {
    pub mode: u32,
    pub gid: Option<u32>,
    pub allow_uids: Arc<[u32]>,
    pub acl_uids: Arc<[u32]>,
}

impl Default for UnixSocketOptions {
    fn default() -> Self {
        Self {
            mode: 0o600,
            gid: None,
            allow_uids: Arc::from([]),
            acl_uids: Arc::from([]),
        }
    }
}

/// Live Unix socket policy (ADR-0022, v0.8): the mode, owning group and
/// peer-uid allowlist of the socket a running plane already bound.
///
/// [`AdminHandle`] hands one out for a Unix endpoint, and that is all the
/// configuration task needs to change the policy on SIGHUP: the listener, the
/// accept loop and the dataplane are untouched, because only the file's bits
/// and the list the accept loop consults move. A TCP plane has no policy at
/// all, so the two cannot be confused.
#[derive(Clone, Debug)]
pub struct UnixSocketPolicy {
    path: PathBuf,
    /// Read once per accepted connection (a cheap `Arc` clone), written only
    /// by [`Self::apply`]. No lock is held across an await.
    state: Arc<RwLock<UnixSocketOptions>>,
}

impl UnixSocketPolicy {
    fn new(path: PathBuf, options: UnixSocketOptions) -> Self {
        Self {
            path,
            state: Arc::new(RwLock::new(options)),
        }
    }

    /// Policy in force for the next accepted peer and the next write.
    #[must_use]
    pub fn options(&self) -> UnixSocketOptions {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn allow_uids(&self) -> Arc<[u32]> {
        Arc::clone(
            &self
                .state
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .allow_uids,
        )
    }

    /// Applies `next` to the live socket and to the allowlist the accept loop
    /// reads. All-or-nothing: `chown` runs first (it can clear mode bits),
    /// then `chmod`; a failure restores the previous ownership and mode and
    /// leaves the allowlist untouched, so a rejected reload never leaves a
    /// socket half-widened.
    ///
    /// A few syscalls on a path this process created, called from the
    /// configuration task between swaps, never from the accept loop.
    pub fn apply(&self, next: &UnixSocketOptions) -> std::io::Result<()> {
        let current = self.options();
        if (current.gid != next.gid
            || current.mode != next.mode
            || current.acl_uids != next.acl_uids)
            && let Err(error) = write_file_policy(&self.path, next)
        {
            if let Err(restore) = write_file_policy(&self.path, &current) {
                eprintln!(
                    "WARN admin socket {} could not be restored to mode {:04o}: {restore}",
                    self.path.display(),
                    current.mode
                );
            }
            return Err(error);
        }
        *self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = next.clone();
        Ok(())
    }
}

/// Writes the file half of a policy: group first (a `chown` may clear mode
/// bits), then the exact mode, then the access ACL. `None` leaves the group as
/// it is: mode `0600` already gates access to the owner, so reverting to it
/// needs no group lookup. One implementation for the first bind and every
/// reload, so the two cannot drift.
#[cfg(unix)]
fn write_file_policy(path: &Path, options: &UnixSocketOptions) -> std::io::Result<()> {
    if let Some(gid) = options.gid {
        std::os::unix::fs::chown(path, None, Some(gid))?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(options.mode))?;
    // Last, because `chmod` rewrites the ACL mask; an empty list removes the
    // attribute so a reload cannot leave a named user behind.
    crate::unix_acl::set_access(path, &options.acl_uids)
}

/// A Unix policy cannot exist where the endpoint itself cannot be bound; the
/// stub keeps [`UnixSocketPolicy::apply`] compiling on those targets.
#[cfg(not(unix))]
fn write_file_policy(_path: &Path, _options: &UnixSocketOptions) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Unix domain sockets are not supported on this platform",
    ))
}

/// Resolved admin plane: where it listens and the secrets it demands.
#[derive(Clone)]
pub struct ResolvedAdmin {
    pub endpoint: AdminEndpoint,
    /// Only consulted for [`AdminEndpoint::Unix`].
    pub unix: UnixSocketOptions,
    pub token: Arc<str>,
    /// `None` = writes disabled (the plane is read-only).
    pub write_token: Option<Arc<str>>,
    /// `[admin] panel` (ADR-0029): serve the web panel on this plane.
    pub panel: bool,
}

/// One listener as the API reports it (from the validated config).
#[derive(Debug, Clone, Serialize)]
pub struct ListenerInfo {
    pub name: String,
    pub listen: String,
    pub mode: String,
    pub backend: String,
    pub maxconn: u32,
    /// `sha256:<hex>` of the certificate this listener is serving (D7);
    /// `null` for a plain-TCP listener. Read from the live acceptor, so it is
    /// the certificate on the wire, not the file the config names.
    pub tls_fingerprint: Option<String>,
}

/// One listener's certificate in the answer of a renewal (D7).
#[derive(Debug, Clone, Serialize)]
pub struct CertificateInfo {
    pub listener: String,
    pub listen: String,
    /// `sha256:<hex>` of the leaf served after the reload.
    pub fingerprint: String,
    /// `true` when this reload changed what the listener serves.
    pub changed: bool,
    /// `true` when the same address also serves HTTP/3.
    pub quic: bool,
}

/// The applied topology the plane reports, replaced only after a swap has
/// **committed**. Kept behind a lock so the status read and the config write
/// never disagree about which generation is serving.
#[derive(Debug)]
pub struct AdminTopology {
    /// Opaque revision of the applied configuration (the value `If-Match`
    /// takes and `ETag` returns). Changes on every committed apply/reload.
    pub revision: String,
    pub listeners: Vec<ListenerInfo>,
    /// One entry per validated backend, in configuration order. The balancer
    /// inside each one answers with its live health and in-flight count.
    pub backends: Vec<Arc<ResolvedBackend>>,
    /// Live response caches, one per listener with `[listener.*.cache]`
    /// (B-N7/H1). The `Arc` is the serving instance, so `GET /api/v1/cache`
    /// reports what is actually stored, not the configuration that asked
    /// for it.
    pub caches: Vec<Arc<crate::cache::Cache>>,
}

/// What the API serves. The counters and the per-server state are live
/// (`Metrics`, `Balancer` and the shared [`ServerModes`]); the topology is a
/// snapshot of the last **committed** generation.
#[derive(Debug)]
pub struct AdminState {
    pub version: &'static str,
    pub started: Instant,
    pub topology: Arc<RwLock<AdminTopology>>,
    /// Shared administration state (ADR-0018): the same registry the
    /// balancers consult, so a `drain` is in force for new picks at once and
    /// survives a reload.
    pub modes: Arc<ServerModes>,
    pub metrics: Arc<Metrics>,
    /// Configuration write pipeline (ADR-0019). `None` = no applier attached:
    /// configuration `PUT`s answer `503 config_unavailable`.
    pub apply: Option<mpsc::Sender<ApplyMessage>>,
    /// Web panel (ADR-0029). `None` = `[admin] panel` is off and every
    /// `/panel` path is a `404` like any other unknown route.
    pub panel: Option<Arc<crate::panel::Panel>>,
}

impl AdminState {
    pub(crate) fn read_topology(&self) -> RwLockReadGuard<'_, AdminTopology> {
        self.topology
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// One configuration mutation requested through the API. The body is the
/// **table body**, not a whole document: the same TOML a `[backend.name]` or
/// `[listener.name]` section holds.
#[derive(Debug)]
pub enum ConfigChange {
    Backend {
        name: String,
        table: String,
    },
    Listener {
        name: String,
        table: String,
    },
    /// Re-read the configuration and its certificate files: SIGHUP and
    /// `POST /api/v1/certificates/reload` (D7).
    Reload,
}

impl ConfigChange {
    /// `backend` or `listener` (audit and error wording).
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Backend { .. } => "backend",
            Self::Listener { .. } => "listener",
            Self::Reload => "reload",
        }
    }
}
/// A mutation waiting for the configuration task (single consumer, which is
/// what serializes revision checks and swaps).
pub struct ApplyMessage {
    pub change: ConfigChange,
    pub if_match: Option<String>,
    pub reply: oneshot::Sender<ApplyReply>,
}

/// Answer of the configuration task. `Applied` is sent only after the
/// dataplane committed the candidate, so a `200` is not optimistic.
#[derive(Debug)]
pub enum ApplyReply {
    Applied {
        revision: String,
        summary: String,
        elapsed_ms: u64,
        listeners: Vec<(String, String)>,
        /// Certificate identity per TLS listener after the swap (D7).
        certificates: Vec<CertificateInfo>,
    },
    /// The candidate is valid but its base revision is stale.
    Precondition { revision: String },
    /// The candidate cannot be parsed or validated; nothing was swapped.
    Invalid { message: String },
    /// The dataplane refused the swap (bind conflict, etc.); nothing changed.
    Rejected { message: String },
}

/// Body of `GET /api/v1/status`.
#[derive(Serialize)]
struct Status<'a> {
    version: &'a str,
    uptime_seconds: u64,
    /// Applied configuration revision (`If-Match`/`ETag`).
    revision: &'a str,
    listeners: &'a [ListenerInfo],
    backends: Vec<BackendStatus<'a>>,
    /// Opt-in per-server/per-route series plus the budget that bounds them
    /// (CE4): `enabled`, `budget`, `series`, `dropped` and the rows.
    metrics_detail: eqproxy_core::metrics::DetailSnapshot,
    counters: eqproxy_core::MetricsSnapshot,
}

#[derive(Serialize)]
struct BackendStatus<'a> {
    name: &'a str,
    balance: &'static str,
    /// `option allbackups` (B8): the whole backup tier balances at once
    /// instead of serving one rung at a time. The read plane says which
    /// policy is live, so an operator can tell the two modes apart.
    all_backups: bool,
    health_check: bool,
    servers: Vec<ServerStatus>,
}

/// One server slot: the configured target plus its **live** state.
#[derive(Serialize)]
struct ServerStatus {
    /// Configured target (`HOSTNAME:PORT` or `IP:PORT`): the key of the
    /// write route, stable across DNS changes.
    addr: String,
    /// Address currently in use (`null` while a name is unresolved).
    resolved: Option<String>,
    weight: u32,
    /// Backup class (B8): selected only when no primary is eligible.
    backup: bool,
    /// Failover order among backups (EQProxy extension): higher first, ties
    /// by configuration order; `0` on primaries.
    priority: u32,
    /// `ready` or `drain` (ADR-0018).
    state: &'static str,
    /// Health machine (B11), independent of `state`.
    healthy: bool,
    /// Exchanges in flight on this slot.
    active: u32,
    /// `true` when the slot is drained and nothing is in flight on it any
    /// more: the drain finished (H3). Always `false` for a `ready` slot.
    drained: bool,
}

/// Running admin plane: stop it on shutdown, or abort it to prove the
/// dataplane does not depend on it.
pub struct AdminHandle {
    endpoint: AdminEndpoint,
    stop: eqproxy_core::ShutdownHandle,
    task: Option<JoinHandle<()>>,
    /// The socket file this process created, removed on a clean drop when it
    /// is still the same inode (never somebody else's file).
    #[cfg(unix)]
    socket_file: Option<SocketFile>,
    /// Mode, group and peer-uid allowlist of a Unix socket; `None` for TCP,
    /// which has no such policy to reload.
    unix_policy: Option<UnixSocketPolicy>,
}

impl AdminHandle {
    /// Endpoint actually bound (port 0 resolves an ephemeral one).
    #[must_use]
    pub fn endpoint(&self) -> &AdminEndpoint {
        &self.endpoint
    }

    /// Bound TCP address, `None` when the plane is on a Unix socket.
    #[must_use]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        match self.endpoint {
            AdminEndpoint::Tcp(addr) => Some(addr),
            AdminEndpoint::Unix(_) => None,
        }
    }

    /// Bound Unix socket path, `None` when the plane is on TCP.
    #[must_use]
    pub fn socket_path(&self) -> Option<&Path> {
        match &self.endpoint {
            AdminEndpoint::Tcp(_) => None,
            AdminEndpoint::Unix(path) => Some(path),
        }
    }

    /// Hot policy of a Unix plane, `None` for TCP. Cloning the returned handle
    /// keeps the same cell, so [`UnixSocketPolicy::apply`] reaches the accept
    /// loop that is already running.
    #[must_use]
    pub fn unix_policy(&self) -> Option<&UnixSocketPolicy> {
        self.unix_policy.as_ref()
    }

    /// Stops the accept loop and waits for it. Dropping `self` then removes
    /// the Unix socket file when this process still owns it.
    pub async fn shutdown(mut self) {
        self.stop.trigger();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }

    /// Simulates the plane dying (test seam): the dataplane must keep
    /// serving, which is what SPEC §9 requires of the panel. Aborting the
    /// task leaves a Unix socket file behind, exactly like a crash; the next
    /// bind recognises it as stale and replaces it (a later drop of the
    /// handle still removes the file).
    pub fn abort(&self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

impl Drop for AdminHandle {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(file) = &self.socket_file {
            file.remove_if_ours();
        }
    }
}

/// Binds the admin listener. Unlike the dataplane, failing to bind here is
/// fatal for the process: a configured plane that cannot open is a
/// configuration error, not a silent downgrade (the CLI exits with 1).
pub async fn bind(cfg: ResolvedAdmin, state: Arc<AdminState>) -> std::io::Result<AdminHandle> {
    let tokens = Tokens {
        read: cfg.token,
        write: cfg.write_token,
    };
    match cfg.endpoint {
        AdminEndpoint::Tcp(addr) => {
            let listener = TcpListener::bind(addr).await?;
            let local = listener.local_addr()?;
            let (stop, shutdown) = shutdown::channel();
            let task = tokio::spawn(serve(
                AdminListener::Tcp(listener),
                tokens,
                state,
                None,
                shutdown,
            ));
            Ok(AdminHandle {
                endpoint: AdminEndpoint::Tcp(local),
                stop,
                task: Some(task),
                #[cfg(unix)]
                socket_file: None,
                unix_policy: None,
            })
        }
        AdminEndpoint::Unix(path) => bind_unix(path, cfg.unix, tokens, state).await,
    }
}

/// Binds the Unix socket (ADR-0021/0022): refuses to steal a live one,
/// replaces a stale socket left by a crash, never deletes a file that is not
/// a socket, and applies the configured owner/group mode (`0600` by default,
/// `0660` with a group).
#[cfg(unix)]
async fn bind_unix(
    path: PathBuf,
    unix: UnixSocketOptions,
    tokens: Tokens,
    state: Arc<AdminState>,
) -> std::io::Result<AdminHandle> {
    prepare_socket_path(&path)?;
    let listener = UnixListener::bind(&path)?;
    let file = match SocketFile::capture(&path) {
        Ok(file) => file,
        Err(error) => {
            // The bind already failed; report the cleanup failure without
            // replacing the error that explains why startup is aborting.
            if let Err(cleanup) = std::fs::remove_file(&path) {
                eprintln!(
                    "WARN admin cannot remove {} after a failed bind: {cleanup}",
                    path.display()
                );
            }
            return Err(error);
        }
    };
    // Group, mode and ACL in one place, shared with the reload path. An
    // unprivileged process may only select a group it belongs to and only
    // write an ACL its filesystem supports; a failure here aborts startup
    // instead of serving a wider (or differently gated) socket.
    if let Err(error) = write_file_policy(&path, &unix) {
        drop(listener);
        file.remove_if_ours();
        return Err(error);
    }
    let (stop, shutdown) = shutdown::channel();
    let policy = UnixSocketPolicy::new(path.clone(), unix);
    let task = tokio::spawn(serve(
        AdminListener::Unix(listener),
        tokens,
        state,
        Some(policy.clone()),
        shutdown,
    ));
    Ok(AdminHandle {
        endpoint: AdminEndpoint::Unix(path),
        stop,
        task: Some(task),
        socket_file: Some(file),
        unix_policy: Some(policy),
    })
}

#[cfg(not(unix))]
async fn bind_unix(
    _path: PathBuf,
    _unix: UnixSocketOptions,
    _tokens: Tokens,
    _state: Arc<AdminState>,
) -> std::io::Result<AdminHandle> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Unix domain sockets are not supported on this platform",
    ))
}

/// Clears the path for a new socket: absent is fine, a live socket is a
/// conflict, a stale socket is replaced, and any other file is preserved.
#[cfg(unix)]
fn prepare_socket_path(path: &Path) -> std::io::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{} exists and is not a socket; refusing to remove it",
                path.display()
            ),
        ));
    }
    // A socket with a listener answers; one left by a crash refuses. Only
    // the second is ours to replace.
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            format!("{} is already served by another process", path.display()),
        )),
        Err(_) => std::fs::remove_file(path),
    }
}

/// Identity of the socket file this process created, so cleanup can prove it
/// is still the same inode before unlinking.
#[cfg(unix)]
struct SocketFile {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

#[cfg(unix)]
impl SocketFile {
    fn capture(path: &Path) -> std::io::Result<Self> {
        let metadata = std::fs::symlink_metadata(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }

    fn remove_if_ours(&self) {
        let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.dev() == self.dev
            && metadata.ino() == self.ino
            && let Err(error) = std::fs::remove_file(&self.path)
        {
            // Best effort during drop, but not silent: a socket file that
            // survives shutdown makes the next start recover it as stale.
            eprintln!(
                "WARN admin cannot remove socket {}: {error}",
                self.path.display()
            );
        }
    }
}

/// The configured secrets. `write = None` disables every write.
#[derive(Clone)]
pub(crate) struct Tokens {
    read: Arc<str>,
    write: Option<Arc<str>>,
}

impl Tokens {
    /// Whether a write secret is configured at all: the panel answers
    /// `write_disabled` (the plane is read-only) or `read_only_session` (this
    /// session holds the read token) on that distinction.
    pub(crate) fn write_configured(&self) -> bool {
        self.write.is_some()
    }

    /// `(role, authenticated)`: both secrets are compared even after a match,
    /// so a timing observer cannot learn which one was tried.
    pub(crate) fn role(&self, present: Option<&str>) -> Role {
        let Some(secret) = present else {
            return Role::None;
        };
        let read = token_matches(&self.read, secret);
        let write = self
            .write
            .as_deref()
            .is_some_and(|token| token_matches(token, secret));
        if write {
            Role::Write
        } else if read {
            Role::Read
        } else {
            Role::None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    None,
    Read,
    Write,
}

impl Role {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Read => "read",
            Self::Write => "operate",
        }
    }
}

/// One bound listener: the accept path and the peer identity are the only
/// differences between TCP and a Unix socket; the HTTP handling below is
/// shared.
enum AdminListener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener),
}

impl AdminListener {
    async fn accept(&self) -> std::io::Result<(AdminStream, Peer)> {
        match self {
            Self::Tcp(listener) => {
                let (stream, peer) = listener.accept().await?;
                Ok((AdminStream::Tcp(stream), Peer::Tcp(peer)))
            }
            #[cfg(unix)]
            Self::Unix(listener) => {
                let (stream, _) = listener.accept().await?;
                let uid = stream.peer_cred().ok().map(|credentials| credentials.uid());
                Ok((AdminStream::Unix(stream), Peer::Unix { uid }))
            }
        }
    }
}

/// Accepted admin connection. Both variants are byte streams; the HTTP
/// parser does not care which one carried the request.
enum AdminStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl AsyncRead for AdminStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(context, buffer),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for AdminStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(context, buffer),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_write(context, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(context),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(context),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}

/// Who is calling: the TCP peer address, or the Unix socket peer's uid when
/// the kernel reports it. The bearer token remains the authorization; this is
/// what the audit line can attest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Peer {
    Tcp(SocketAddr),
    Unix { uid: Option<u32> },
}

impl fmt::Display for Peer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(addr) => write!(formatter, "{addr}"),
            Self::Unix { uid: Some(uid) } => write!(formatter, "unix-socket:uid={uid}"),
            Self::Unix { uid: None } => write!(formatter, "unix-socket"),
        }
    }
}

/// Peer-uid policy (ADR-0022). An empty list keeps the filesystem as the only
/// boundary; a non-empty list is fail-closed: a peer whose uid the kernel did
/// not report is refused, never treated as allowed.
fn peer_allowed(peer: Peer, allow_uids: &[u32]) -> bool {
    if allow_uids.is_empty() {
        return true;
    }
    match peer {
        Peer::Unix { uid: Some(uid) } => allow_uids.contains(&uid),
        Peer::Unix { uid: None } | Peer::Tcp(_) => false,
    }
}

async fn serve(
    listener: AdminListener,
    tokens: Tokens,
    state: Arc<AdminState>,
    // `Some` only for a Unix listener: the allowlist is read per connection,
    // so a reload applies to the next peer without a rebind.
    policy: Option<UnixSocketPolicy>,
    mut shutdown: Shutdown,
) {
    let mut connections: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.wait() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    if connections.len() >= MAX_ADMIN_CONNECTIONS {
                        // Explicit refusal, never an unbounded accept queue.
                        drop(stream);
                        continue;
                    }
                    // SO_PEERCRED/getpeereid decision before any HTTP byte:
                    // an unauthorized uid gets EOF, not a route to probe. The
                    // list is snapshotted here, never held across the spawn.
                    if let Some(policy) = &policy
                        && !peer_allowed(peer, &policy.allow_uids())
                    {
                        eprintln!(
                            "WARN admin connection refused: {peer} is not in unix_socket_allow_uids"
                        );
                        drop(stream);
                        continue;
                    }
                    connections.spawn(handle_connection(
                        stream,
                        tokens.clone(),
                        Arc::clone(&state),
                        peer,
                    ));
                }
                Err(error) => {
                    // Transient (fd exhaustion, aborted accept): back off a
                    // little instead of spinning.
                    eprintln!("ERROR admin accept failed: {error}");
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            },
        }
        while connections.try_join_next().is_some() {}
    }
    connections.abort_all();
}

async fn handle_connection(
    mut stream: AdminStream,
    tokens: Tokens,
    state: Arc<AdminState>,
    peer: Peer,
) {
    let mut buffer = Vec::with_capacity(1024);
    let read = tokio::time::timeout(ADMIN_IO_TIMEOUT, async {
        read_head(&mut stream, &mut buffer).await?;
        // The head reader stops at the blank line but a single read may have
        // carried body bytes: they belong to the request, not the head.
        let Some(end) = head_end(&buffer) else {
            return Err(HeadError::Io);
        };
        let initial = buffer.split_off(end);
        let head = std::str::from_utf8(&buffer)
            .map_err(|_| HeadError::Io)?
            .to_owned();
        let mut body = None;
        // Only a `PUT` (JSON table or state) or a panel `POST` (form) carries
        // a body, and only the declared, bounded length is read. A missing or
        // oversized length is answered by the router (411/413) without
        // touching the socket again.
        if matches!(head.split(' ').next(), Some("PUT") | Some("POST"))
            && let Some(length) = content_length(&head)
            && length <= MAX_CONFIG_BODY_BYTES
        {
            // A short read is not a transport failure for the plane: the
            // answer is the explicit 400 the body validation produces.
            body = Some(
                read_body(&mut stream, length, &initial)
                    .await
                    .unwrap_or_default(),
            );
        }
        Ok((head, body))
    })
    .await;
    let (head, body) = match read {
        Ok(Ok(parsed)) => parsed,
        Ok(Err(HeadError::TooLarge)) => {
            answer(&mut stream, Response::text(431, "request head too large")).await;
            return;
        }
        // The peer closed before sending a full head: nothing to answer.
        Ok(Err(HeadError::Closed)) => return,
        Ok(Err(HeadError::Io)) => {
            answer(&mut stream, Response::text(400, "bad request")).await;
            return;
        }
        Err(_) => {
            answer(&mut stream, Response::text(408, "request timeout")).await;
            return;
        }
    };
    // `/panel` is served by the panel module when the config turned it on
    // (ADR-0029); every other path keeps the JSON API router untouched.
    let outcome = match state.panel.as_ref() {
        Some(panel) if crate::panel::wants(&head) => {
            panel.respond(&head, body.as_deref(), &tokens, &state, peer)
        }
        _ => respond(&head, body.as_deref(), &tokens, &state, peer),
    };
    match outcome {
        Outcome::Done(response, audit) => {
            log_audit(audit);
            answer(&mut stream, response).await;
        }
        Outcome::Apply {
            change,
            if_match,
            role,
            method,
            path,
            back_to_panel,
        } => {
            let (response, status) = apply_config(&state, change, if_match).await;
            log_audit(Some(audit(
                peer,
                role,
                method,
                path,
                status,
                AuditFields::default(),
            )));
            let response = if back_to_panel {
                panel_result_redirect(status, &response)
            } else {
                response
            };
            answer(&mut stream, response).await;
        }
    }
}

/// Turns the applier's answer into the page the browser comes back to: the
/// panel never shows a JSON body, and a `303` makes a reload re-read the
/// status instead of re-sending the write (ADR-0029). The error code is the
/// applier's own (`invalid_config`, `swap_rejected`, `precondition_failed`,
/// …), so the panel cannot invent a different diagnosis.
fn panel_result_redirect(status: u16, response: &Response) -> Response {
    let code = serde_json::from_slice::<serde_json::Value>(&response.body)
        .ok()
        .and_then(|value| {
            value
                .get("error")
                .and_then(|value| value.as_str())
                .map(str::to_owned)
        });
    match (status, code) {
        (200, _) => Response::redirect("/panel?applied=1"),
        (_, Some(code)) => Response::redirect(&format!("/panel?error={code}")),
        (_, None) => Response::redirect(&format!("/panel?error=http_{status}")),
    }
}

/// One durable line per write attempt, whatever the outcome. The sink is the
/// process log (collected by the supervisor/container); a file-backed sink is
/// a later slice.
fn log_audit(audit: Option<Audit<'_>>) {
    if let Some(audit) = audit
        && let Ok(line) = serde_json::to_string(&audit)
    {
        eprintln!("AUDIT {line}");
    }
}

/// Sends the mutation to the configuration task and maps its answer to HTTP.
/// The answer only arrives after the dataplane committed the swap (or refused
/// it), which is what makes a `200` mean "applied".
async fn apply_config(
    state: &AdminState,
    change: ConfigChange,
    if_match: Option<String>,
) -> (Response, u16) {
    let Some(applier) = &state.apply else {
        return (Response::error(503, "config_unavailable"), 503);
    };
    let (tx, rx) = oneshot::channel();
    if applier
        .send(ApplyMessage {
            change,
            if_match,
            reply: tx,
        })
        .await
        .is_err()
    {
        return (Response::error(503, "config_unavailable"), 503);
    }
    let reply = tokio::time::timeout(Duration::from_secs(10), rx).await;
    match reply {
        Ok(Ok(ApplyReply::Applied {
            revision,
            summary,
            elapsed_ms,
            listeners,
            certificates,
        })) => {
            let bound: Vec<serde_json::Value> = listeners
                .into_iter()
                .map(|(name, addr)| serde_json::json!({"name": name, "listen": addr}))
                .collect();
            let body = serde_json::json!({
                "revision": revision,
                "summary": summary,
                "elapsed_ms": elapsed_ms,
                "listeners": bound,
                "certificates": certificates,
            });
            let response = Response::json(200, body.to_string().into_bytes())
                .with_header("etag", format!("\"{revision}\""));
            (response, 200)
        }
        Ok(Ok(ApplyReply::Precondition { revision })) => {
            let body = serde_json::json!({
                "error": "precondition_failed",
                "revision": revision,
            });
            (
                Response::json(412, body.to_string().into_bytes())
                    .with_header("etag", format!("\"{revision}\"")),
                412,
            )
        }
        Ok(Ok(ApplyReply::Invalid { message })) => {
            let body = serde_json::json!({"error": "invalid_config", "message": message});
            (Response::json(400, body.to_string().into_bytes()), 400)
        }
        Ok(Ok(ApplyReply::Rejected { message })) => {
            let body = serde_json::json!({"error": "swap_rejected", "message": message});
            (Response::json(409, body.to_string().into_bytes()), 409)
        }
        // The applier died or did not answer: nothing was confirmed.
        Ok(Err(_)) | Err(_) => (Response::error(500, "apply_unconfirmed"), 500),
    }
}

/// Writes the answer and closes cleanly. The peer may still be sending (an
/// oversized head is refused before it ends); closing with unread input
/// turns the answer into a TCP reset, so drain briefly so the client can
/// read the status it was given.
async fn answer<S>(stream: &mut S, response: Response)
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let _ = tokio::time::timeout(ADMIN_IO_TIMEOUT, response.write(stream)).await;
    let mut sink = [0u8; 1024];
    let _ = tokio::time::timeout(Duration::from_millis(50), async {
        while let Ok(read) = stream.read(&mut sink).await {
            if read == 0 {
                break;
            }
        }
    })
    .await;
    let _ = stream.shutdown().await;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeadError {
    TooLarge,
    Closed,
    Io,
}

/// Reads until the blank line that ends an HTTP/1.x head, bounded by
/// [`MAX_ADMIN_HEAD_BYTES`].
async fn read_head<S>(stream: &mut S, head: &mut Vec<u8>) -> Result<(), HeadError>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await.map_err(|_| HeadError::Io)?;
        if read == 0 {
            return Err(HeadError::Closed);
        }
        head.extend_from_slice(&chunk[..read]);
        if head_end(head).is_some() {
            return Ok(());
        }
        if head.len() > MAX_ADMIN_HEAD_BYTES {
            return Err(HeadError::TooLarge);
        }
    }
}

/// Offset just past the `\r\n\r\n` that ends the head.
fn head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4)
}

/// Reads exactly `length` body bytes (the caller validated the bound). The
/// length comes from the head (`content-length`); chunked framing is not
/// accepted on the plane (a write body is a small JSON document, so a missing
/// length is a client error, not something to stream).
async fn read_body<S>(stream: &mut S, length: usize, initial: &[u8]) -> Result<Vec<u8>, HeadError>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut body = Vec::with_capacity(length);
    body.extend_from_slice(initial);
    while body.len() < length {
        let mut chunk = [0u8; 1024];
        let read = stream.read(&mut chunk).await.map_err(|_| HeadError::Io)?;
        if read == 0 {
            return Err(HeadError::Closed);
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(length);
    Ok(body)
}

/// `content-length` of a head; duplicate headers are ambiguous and refused.
fn content_length(head: &str) -> Option<usize> {
    let mut values = header_values(head, "content-length").into_iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.trim().parse().ok()
}

/// All values of one header, case-insensitively (head only, no folding).
pub(crate) fn header_values<'a>(head: &'a str, name: &str) -> Vec<&'a str> {
    head.split("\r\n")
        .skip(1)
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
        .collect()
}

/// `Authorization: Bearer <secret>` value, exactly one header.
fn bearer(head: &str) -> Option<&str> {
    let values = header_values(head, "authorization");
    let [value] = values.as_slice() else {
        return None;
    };
    let (scheme, secret) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| secret.trim())
}

/// One answer, built without touching the socket so it can be unit-tested.
#[derive(Debug)]
pub(crate) struct Response {
    pub(crate) status: u16,
    pub(crate) content_type: &'static str,
    pub(crate) extra: Vec<(&'static str, String)>,
    pub(crate) body: Vec<u8>,
}

impl Response {
    pub(crate) fn text(status: u16, body: &str) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            extra: Vec::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    pub(crate) fn json(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: "application/json; charset=utf-8",
            extra: Vec::new(),
            body,
        }
    }

    pub(crate) fn error(status: u16, code: &str) -> Self {
        // Machine-readable, and deliberately empty of detail: an unauthorized
        // caller learns nothing about the plane.
        let body = format!("{{\"error\":\"{code}\"}}\n");
        Self::json(status, body.into_bytes())
    }

    /// A page or form action that sends the browser back to a `GET`.
    pub(crate) fn redirect(location: &str) -> Self {
        Self::text(303, "").with_header("location", location.to_owned())
    }

    pub(crate) fn with_header(mut self, name: &'static str, value: String) -> Self {
        self.extra.push((name, value));
        self
    }

    async fn write<S>(self, stream: &mut S) -> std::io::Result<()>
    where
        S: AsyncWrite + Unpin + ?Sized,
    {
        let reason = reason(self.status);
        let mut out = format!(
            "HTTP/1.1 {} {reason}\r\ncontent-type: {}\r\ncontent-length: {}\r\ncache-control: no-store\r\nconnection: close\r\n",
            self.status,
            self.content_type,
            self.body.len()
        );
        for (name, value) in &self.extra {
            out.push_str(name);
            out.push_str(": ");
            out.push_str(value);
            out.push_str("\r\n");
        }
        out.push_str("\r\n");
        stream.write_all(out.as_bytes()).await?;
        stream.write_all(&self.body).await
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        428 => "Precondition Required",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        505 => "HTTP Version Not Supported",
        _ => "Error",
    }
}

/// One audit record per write attempt (ADR-0018). No token, no secret: the
/// role and the peer are the identity this slice can attest.
#[derive(Debug, Serialize)]
pub(crate) struct Audit<'a> {
    event: &'static str,
    ts_unix: u64,
    remote: String,
    role: &'static str,
    method: &'a str,
    path: &'a str,
    status: u16,
    backend: Option<&'a str>,
    server: Option<&'a str>,
    from: Option<&'static str>,
    to: Option<&'static str>,
}

/// What one audited write touched. Default = nothing known yet (a refused
/// request may not have reached the target lookup).
#[derive(Default)]
pub(crate) struct AuditFields<'a> {
    backend: Option<&'a str>,
    server: Option<&'a str>,
    from: Option<ServerMode>,
    to: Option<ServerMode>,
}

pub(crate) fn audit<'a>(
    peer: Peer,
    role: Role,
    method: &'a str,
    path: &'a str,
    status: u16,
    fields: AuditFields<'a>,
) -> Audit<'a> {
    Audit {
        event: "admin_write",
        ts_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs()),
        remote: peer.to_string(),
        role: role.as_str(),
        method,
        path,
        status,
        backend: fields.backend,
        server: fields.server,
        from: fields.from.map(ServerMode::as_str),
        to: fields.to.map(ServerMode::as_str),
    }
}

/// What a fully parsed request asks for: an immediate answer, or a
/// configuration mutation whose answer depends on the dataplane.
pub(crate) enum Outcome<'a> {
    Done(Response, Option<Audit<'a>>),
    Apply {
        change: ConfigChange,
        if_match: Option<String>,
        role: Role,
        method: &'a str,
        path: &'a str,
        /// `false` answers the JSON API (the reply of the applier); `true`
        /// answers a browser form with a `303` back to the panel, so a
        /// reload never re-submits a write (ADR-0029).
        back_to_panel: bool,
    },
}

impl<'a> Outcome<'a> {
    pub(crate) fn done(response: Response) -> Self {
        Self::Done(response, None)
    }

    pub(crate) fn done_with(response: Response, audit: Option<Audit<'a>>) -> Self {
        Self::Done(response, audit)
    }
}

/// Parses a complete head (and optional body) and produces the answer. Pure:
/// routing, authorization and the audit record are tested without sockets.
fn respond<'a>(
    head: &'a str,
    body: Option<&[u8]>,
    tokens: &Tokens,
    state: &AdminState,
    peer: Peer,
) -> Outcome<'a> {
    let mut lines = head.split("\r\n");
    let Some(request_line) = lines.next() else {
        return Outcome::done(Response::text(400, "bad request"));
    };
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Outcome::done(Response::text(400, "bad request"));
    };
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Outcome::done(Response::text(505, "unsupported HTTP version"));
    }
    let path = target.split('?').next().unwrap_or(target);
    let is_write = method == "PUT" || method == "POST";
    let role = tokens.role(bearer(head));
    if role == Role::None {
        let audit = is_write.then(|| audit(peer, role, method, path, 401, AuditFields::default()));
        return Outcome::done_with(
            Response::error(401, "unauthorized").with_header(
                "www-authenticate",
                "Bearer realm=\"eqproxy-admin\"".to_owned(),
            ),
            audit,
        );
    }

    match method {
        "GET" => {
            let topology = state.read_topology();
            let response = match path {
                "/api/v1/status" => {
                    let status = Status {
                        version: state.version,
                        uptime_seconds: state.started.elapsed().as_secs(),
                        revision: &topology.revision,
                        listeners: &topology.listeners,
                        backends: topology
                            .backends
                            .iter()
                            .map(|b| backend_status(b))
                            .collect(),
                        metrics_detail: state.metrics.detail.snapshot(),
                        counters: state.metrics.snapshot(),
                    };
                    match serde_json::to_vec(&status) {
                        // `ETag` lets a client cache the status and send the
                        // exact revision back as `If-Match` on its next write.
                        Ok(body) => Response::json(200, body)
                            .with_header("etag", format!("\"{}\"", topology.revision)),
                        // Unreachable for this struct, but a 500 is not invented.
                        Err(_) => Response::error(500, "internal_error"),
                    }
                }
                "/metrics" => Response {
                    status: 200,
                    content_type: "text/plain; version=0.0.4; charset=utf-8",
                    extra: Vec::new(),
                    body: prometheus_body(
                        &state.metrics.snapshot(),
                        &state.metrics.detail.snapshot(),
                        &topology,
                    )
                    .into_bytes(),
                },
                // Cache contents (B-N7/H1, H1 visibility): entries with
                // age, TTL, hits and size, plus the listener totals. The
                // counters live in the shared snapshot and `/metrics`.
                "/api/v1/cache" => {
                    let snapshots: Vec<crate::cache::CacheSnapshot> = topology
                        .caches
                        .iter()
                        .map(|cache| cache.snapshot())
                        .collect();
                    match serde_json::to_vec(&snapshots) {
                        Ok(body) => Response::json(200, body),
                        Err(_) => Response::error(500, "internal_error"),
                    }
                }
                _ => Response::error(404, "not_found"),
            };
            Outcome::done(response)
        }
        "PUT" => {
            if is_config_path(path) {
                put_config(head, body, tokens, role, peer, method, path)
            } else {
                let (response, audit) =
                    put_server_state(head, body, tokens, role, state, peer, path);
                Outcome::done_with(response, audit)
            }
        }
        "POST" => {
            if path == CERTIFICATE_RELOAD_PATH {
                post_certificates(head, tokens, role, peer, path)
            } else {
                method_not_allowed(tokens)
            }
        }
        _ => method_not_allowed(tokens),
    }
}

/// `405` plus the methods this plane serves (a `POST` exists only for the
/// certificate action, so the list is still short and honest).
fn method_not_allowed(tokens: &Tokens) -> Outcome<'static> {
    let allow = if tokens.write.is_some() {
        "GET, PUT, POST"
    } else {
        "GET"
    };
    Outcome::done(Response::error(405, "method_not_allowed").with_header("allow", allow.to_owned()))
}

/// `/api/v1/backends/{name}` or `/api/v1/listeners/{name}`.
fn config_route(path: &str) -> Option<(ConfigChangeKind, &str)> {
    match path.split('/').collect::<Vec<_>>().as_slice() {
        ["", "api", "v1", "backends", name] if !name.is_empty() => {
            Some((ConfigChangeKind::Backend, *name))
        }
        ["", "api", "v1", "listeners", name] if !name.is_empty() => {
            Some((ConfigChangeKind::Listener, *name))
        }
        _ => None,
    }
}

fn is_config_path(path: &str) -> bool {
    config_route(path).is_some()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigChangeKind {
    Backend,
    Listener,
}

/// `PUT /api/v1/{backends|listeners}/{name}` with a TOML table body.
///
/// Requires the write role, no `Origin`, `application/toml`, a declared body
/// up to [`MAX_CONFIG_BODY_BYTES`] and `If-Match` with the revision the
/// client read from `GET /api/v1/status`. A malformed body never reaches the
/// dataplane: the configuration task parses and validates the whole candidate
/// exactly like the TOML file before it swaps.
fn put_config<'a>(
    head: &str,
    body: Option<&[u8]>,
    tokens: &Tokens,
    role: Role,
    peer: Peer,
    method: &'a str,
    path: &'a str,
) -> Outcome<'a> {
    let adjudicate = |status: u16| -> Option<Audit<'a>> {
        Some(audit(
            peer,
            role,
            method,
            path,
            status,
            AuditFields::default(),
        ))
    };
    let Some((kind, name)) = config_route(path) else {
        return Outcome::done(Response::error(404, "not_found"));
    };
    if role != Role::Write {
        let code = if tokens.write.is_none() {
            "write_disabled"
        } else {
            "forbidden"
        };
        return Outcome::done_with(Response::error(403, code), adjudicate(403));
    }
    if !header_values(head, "origin").is_empty() {
        return Outcome::done_with(Response::error(403, "origin_forbidden"), adjudicate(403));
    }
    if !header_values(head, "content-type")
        .first()
        .is_some_and(|value| value.starts_with("application/toml"))
    {
        return Outcome::done_with(
            Response::error(415, "unsupported_media_type"),
            adjudicate(415),
        );
    }
    let Some(length) = content_length(head) else {
        return Outcome::done_with(Response::error(411, "length_required"), adjudicate(411));
    };
    if length > MAX_CONFIG_BODY_BYTES {
        return Outcome::done_with(Response::error(413, "content_too_large"), adjudicate(413));
    }
    let if_match = match header_values(head, "if-match").as_slice() {
        [value] => value
            .trim()
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .unwrap_or(value.trim())
            .to_owned(),
        // Missing or repeated: the write is conditional by contract.
        [] => {
            return Outcome::done_with(
                Response::error(428, "precondition_required"),
                adjudicate(428),
            );
        }
        _ => {
            return Outcome::done_with(Response::error(400, "invalid_if_match"), adjudicate(400));
        }
    };
    let Ok(table) = std::str::from_utf8(body.unwrap_or_default()) else {
        return Outcome::done_with(Response::error(400, "invalid_body"), adjudicate(400));
    };
    let change = match kind {
        ConfigChangeKind::Backend => ConfigChange::Backend {
            name: name.to_owned(),
            table: table.to_owned(),
        },
        ConfigChangeKind::Listener => ConfigChange::Listener {
            name: name.to_owned(),
            table: table.to_owned(),
        },
    };
    Outcome::Apply {
        change,
        if_match: Some(if_match),
        role,
        method,
        path,
        back_to_panel: false,
    }
}

/// The one action route: re-read the configuration and its certificate files
/// and apply them (D7).
const CERTIFICATE_RELOAD_PATH: &str = "/api/v1/certificates/reload";

/// `POST /api/v1/certificates/reload`.
///
/// The renewal HAProxy does with `set ssl cert`: the operator writes the new
/// files where the configuration already points and asks the plane to load
/// them. It is an **action**, not a document edit — it declares no state and
/// carries no body — so it needs no `If-Match` (ADR-0025), but it does need
/// the write role, no browser `Origin`, and it is audited like any write.
///
/// The answer reports the certificate each TLS listener serves **after** the
/// dataplane committed the swap; a reload whose candidate fails validation
/// answers `400` and leaves the previous certificate serving.
fn post_certificates<'a>(
    head: &str,
    tokens: &Tokens,
    role: Role,
    peer: Peer,
    path: &'a str,
) -> Outcome<'a> {
    let adjudicate = |status: u16| -> Option<Audit<'a>> {
        Some(audit(
            peer,
            role,
            "POST",
            path,
            status,
            AuditFields::default(),
        ))
    };
    if role != Role::Write {
        let code = if tokens.write.is_none() {
            "write_disabled"
        } else {
            "forbidden"
        };
        return Outcome::done_with(Response::error(403, code), adjudicate(403));
    }
    if !header_values(head, "origin").is_empty() {
        return Outcome::done_with(Response::error(403, "origin_forbidden"), adjudicate(403));
    }
    // The action carries no payload: a body would be a client inventing a
    // request shape this route does not define.
    if content_length(head).unwrap_or(0) != 0
        || !header_values(head, "transfer-encoding").is_empty()
    {
        return Outcome::done_with(Response::error(400, "body_not_allowed"), adjudicate(400));
    }
    Outcome::Apply {
        change: ConfigChange::Reload,
        if_match: None,
        role,
        method: "POST",
        path,
        back_to_panel: false,
    }
}

/// Prometheus exposition of the dataplane counters, the removal series this
/// plane derives from the live topology (H3, ADR-0028), and the opt-in detail
/// registry (CE4). The removal series are label-free: one line each, so a
/// scrape cannot grow the index. The labelled families exist only while
/// `[metrics] detailed` is on, and only for the series that fit the
/// configured budget.
fn prometheus_body(
    snapshot: &eqproxy_core::MetricsSnapshot,
    detail: &eqproxy_core::metrics::DetailSnapshot,
    topology: &AdminTopology,
) -> String {
    let mut body = snapshot.prometheus();
    body.push_str(&detail.prometheus());
    let mut draining = 0u64;
    let mut maintenance = 0u64;
    let mut completed = 0u64;
    for backend in &topology.backends {
        completed = completed.saturating_add(backend.balancer.drains_completed());
        for server in backend.balancer.servers_view() {
            match server.mode {
                ServerMode::Drain => draining = draining.saturating_add(1),
                ServerMode::Maintenance => maintenance = maintenance.saturating_add(1),
                ServerMode::Ready => {}
            }
        }
    }
    // `draining`/`maintenance` count slots declared in each removal state
    // (with or without work left); the per-slot `active`/`drained` pair that
    // says *how far* the removal is lives in the status JSON, where the
    // budget is the configured topology. `drains_completed_total` counts
    // drain completions only: maintenance has no counter (ADR-0028), its
    // window opening is the `INFO server ready for maintenance` line.
    body.push_str(&format!(
        "# TYPE eqproxy_backend_servers_draining gauge\n\
         eqproxy_backend_servers_draining {draining}\n\
         # TYPE eqproxy_backend_servers_maintenance gauge\n\
         eqproxy_backend_servers_maintenance {maintenance}\n\
         # TYPE eqproxy_backend_drains_completed_total counter\n\
         eqproxy_backend_drains_completed_total {completed}\n"
    ));
    body
}

fn backend_status(backend: &ResolvedBackend) -> BackendStatus<'_> {
    BackendStatus {
        name: &backend.name,
        balance: backend.balancer.algorithm().as_str(),
        all_backups: backend.balancer.all_backups(),
        health_check: backend.health_check.is_some(),
        servers: backend
            .balancer
            .servers_view()
            .into_iter()
            .map(|server| ServerStatus {
                addr: server.target,
                resolved: server.addr.map(|addr| addr.to_string()),
                weight: server.weight,
                backup: server.backup,
                priority: server.priority,
                state: server.mode.as_str(),
                healthy: server.up,
                active: server.active,
                drained: server.drained,
            })
            .collect(),
    }
}

/// `PUT /api/v1/backends/{backend}/servers/{target}/state`.
///
/// Order of checks: role, browser origin, media type, length, body shape,
/// state value, existence. A refused request never changes a slot; an
/// accepted one is idempotent and reports the previous state. An accepted
/// `maintenance` additionally closes the slot's idle pooled connections
/// (h1 pool and backend h2 session) at the transition (ADR-0028).
fn put_server_state<'a>(
    head: &str,
    body: Option<&[u8]>,
    tokens: &Tokens,
    role: Role,
    state: &AdminState,
    peer: Peer,
    path: &'a str,
) -> (Response, Option<Audit<'a>>) {
    let record = |status: u16,
                  backend: Option<&'a str>,
                  server: Option<&'a str>,
                  from: Option<ServerMode>,
                  to: Option<ServerMode>| {
        audit(
            peer,
            role,
            "PUT",
            path,
            status,
            AuditFields {
                backend,
                server,
                from,
                to,
            },
        )
    };
    if role != Role::Write {
        // One role may only read: either the plane has no write secret at all
        // (writes are off) or this token is the read one.
        let code = if tokens.write.is_none() {
            "write_disabled"
        } else {
            "forbidden"
        };
        return (
            Response::error(403, code),
            Some(record(403, None, None, None, None)),
        );
    }
    if !header_values(head, "origin").is_empty() {
        // A browser-originated request never belongs on a token-authenticated
        // API; refusing it closes the DNS-rebinding path.
        return (
            Response::error(403, "origin_forbidden"),
            Some(record(403, None, None, None, None)),
        );
    }
    if !header_values(head, "content-type")
        .first()
        .is_some_and(|value| value.starts_with("application/json"))
    {
        return (
            Response::error(415, "unsupported_media_type"),
            Some(record(415, None, None, None, None)),
        );
    }
    let Some(length) = content_length(head) else {
        return (
            Response::error(411, "length_required"),
            Some(record(411, None, None, None, None)),
        );
    };
    if length > MAX_ADMIN_BODY_BYTES {
        return (
            Response::error(413, "content_too_large"),
            Some(record(413, None, None, None, None)),
        );
    }
    let body = body.unwrap_or_default();
    let Ok(text) = std::str::from_utf8(body) else {
        return (
            Response::error(400, "invalid_body"),
            Some(record(400, None, None, None, None)),
        );
    };
    let Ok(parsed) = serde_json::from_str::<StateRequest>(text) else {
        return (
            Response::error(400, "invalid_body"),
            Some(record(400, None, None, None, None)),
        );
    };
    let Some(mode) = ServerMode::parse(&parsed.state) else {
        return (
            Response::error(400, "invalid_state"),
            Some(record(400, None, None, None, None)),
        );
    };
    let segments: Vec<&str> = path.split('/').collect();
    let route = match segments.as_slice() {
        [
            "",
            "api",
            "v1",
            "backends",
            backend,
            "servers",
            server,
            "state",
        ] if !backend.is_empty() && !server.is_empty() => Some((*backend, *server)),
        _ => None,
    };
    let Some((backend_name, target)) = route else {
        return (
            Response::error(404, "not_found"),
            Some(record(404, None, None, None, None)),
        );
    };
    match apply_server_state(state, backend_name, target, mode) {
        Ok((answer, previous)) => match serde_json::to_vec(&answer) {
            Ok(body) => (
                Response::json(200, body),
                Some(record(
                    200,
                    Some(backend_name),
                    Some(target),
                    Some(previous),
                    Some(mode),
                )),
            ),
            Err(_) => (
                Response::error(500, "internal_error"),
                Some(record(
                    500,
                    Some(backend_name),
                    Some(target),
                    Some(previous),
                    Some(mode),
                )),
            ),
        },
        Err((status, code)) => (
            Response::error(status, code),
            Some(record(status, Some(backend_name), Some(target), None, None)),
        ),
    }
}

/// Applies one administrative state to one slot: the single implementation
/// the JSON route and the panel both call (ADR-0029), so "what `maintenance`
/// does" cannot drift between the two clients. Returns the applied document
/// and the previous state, or the HTTP status and error code to answer with.
pub(crate) fn apply_server_state(
    state: &AdminState,
    backend_name: &str,
    target: &str,
    mode: ServerMode,
) -> Result<(serde_json::Value, ServerMode), (u16, &'static str)> {
    let topology = state.read_topology();
    let Some(backend) = topology.backends.iter().find(|b| b.name == backend_name) else {
        return Err((404, "not_found"));
    };
    let Some(server) = backend
        .balancer
        .servers_view()
        .into_iter()
        .find(|server| server.target == target)
    else {
        return Err((404, "not_found"));
    };
    let previous = server.mode;
    let applied = state.modes.set(backend_name, target, mode);
    if mode == ServerMode::Maintenance {
        // The patch window's contract (ADR-0028): nothing of ours stays on
        // the server. The pool closes what is parked right now; a connection
        // of an exchange that ends later is never parked either, the
        // completion path refuses to pool a maintenance slot
        // (`ActiveGuard::mode`). The mode is set first on purpose: a
        // connection parked in between is closed by the sweep below.
        if let Some(addr) = server.addr {
            backend.pool.close_idle(&addr);
            if let Some(hub) = backend.h2.as_ref() {
                hub.close_idle(addr);
            }
        }
    }
    let answer = serde_json::json!({
        "backend": backend_name,
        "server": target,
        "state": mode.as_str(),
        "previous": applied.as_str(),
        "active": server.active,
        "healthy": server.up,
        "drained": mode != ServerMode::Ready && server.active == 0,
        "changed": previous != mode,
    });
    Ok((answer, previous))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StateRequest {
    state: String,
}

/// Constant-time token comparison: an attacker who can time the answers must
/// not learn how many leading bytes of the token are right.
pub(crate) fn token_matches(expected: &str, given: &str) -> bool {
    let expected = expected.as_bytes();
    let given = given.as_bytes();
    let mut diff = u8::from(expected.len() != given.len());
    let longest = expected.len().max(given.len());
    for index in 0..longest {
        let a = expected.get(index).copied().unwrap_or(0);
        let b = given.get(index).copied().unwrap_or(0);
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::balancer::{Balance, ResolvedServer};
    use crate::proxy::ResolvedBackend;

    const TOKEN: &str = "correct-horse-battery-staple";
    const WRITE: &str = "write-secret-0123456789";

    fn peer() -> Peer {
        Peer::Tcp("127.0.0.1:50000".parse().expect("peer"))
    }

    fn backend(modes: &Arc<ServerModes>) -> Arc<ResolvedBackend> {
        Arc::new(
            ResolvedBackend::new(
                "api",
                vec![
                    ResolvedServer {
                        addr: crate::ServerAddr::Ip("127.0.0.1:9000".parse().expect("addr")),
                        weight: 1,
                        backup: false,
                        priority: 0,
                        maxconn: 0,
                    },
                    ResolvedServer {
                        addr: crate::ServerAddr::Ip("127.0.0.1:9001".parse().expect("addr")),
                        weight: 2,
                        backup: false,
                        priority: 0,
                        maxconn: 0,
                    },
                ],
                3,
                2,
            )
            .with_balance(Balance::LeastConn, Duration::ZERO)
            .with_server_modes(Arc::clone(modes)),
        )
    }

    fn state() -> AdminState {
        state_with(Arc::new(ServerModes::new()), None)
    }

    fn state_with(
        modes: Arc<ServerModes>,
        apply: Option<mpsc::Sender<ApplyMessage>>,
    ) -> AdminState {
        AdminState {
            version: "0.0.0-test",
            started: Instant::now(),
            topology: Arc::new(RwLock::new(AdminTopology {
                revision: "v1".to_owned(),
                listeners: vec![ListenerInfo {
                    name: "web".to_owned(),
                    listen: "127.0.0.1:8080".to_owned(),
                    mode: "http".to_owned(),
                    backend: "api".to_owned(),
                    maxconn: 1024,
                    tls_fingerprint: None,
                }],
                backends: vec![backend(&modes)],
                caches: Vec::new(),
            })),
            modes,
            metrics: Arc::new(Metrics::default()),
            apply,
            panel: None,
        }
    }

    /// The unit tests that predate the config-apply route only exercise
    /// answers that never reach the applier; a config `PUT` in one of them is
    /// a test bug.
    fn respond<'a>(
        head: &'a str,
        body: Option<&[u8]>,
        tokens: &Tokens,
        state: &AdminState,
        peer: Peer,
    ) -> (Response, Option<Audit<'a>>) {
        match super::respond(head, body, tokens, state, peer) {
            Outcome::Done(response, audit) => (response, audit),
            Outcome::Apply { path, .. } => {
                panic!("{path} reached the applier in a pure unit test")
            }
        }
    }

    fn tokens() -> Tokens {
        Tokens {
            read: Arc::from(TOKEN),
            write: Some(Arc::from(WRITE)),
        }
    }

    fn request(method: &str, path: &str, authorization: Option<&str>) -> String {
        let mut head = format!("{method} {path} HTTP/1.1\r\nhost: admin\r\n");
        if let Some(value) = authorization {
            head.push_str(&format!("authorization: {value}\r\n"));
        }
        head.push_str("\r\n");
        head
    }

    fn put(path: &str, secret: &str, content_type: &str, body: &str) -> String {
        format!(
            "PUT {path} HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {secret}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    fn body_json(response: &Response) -> serde_json::Value {
        serde_json::from_slice(&response.body).expect("json body")
    }

    #[test]
    fn token_comparison_is_exact() {
        assert!(token_matches(TOKEN, TOKEN));
        assert!(!token_matches(TOKEN, "correct-horse-battery-stapl"));
        assert!(!token_matches(TOKEN, "correct-horse-battery-stapleX"));
        assert!(!token_matches(TOKEN, ""));
        assert!(!token_matches(TOKEN, "Correct-Horse-Battery-Staple"));
    }

    #[test]
    fn every_route_requires_the_bearer_token() {
        let state = state();
        for path in ["/api/v1/status", "/metrics", "/nope"] {
            let head = request("GET", path, None);
            let (response, audit) = respond(&head, None, &tokens(), &state, peer());
            assert_eq!(response.status, 401, "{path} without a token");
            assert!(audit.is_none(), "a GET is not audited as a write");
            assert!(
                response
                    .extra
                    .iter()
                    .any(|(name, _)| *name == "www-authenticate"),
                "{path} must advertise the scheme"
            );
            let head = request("GET", path, Some("Bearer not-the-token"));
            let (wrong, _) = respond(&head, None, &tokens(), &state, peer());
            assert_eq!(wrong.status, 401, "{path} with a wrong token");
            assert!(
                !String::from_utf8_lossy(&wrong.body).contains(TOKEN),
                "the token never appears in an answer"
            );
        }
    }

    #[test]
    fn status_reports_live_servers_and_the_live_counters() {
        let state = state();
        state
            .metrics
            .http_requests_proxied
            .fetch_add(7, std::sync::atomic::Ordering::Relaxed);
        state.modes.set("api", "127.0.0.1:9001", ServerMode::Drain);
        let (response, _) = respond(
            &request("GET", "/api/v1/status", Some(&format!("Bearer {TOKEN}"))),
            None,
            &tokens(),
            &state,
            peer(),
        );
        assert_eq!(response.status, 200);
        let parsed = body_json(&response);
        assert_eq!(parsed["version"], "0.0.0-test");
        assert_eq!(parsed["listeners"][0]["name"], "web");
        assert_eq!(parsed["listeners"][0]["mode"], "http");
        assert_eq!(parsed["backends"][0]["name"], "api");
        assert_eq!(parsed["backends"][0]["balance"], "least_conn");
        assert_eq!(
            parsed["backends"][0]["servers"][0]["addr"],
            "127.0.0.1:9000"
        );
        assert_eq!(parsed["backends"][0]["servers"][0]["state"], "ready");
        assert_eq!(parsed["backends"][0]["servers"][1]["state"], "drain");
        assert_eq!(parsed["backends"][0]["servers"][1]["weight"], 2);
        assert_eq!(parsed["backends"][0]["servers"][1]["active"], 0);
        // H3: an idle drained slot reports the drain as finished, and a
        // ready slot never does.
        assert_eq!(parsed["backends"][0]["servers"][1]["drained"], true);
        assert_eq!(parsed["backends"][0]["servers"][0]["drained"], false);
        assert_eq!(
            parsed["backends"][0]["servers"][0]["resolved"],
            "127.0.0.1:9000"
        );
        assert_eq!(parsed["counters"]["http_requests_proxied"], 7);
        assert!(parsed["uptime_seconds"].is_u64());
        let body = String::from_utf8(response.body).expect("json");
        assert!(!body.contains(TOKEN), "the status never echoes the token");
    }

    #[test]
    fn status_marks_backup_servers() {
        let backend = Arc::new(ResolvedBackend::new(
            "api",
            vec![
                ResolvedServer {
                    addr: crate::ServerAddr::Ip("127.0.0.1:9000".parse().expect("addr")),
                    weight: 1,
                    backup: false,
                    priority: 0,
                    maxconn: 0,
                },
                ResolvedServer {
                    addr: crate::ServerAddr::Ip("127.0.0.1:9001".parse().expect("addr")),
                    weight: 1,
                    backup: true,
                    priority: 10,
                    maxconn: 0,
                },
            ],
            3,
            2,
        ));
        let status = serde_json::to_value(backend_status(&backend)).expect("status json");
        assert_eq!(status["servers"][0]["backup"], false);
        assert_eq!(
            status["servers"][1]["backup"], true,
            "the read plane says which slot is a backup (B8)"
        );
        assert_eq!(status["servers"][0]["priority"], 0);
        assert_eq!(
            status["servers"][1]["priority"], 10,
            "the read plane publishes the failover rung"
        );
        assert_eq!(
            status["all_backups"], false,
            "the default is one backup rung at a time (B8)"
        );

        // `option allbackups` on the same slots: the policy is part of the
        // read plane, so an operator can tell the two modes apart.
        let pooled = Arc::new(
            ResolvedBackend::new(
                "api",
                vec![
                    ResolvedServer {
                        addr: crate::ServerAddr::Ip("127.0.0.1:9000".parse().expect("addr")),
                        weight: 1,
                        backup: true,
                        priority: 0,
                        maxconn: 0,
                    },
                    ResolvedServer {
                        addr: crate::ServerAddr::Ip("127.0.0.1:9001".parse().expect("addr")),
                        weight: 1,
                        backup: true,
                        priority: 0,
                        maxconn: 0,
                    },
                ],
                3,
                2,
            )
            .with_all_backups(true),
        );
        let status = serde_json::to_value(backend_status(&pooled)).expect("status json");
        assert_eq!(
            status["all_backups"], true,
            "the read plane says the backup tier balances as one pool"
        );
    }

    #[test]
    fn metrics_are_prometheus_text_with_bounded_cardinality() {
        let state = state();
        state
            .metrics
            .connections_accepted
            .fetch_add(3, std::sync::atomic::Ordering::Relaxed);
        let (response, _) = respond(
            &request("GET", "/metrics", Some(&format!("Bearer {TOKEN}"))),
            None,
            &tokens(),
            &state,
            peer(),
        );
        assert_eq!(response.status, 200);
        assert_eq!(
            response.content_type,
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let body = String::from_utf8(response.body).expect("prometheus text");
        assert!(body.contains("# TYPE eqproxy_connections_accepted_total counter"));
        assert!(body.contains("eqproxy_connections_accepted_total 3"));
        assert!(body.contains("eqproxy_connections_active 0"));
        assert!(body.contains("eqproxy_build_info{version="));
        // H3: the drain series exist before any drain happens, at zero, so a
        // dashboard can be built against a running process.
        assert!(body.contains("# TYPE eqproxy_backend_servers_draining gauge"));
        assert!(body.contains("eqproxy_backend_servers_draining 0"));
        assert!(body.contains("# TYPE eqproxy_backend_drains_completed_total counter"));
        assert!(body.contains("eqproxy_backend_drains_completed_total 0"));
        // CE4: detail is off by default, and the four accounting series say so
        // without a single label — a scraper can tell "no traffic" from
        // "detail disabled" without asking the process.
        assert!(body.contains("eqproxy_metrics_detail_enabled 0"));
        assert!(body.contains("eqproxy_metrics_detail_series 0"));
        assert!(body.contains("eqproxy_metrics_detail_budget 128"));
        assert!(body.contains("eqproxy_metrics_detail_dropped_total 0"));
        assert!(!body.contains("eqproxy_server_requests_total{"));
        assert!(!body.contains("eqproxy_route_requests_total{"));
        // Every value line is `metric_name {value}` with no labels; only the
        // build-info gauge carries one, so cardinality cannot grow per scrape.
        for line in body
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
        {
            assert_eq!(
                line.matches('{').count(),
                usize::from(line.starts_with("eqproxy_build_info")),
                "{line}"
            );
        }
    }

    #[test]
    fn detail_series_and_their_budget_are_exported_when_enabled() {
        let state = state();
        state.metrics.detail.set_enabled(true);
        state
            .metrics
            .detail
            .record_server("api", "127.0.0.1:9000", false);
        state
            .metrics
            .detail
            .record_server("api", "127.0.0.1:9000", true);
        state.metrics.detail.record_route("web", "alpha", false);
        let (response, _) = respond(
            &request("GET", "/metrics", Some(&format!("Bearer {TOKEN}"))),
            None,
            &tokens(),
            &state,
            peer(),
        );
        assert_eq!(response.status, 200);
        let body = String::from_utf8(response.body).expect("prometheus text");
        assert!(body.contains("eqproxy_metrics_detail_enabled 1"), "{body}");
        assert!(body.contains("eqproxy_metrics_detail_series 2"), "{body}");
        assert!(
            body.contains(
                "eqproxy_server_requests_total{backend=\"api\",server=\"127.0.0.1:9000\"} 2"
            ),
            "{body}"
        );
        assert!(
            body.contains(
                "eqproxy_server_errors_total{backend=\"api\",server=\"127.0.0.1:9000\"} 1"
            ),
            "{body}"
        );
        assert!(
            body.contains("eqproxy_route_requests_total{listener=\"web\",route=\"alpha\"} 1"),
            "{body}"
        );
        // The same rows are in the JSON API, under the same budget.
        let (status, _) = respond(
            &request("GET", "/api/v1/status", Some(&format!("Bearer {TOKEN}"))),
            None,
            &tokens(),
            &state,
            peer(),
        );
        let parsed = body_json(&status);
        assert_eq!(parsed["metrics_detail"]["enabled"], true);
        assert_eq!(parsed["metrics_detail"]["budget"], 128);
        assert_eq!(parsed["metrics_detail"]["series"], 2);
        assert_eq!(parsed["metrics_detail"]["rows"][0]["kind"], "server");
        assert_eq!(parsed["metrics_detail"]["rows"][0]["key"], "127.0.0.1:9000");
        assert_eq!(parsed["metrics_detail"]["rows"][1]["kind"], "route");
        assert_eq!(parsed["metrics_detail"]["rows"][1]["key"], "alpha");
    }

    #[test]
    fn only_the_documented_methods_are_served() {
        let state = state();
        // `POST` exists only for the certificate action; every other method
        // on every path is refused with the list that plane really serves.
        for method in ["DELETE", "HEAD", "PATCH", "TRACE"] {
            let (response, _) = respond(
                &request(method, "/api/v1/status", Some(&format!("Bearer {TOKEN}"))),
                None,
                &tokens(),
                &state,
                peer(),
            );
            assert_eq!(response.status, 405, "{method} must not be served");
            assert!(
                response
                    .extra
                    .iter()
                    .any(|(name, value)| *name == "allow" && value == "GET, PUT, POST"),
                "{method}: {:?}",
                response.extra
            );
        }
        let (response, _) = respond(
            &request("POST", "/api/v1/status", Some(&format!("Bearer {TOKEN}"))),
            None,
            &tokens(),
            &state,
            peer(),
        );
        assert_eq!(response.status, 405, "POST exists on one path only");
    }

    #[test]
    fn unknown_routes_are_404_once_authenticated() {
        let state = state();
        for path in ["/", "/api", "/api/v1", "/api/v1/status/", "/metricsx"] {
            let (response, _) = respond(
                &request("GET", path, Some(&format!("Bearer {TOKEN}"))),
                None,
                &tokens(),
                &state,
                peer(),
            );
            assert_eq!(response.status, 404, "{path}");
        }
        // Query strings are ignored, not part of the route.
        let (response, _) = respond(
            &request("GET", "/metrics?debug=1", Some(&format!("Bearer {TOKEN}"))),
            None,
            &tokens(),
            &state,
            peer(),
        );
        assert_eq!(response.status, 200);
    }

    #[test]
    fn malformed_requests_are_refused() {
        let state = state();
        for head in ["", "GET", "GET /metrics", "GET /metrics HTTP/2.0\r\n\r\n"] {
            let (response, _) = respond(head, None, &tokens(), &state, peer());
            assert!(
                response.status == 400 || response.status == 505,
                "{head:?} -> {}",
                response.status
            );
        }
    }

    // ---------------------------------------- ADR-0018: write path -------

    #[test]
    fn read_token_cannot_write_and_the_write_token_can() {
        let state = state();
        let path = "/api/v1/backends/api/servers/127.0.0.1:9000/state";
        let head = put(path, TOKEN, "application/json", "{\"state\":\"drain\"}");
        let (refused, audit) = respond(
            &head,
            Some(b"{\"state\":\"drain\"}"),
            &tokens(),
            &state,
            peer(),
        );
        assert_eq!(refused.status, 403, "the read role is not allowed to write");
        let audit = audit.expect("a refused write is still audited");
        assert_eq!(audit.status, 403);
        assert_eq!(audit.role, "read");
        assert_eq!(
            state.modes.get("api", "127.0.0.1:9000"),
            ServerMode::Ready,
            "a refused write changes nothing"
        );

        let head = put(path, WRITE, "application/json", "{\"state\":\"drain\"}");
        let (accepted, audit) = respond(
            &head,
            Some(b"{\"state\":\"drain\"}"),
            &tokens(),
            &state,
            peer(),
        );
        assert_eq!(accepted.status, 200);
        let parsed = body_json(&accepted);
        assert_eq!(parsed["state"], "drain");
        assert_eq!(parsed["previous"], "ready");
        assert_eq!(parsed["changed"], true);
        assert_eq!(state.modes.get("api", "127.0.0.1:9000"), ServerMode::Drain);
        let audit = audit.expect("an accepted write is audited");
        assert_eq!(audit.status, 200);
        assert_eq!(audit.role, "operate");
        assert_eq!(audit.from, Some("ready"));
        assert_eq!(audit.to, Some("drain"));
        assert_eq!(audit.backend, Some("api"));
        assert_eq!(audit.server, Some("127.0.0.1:9000"));
        let line = serde_json::to_string(&audit).expect("audit json");
        assert!(!line.contains(WRITE), "the audit never carries the secret");

        // Idempotent: same declaration again, `changed = false`.
        let head = put(path, WRITE, "application/json", "{\"state\":\"drain\"}");
        let (again, _) = respond(
            &head,
            Some(b"{\"state\":\"drain\"}"),
            &tokens(),
            &state,
            peer(),
        );
        assert_eq!(again.status, 200);
        assert_eq!(body_json(&again)["changed"], false);
        assert_eq!(body_json(&again)["previous"], "drain");

        // Back to rotation.
        let head = put(path, WRITE, "application/json", "{\"state\":\"ready\"}");
        let (ready, _) = respond(
            &head,
            Some(b"{\"state\":\"ready\"}"),
            &tokens(),
            &state,
            peer(),
        );
        assert_eq!(ready.status, 200);
        assert_eq!(state.modes.get("api", "127.0.0.1:9000"), ServerMode::Ready);
    }

    #[test]
    fn a_maintenance_write_closes_the_idle_connections_of_the_slot() {
        use crate::proxy::{BoxRead, BoxWrite};
        use tokio::io::{BufReader, duplex, split};

        let modes = Arc::new(ServerModes::new());
        let state = state_with(Arc::clone(&modes), None);
        let backend = state.read_topology().backends[0].clone();
        let addr: SocketAddr = "127.0.0.1:9000".parse().expect("addr");
        // Park one clean idle connection for the slot, exactly as the
        // completion path would after a keep-alive exchange.
        let (near, _far) = duplex(1024);
        let (read, write) = split(near);
        backend.pool.note_in_flight(addr, 1);
        backend.pool.checkin(
            addr,
            BufReader::new(Box::new(read) as BoxRead),
            Box::new(write) as BoxWrite,
            Instant::now(),
        );
        assert_eq!(
            backend.pool.idle_count(&addr),
            1,
            "test setup parks a connection"
        );

        // `drain` is graceful: the parked connection stays (it ages out on
        // its own timer, ADR-0018).
        let path = "/api/v1/backends/api/servers/127.0.0.1:9000/state";
        let head = put(path, WRITE, "application/json", "{\"state\":\"drain\"}");
        let (drained, _) = respond(
            &head,
            Some(b"{\"state\":\"drain\"}"),
            &tokens(),
            &state,
            peer(),
        );
        assert_eq!(drained.status, 200);
        assert_eq!(body_json(&drained)["drained"], true);
        assert_eq!(
            backend.pool.idle_count(&addr),
            1,
            "a drain keeps pooled connections: they age out on their own"
        );

        // `maintenance` closes them at the transition (ADR-0028).
        let head = put(
            path,
            WRITE,
            "application/json",
            "{\"state\":\"maintenance\"}",
        );
        let (maintained, _) = respond(
            &head,
            Some(b"{\"state\":\"maintenance\"}"),
            &tokens(),
            &state,
            peer(),
        );
        assert_eq!(maintained.status, 200);
        let parsed = body_json(&maintained);
        assert_eq!(parsed["state"], "maintenance");
        assert_eq!(parsed["previous"], "drain");
        assert_eq!(parsed["changed"], true);
        assert_eq!(
            parsed["drained"], true,
            "an idle maintenance slot is already finished"
        );
        assert_eq!(
            state.modes.get("api", "127.0.0.1:9000"),
            ServerMode::Maintenance
        );
        assert_eq!(
            backend.pool.idle_count(&addr),
            0,
            "the patch window's contract: nothing of ours stays parked"
        );

        // Back to rotation and the slot serves again.
        let head = put(path, WRITE, "application/json", "{\"state\":\"ready\"}");
        let (ready, _) = respond(
            &head,
            Some(b"{\"state\":\"ready\"}"),
            &tokens(),
            &state,
            peer(),
        );
        assert_eq!(ready.status, 200);
        assert_eq!(state.modes.get("api", "127.0.0.1:9000"), ServerMode::Ready);
    }

    #[test]
    fn without_a_write_token_every_write_is_disabled() {
        let state = state();
        let tokens = Tokens {
            read: Arc::from(TOKEN),
            write: None,
        };
        let path = "/api/v1/backends/api/servers/127.0.0.1:9000/state";
        let head = put(path, TOKEN, "application/json", "{\"state\":\"drain\"}");
        let (response, audit) = respond(
            &head,
            Some(b"{\"state\":\"drain\"}"),
            &tokens,
            &state,
            peer(),
        );
        assert_eq!(response.status, 403);
        assert_eq!(body_json(&response)["error"], "write_disabled");
        assert_eq!(audit.expect("audited").role, "read");
        // GET still works with the only configured token.
        let (status, _) = respond(
            &request("GET", "/api/v1/status", Some(&format!("Bearer {TOKEN}"))),
            None,
            &tokens,
            &state,
            peer(),
        );
        assert_eq!(status.status, 200);
    }

    #[test]
    fn write_body_and_browser_requests_are_validated() {
        let state = state();
        let path = "/api/v1/backends/api/servers/127.0.0.1:9000/state";
        let cases = [
            (
                "text/plain",
                "{\"state\":\"drain\"}",
                415,
                "unsupported_media_type",
            ),
            (
                "application/json",
                "{\"state\":\"pause\"}",
                400,
                "invalid_state",
            ),
            (
                "application/json",
                "{\"status\":\"drain\"}",
                400,
                "invalid_body",
            ),
            (
                "application/json",
                "{\"state\":\"drain\",\"x\":1}",
                400,
                "invalid_body",
            ),
            ("application/json", "not json", 400, "invalid_body"),
        ];
        for (content_type, body, status, code) in cases {
            let head = put(path, WRITE, content_type, body);
            let (response, audit) =
                respond(&head, Some(body.as_bytes()), &tokens(), &state, peer());
            assert_eq!(response.status, status, "{body}");
            assert_eq!(body_json(&response)["error"], code, "{body}");
            assert_eq!(audit.expect("audited").status, status);
        }
        // A browser request (Origin present) is refused even with a valid
        // token and body: no CORS surface exists on the plane.
        let head = format!(
            "PUT {path} HTTP/1.1\r\nhost: admin\r\norigin: https://evil.example\r\nauthorization: Bearer {WRITE}\r\ncontent-type: application/json\r\ncontent-length: 17\r\n\r\n"
        );
        let (response, audit) = respond(
            &head,
            Some(b"{\"state\":\"drain\"}"),
            &tokens(),
            &state,
            peer(),
        );
        assert_eq!(response.status, 403);
        assert_eq!(body_json(&response)["error"], "origin_forbidden");
        assert_eq!(audit.expect("audited").status, 403);
        assert_eq!(state.modes.get("api", "127.0.0.1:9000"), ServerMode::Ready);
        // A missing length cannot be read, so the plane says so.
        let head = format!(
            "PUT {path} HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {WRITE}\r\ncontent-type: application/json\r\n\r\n"
        );
        let (response, _) = respond(&head, None, &tokens(), &state, peer());
        assert_eq!(response.status, 411);
    }

    #[test]
    fn unknown_backend_or_server_never_changes_anything() {
        let state = state();
        for path in [
            "/api/v1/backends/nope/servers/127.0.0.1:9000/state",
            "/api/v1/backends/api/servers/127.0.0.1:9999/state",
            "/api/v1/backends/api/servers//state",
            "/api/v1/backends/api/servers/127.0.0.1:9000",
        ] {
            let head = put(path, WRITE, "application/json", "{\"state\":\"drain\"}");
            let (response, audit) = respond(
                &head,
                Some(b"{\"state\":\"drain\"}"),
                &tokens(),
                &state,
                peer(),
            );
            assert_eq!(response.status, 404, "{path}");
            assert_eq!(audit.expect("audited").status, 404, "{path}");
        }
        assert_eq!(state.modes.get("api", "127.0.0.1:9000"), ServerMode::Ready);
    }

    // ------------------------------- ADR-0019: configuration writes -----

    fn config_put(
        path: &str,
        secret: &str,
        content_type: &str,
        if_match: Option<&str>,
        body: &str,
    ) -> String {
        let mut head = format!(
            "PUT {path} HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {secret}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\n",
            body.len()
        );
        if let Some(value) = if_match {
            head.push_str(&format!("if-match: {value}\r\n"));
        }
        head.push_str("\r\n");
        head.push_str(body);
        head
    }

    #[test]
    fn config_routes_accept_only_one_name_segment() {
        assert!(config_route("/api/v1/backends/api").is_some());
        assert!(config_route("/api/v1/listeners/web").is_some());
        for path in [
            "/api/v1/backends",
            "/api/v1/backends/",
            "/api/v1/backends/api/servers",
            "/api/v1/listeners/web/extra",
            "/api/v1/maps/m",
        ] {
            assert_eq!(config_route(path), None, "{path}");
        }
        // The per-server state route is not a whole-table write.
        assert!(!is_config_path(
            "/api/v1/backends/api/servers/127.0.0.1:9000/state"
        ));
    }

    #[test]
    fn config_write_requires_the_write_role_and_a_conditional_request() {
        let state = state();
        let path = "/api/v1/backends/api";
        let body = "server = \"127.0.0.1:9000\"\n";

        // The read token never configures.
        let head = config_put(path, TOKEN, "application/toml", Some("\"v1\""), body);
        let (response, audit) = respond(&head, Some(body.as_bytes()), &tokens(), &state, peer());
        assert_eq!(response.status, 403);
        assert_eq!(body_json(&response)["error"], "forbidden");
        assert_eq!(audit.expect("audited").status, 403);

        // Media type, declared length and the conditional header are part of
        // the contract; each refusal is explicit.
        let cases = [
            ("application/json", Some("\"v1\""), 415),
            ("application/toml", None, 428),
        ];
        for (content_type, if_match, status) in cases {
            let head = config_put(path, WRITE, content_type, if_match, body);
            let (response, _) = respond(&head, Some(body.as_bytes()), &tokens(), &state, peer());
            assert_eq!(response.status, status, "{content_type} {if_match:?}");
        }
        let head = format!(
            "PUT {path} HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {WRITE}\r\ncontent-type: application/toml\r\nif-match: \"v1\"\r\n\r\n"
        );
        let (response, _) = respond(&head, None, &tokens(), &state, peer());
        assert_eq!(response.status, 411);

        // Origin, like the state route, closes the DNS-rebinding path.
        let head = format!(
            "PUT {path} HTTP/1.1\r\nhost: admin\r\norigin: https://evil.example\r\nauthorization: Bearer {WRITE}\r\ncontent-type: application/toml\r\ncontent-length: {}\r\nif-match: \"v1\"\r\n\r\n{body}",
            body.len()
        );
        let (response, _) = respond(&head, Some(body.as_bytes()), &tokens(), &state, peer());
        assert_eq!(response.status, 403);
        assert_eq!(body_json(&response)["error"], "origin_forbidden");

        // A valid conditional write is handed to the applier as a table.
        let head = config_put(path, WRITE, "application/toml", Some("\"v1\""), body);
        match super::respond(&head, Some(body.as_bytes()), &tokens(), &state, peer()) {
            Outcome::Apply {
                change, if_match, ..
            } => {
                assert_eq!(if_match.as_deref(), Some("v1"));
                match change {
                    ConfigChange::Backend { name, table } => {
                        assert_eq!(name, "api");
                        assert_eq!(table, body);
                    }
                    other => panic!("unexpected change: {other:?}"),
                }
            }
            Outcome::Done(response, _) => panic!("must be applied: {}", response.status),
        }
    }

    // ------------------------- ADR-0025: certificate renewal (D7) -------

    fn certificate_reload(secret: Option<&str>, extra_headers: &str) -> String {
        let mut head = format!("POST {CERTIFICATE_RELOAD_PATH} HTTP/1.1\r\nhost: admin\r\n");
        if let Some(secret) = secret {
            head.push_str(&format!("authorization: Bearer {secret}\r\n"));
        }
        head.push_str(extra_headers);
        head.push_str("\r\n");
        head
    }

    #[test]
    fn certificate_reload_needs_the_write_role_and_no_browser_origin() {
        let state = state();

        // Anonymous: nothing about the plane, and the attempt is audited as a
        // POST (the log must show what was tried, not only what was applied).
        let head = certificate_reload(None, "");
        let (response, audit) = respond(&head, None, &tokens(), &state, peer());
        assert_eq!(response.status, 401);
        let audit = audit.expect("an unauthenticated renewal is audited");
        assert_eq!(audit.method, "POST");
        assert_eq!(audit.status, 401);

        // The read token cannot renew certificates.
        let read_attempt = certificate_reload(Some(TOKEN), "");
        let (response, audit) = respond(&read_attempt, None, &tokens(), &state, peer());
        assert_eq!(response.status, 403);
        assert_eq!(body_json(&response)["error"], "forbidden");
        assert_eq!(audit.expect("audited").status, 403);

        // A plane with no write secret at all says so instead of pretending.
        let read_only = Tokens {
            read: Arc::from(TOKEN),
            write: None,
        };
        let (response, _) = respond(
            &certificate_reload(Some(TOKEN), ""),
            None,
            &read_only,
            &state,
            peer(),
        );
        assert_eq!(response.status, 403);
        assert_eq!(body_json(&response)["error"], "write_disabled");

        // A browser-originated request never renews a certificate.
        let (response, _) = respond(
            &certificate_reload(Some(WRITE), "origin: https://evil.example\r\n"),
            None,
            &tokens(),
            &state,
            peer(),
        );
        assert_eq!(response.status, 403);
        assert_eq!(body_json(&response)["error"], "origin_forbidden");
    }

    #[test]
    fn certificate_reload_rejects_a_body_and_reaches_the_applier_as_an_action() {
        let state = state();

        for extra in ["content-length: 4\r\n", "transfer-encoding: chunked\r\n"] {
            let attempt = certificate_reload(Some(WRITE), extra);
            let (response, audit) = respond(&attempt, None, &tokens(), &state, peer());
            assert_eq!(response.status, 400, "{extra}");
            assert_eq!(body_json(&response)["error"], "body_not_allowed");
            assert_eq!(audit.expect("audited").status, 400);
        }

        // A clean request is a reload action: no revision precondition, no
        // body, and the method travels with it so the audit line is honest.
        let path = CERTIFICATE_RELOAD_PATH;
        match super::respond(
            &certificate_reload(Some(WRITE), ""),
            None,
            &tokens(),
            &state,
            peer(),
        ) {
            Outcome::Apply {
                change,
                if_match,
                method,
                path: seen,
                ..
            } => {
                assert_eq!(method, "POST");
                assert_eq!(seen, path);
                assert!(if_match.is_none(), "an action is not a conditional edit");
                assert!(
                    matches!(change, ConfigChange::Reload),
                    "unexpected change: {change:?}"
                );
            }
            Outcome::Done(response, _) => panic!("must be applied: {}", response.status),
        }

        // Only the documented path exists, and the method list advertises it.
        let (response, _) = respond(
            &request(
                "POST",
                "/api/v1/certificates",
                Some(&format!("Bearer {WRITE}")),
            ),
            None,
            &tokens(),
            &state,
            peer(),
        );
        assert_eq!(response.status, 405, "POST exists on one path only");
        let (response, _) = respond(
            &request("DELETE", path, Some(&format!("Bearer {WRITE}"))),
            None,
            &tokens(),
            &state,
            peer(),
        );
        assert_eq!(response.status, 405);
        assert!(
            response
                .extra
                .iter()
                .any(|(name, value)| *name == "allow" && value.contains("POST")),
            "a write-capable plane advertises POST: {:?}",
            response.extra
        );
    }

    #[test]
    fn anonymous_writes_are_401_and_audited() {
        let state = state();
        let path = "/api/v1/backends/api/servers/127.0.0.1:9000/state";
        let head = format!(
            "PUT {path} HTTP/1.1\r\nhost: admin\r\ncontent-type: application/json\r\ncontent-length: 17\r\n\r\n"
        );
        let (response, audit) = respond(
            &head,
            Some(b"{\"state\":\"drain\"}"),
            &tokens(),
            &state,
            peer(),
        );
        assert_eq!(response.status, 401);
        let audit = audit.expect("an unauthenticated write is audited");
        assert_eq!(audit.role, "none");
        assert_eq!(audit.status, 401);
    }
}
