//! Administration plane (v0.8, D6): read API, Prometheus metrics and the
//! first write path — per-server administration state (ADR-0018).
//!
//! Scope: `GET /api/v1/status`, `GET /metrics`, the per-server state write
//! (`PUT /api/v1/backends/{backend}/servers/{target}/state` with
//! `{"state":"ready"|"drain"}`, ADR-0018) and the configuration writes
//! (`PUT /api/v1/backends/{name}` and `PUT /api/v1/listeners/{name}`, ADR-0019).
//! The read token opens the two `GET`s; the write token is required for every
//! `PUT` (and may also read). Without a write token the whole plane stays
//! read-only and every `PUT` is `403 write_disabled` — absent means off,
//! never an implicit grant.
//!
//! Authorization is per route (RBAC with two roles), and every `PUT` leaves
//! one `AUDIT` JSON line on stderr with its outcome, the peer and the
//! transition. The token never appears in a response or a log line.
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
//! response, a log line or an error body. Loopback is the default bind and a
//! non-loopback one is rejected by validation unless `allow_remote` is set,
//! because this slice has no TLS on the plane.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock, RwLockReadGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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

/// Resolved admin plane: where it listens and the secrets it demands.
#[derive(Clone)]
pub struct ResolvedAdmin {
    pub listen: SocketAddr,
    pub token: Arc<str>,
    /// `None` = writes disabled (the plane is read-only).
    pub write_token: Option<Arc<str>>,
}

/// One listener as the API reports it (from the validated config).
#[derive(Debug, Clone, Serialize)]
pub struct ListenerInfo {
    pub name: String,
    pub listen: String,
    pub mode: String,
    pub backend: String,
    pub maxconn: u32,
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
    /// `metrics.detailed`: per-server counters are opt-in (CE4); the flag is
    /// reported so a scraper knows whether that detail exists.
    pub metrics_detailed: bool,
    /// Configuration write pipeline (ADR-0019). `None` = no applier attached:
    /// configuration `PUT`s answer `503 config_unavailable`.
    pub apply: Option<mpsc::Sender<ApplyMessage>>,
}

impl AdminState {
    fn read_topology(&self) -> RwLockReadGuard<'_, AdminTopology> {
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
    /// Re-read the configuration file (SIGHUP). Internal to the process; it
    /// carries no HTTP route and is never sent by a client.
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
    metrics_detailed: bool,
    counters: eqproxy_core::MetricsSnapshot,
}

#[derive(Serialize)]
struct BackendStatus<'a> {
    name: &'a str,
    balance: &'static str,
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
    /// `ready` or `drain` (ADR-0018).
    state: &'static str,
    /// Health machine (B11), independent of `state`.
    healthy: bool,
    /// Exchanges in flight on this slot.
    active: u32,
}

/// Running admin plane: stop it on shutdown, or abort it to prove the
/// dataplane does not depend on it.
pub struct AdminHandle {
    local: SocketAddr,
    stop: eqproxy_core::ShutdownHandle,
    task: JoinHandle<()>,
}

impl AdminHandle {
    /// Real address (port 0 resolves an ephemeral one).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Stops the accept loop and waits for it.
    pub async fn shutdown(self) {
        self.stop.trigger();
        let _ = self.task.await;
    }

    /// Simulates the plane dying (test seam): the dataplane must keep
    /// serving, which is what SPEC §9 requires of the panel.
    pub fn abort(&self) {
        self.task.abort();
    }
}

/// Binds the admin listener. Unlike the dataplane, failing to bind here is
/// fatal for the process: a configured plane that cannot open is a
/// configuration error, not a silent downgrade (the CLI exits with 1).
pub async fn bind(cfg: ResolvedAdmin, state: Arc<AdminState>) -> std::io::Result<AdminHandle> {
    let listener = TcpListener::bind(cfg.listen).await?;
    let local = listener.local_addr()?;
    let (stop, shutdown) = shutdown::channel();
    let tokens = Tokens {
        read: cfg.token,
        write: cfg.write_token,
    };
    let task = tokio::spawn(serve(listener, tokens, state, shutdown));
    Ok(AdminHandle { local, stop, task })
}

/// The configured secrets. `write = None` disables every write.
#[derive(Clone)]
struct Tokens {
    read: Arc<str>,
    write: Option<Arc<str>>,
}

impl Tokens {
    /// `(role, authenticated)`: both secrets are compared even after a match,
    /// so a timing observer cannot learn which one was tried.
    fn role(&self, present: Option<&str>) -> Role {
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
enum Role {
    None,
    Read,
    Write,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Read => "read",
            Self::Write => "operate",
        }
    }
}

async fn serve(
    listener: TcpListener,
    tokens: Tokens,
    state: Arc<AdminState>,
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
    mut stream: TcpStream,
    tokens: Tokens,
    state: Arc<AdminState>,
    peer: SocketAddr,
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
        // Only a `PUT` carries a body, and only the declared, bounded length
        // is read. A missing or oversized length is answered by `respond`
        // (411/413) without touching the socket again.
        if head.split(' ').next() == Some("PUT")
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
    match respond(&head, body.as_deref(), &tokens, &state, peer) {
        Outcome::Done(response, audit) => {
            log_audit(audit);
            answer(&mut stream, response).await;
        }
        Outcome::Apply {
            change,
            if_match,
            role,
            path,
        } => {
            let (response, status) = apply_config(&state, change, if_match).await;
            log_audit(Some(audit(
                peer,
                role,
                path,
                status,
                AuditFields::default(),
            )));
            answer(&mut stream, response).await;
        }
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
async fn answer(stream: &mut TcpStream, response: Response) {
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
async fn read_head(stream: &mut TcpStream, head: &mut Vec<u8>) -> Result<(), HeadError> {
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
async fn read_body(
    stream: &mut TcpStream,
    length: usize,
    initial: &[u8],
) -> Result<Vec<u8>, HeadError> {
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
fn header_values<'a>(head: &'a str, name: &str) -> Vec<&'a str> {
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
struct Response {
    status: u16,
    content_type: &'static str,
    extra: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

impl Response {
    fn text(status: u16, body: &str) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            extra: Vec::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    fn json(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: "application/json; charset=utf-8",
            extra: Vec::new(),
            body,
        }
    }

    fn error(status: u16, code: &str) -> Self {
        // Machine-readable, and deliberately empty of detail: an unauthorized
        // caller learns nothing about the plane.
        let body = format!("{{\"error\":\"{code}\"}}\n");
        Self::json(status, body.into_bytes())
    }

    fn with_header(mut self, name: &'static str, value: String) -> Self {
        self.extra.push((name, value));
        self
    }

    async fn write(self, stream: &mut TcpStream) -> std::io::Result<()> {
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
struct Audit<'a> {
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
struct AuditFields<'a> {
    backend: Option<&'a str>,
    server: Option<&'a str>,
    from: Option<ServerMode>,
    to: Option<ServerMode>,
}

fn audit<'a>(
    peer: SocketAddr,
    role: Role,
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
        // The only write route in this slice is a `PUT`.
        method: "PUT",
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
enum Outcome<'a> {
    Done(Response, Option<Audit<'a>>),
    Apply {
        change: ConfigChange,
        if_match: Option<String>,
        role: Role,
        path: &'a str,
    },
}

impl<'a> Outcome<'a> {
    fn done(response: Response) -> Self {
        Self::Done(response, None)
    }

    fn done_with(response: Response, audit: Option<Audit<'a>>) -> Self {
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
    peer: SocketAddr,
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
    let is_write = method == "PUT";
    let role = tokens.role(bearer(head));
    if role == Role::None {
        let audit = is_write.then(|| audit(peer, role, path, 401, AuditFields::default()));
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
                        metrics_detailed: state.metrics_detailed,
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
                    body: state.metrics.snapshot().prometheus().into_bytes(),
                },
                _ => Response::error(404, "not_found"),
            };
            Outcome::done(response)
        }
        "PUT" => {
            if is_config_path(path) {
                put_config(head, body, tokens, role, peer, path)
            } else {
                let (response, audit) =
                    put_server_state(head, body, tokens, role, state, peer, path);
                Outcome::done_with(response, audit)
            }
        }
        _ => {
            let allow = if tokens.write.is_some() {
                "GET, PUT"
            } else {
                "GET"
            };
            Outcome::done(
                Response::error(405, "method_not_allowed").with_header("allow", allow.to_owned()),
            )
        }
    }
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
    peer: SocketAddr,
    path: &'a str,
) -> Outcome<'a> {
    let adjudicate = |status: u16| -> Option<Audit<'a>> {
        Some(audit(peer, role, path, status, AuditFields::default()))
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
        path,
    }
}

fn backend_status(backend: &ResolvedBackend) -> BackendStatus<'_> {
    BackendStatus {
        name: &backend.name,
        balance: match backend.balancer.algorithm() {
            crate::balancer::Balance::RoundRobin => "round_robin",
            crate::balancer::Balance::LeastConn => "least_conn",
        },
        health_check: backend.health_check.is_some(),
        servers: backend
            .balancer
            .servers_view()
            .into_iter()
            .map(|server| ServerStatus {
                addr: server.target,
                resolved: server.addr.map(|addr| addr.to_string()),
                weight: server.weight,
                state: server.mode.as_str(),
                healthy: server.up,
                active: server.active,
            })
            .collect(),
    }
}

/// `PUT /api/v1/backends/{backend}/servers/{target}/state`.
///
/// Order of checks: role, browser origin, media type, length, body shape,
/// state value, existence. A refused request never changes a slot; an
/// accepted one is idempotent and reports the previous state.
fn put_server_state<'a>(
    head: &str,
    body: Option<&[u8]>,
    tokens: &Tokens,
    role: Role,
    state: &AdminState,
    peer: SocketAddr,
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
    let topology = state.read_topology();
    let Some(backend) = topology.backends.iter().find(|b| b.name == backend_name) else {
        return (
            Response::error(404, "not_found"),
            Some(record(404, Some(backend_name), None, None, None)),
        );
    };
    let Some(server) = backend
        .balancer
        .servers_view()
        .into_iter()
        .find(|server| server.target == target)
    else {
        return (
            Response::error(404, "not_found"),
            Some(record(404, Some(backend_name), Some(target), None, None)),
        );
    };
    let previous = server.mode;
    let applied = state.modes.set(backend_name, target, mode);
    let answer = serde_json::json!({
        "backend": backend_name,
        "server": target,
        "state": mode.as_str(),
        "previous": applied.as_str(),
        "active": server.active,
        "healthy": server.up,
        "changed": previous != mode,
    });
    match serde_json::to_vec(&answer) {
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
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StateRequest {
    state: String,
}

/// Constant-time token comparison: an attacker who can time the answers must
/// not learn how many leading bytes of the token are right.
fn token_matches(expected: &str, given: &str) -> bool {
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

    fn peer() -> SocketAddr {
        "127.0.0.1:50000".parse().expect("peer")
    }

    fn backend(modes: &Arc<ServerModes>) -> Arc<ResolvedBackend> {
        Arc::new(
            ResolvedBackend::new(
                "api",
                vec![
                    ResolvedServer {
                        addr: crate::ServerAddr::Ip("127.0.0.1:9000".parse().expect("addr")),
                        weight: 1,
                    },
                    ResolvedServer {
                        addr: crate::ServerAddr::Ip("127.0.0.1:9001".parse().expect("addr")),
                        weight: 2,
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
                }],
                backends: vec![backend(&modes)],
            })),
            modes,
            metrics: Arc::new(Metrics::default()),
            metrics_detailed: false,
            apply,
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
        peer: SocketAddr,
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
    fn only_get_and_the_state_put_are_served() {
        let state = state();
        for method in ["POST", "DELETE", "HEAD", "PATCH"] {
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
                    .any(|(name, value)| *name == "allow" && value == "GET, PUT")
            );
        }
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
                "{\"state\":\"maintenance\"}",
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
