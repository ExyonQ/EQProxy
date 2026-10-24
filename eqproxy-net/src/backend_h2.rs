//! HTTP/2 to the backend (B-H1/B-N1/B-I1/B-E2): `http2_protocol_options`.
//!
//! A backend whose TLS handshake negotiates `h2` — `[backend.X.tls] alpn`
//! lists it — is reached with a **real HTTP/2 session**, never with h1 bytes
//! that a server expecting frames would reject. The rest of the proxy keeps
//! its single exchange engine (`http1::serve_http` owns routing, auth,
//! retries, the keep-alive pool and the error surface), so this module is the
//! mirror of `http2`: one HTTP/1.1 message on an in-memory pipe becomes one
//! h2 stream, and the h2 answer becomes exactly one h1 message.
//!
//! Translation, both directions:
//! - Request: h1 head/body → HEADERS + DATA. `content-length` is kept only
//!   when the h1 side declared one; a `chunked` body becomes DATA frames and
//!   its trailers become trailing HEADERS. Hop-by-hop h1 headers (`connection`,
//!   `transfer-encoding`, `upgrade`, `te`, …), `host` (replaced by
//!   `:authority`) and `expect` (an h1 mechanism) never cross.
//! - Response: HEADERS + DATA → h1 head/body. A backend `content-length` is
//!   preserved (the h1 side copies exactly that many bytes and the connection
//!   stays message-aligned for the pool); without one the body is relayed as
//!   `chunked`, and h2 trailers are appended as h1 trailers.
//!
//! Multiplexing: a backend **server** owns one h2 session (the `Hub`) and
//! every exchange gets its own in-memory pipe mapped to a stream on it, so
//! concurrent exchanges share the session instead of queueing behind one
//! connection. The `h2` crate queues a request that arrives at the server's
//! concurrent-stream limit and opens it when capacity returns; the engine's
//! own pool is bypassed for h2 exchanges because a pipe is per exchange.
//!
//! Session lifecycle:
//! - **Idle close**: a session with no exchange for the listener's
//!   `idle_timeout` leaves the hub and its sender is dropped, so the
//!   connection closes instead of holding a TLS+h2 session for the process
//!   lifetime. An exchange in flight is never cut: the session counts them
//!   and only an idle one closes. The `h2` client API has no client-side
//!   GOAWAY (only server connections can send one), so an idle close ends the
//!   connection after its last stream instead of announcing it.
//! - **GOAWAY drain**: when the peer announces GOAWAY, in-flight streams
//!   finish on the old session (the h2 connection stays alive until they
//!   do), the session stops being handed out, and the next exchange dials a
//!   fresh one.
//! - **Safe refusal retry**: a stream the peer refused before processing it
//!   (a received GOAWAY, or `RST_STREAM` with `REFUSED_STREAM`) is replayed
//!   once on a fresh session when no request body was consumed. A stream cut
//!   after the server processed it is never replayed (no duplicate side
//!   effects): it fails explicitly, as before.
//!
//! Deliberate limits of this slice, all explicit:
//! - h2 is chosen only from the TLS ALPN result: a plaintext backend keeps
//!   speaking HTTP/1.1 (there is no `h2c`-to-backend option yet).
//! - `CONNECT`/protocol upgrades have no h2 backend equivalent (h2 has no
//!   `101`): they end as an explicit failure, never a half-open tunnel.
//! - h2 interim (1xx) responses are consumed by the client library; h1
//!   `100-continue` is answered by the proxy itself, never forwarded.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use bytes::Bytes;
use eqproxy_core::Metrics;
use h2::SendStream;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::http1::{
    BodyFraming, FORBIDDEN_TRAILERS, HeadError, MAX_LINE_BYTES, Prefixed, RequestHead,
    parse_chunk_size, parse_header_line, parse_request_head, phrase, read_crlf_line, read_head,
};
use crate::http2::{DATA_CHUNK, StreamError, capacity, copy_error, is_hop_by_hop};
use crate::proxy::{BoxRead, BoxWrite};

/// In-memory pipe between the engine and the h2 backend session. Bounded:
/// a slow backend applies backpressure through it instead of buffering.
const PIPE_BUFFER: usize = 64 * 1024;

/// Process-unique id of a session, used by the hub to remove exactly the
/// session it registered (never a newer one for the same address).
static NEXT_SESSION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// One live HTTP/2 session to a backend server, shared by every exchange
/// that reaches it while it is alive.
pub struct Session {
    /// Listener name and chosen server, for the lifecycle log lines.
    name: String,
    addr: SocketAddr,
    /// Identity compared by the hub (unique per process).
    id: u64,
    /// The hub holding this session, so closing it unregisters it.
    hub: Weak<Hub>,
    /// Lifecycle counters (`idle close`, `GOAWAY`, refused replays).
    metrics: Arc<Metrics>,
    /// No exchange for this window closes the session.
    idle: Duration,
    /// Submitter of new streams plus the session's accounting. One lock makes
    /// "an exchange enters" and "the session closes" atomic, so a close can
    /// never cut an exchange that was already admitted.
    state: Mutex<State>,
    /// Whether the connection task still drives the session.
    alive: AtomicBool,
    /// Abort handle of the connection task: an idle close ends the socket
    /// this way, because the h2 client API has no graceful shutdown of its
    /// own (only the server side can emit a GOAWAY).
    connection: Mutex<Option<tokio::task::AbortHandle>>,
}

struct State {
    /// `None` once the session is closing: dropping the last sender ends the
    /// h2 connection after its streams, which is the graceful close.
    send: Option<h2::client::SendRequest<Bytes>>,
    /// Exchanges admitted and not finished yet.
    active: usize,
    /// When the last exchange finished: idleness starts here.
    last_idle: Instant,
    /// The peer sent GOAWAY or the session is closing: never handed out.
    going_away: bool,
}

impl Session {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Whether a new exchange may use this session.
    fn usable(&self) -> bool {
        if !self.alive.load(Ordering::Acquire) {
            return false;
        }
        let state = self.lock();
        state.send.is_some() && !state.going_away
    }

    /// Admits one exchange and returns its stream handle. The [`ExchangeSlot`]
    /// keeps the session from closing while the exchange runs.
    pub(crate) fn enter(
        self: &Arc<Self>,
    ) -> Option<(ExchangeSlot, h2::client::SendRequest<Bytes>)> {
        if !self.alive.load(Ordering::Acquire) {
            return None;
        }
        let mut state = self.lock();
        if state.going_away {
            return None;
        }
        let send = state.send.clone()?;
        state.active += 1;
        Some((
            ExchangeSlot {
                session: Arc::clone(self),
            },
            send,
        ))
    }

    /// The peer announced GOAWAY: in-flight streams finish (their senders are
    /// clones of the handle), no new exchange is admitted, and the hub stops
    /// handing this session out.
    fn going_away(&self) {
        let mut state = self.lock();
        if state.going_away {
            return;
        }
        state.going_away = true;
        state.send = None;
        drop(state);
        self.metrics
            .h2_goaway_received
            .fetch_add(1, Ordering::Relaxed);
        eprintln!(
            "WARN [{}] backend {} is closing its HTTP/2 session (GOAWAY): in-flight streams drain, new exchanges dial a fresh session",
            self.name, self.addr
        );
        self.unregister();
    }

    /// Ends the connection once no exchange is in flight. The h2 client API
    /// offers no client-side GOAWAY, so the socket is closed instead of being
    /// announced; nothing is in flight, so no stream is lost.
    fn abort_connection(&self) {
        let handle = self
            .connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(handle) = handle {
            handle.abort();
        }
    }

    /// Stops handing this session out without counting a GOAWAY: the peer
    /// refused one stream, or the connection itself ended.
    fn retire(&self) {
        let mut state = self.lock();
        state.going_away = true;
        state.send = None;
        drop(state);
        self.unregister();
    }

    /// Removes this session from the hub, if it is still the registered one.
    fn unregister(&self) {
        if let Some(hub) = self.hub.upgrade() {
            hub.forget(self.addr, self.id);
        }
    }
}

/// An admitted exchange. Dropping it returns the session to idle (and is what
/// lets the idle monitor close a session nobody is using).
pub struct ExchangeSlot {
    session: Arc<Session>,
}

impl Drop for ExchangeSlot {
    fn drop(&mut self) {
        let mut state = self.session.lock();
        state.active = state.active.saturating_sub(1);
        state.last_idle = Instant::now();
    }
}

/// Dials a replacement session for the same server after the peer refused a
/// stream. Implemented by the dataplane (the only layer that owns the TLS
/// client and the chosen address): this module knows sessions, not dialing.
pub trait SessionDialer: Send + Sync {
    /// A usable session for the server this dialer was built for, or `None`
    /// when it cannot be reached right now. The flag is `true` when the
    /// session was dialed (a new connection), `false` when a live one was
    /// reused, so the caller's counters describe what actually happened.
    fn dial(&self) -> DialFuture<'_>;
}

/// What [`SessionDialer::dial`] returns: a session and whether it was dialed.
pub type DialFuture<'a> = Pin<Box<dyn Future<Output = Option<(Arc<Session>, bool)>> + Send + 'a>>;

/// Watches one session: once it has been idle for its window, it is removed
/// from the hub and its sender dropped, so the connection closes.
fn spawn_idle_monitor(session: &Arc<Session>) {
    let session = Arc::clone(session);
    tokio::spawn(async move {
        let window = session.idle;
        // A quarter of the window keeps the close near its deadline without a
        // wake per session per millisecond.
        let tick = (window / 4).clamp(Duration::from_millis(10), Duration::from_millis(500));
        loop {
            tokio::time::sleep(tick).await;
            let mut state = session.lock();
            if state.going_away || !session.alive.load(Ordering::Acquire) {
                return;
            }
            if state.active > 0 || state.last_idle.elapsed() < window {
                continue;
            }
            state.going_away = true;
            state.send = None;
            drop(state);
            session
                .metrics
                .h2_sessions_idle_closed
                .fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "INFO [{}] closed an idle HTTP/2 session to {} after {:?}",
                session.name, session.addr, window
            );
            session.unregister();
            session.abort_connection();
            return;
        }
    });
}

/// Live h2 sessions of one backend, keyed by the chosen server address.
///
/// This is what makes multiplexing real: the engine's pool lends a connection
/// to one exchange, so it is bypassed for h2 — every exchange opens a stream
/// on the session registered here instead of dialing.
#[derive(Default)]
pub struct Hub {
    sessions: Mutex<HashMap<SocketAddr, Arc<Session>>>,
    /// One gate per server address: the exchange that finds the server cold
    /// holds it while it dials and handshakes, and the exchanges that arrive
    /// meanwhile take a stream on the session it installs. Without the gate
    /// two concurrent first requests each dial their own connection, which is
    /// exactly the multiplexing this module exists to provide, lost.
    gates: Mutex<HashMap<SocketAddr, Arc<tokio::sync::Mutex<()>>>>,
}

impl std::fmt::Debug for Hub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The handles are not printable; the count is what a log needs.
        f.debug_struct("Hub")
            .field("sessions", &self.lock().len())
            .finish()
    }
}

impl Hub {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<SocketAddr, Arc<Session>>> {
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Alive session for `addr`, or `None` when the caller must dial. A dead,
    /// closing or draining entry is removed here, so the next exchange never
    /// trusts it.
    pub fn lookup(&self, addr: SocketAddr) -> Option<Arc<Session>> {
        let mut sessions = self.lock();
        match sessions.get(&addr) {
            Some(session) if session.usable() => Some(Arc::clone(session)),
            Some(_) => {
                sessions.remove(&addr);
                None
            }
            None => None,
        }
    }

    /// Gate for the initial handshake of `addr`. Callers re-check
    /// [`Self::lookup`] after acquiring it: the session may have appeared.
    pub fn connect_gate(&self, addr: SocketAddr) -> Arc<tokio::sync::Mutex<()>> {
        let mut gates = self
            .gates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Arc::clone(gates.entry(addr).or_default())
    }

    fn install(&self, addr: SocketAddr, session: &Arc<Session>) {
        self.lock().insert(addr, Arc::clone(session));
    }

    /// Removes the session with `id` only when it is still the registered one
    /// (a newer session for the same address must not be evicted by an older
    /// one).
    fn forget(&self, addr: SocketAddr, id: u64) {
        let mut sessions = self.lock();
        if sessions.get(&addr).is_some_and(|current| current.id == id) {
            sessions.remove(&addr);
        }
    }
}

/// Handshakes a real HTTP/2 session on `io` (already TLS with ALPN `h2`) and
/// registers it in `hub`.
///
/// The handshake happens **before** returning: a backend that is not really
/// h2 is a connect-phase failure (retried by B-H7, answered with `502`),
/// never a connection that looks open and then fails per request.
pub async fn connect<IO>(
    hub: Arc<Hub>,
    io: IO,
    name: &str,
    addr: SocketAddr,
    connect_timeout: Duration,
    idle: Duration,
    metrics: Arc<Metrics>,
) -> Result<Arc<Session>, io::Error>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (send_request, connection) =
        match tokio::time::timeout(connect_timeout, h2::client::handshake(io)).await {
            Err(_) => {
                return Err(io::Error::other(
                    "HTTP/2 handshake to the backend timed out",
                ));
            }
            Ok(Err(err)) => {
                return Err(io::Error::other(format!(
                    "HTTP/2 handshake to the backend failed: {err}"
                )));
            }
            Ok(Ok(handshake)) => handshake,
        };
    let session = Arc::new(Session {
        name: name.to_owned(),
        addr,
        id: NEXT_SESSION.fetch_add(1, Ordering::Relaxed),
        hub: Arc::downgrade(&hub),
        metrics,
        idle,
        state: Mutex::new(State {
            send: Some(send_request),
            active: 0,
            last_idle: Instant::now(),
            going_away: false,
        }),
        alive: AtomicBool::new(true),
        connection: Mutex::new(None),
    });
    hub.install(addr, &session);
    let session_task = Arc::clone(&session);
    let connection_name = name.to_owned();
    let task = tokio::spawn(async move {
        if let Err(err) = connection.await {
            eprintln!("WARN [{connection_name}] HTTP/2 backend connection failed: {err}");
        }
        session_task.alive.store(false, Ordering::Release);
        // A lookup that lands between the notification and the hub removal
        // must not see a usable handle: close the sender first.
        session_task.retire();
    });
    // Detached task: only the abort handle is kept, so an idle close can end
    // the socket without the session owning its own task forever.
    session
        .connection
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .replace(task.abort_handle());
    drop(task);
    spawn_idle_monitor(&session);
    Ok(session)
}

/// Opens one exchange on the session: a fresh in-memory pipe whose only
/// message becomes one stream, so concurrent exchanges share the session.
///
/// `dialer` is only used when the peer refuses the stream with GOAWAY: the
/// replay needs a fresh session, and dialing is the dataplane's job.
pub fn open(
    session: &Arc<Session>,
    dialer: Arc<dyn SessionDialer>,
    name: &str,
    idle: Duration,
) -> Result<(BoxRead, BoxWrite), io::Error> {
    let (slot, send) = session
        .enter()
        .ok_or_else(|| io::Error::other("HTTP/2 backend session is closed"))?;
    let exchange = Exchange {
        session: Arc::clone(session),
        dialer,
        slot,
        send,
        idle,
        retried: false,
    };
    let (engine, backend) = tokio::io::duplex(PIPE_BUFFER);
    let (engine_read, engine_write) = tokio::io::split(engine);
    let (pipe_read, pipe_write) = tokio::io::split(backend);
    let label = name.to_owned();
    tokio::spawn(async move {
        if let Err(err) = exchange.serve(pipe_read, pipe_write).await {
            eprintln!(
                "WARN [{label}] HTTP/2 backend exchange ended: {}",
                describe(err)
            );
        }
    });
    Ok((Box::new(engine_read), Box::new(engine_write)))
}

/// Human-readable reason for a cut stream (the log names the cause).
fn describe(err: StreamError) -> &'static str {
    match err {
        StreamError::Truncated => "body shorter than its declared length",
        StreamError::Framing => "framing that has no HTTP/2 translation",
        StreamError::Io => "I/O or timeout",
        StreamError::H2 => "HTTP/2 protocol error",
        StreamError::H3 => "HTTP/3 stream error",
        StreamError::Refused => "refused by a GOAWAY and not replayable",
        StreamError::StreamRefused => "reset with REFUSED_STREAM and not replayable",
    }
}

/// Did the peer refuse this stream **without processing it**? That is the one
/// failure that is safe to replay: a received GOAWAY, or a received
/// `RST_STREAM(REFUSED_STREAM)` (RFC 9113 §8.1.4 states the stream was not
/// processed), unlike a cut connection whose processed streams must never run
/// twice.
fn refused_by_peer(err: &h2::Error) -> bool {
    if !err.is_remote() {
        return false;
    }
    err.is_go_away() || (err.is_reset() && err.reason() == Some(h2::Reason::REFUSED_STREAM))
}

/// A received GOAWAY (the session is going away) rather than a per-stream
/// `REFUSED_STREAM` (the session stays healthy and keeps serving).
fn went_away(err: &h2::Error) -> bool {
    err.is_remote() && err.is_go_away()
}

/// One admitted exchange: the session it runs on, the guard that keeps that
/// session from closing underneath it, and the handle its stream is built
/// from.
struct Exchange {
    session: Arc<Session>,
    /// Fresh sessions for the one replay a refusal allows.
    dialer: Arc<dyn SessionDialer>,
    slot: ExchangeSlot,
    send: h2::client::SendRequest<Bytes>,
    idle: Duration,
    /// At most one replay, and only after a GOAWAY refusal.
    retried: bool,
}

impl Exchange {
    /// Serves exactly one h1 message from the engine over one h2 stream. The
    /// pipe is owned by a single exchange, so the function returns as soon as
    /// its answer has been relayed (nothing is pooled behind it).
    async fn serve<R, W>(mut self, pipe_read: R, mut pipe_write: W) -> Result<(), StreamError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut reader = BufReader::new(pipe_read);
        let mut first = [0u8; 1];
        match reader.read_exact(&mut first).await {
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(_) => return Err(StreamError::Io),
            Ok(_) => {}
        }
        let mut source = Prefixed {
            prefix: first.to_vec(),
            pos: 0,
            inner: &mut reader,
        };
        let (head, rest) = match read_head(&mut source, self.idle).await {
            Ok(pair) => pair,
            Err(HeadError::Timeout) => return Err(StreamError::Io),
            Err(_) => return Err(StreamError::Framing),
        };
        // Exact stream remainder: bytes read past the head plus prefix bytes
        // read_head never consumed.
        let unread = source.prefix.split_off(source.pos);
        let mut prefix = rest;
        prefix.extend(unread);
        let request = parse_request_head(&head).map_err(|_| StreamError::Framing)?;
        let mut body = Prefixed {
            prefix,
            pos: 0,
            inner: &mut reader,
        };
        loop {
            match self.forward(&request, &mut body, &mut pipe_write).await {
                // The peer refused this stream before processing it: it
                // delivered nothing, so replaying it once is safe.
                Err(StreamError::Refused) => self.replay(true).await?,
                Err(StreamError::StreamRefused) => self.replay(false).await?,
                result => return result,
            }
        }
    }

    /// Replaces a session that refused the stream: the old one stops being
    /// handed out (its in-flight streams still finish), a fresh one is dialed
    /// and the exchange joins it with the same request head.
    async fn replay(&mut self, goaway: bool) -> Result<(), StreamError> {
        if self.retried {
            // A second refusal is reported, never retried in a loop.
            return Err(StreamError::H2);
        }
        self.retried = true;
        if goaway {
            self.session.going_away();
        } else {
            // The peer refused one stream, not the session: retire it anyway
            // so the replay lands on a fresh connection instead of retrying
            // into the same refusal.
            self.session.retire();
        }
        let Some((fresh, dialed)) = self.dialer.dial().await else {
            return Err(StreamError::H2);
        };
        let Some((slot, send)) = fresh.enter() else {
            return Err(StreamError::H2);
        };
        if dialed {
            fresh
                .metrics
                .backend_connections_opened
                .fetch_add(1, Ordering::Relaxed);
        }
        fresh
            .metrics
            .h2_refused_retried
            .fetch_add(1, Ordering::Relaxed);
        // Assigning the slot drops the previous one: the old session counts
        // this exchange as finished (and is never reused).
        self.slot = slot;
        self.session = fresh;
        self.send = send;
        Ok(())
    }

    /// One h1 message → one h2 stream → one h1 message. A `Refused` return
    /// happens before a single byte reached `out`, so the caller may replay.
    async fn forward<R, W>(
        &mut self,
        request: &RequestHead,
        body: &mut Prefixed<R>,
        out: &mut W,
    ) -> Result<(), StreamError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let idle = self.idle;
        let (h2_request, end_of_stream) = build_request(request)?;
        let (response, mut send) = match self.send.send_request(h2_request, end_of_stream) {
            Ok(pair) => pair,
            Err(err) if refused_by_peer(&err) => {
                return Err(if went_away(&err) {
                    StreamError::Refused
                } else {
                    StreamError::StreamRefused
                });
            }
            Err(_) => return Err(StreamError::H2),
        };
        if !end_of_stream {
            forward_request_body(body, &mut send, request.framing, idle).await?;
        }
        let response = tokio::time::timeout(idle, response)
            .await
            .map_err(|_| StreamError::Io)?
            .map_err(|err| {
                // Only a stream that carried no body at all can be replayed:
                // a consumed body would need a buffer, and a stream the server
                // did process must never run twice.
                if !end_of_stream || !refused_by_peer(&err) {
                    return StreamError::H2;
                }
                if went_away(&err) {
                    StreamError::Refused
                } else {
                    StreamError::StreamRefused
                }
            })?;
        // `HEAD`, `204` and `304` never carry a body: the h2 response may still
        // declare a length, it just must not be awaited or relayed.
        let body_expected = request.method != "HEAD"
            && response.status() != http::StatusCode::NO_CONTENT
            && response.status() != http::StatusCode::NOT_MODIFIED;
        let declared = write_response_head(out, &response, body_expected, idle).await?;
        let recv = response.into_body();
        if body_expected {
            relay_response_body(out, recv, declared, idle).await
        } else {
            drain_body(recv, idle).await
        }
    }
}

/// h2 request head for one h1 request, plus whether the stream starts already
/// ended (no body at all).
fn build_request(request: &RequestHead) -> Result<(Request<()>, bool), StreamError> {
    if request.method == "CONNECT" {
        // A tunnel needs h1 `CONNECT`/`101` semantics the h2 backend side has
        // no translation for: refuse explicitly instead of guessing a path.
        return Err(StreamError::Framing);
    }
    let host = request.host.trim();
    if host.is_empty() {
        // h2 requires `:authority`; h1 requires `Host`: an h1 request without
        // one cannot be translated without inventing a target.
        return Err(StreamError::Framing);
    }
    let uri: http::Uri =
        if request.target.starts_with("http://") || request.target.starts_with("https://") {
            // Absolute-form (a client that proxies explicitly): keep its target.
            request.target.parse().map_err(|_| StreamError::Framing)?
        } else {
            format!("https://{host}{}", request.target)
                .parse()
                .map_err(|_| StreamError::Framing)?
        };
    let mut builder = Request::builder()
        .method(request.method.as_str())
        .uri(uri)
        .version(http::Version::HTTP_2);
    for (name, value) in &request.headers {
        if name == "host"
            || name == "content-length"
            || name == "expect"
            || name == "te"
            || name == "trailer"
            || is_hop_by_hop(name)
        {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_str());
    }
    if let BodyFraming::ContentLength(len) = request.framing {
        builder = builder.header("content-length", len);
    }
    let out = builder.body(()).map_err(|_| StreamError::Framing)?;
    Ok((out, request.framing == BodyFraming::None))
}

/// Relays the h1 request body into h2 DATA frames (and its trailers into
/// trailing HEADERS), honoring flow control.
async fn forward_request_body<R>(
    body: &mut Prefixed<R>,
    send: &mut SendStream<Bytes>,
    framing: BodyFraming,
    idle: Duration,
) -> Result<(), StreamError>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; DATA_CHUNK];
    match framing {
        BodyFraming::None => return Ok(()),
        BodyFraming::ContentLength(mut remaining) => {
            while remaining > 0 {
                let want = (remaining as usize).min(DATA_CHUNK);
                let got = read_some(body, &mut buf[..want], idle).await?;
                if got == 0 {
                    return Err(StreamError::Truncated);
                }
                send_data(send, &buf[..got], idle).await?;
                remaining -= got as u64;
            }
        }
        BodyFraming::UntilEof => {
            // A request body without a boundary cannot be framed as DATA.
            return Err(StreamError::Framing);
        }
        BodyFraming::Chunked => loop {
            let line = read_crlf_line(body, idle, MAX_LINE_BYTES)
                .await
                .map_err(copy_error)?;
            let size = parse_chunk_size(&line).map_err(copy_error)?;
            if size == 0 {
                let trailers = read_trailers(body, idle).await?;
                return if trailers.is_empty() {
                    send.send_data(Bytes::new(), true)
                } else {
                    send.send_trailers(trailers)
                }
                .map_err(|_| StreamError::H2);
            }
            let mut remaining = size;
            while remaining > 0 {
                let want = (remaining as usize).min(DATA_CHUNK);
                let got = read_some(body, &mut buf[..want], idle).await?;
                if got == 0 {
                    return Err(StreamError::Truncated);
                }
                send_data(send, &buf[..got], idle).await?;
                remaining -= got as u64;
            }
            let mut crlf = [0u8; 2];
            match tokio::time::timeout(idle, body.read_exact(&mut crlf)).await {
                Err(_) => return Err(StreamError::Io),
                Ok(Err(_)) => return Err(StreamError::Truncated),
                Ok(Ok(_)) => {}
            }
            if crlf != *b"\r\n" {
                return Err(StreamError::Framing);
            }
        },
    }
    send.send_data(Bytes::new(), true)
        .map_err(|_| StreamError::H2)
}

/// Sends one block of body bytes as DATA frames, waiting for capacity first
/// (never an unbounded write into the h2 session).
async fn send_data(
    send: &mut SendStream<Bytes>,
    data: &[u8],
    idle: Duration,
) -> Result<(), StreamError> {
    let mut offset = 0;
    while offset < data.len() {
        let available = capacity(send, DATA_CHUNK, idle).await?;
        let take = available.min(data.len() - offset);
        send.send_data(Bytes::copy_from_slice(&data[offset..offset + take]), false)
            .map_err(|_| StreamError::H2)?;
        offset += take;
    }
    Ok(())
}

/// h1 trailers of a chunked body as a header map (forbidden names refused).
async fn read_trailers<R>(body: &mut Prefixed<R>, idle: Duration) -> Result<HeaderMap, StreamError>
where
    R: AsyncRead + Unpin,
{
    let mut trailers = HeaderMap::new();
    loop {
        let line = read_crlf_line(body, idle, MAX_LINE_BYTES)
            .await
            .map_err(copy_error)?;
        if line == b"\r\n" {
            return Ok(trailers);
        }
        let (name, value) =
            parse_header_line(&line[..line.len() - 2]).map_err(|_| StreamError::Framing)?;
        if FORBIDDEN_TRAILERS.contains(&name.as_str()) {
            return Err(StreamError::Framing);
        }
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            trailers.append(name, value);
        }
    }
}

/// Writes the h1 response head for an h2 response. Returns the declared
/// `content-length` when the head carries one (the caller then copies exactly
/// that many bytes and relays nothing else).
async fn write_response_head<W>(
    out: &mut W,
    response: &Response<h2::RecvStream>,
    body_expected: bool,
    idle: Duration,
) -> Result<Option<u64>, StreamError>
where
    W: AsyncWrite + Unpin,
{
    let status = response.status().as_u16();
    let mut head = Vec::with_capacity(256);
    head.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", status, phrase(status)).as_bytes());
    let mut declared = None;
    for (name, value) in response.headers() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        if name == http::header::CONTENT_LENGTH {
            declared = value
                .to_str()
                .ok()
                .and_then(|text| text.trim().parse::<u64>().ok());
        }
        head.extend_from_slice(name.as_str().as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    if body_expected && declared.is_none() {
        // No length from the backend: chunked keeps the h1 side at a real
        // message boundary (and the pool reusable) while streaming.
        head.extend_from_slice(b"transfer-encoding: chunked\r\n");
    }
    head.extend_from_slice(b"\r\n");
    write_all(out, &head, idle).await?;
    Ok(declared.filter(|_| body_expected))
}

/// Relays the h2 response body as an h1 body: exactly `declared` bytes when
/// the head carried a length, `chunked` otherwise.
async fn relay_response_body<W>(
    out: &mut W,
    mut recv: h2::RecvStream,
    declared: Option<u64>,
    idle: Duration,
) -> Result<(), StreamError>
where
    W: AsyncWrite + Unpin,
{
    match declared {
        Some(len) => {
            let mut total = 0u64;
            loop {
                let chunk = match next_data(&mut recv, idle).await? {
                    Some(chunk) => chunk,
                    None => break,
                };
                if total + chunk.len() as u64 > len {
                    // More than declared: the h1 head already promised a
                    // shorter body — never over-send into the pipe.
                    return Err(StreamError::Framing);
                }
                write_all(out, &chunk, idle).await?;
                total += chunk.len() as u64;
            }
            if total != len {
                return Err(StreamError::Truncated);
            }
            Ok(())
        }
        None => {
            loop {
                let Some(chunk) = next_data(&mut recv, idle).await? else {
                    break;
                };
                write_all(out, format!("{:x}\r\n", chunk.len()).as_bytes(), idle).await?;
                write_all(out, &chunk, idle).await?;
                write_all(out, b"\r\n", idle).await?;
            }
            let trailers = match tokio::time::timeout(idle, recv.trailers()).await {
                Err(_) => return Err(StreamError::Io),
                Ok(Err(_)) => return Err(StreamError::H2),
                Ok(Ok(Some(trailers))) => trailers,
                Ok(Ok(None)) => HeaderMap::new(),
            };
            write_all(out, b"0\r\n", idle).await?;
            for (name, value) in &trailers {
                if FORBIDDEN_TRAILERS.contains(&name.as_str()) {
                    return Err(StreamError::Framing);
                }
                let mut line = Vec::with_capacity(name.as_str().len() + value.as_bytes().len() + 4);
                line.extend_from_slice(name.as_str().as_bytes());
                line.extend_from_slice(b": ");
                line.extend_from_slice(value.as_bytes());
                line.extend_from_slice(b"\r\n");
                write_all(out, &line, idle).await?;
            }
            write_all(out, b"\r\n", idle).await
        }
    }
}

/// Consumes a response stream whose message has no body (HEAD/204/304).
async fn drain_body(mut recv: h2::RecvStream, idle: Duration) -> Result<(), StreamError> {
    while next_data(&mut recv, idle).await?.is_some() {}
    match tokio::time::timeout(idle, recv.trailers()).await {
        Err(_) => Err(StreamError::Io),
        Ok(Err(_)) => Err(StreamError::H2),
        Ok(Ok(_)) => Ok(()),
    }
}

/// Next non-empty DATA payload, releasing flow-control capacity as it goes.
async fn next_data(
    recv: &mut h2::RecvStream,
    idle: Duration,
) -> Result<Option<Bytes>, StreamError> {
    loop {
        match tokio::time::timeout(idle, recv.data()).await {
            Err(_) => return Err(StreamError::Io),
            Ok(None) => return Ok(None),
            Ok(Some(Err(_))) => return Err(StreamError::H2),
            Ok(Some(Ok(chunk))) => {
                if chunk.is_empty() {
                    continue;
                }
                recv.flow_control()
                    .release_capacity(chunk.len())
                    .map_err(|_| StreamError::H2)?;
                return Ok(Some(chunk));
            }
        }
    }
}

async fn read_some<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
    idle: Duration,
) -> Result<usize, StreamError> {
    match tokio::time::timeout(idle, reader.read(buf)).await {
        Err(_) => Err(StreamError::Io),
        Ok(Err(_)) => Err(StreamError::Io),
        Ok(Ok(got)) => Ok(got),
    }
}

async fn write_all<W: AsyncWrite + Unpin>(
    out: &mut W,
    buf: &[u8],
    idle: Duration,
) -> Result<(), StreamError> {
    match tokio::time::timeout(idle, out.write_all(buf)).await {
        Err(_) => Err(StreamError::Io),
        Ok(Err(_)) => Err(StreamError::Io),
        Ok(Ok(())) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(
        method: &str,
        target: &str,
        host: &str,
        headers: &[(&str, &str)],
        body: u64,
    ) -> RequestHead {
        RequestHead {
            method: method.to_owned(),
            target: target.to_owned(),
            version: 11,
            framing: BodyFraming::ContentLength(body),
            wants_close: false,
            expect_continue: false,
            wants_upgrade: false,
            host: host.to_owned(),
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
        }
    }

    #[test]
    fn h1_only_headers_never_cross_to_h2() {
        let request = head(
            "GET",
            "/v1/items?q=2",
            "api.example.com",
            &[
                ("host", "api.example.com"),
                ("connection", "keep-alive"),
                ("transfer-encoding", "chunked"),
                ("te", "trailers"),
                ("upgrade", "websocket"),
                ("expect", "100-continue"),
                ("content-length", "0"),
                ("x-request-id", "abc"),
            ],
            0,
        );
        let (out, end_of_stream) = build_request(&request).expect("translatable");
        assert!(
            !end_of_stream,
            "a declared length is a body, even an empty one"
        );
        assert_eq!(out.method(), http::Method::GET);
        assert_eq!(
            out.uri().path_and_query().expect("path").as_str(),
            "/v1/items?q=2"
        );
        assert_eq!(
            out.uri().authority().expect("authority").as_str(),
            "api.example.com"
        );
        assert_eq!(out.uri().scheme_str(), Some("https"));
        for gone in [
            "host",
            "connection",
            "transfer-encoding",
            "te",
            "upgrade",
            "expect",
        ] {
            assert!(
                out.headers().get(gone).is_none(),
                "{gone} must not reach an h2 backend"
            );
        }
        assert_eq!(out.headers().get("content-length").expect("cl"), "0");
        assert_eq!(out.headers().get("x-request-id").expect("kept"), "abc");
    }

    #[test]
    fn a_chunked_body_carries_no_length_and_no_body_ends_the_stream() {
        let mut chunked = head("POST", "/upload", "api.example.com", &[], 0);
        chunked.framing = BodyFraming::Chunked;
        let (out, end_of_stream) = build_request(&chunked).expect("chunked");
        assert!(!end_of_stream);
        assert!(out.headers().get("content-length").is_none());

        let mut empty = chunked.clone();
        empty.framing = BodyFraming::None;
        let (_out, end_of_stream) = build_request(&empty).expect("no body");
        assert!(
            end_of_stream,
            "a body-less request must end its stream at once"
        );
    }

    #[test]
    fn connect_and_hostless_requests_are_refused_not_guessed() {
        let connect = head(
            "CONNECT",
            "api.example.com:443",
            "api.example.com:443",
            &[],
            0,
        );
        assert!(
            build_request(&connect).is_err_and(|err| err == StreamError::Framing),
            "CONNECT has no h2 backend translation"
        );

        let hostless = head("GET", "/", "", &[], 0);
        assert!(
            build_request(&hostless).is_err_and(|err| err == StreamError::Framing),
            "without Host there is no :authority to send"
        );
    }

    #[test]
    fn an_absolute_form_target_keeps_its_own_authority() {
        let request = head(
            "GET",
            "https://other.example/v1/x",
            "ignored.example",
            &[],
            0,
        );
        let (out, _) = build_request(&request).expect("absolute form");
        assert_eq!(
            out.uri().authority().expect("authority").as_str(),
            "other.example"
        );
    }
}
