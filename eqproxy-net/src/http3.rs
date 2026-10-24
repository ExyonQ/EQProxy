//! HTTP/3 termination (B-H2): QUIC in, HTTP/1.1 out to the backend.
//!
//! The UDP endpoint is opened by [`crate::proxy::bind`] on the listener's own
//! address and port; this module owns what happens after a QUIC handshake:
//! h3 (RFC 9114) request streams are turned into **one HTTP/1.1 message** on
//! an in-memory duplex and handed to [`crate::http1::serve_http`], the same
//! engine an HTTP/1.1 client uses. Routing rules, authentication, CORS,
//! redirects, direct answers, mirroring, retries, the keep-alive pool and
//! response compression therefore make exactly one decision per request,
//! instead of a second engine drifting from the first. The translation is the
//! same one the HTTP/2 path uses ([`crate::http2::build_request_head`]).
//!
//! Two tasks per exchange, because h3 exposes one `RequestStream` for both
//! directions: the one holding the stream forwards the request body and
//! applies response commands, while the other reads the h1 answer and sends
//! those commands through a bounded channel. That keeps a slow or absent
//! request body from blocking an early backend response (and the channels are
//! bounded: no unbounded buffering per stream).
//!
//! Deliberate limits of this slice, all explicit:
//! - No `CONNECT` on HTTP/3: an h3 request with method `CONNECT` is refused
//!   with `501` (WebSocket over HTTP/3, RFC 9220, is out of scope).
//! - No interim (1xx) responses: h3 0.0.8 has no `send_informational`, so an
//!   upstream `100 Continue`/`103` is logged and skipped; the final response
//!   is still relayed.
//! - gRPC over HTTP/3 is not routed as a native h2 stream (there is no h3
//!   equivalent); a gRPC request is translated to h1 like any other request.
//! - Hop-by-hop h1 headers and h1 framing headers are stripped in both
//!   directions (RFC 9114 §4.2 references the HTTP/2 rules).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use eqproxy_core::Metrics;

use crate::http1::{
    BodyFraming, FORBIDDEN_TRAILERS, MAX_LINE_BYTES, Prefixed, parse_chunk_size, parse_header_line,
    parse_response_head, read_crlf_line, read_head,
};
use crate::http2::{ClientBody, StreamError, build_request_head, copy_error};
use crate::proxy::{ResolvedListener, SharedCfg, current_cfg};

/// Streams one HTTP/3 connection may run concurrently (bounded on purpose:
/// each stream holds one backend exchange and two tasks).
pub const MAX_CONCURRENT_STREAMS: u32 = 128;

/// Largest DATA payload read or written per iteration.
const DATA_CHUNK: usize = 16 * 1024;

/// In-memory pipe between one h3 stream and the h1 engine (bounded: a slow
/// backend applies backpressure instead of buffering the body). One request
/// head plus one DATA chunk fit; a larger pipe only costs an allocation per
/// exchange and is never filled by a 1 KiB response.
const PIPE_BUFFER: usize = 16 * 1024;

/// Bounded response-command queue: at most four 16 KiB chunks are ever held
/// outside QUIC's own flow control.
const RESPONSE_QUEUE: usize = 4;

type H3Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// Serves every QUIC connection of one listener until shutdown.
///
/// `maxconn` is enforced per QUIC connection exactly like TCP: when full the
/// handshake is refused (quinn sends CONNECTION_CLOSE) and `connections_rejected`
/// counts it — there is never an unbounded accept queue.
pub(crate) async fn serve_endpoint(
    endpoint: quinn::Endpoint,
    shared: SharedCfg,
    name: String,
    metrics: Arc<Metrics>,
    mut shutdown: eqproxy_core::Shutdown,
) {
    let local = endpoint.local_addr().ok();
    loop {
        let incoming = tokio::select! {
            _ = shutdown.wait() => break,
            incoming = endpoint.accept() => incoming,
        };
        let Some(incoming) = incoming else {
            break;
        };
        let cfg = current_cfg(&shared);
        if !metrics.try_acquire_connection(cfg.maxconn) {
            metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
            incoming.refuse();
            continue;
        }
        metrics.connections_accepted.fetch_add(1, Ordering::Relaxed);
        let peer = incoming.remote_address();
        let local = local.unwrap_or_else(|| SocketAddr::new(peer.ip(), cfg.listen.port()));
        let task_metrics = Arc::clone(&metrics);
        let connection_name = name.clone();
        tokio::spawn(async move {
            serve_connection(incoming, peer, local, cfg, connection_name, task_metrics).await;
        });
    }
    // CONNECTION_CLOSE for every live connection: a shutdown never leaves
    // QUIC peers waiting for an idle timeout.
    endpoint.close(0u32.into(), b"shutdown");
}

/// One QUIC connection: h3 handshake, then one task per accepted request.
async fn serve_connection(
    incoming: quinn::Incoming,
    peer: SocketAddr,
    local: SocketAddr,
    cfg: Arc<ResolvedListener>,
    name: String,
    metrics: Arc<Metrics>,
) {
    let _guard = crate::proxy::ConnectionGuard::new(Arc::clone(&metrics));
    let connection = match tokio::time::timeout(cfg.client_header_timeout, incoming).await {
        Ok(Ok(connection)) => connection,
        Ok(Err(err)) => {
            metrics
                .tls_handshake_failures
                .fetch_add(1, Ordering::Relaxed);
            eprintln!("WARN [{name}] failed QUIC handshake (peer {peer}): {err}");
            return;
        }
        Err(_) => {
            metrics
                .tls_handshake_failures
                .fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "ERROR [{name}] QUIC handshake timeout (peer {peer}) after {:?}",
                cfg.client_header_timeout
            );
            return;
        }
    };
    // The QUIC handle is kept next to the h3 connection: the h3 error alone
    // does not say whether a peer closed normally (`ApplicationClose` code 0)
    // or with a real error, and only the QUIC close reason carries that code.
    let quic = connection.clone();
    // h3 0.0.8 greases the last stream frame before FIN by default. aioquic
    // 1.2.0 then swallows the end-of-stream (an unknown frame between DATA and
    // FIN leaves its DATA event with `stream_ended = false`), which hides a
    // complete response from the client. Grease is optional (RFC 9114 §7.2.8),
    // so it is disabled for interop and the decision is recorded in ADR-0011.
    let mut builder = h3::server::builder();
    builder.send_grease(false);
    let mut h3_connection = match tokio::time::timeout(
        cfg.client_header_timeout,
        builder.build(h3_quinn::Connection::new(connection)),
    )
    .await
    {
        Ok(Ok(connection)) => connection,
        Ok(Err(err)) => {
            // A peer may open QUIC and walk away cleanly before the h3
            // handshake finishes (probes, health checks, a client that gave
            // up): the same close classification applies here, so that end
            // is counted clean instead of reported as a fault.
            classify_h3_close(
                &quic,
                &err,
                &name,
                peer,
                &metrics,
                "failed HTTP/3 handshake",
            );
            return;
        }
        Err(_) => {
            eprintln!(
                "ERROR [{name}] HTTP/3 handshake timeout (peer {peer}) after {:?}",
                cfg.client_header_timeout
            );
            return;
        }
    };
    loop {
        let resolver = match h3_connection.accept().await {
            Ok(Some(resolver)) => resolver,
            // A graceful GOAWAY from the client: no more requests.
            Ok(None) => break,
            Err(err) => {
                // A session that ends the way RFC 9114 §8.1 describes is not
                // a fault: `H3_NO_ERROR`, or application code 0, which real
                // clients (aioquic, quic-go, browser stacks) send for a clean
                // close. Every other end — protocol error code, transport
                // error, reset, timeout — stays an error and is logged; the
                // classification is tested one code at a time.
                classify_h3_close(
                    &quic,
                    &err,
                    &name,
                    peer,
                    &metrics,
                    "HTTP/3 connection error",
                );
                break;
            }
        };
        let stream_cfg = Arc::clone(&cfg);
        let stream_metrics = Arc::clone(&metrics);
        let stream_name = name.clone();
        tokio::spawn(async move {
            let (request, stream) = match resolver.resolve_request().await {
                Ok(pair) => pair,
                Err(err) => {
                    eprintln!("WARN [{stream_name}] invalid HTTP/3 request from {peer}: {err}");
                    return;
                }
            };
            exchange(request, stream, peer, local, stream_cfg, stream_metrics).await;
        });
    }
}

/// Whether a closed HTTP/3 connection is a normal end of session rather than
/// a fault we must report.
///
/// Two application codes are normal: `H3_NO_ERROR` (`0x0100`, RFC 9114
/// §8.1), which h3 reports as such, and QUIC application code `0`, which real
/// clients use for a clean close even though h3 reserves `0x0100` for it
/// (aioquic and quic-go close with `0`; the h3 error alone cannot tell the
/// two apart, so the QUIC close reason is required). A protocol error code
/// (`0x0101`+), a transport error, a stateless reset or a timeout is a real
/// event and is never classified clean.
const H3_NO_ERROR_CODE: u64 = 0x0100;

fn is_clean_close_code(code: u64) -> bool {
    code == 0 || code == H3_NO_ERROR_CODE
}

fn is_normal_h3_close(h3_no_error: bool, quic: Option<&quinn::ConnectionError>) -> bool {
    if h3_no_error {
        return true;
    }
    matches!(
        quic,
        Some(quinn::ConnectionError::ApplicationClosed(close))
            if is_clean_close_code(u64::from(close.error_code))
    )
}

/// Counts one ended h3 connection and logs it only when it is a real error.
///
/// The h3 error alone cannot tell a normal close from a fault, so the QUIC
/// close reason (kept next to the connection) decides. `kind` names the phase
/// for the operator: the handshake and the session end read differently.
fn classify_h3_close(
    quic: &quinn::Connection,
    err: &h3::error::ConnectionError,
    name: &str,
    peer: SocketAddr,
    metrics: &Metrics,
    kind: &str,
) {
    let reason = quic.close_reason();
    if is_normal_h3_close(err.is_h3_no_error(), reason.as_ref()) {
        metrics.h3_clean_closes.fetch_add(1, Ordering::Relaxed);
        return;
    }
    metrics.h3_connection_errors.fetch_add(1, Ordering::Relaxed);
    let cause = match &reason {
        Some(reason) => format!("{err} [{reason}]"),
        None => err.to_string(),
    };
    eprintln!("{}", h3_close_log_line(name, peer, kind, &cause));
}

/// The one line emitted for a real HTTP/3 connection error. Built separately
/// from the emission so a test can assert what an operator will see.
fn h3_close_log_line(
    name: &str,
    peer: SocketAddr,
    kind: &str,
    cause: &dyn std::fmt::Display,
) -> String {
    format!("WARN [{name}] {kind} (peer {peer}): {cause}")
}

/// One h3 request stream: translate to h1, run the engine, relay the answer.
async fn exchange(
    request: Request<()>,
    mut stream: H3Stream,
    peer: SocketAddr,
    local: SocketAddr,
    cfg: Arc<ResolvedListener>,
    metrics: Arc<Metrics>,
) {
    let method = request.method().clone();
    if method == Method::CONNECT {
        metrics
            .http_requests_rejected
            .fetch_add(1, Ordering::Relaxed);
        refuse(&mut stream, StatusCode::NOT_IMPLEMENTED).await;
        return;
    }
    // Whether the client sent END_STREAM on the HEADERS frame is not exposed
    // by h3: peek once without waiting, so a body-less GET keeps an exact
    // translation (no synthetic `transfer-encoding: chunked` upstream).
    let (body_empty, first_chunk) = match peek_first_chunk(&mut stream).await {
        Ok(pair) => pair,
        Err(()) => {
            metrics
                .http_requests_rejected
                .fetch_add(1, Ordering::Relaxed);
            stream.stop_stream(h3::error::Code::H3_REQUEST_INCOMPLETE);
            return;
        }
    };
    let translated = match build_request_head(&method, request.uri(), request.headers(), body_empty)
    {
        Ok(translated) => translated,
        Err(()) => {
            metrics
                .http_requests_rejected
                .fetch_add(1, Ordering::Relaxed);
            refuse(&mut stream, StatusCode::BAD_REQUEST).await;
            return;
        }
    };
    let head_request = method == Method::HEAD;
    let framing = translated.framing;

    // One h1 exchange on a bounded in-memory pipe; the engine owns the
    // server half and makes every routing/auth/compression decision.
    let (pipe_ours, pipe_engine) = tokio::io::duplex(PIPE_BUFFER);
    let (engine_read, engine_write) = tokio::io::split(pipe_engine);
    let engine_cfg = Arc::clone(&cfg);
    let engine_metrics = Arc::clone(&metrics);
    let mut engine = tokio::spawn(async move {
        crate::http1::serve_http(
            engine_read,
            engine_write,
            peer,
            local,
            &engine_cfg,
            engine_metrics,
        )
        .await;
    });

    let (pipe_read, mut pipe_write) = tokio::io::split(pipe_ours);
    if pipe_write.write_all(&translated.head).await.is_err() {
        engine.abort();
        return;
    }

    let idle = cfg.idle_timeout;
    let mut total = 0_u64;
    let mut body_done = framing == ClientBody::None;
    if let Some(chunk) = first_chunk
        && write_body_chunk(&mut pipe_write, framing, &chunk, &mut total)
            .await
            .is_err()
    {
        stream.stop_stream(h3::error::Code::H3_REQUEST_INCOMPLETE);
        engine.abort();
        return;
    }

    // A request whose head carried END_STREAM is complete in the pipe: no
    // client byte can still arrive, so the answer is relayed straight onto the
    // h3 stream. Skipping the relay task, the command channel and the timer of
    // every step removes most of the per-request overhead of a GET.
    if body_done {
        if pipe_write.shutdown().await.is_ok() {
            relay_stream(BufReader::new(pipe_read), &mut stream, head_request, &cfg).await;
            if tokio::time::timeout(Duration::from_secs(1), &mut engine)
                .await
                .is_err()
            {
                engine.abort();
            }
        } else {
            engine.abort();
        }
        return;
    }

    let (commands_tx, mut commands_rx) = mpsc::channel(RESPONSE_QUEUE);
    let relay_cfg = Arc::clone(&cfg);
    let mut relay = tokio::spawn(async move {
        relay_response(
            BufReader::new(pipe_read),
            commands_tx,
            head_request,
            relay_cfg,
        )
        .await;
    });

    let mut head_seen = false;
    loop {
        // Before the head arrives the wait must not preempt the engine's own
        // `server_header_timeout` (it answers 504 when that fires).
        let wait = if head_seen {
            idle
        } else {
            cfg.server_header_timeout.max(idle)
        };
        let event = next_event(&mut stream, &mut commands_rx, !body_done, wait).await;
        match event {
            Event::Response(Command::Head { status, headers }) => {
                head_seen = true;
                let mut out = Response::new(());
                *out.status_mut() = status;
                *out.headers_mut() = headers;
                if stream.send_response(out).await.is_err() {
                    relay.abort();
                    break;
                }
            }
            Event::Response(Command::Data(bytes)) => {
                if stream.send_data(bytes).await.is_err() {
                    relay.abort();
                    break;
                }
            }
            Event::Response(Command::Trailers(trailers)) => {
                let _ = stream.send_trailers(trailers).await;
                let _ = stream.finish().await;
                break;
            }
            Event::Response(Command::Finish) => {
                let _ = stream.finish().await;
                break;
            }
            Event::Response(Command::Reset) | Event::RelayGone | Event::BodyError => {
                stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                relay.abort();
                break;
            }
            Event::Body(Some(chunk)) => {
                if write_body_chunk(&mut pipe_write, framing, &chunk, &mut total)
                    .await
                    .is_err()
                {
                    stream.stop_stream(h3::error::Code::H3_REQUEST_INCOMPLETE);
                    relay.abort();
                    break;
                }
            }
            // An empty DATA frame is legal and carries nothing.
            Event::Body(None) => {}
            Event::BodyEnd => {
                if finish_request_body(&mut stream, &mut pipe_write, framing, total, idle)
                    .await
                    .is_err()
                {
                    stream.stop_stream(h3::error::Code::H3_REQUEST_INCOMPLETE);
                    relay.abort();
                    break;
                }
                body_done = true;
            }
            // Reading the body keeps the exchange alive; a response command
            // arrives within the same window when the backend answers. With
            // the body finished there is nothing left to wait for but the
            // response itself.
            Event::Idle => {
                metrics.idle_timeouts.fetch_add(1, Ordering::Relaxed);
                stream.stop_stream(h3::error::Code::H3_NO_ERROR);
                relay.abort();
                break;
            }
        }
    }
    // Bounded waits: no task outlives its stream, even when the peer left.
    if tokio::time::timeout(Duration::from_secs(1), &mut relay)
        .await
        .is_err()
    {
        relay.abort();
    }
    if tokio::time::timeout(Duration::from_secs(1), &mut engine)
        .await
        .is_err()
    {
        engine.abort();
    }
}

/// Reads the first body chunk without waiting when there is none:
/// `poll_recv_data` knows END_STREAM synchronously. A pending body leaves the
/// request on the chunked path (the stream is still open).
async fn peek_first_chunk(stream: &mut H3Stream) -> Result<(bool, Option<Bytes>), ()> {
    match std::future::poll_fn(|cx| std::task::Poll::Ready(stream.poll_recv_data(cx))).await {
        std::task::Poll::Ready(Ok(Some(mut buf))) => {
            let bytes = buf.copy_to_bytes(buf.remaining());
            if bytes.is_empty() {
                Ok((false, None))
            } else {
                Ok((false, Some(bytes)))
            }
        }
        std::task::Poll::Ready(Ok(None)) => Ok((true, None)),
        std::task::Poll::Ready(Err(_)) => Err(()),
        std::task::Poll::Pending => Ok((false, None)),
    }
}

/// What woke the stream task.
enum Event {
    Response(Command),
    Body(Option<Bytes>),
    BodyEnd,
    BodyError,
    RelayGone,
    Idle,
}

/// One response step produced by the h1 side and applied by the h3 side.
enum Command {
    Head {
        status: StatusCode,
        headers: HeaderMap,
    },
    Data(Bytes),
    Trailers(HeaderMap),
    Finish,
    Reset,
}

/// Waits for whichever happens first: a response command or the next request
/// body chunk. Response commands win ties (they are bounded), so the relay is
/// never starved while a client uploads.
async fn next_event(
    stream: &mut H3Stream,
    commands: &mut mpsc::Receiver<Command>,
    read_body: bool,
    idle: Duration,
) -> Event {
    let next = std::future::poll_fn(|cx| {
        match commands.poll_recv(cx) {
            std::task::Poll::Ready(Some(command)) => {
                return std::task::Poll::Ready(Event::Response(command));
            }
            std::task::Poll::Ready(None) => return std::task::Poll::Ready(Event::RelayGone),
            std::task::Poll::Pending => {}
        }
        if !read_body {
            return std::task::Poll::Pending;
        }
        match stream.poll_recv_data(cx) {
            std::task::Poll::Ready(Ok(Some(mut buf))) => {
                let bytes = buf.copy_to_bytes(buf.remaining());
                std::task::Poll::Ready(if bytes.is_empty() {
                    Event::Body(None)
                } else {
                    Event::Body(Some(bytes))
                })
            }
            std::task::Poll::Ready(Ok(None)) => std::task::Poll::Ready(Event::BodyEnd),
            std::task::Poll::Ready(Err(_)) => std::task::Poll::Ready(Event::BodyError),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    });
    match tokio::time::timeout(idle, next).await {
        Ok(event) => event,
        Err(_) => Event::Idle,
    }
}

/// Writes one request body chunk into the h1 message, honoring the framing
/// chosen for the head.
async fn write_body_chunk<W: AsyncWrite + Unpin>(
    out: &mut W,
    framing: ClientBody,
    chunk: &[u8],
    total: &mut u64,
) -> Result<(), StreamError> {
    match framing {
        ClientBody::None => return Err(StreamError::Framing),
        ClientBody::Length(len) if *total + chunk.len() as u64 > len => {
            return Err(StreamError::Framing);
        }
        ClientBody::Length(_) => {}
        ClientBody::Chunked => {
            out.write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                .await
                .map_err(|_| StreamError::Io)?;
        }
    }
    out.write_all(chunk).await.map_err(|_| StreamError::Io)?;
    if framing == ClientBody::Chunked {
        out.write_all(b"\r\n").await.map_err(|_| StreamError::Io)?;
    }
    *total += chunk.len() as u64;
    Ok(())
}

/// Terminates the h1 request body: exact length or a chunked terminator with
/// the client's h3 trailers, then EOF so the engine can answer.
async fn finish_request_body<W: AsyncWrite + Unpin>(
    stream: &mut H3Stream,
    out: &mut W,
    framing: ClientBody,
    total: u64,
    idle: Duration,
) -> Result<(), StreamError> {
    match framing {
        ClientBody::Chunked => {
            // h3 exposes trailers only after the DATA stream ends.
            let trailers = match tokio::time::timeout(idle, stream.recv_trailers()).await {
                Ok(Ok(trailers)) => trailers.unwrap_or_default(),
                Ok(Err(_)) => return Err(StreamError::H3),
                Err(_) => return Err(StreamError::Io),
            };
            out.write_all(b"0\r\n").await.map_err(|_| StreamError::Io)?;
            for (name, value) in &trailers {
                if FORBIDDEN_TRAILERS.contains(&name.as_str()) {
                    return Err(StreamError::Framing);
                }
                out.write_all(name.as_str().as_bytes())
                    .await
                    .map_err(|_| StreamError::Io)?;
                out.write_all(b": ").await.map_err(|_| StreamError::Io)?;
                out.write_all(value.as_bytes())
                    .await
                    .map_err(|_| StreamError::Io)?;
                out.write_all(b"\r\n").await.map_err(|_| StreamError::Io)?;
            }
            out.write_all(b"\r\n").await.map_err(|_| StreamError::Io)?;
        }
        ClientBody::Length(len) if total != len => return Err(StreamError::Truncated),
        ClientBody::Length(_) | ClientBody::None => {}
    }
    out.shutdown().await.map_err(|_| StreamError::Io)
}

/// Where the relayed answer goes: the h3 stream itself (body-less requests,
/// relayed in the stream task) or a bounded channel read by the stream task
/// while it keeps forwarding the client body.
enum Sink<'a> {
    Channel(&'a mpsc::Sender<Command>),
    Stream(&'a mut H3Stream),
}

impl Sink<'_> {
    async fn head(&mut self, status: StatusCode, headers: HeaderMap) -> Result<(), StreamError> {
        match self {
            Sink::Channel(commands) => commands
                .send(Command::Head { status, headers })
                .await
                .map_err(|_| StreamError::H3),
            Sink::Stream(stream) => {
                let mut out = Response::new(());
                *out.status_mut() = status;
                *out.headers_mut() = headers;
                stream.send_response(out).await.map_err(|_| StreamError::H3)
            }
        }
    }

    async fn data(&mut self, bytes: Bytes) -> Result<(), StreamError> {
        match self {
            Sink::Channel(commands) => commands
                .send(Command::Data(bytes))
                .await
                .map_err(|_| StreamError::H3),
            Sink::Stream(stream) => stream.send_data(bytes).await.map_err(|_| StreamError::H3),
        }
    }

    /// h1 trailers close the message: the channel path relies on the stream
    /// task's `Command::Trailers` arm, the direct path finishes here.
    async fn trailers(&mut self, trailers: HeaderMap) -> Result<(), StreamError> {
        match self {
            Sink::Channel(commands) => commands
                .send(Command::Trailers(trailers))
                .await
                .map_err(|_| StreamError::H3),
            Sink::Stream(stream) => {
                stream
                    .send_trailers(trailers)
                    .await
                    .map_err(|_| StreamError::H3)?;
                stream.finish().await.map_err(|_| StreamError::H3)
            }
        }
    }

    async fn finish(&mut self) -> Result<(), StreamError> {
        match self {
            Sink::Channel(commands) => commands
                .send(Command::Finish)
                .await
                .map_err(|_| StreamError::H3),
            Sink::Stream(stream) => stream.finish().await.map_err(|_| StreamError::H3),
        }
    }

    async fn reset(&mut self) {
        match self {
            Sink::Channel(commands) => {
                let _ = commands.send(Command::Reset).await;
            }
            Sink::Stream(stream) => stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR),
        }
    }
}

/// Relays the h1 answer of an already-complete request straight onto its h3
/// stream: no task, no channel and no per-step timer on the hot path.
async fn relay_stream<R: AsyncRead + Unpin>(
    mut reader: BufReader<R>,
    stream: &mut H3Stream,
    head_request: bool,
    cfg: &ResolvedListener,
) {
    let mut sink = Sink::Stream(stream);
    if let Err(err) = relay_inner(&mut reader, &mut sink, head_request, cfg).await {
        sink.reset().await;
        if !matches!(err, StreamError::H3) {
            eprintln!(
                "WARN [{}] HTTP/3 response relay stopped: {:?}",
                cfg.name, err
            );
        }
    }
}

/// Reads the h1 answer from the engine and forwards it as response commands.
/// Every step is ordered through one bounded channel, so DATA arrives after
/// the head and `Finish` after the last chunk.
async fn relay_response<R: AsyncRead + Unpin>(
    mut reader: BufReader<R>,
    commands: mpsc::Sender<Command>,
    head_request: bool,
    cfg: Arc<ResolvedListener>,
) {
    let mut sink = Sink::Channel(&commands);
    if let Err(err) = relay_inner(&mut reader, &mut sink, head_request, &cfg).await {
        sink.reset().await;
        if !matches!(err, StreamError::H3) {
            eprintln!(
                "WARN [{}] HTTP/3 response relay stopped: {:?}",
                cfg.name, err
            );
        }
    }
}

async fn relay_inner<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    sink: &mut Sink<'_>,
    head_request: bool,
    cfg: &ResolvedListener,
) -> Result<(), StreamError> {
    let idle = cfg.idle_timeout;
    let mut carry: Vec<u8> = Vec::new();
    let mut interim = 0_u32;
    let (head, response) = loop {
        let mut source = Prefixed {
            prefix: std::mem::take(&mut carry),
            pos: 0,
            inner: &mut *reader,
        };
        let (head, rest) = match read_head(&mut source, cfg.server_header_timeout).await {
            Ok(pair) => pair,
            Err(_) => return Err(StreamError::Io),
        };
        carry = rest;
        carry.extend(source.prefix.split_off(source.pos));
        let response = match parse_response_head(&head, head_request) {
            Ok(response) => response,
            Err(reject) => {
                eprintln!(
                    "WARN [{}] invalid response head for HTTP/3 stream: {}",
                    cfg.name, reject.reason
                );
                return Err(StreamError::Framing);
            }
        };
        if response.status >= 200 {
            break (head, response);
        }
        if response.status == 101 {
            eprintln!(
                "WARN [{}] backend offered a protocol switch (101) on an HTTP/3 stream; refused",
                cfg.name
            );
            return Err(StreamError::Framing);
        }
        // h3 0.0.8 has no informational-response frame: skip it explicitly
        // instead of turning a legitimate 100/103 into a stream error.
        interim += 1;
        if interim > 8 {
            return Err(StreamError::Framing);
        }
        eprintln!(
            "WARN [{}] interim {} response not forwarded over HTTP/3",
            cfg.name, response.status
        );
    };

    let status = StatusCode::from_u16(response.status).map_err(|_| StreamError::Framing)?;
    let headers = crate::http2::response_headers(&head);
    let end_of_stream = response.framing == BodyFraming::None;
    sink.head(status, headers).await?;
    if end_of_stream {
        sink.finish().await?;
        return Ok(());
    }

    let mut body = Prefixed {
        prefix: carry,
        pos: 0,
        inner: &mut *reader,
    };
    match response.framing {
        BodyFraming::ContentLength(len) => {
            let mut remaining = len;
            while remaining > 0 {
                let chunk = read_bytes(&mut body, DATA_CHUNK.min(remaining as usize), idle).await?;
                if chunk.is_empty() {
                    return Err(StreamError::Truncated);
                }
                remaining -= chunk.len() as u64;
                sink.data(chunk).await?;
            }
        }
        BodyFraming::Chunked => {
            if relay_chunked(&mut body, sink, idle).await? {
                return Ok(());
            }
        }
        BodyFraming::UntilEof => loop {
            let chunk = read_bytes(&mut body, DATA_CHUNK, idle).await?;
            if chunk.is_empty() {
                break;
            }
            sink.data(chunk).await?;
        },
        BodyFraming::None => {}
    }
    sink.finish().await
}

/// h1 `chunked` body → h3 DATA, with the h1 trailers preserved when present.
/// Returns `true` when trailers closed the message (the caller must not send
/// a second FIN), `false` when a plain `Finish` still has to be sent.
async fn relay_chunked<R: AsyncRead + Unpin>(
    body: &mut Prefixed<R>,
    sink: &mut Sink<'_>,
    idle: Duration,
) -> Result<bool, StreamError> {
    loop {
        let line = read_crlf_line(body, idle, MAX_LINE_BYTES)
            .await
            .map_err(copy_error)?;
        let size = parse_chunk_size(&line).map_err(copy_error)?;
        if size == 0 {
            let mut trailers = HeaderMap::new();
            loop {
                let line = read_crlf_line(body, idle, MAX_LINE_BYTES)
                    .await
                    .map_err(copy_error)?;
                if line == b"\r\n" {
                    break;
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
            if !trailers.is_empty() {
                sink.trailers(trailers).await?;
                return Ok(true);
            }
            return Ok(false);
        }
        let mut remaining = size;
        while remaining > 0 {
            let chunk = read_bytes(body, DATA_CHUNK.min(remaining as usize), idle).await?;
            if chunk.is_empty() {
                return Err(StreamError::Truncated);
            }
            remaining -= chunk.len() as u64;
            sink.data(chunk).await?;
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
    }
}

/// Reads up to `want` bytes into a buffer sized for this chunk only: the
/// allocation is exact (1 KiB for a 1 KiB body), nothing is zeroed, and the
/// bytes go to h3 without a second copy.
async fn read_bytes<R: AsyncRead + Unpin>(
    reader: &mut R,
    want: usize,
    idle: Duration,
) -> Result<Bytes, StreamError> {
    let mut buf = BytesMut::with_capacity(want.max(1));
    match tokio::time::timeout(idle, reader.read_buf(&mut buf)).await {
        Err(_) | Ok(Err(_)) => Err(StreamError::Io),
        Ok(Ok(0)) => Ok(Bytes::new()),
        Ok(Ok(_)) => Ok(buf.freeze()),
    }
}

/// Answers a stream that never reaches the backend.
async fn refuse(stream: &mut H3Stream, status: StatusCode) {
    let mut response = Response::new(());
    *response.status_mut() = status;
    if let Ok(length) = HeaderValue::from_str("0") {
        response.headers_mut().insert("content-length", length);
    }
    if stream.send_response(response).await.is_ok() {
        let _ = stream.finish().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_close(code: u64) -> quinn::ConnectionError {
        quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
            error_code: quinn::VarInt::from_u64(code).expect("valid varint"),
            reason: bytes::Bytes::new(),
        })
    }

    /// RFC 9114 §8.1 defines `0x0100` as the normal close; QUIC application
    /// code `0` is what aioquic, quic-go and browser stacks actually send.
    /// Both are the end of a session, not a fault.
    #[test]
    fn only_the_two_normal_close_codes_are_clean() {
        assert!(is_clean_close_code(0), "QUIC application code 0");
        assert!(is_clean_close_code(0x0100), "H3_NO_ERROR");
        assert!(is_normal_h3_close(true, None), "h3 reported H3_NO_ERROR");
        assert!(is_normal_h3_close(false, Some(&app_close(0))));
        assert!(is_normal_h3_close(false, Some(&app_close(0x0100))));
    }

    /// Every HTTP/3 protocol error code stays an error: silencing one would
    /// hide a real fault behind a clean-close counter. Codes are the ones
    /// assigned in RFC 9114 §8.1 plus the unassigned space around them.
    #[test]
    fn every_h3_protocol_error_code_stays_an_error() {
        let codes = [
            0x0101u64, // H3_GENERAL_PROTOCOL_ERROR
            0x0102,    // H3_INTERNAL_ERROR
            0x0103,    // H3_STREAM_CREATION_ERROR
            0x0104,    // H3_CLOSED_CRITICAL_STREAM
            0x0105,    // H3_FRAME_UNEXPECTED
            0x0106,    // H3_FRAME_ERROR
            0x0107,    // H3_EXCESSIVE_LOAD
            0x0108,    // H3_ID_ERROR
            0x0109,    // H3_SETTINGS_ERROR
            0x010a,    // H3_MISSING_SETTINGS
            0x010b,    // H3_REQUEST_REJECTED
            0x010c,    // H3_REQUEST_CANCELLED
            0x010d,    // H3_REQUEST_INCOMPLETE
            0x010e,    // H3_MESSAGE_ERROR
            0x010f,    // H3_CONNECT_ERROR
            0x0110,    // H3_VERSION_FALLBACK
            0x0111,    // first unassigned code after the assigned range
            0x0200,    // unassigned space
            u32::MAX as u64,
        ];
        for code in codes {
            assert!(
                !is_clean_close_code(code),
                "code {code:#x} must stay an error"
            );
            assert!(
                !is_normal_h3_close(false, Some(&app_close(code))),
                "a QUIC close with code {code:#x} must stay an error"
            );
        }
    }

    /// A timeout, a stateless reset, a locally aborted connection and an h3
    /// error with no QUIC close reason are all real events, never clean.
    #[test]
    fn timeouts_resets_and_local_aborts_stay_errors() {
        for reason in [
            quinn::ConnectionError::TimedOut,
            quinn::ConnectionError::Reset,
            quinn::ConnectionError::LocallyClosed,
        ] {
            assert!(
                !is_normal_h3_close(false, Some(&reason)),
                "{reason} must stay an error"
            );
        }
        assert!(
            !is_normal_h3_close(false, None),
            "no QUIC reason must not be assumed clean"
        );
    }

    /// What an operator sees for a real error names the peer, the phase and
    /// the cause; the clean path emits nothing at all.
    #[test]
    fn the_real_error_line_carries_peer_phase_and_cause() {
        let peer: SocketAddr = "127.0.0.1:5555".parse().expect("peer addr");
        let cause = "ApplicationClose(H3_GENERAL_PROTOCOL_ERROR)";
        assert_eq!(
            h3_close_log_line("h3", peer, "HTTP/3 connection error", &cause),
            "WARN [h3] HTTP/3 connection error (peer 127.0.0.1:5555): \
ApplicationClose(H3_GENERAL_PROTOCOL_ERROR)"
        );
        // A close that ends the h3 handshake is classified the same way; the
        // line names that phase so the operator can place it.
        assert_eq!(
            h3_close_log_line("h3", peer, "failed HTTP/3 handshake", &cause),
            "WARN [h3] failed HTTP/3 handshake (peer 127.0.0.1:5555): \
ApplicationClose(H3_GENERAL_PROTOCOL_ERROR)"
        );
    }
}
