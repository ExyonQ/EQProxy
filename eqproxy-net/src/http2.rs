//! HTTP/2 client termination (B-H1/B-N1/B-I1/B-E2): h2 in, HTTP/1.1 out.
//!
//! Scope of this slice: a client negotiates `h2` (ALPN on TLS, or the h2c
//! connection preface on a plaintext listener) and EQProxy terminates HTTP/2
//! on its side while speaking HTTP/1.1 to the backend — the "downgrade to
//! h1" half of the roadmap, done as a **real translation**, never a reply
//! shaped like h2.
//!
//! Why a translation and not a parallel exchange engine: the h1 engine
//! (`http1::serve_http`) already owns routing rules, authentication, CORS,
//! redirects, direct answers, mirroring, retries, the keep-alive pool and
//! the A16 reuse contract. Each h2 stream is turned into exactly one
//! HTTP/1.1 message on an in-memory duplex and handed to that engine, so an
//! h2 request sees **the same decisions and the same error surfaces** as an
//! h1 request, with no second implementation to drift. The cost is one task
//! and one bounded 64 KiB pipe per stream, plus the translation below; it is
//! not hidden (see `docs/evidence/v07-http2.md`).
//!
//! Deliberate limits of this slice, all explicit:
//! - Hop-by-hop h1 headers and the h1 framing headers are stripped in both
//!   directions (RFC 9113 §8.2.2); the h2 side never sees chunk framing.
//! - A backend protocol switch (`101`) cannot cross h2: the stream is reset
//!   and the refusal is logged, never half-forwarded.
//! - A classic `CONNECT` (no `:protocol`) is refused with `501`.
//! - An extended CONNECT (`:protocol = websocket`) is served by `ws`: the
//!   stream becomes a real WebSocket tunnel through the h1 engine, and every
//!   other `:protocol` value is refused with `501` (RFC 8441 §5).
//! - A body truncated by the backend resets the stream instead of ending it
//!   cleanly: a short body must never look complete to the client.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use eqproxy_core::Metrics;

use crate::http1::{
    BodyFraming, CopyError, FORBIDDEN_TRAILERS, MAX_LINE_BYTES, Prefixed, parse_chunk_size,
    parse_header_line, parse_response_head, read_crlf_line, read_head,
};
use crate::proxy::ResolvedListener;

/// HTTP/2 client connection preface (RFC 9113 §3.4). A plaintext listener
/// that starts with these bytes is speaking h2c with prior knowledge.
pub const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Streams one client connection may run concurrently (bounded on purpose:
/// each stream holds one backend exchange).
pub const MAX_CONCURRENT_STREAMS: u32 = 128;

/// Largest DATA payload read from the h1 side per iteration.
pub(crate) const DATA_CHUNK: usize = 16 * 1024;

/// In-memory pipe between one h2 stream and the h1 engine. Bounded: a slow
/// backend applies backpressure through it instead of buffering the body.
const PIPE_BUFFER: usize = 64 * 1024;

/// h1 headers that must not cross into h2 (RFC 9113 §8.2.2), plus the h1
/// framing headers the translation replaces with DATA frames.
const HOP_BY_HOP: [&str; 7] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
];

/// Body framing of the h1 message synthesized for a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientBody {
    /// No body at all (no `content-length`, no `transfer-encoding`).
    None,
    /// Exact `content-length`.
    Length(u64),
    /// `transfer-encoding: chunked`.
    Chunked,
}

/// The HTTP/1.1 request head built from an h2 request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H1Request {
    pub head: Vec<u8>,
    pub framing: ClientBody,
}

/// Why one stream was cut. Every variant ends the stream explicitly (reset
/// or refusal); none of them leaves a half-open stream behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamError {
    /// A body ended before its declared length.
    Truncated,
    /// Framing that cannot be translated.
    Framing,
    /// I/O or timeout on either side.
    Io,
    /// The h2 side is gone or refused the frame.
    H2,
    /// The HTTP/3 side is gone or refused the frame/stream (B-H2).
    H3,
    /// The peer's GOAWAY refused the stream before processing it, and no
    /// request body was consumed: replaying it on a fresh session is safe
    /// (the session it belonged to is going away anyway).
    Refused,
    /// The peer reset the stream with `REFUSED_STREAM` without processing it
    /// (RFC 9113 §8.1.4): replaying it is safe, and the session itself is
    /// still healthy.
    StreamRefused,
}

pub(crate) fn copy_error(err: CopyError) -> StreamError {
    match err {
        CopyError::Truncated => StreamError::Truncated,
        CopyError::Idle | CopyError::Io => StreamError::Io,
        CopyError::Framing(_) => StreamError::Framing,
    }
}

pub(crate) fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP.contains(&name)
}

/// True when the first bytes already received are the h2c connection
/// preface, waiting for the remaining bytes when they are a valid prefix.
///
/// Uses `peek`, so a false answer leaves the plaintext stream byte-identical
/// for the HTTP/1.1 engine (no read is consumed).
pub async fn is_h2c(client: &tokio::net::TcpStream, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf = [0u8; 24];
    loop {
        let got = match client.peek(&mut buf).await {
            Ok(0) | Err(_) => return false,
            Ok(got) => got.min(CLIENT_PREFACE.len()),
        };
        if buf[..got] != CLIENT_PREFACE[..got] {
            return false;
        }
        if got == CLIENT_PREFACE.len() {
            return true;
        }
        // A prefix of the preface: more bytes may still be in flight.
        if tokio::time::timeout_at(deadline, client.readable())
            .await
            .is_err()
        {
            return false;
        }
    }
}

/// Serves one client connection as HTTP/2 until the connection closes.
///
/// Each accepted stream runs in its own task (that is the multiplexing the
/// protocol promises); the connection task keeps driving frames and ends
/// when the client sends GOAWAY or the transport fails.
pub async fn serve_h2<IO>(
    io: IO,
    peer: SocketAddr,
    local: SocketAddr,
    cfg: Arc<ResolvedListener>,
    metrics: Arc<Metrics>,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = h2::server::Builder::new();
    builder.max_concurrent_streams(MAX_CONCURRENT_STREAMS);
    // RFC 8441: advertise that extended CONNECT is understood, so a client
    // may use `:protocol = websocket` on this connection.
    builder.enable_connect_protocol();
    let mut connection = match builder.handshake(io).await {
        Ok(connection) => connection,
        Err(err) => {
            metrics
                .http_requests_rejected
                .fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "WARN [{}] failed HTTP/2 handshake (peer {peer}): {err}",
                cfg.name
            );
            return;
        }
    };
    while let Some(accepted) = connection.accept().await {
        let (request, respond) = match accepted {
            Ok(pair) => pair,
            Err(err) => {
                eprintln!(
                    "WARN [{}] HTTP/2 connection error (peer {peer}): {err}",
                    cfg.name
                );
                break;
            }
        };
        let stream_cfg = Arc::clone(&cfg);
        let stream_metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            exchange(request, respond, peer, local, stream_cfg, stream_metrics).await;
        });
    }
}

/// One h2 stream: build the h1 message, run it through the h1 engine on a
/// pipe and translate the answer back into h2 frames.
async fn exchange(
    request: Request<h2::RecvStream>,
    respond: h2::server::SendResponse<Bytes>,
    peer: SocketAddr,
    local: SocketAddr,
    cfg: Arc<ResolvedListener>,
    metrics: Arc<Metrics>,
) {
    let method = request.method().clone();
    let (request, mut respond) = if method == Method::CONNECT {
        // Extended CONNECT (RFC 8441) becomes a real WebSocket tunnel; any
        // other CONNECT is refused explicitly instead of opening a stream
        // that can never complete.
        match crate::ws::serve(request, respond, peer, local, &cfg, &metrics).await {
            Ok(()) => return,
            Err(pair) => pair,
        }
    } else {
        (request, respond)
    };
    if method == Method::CONNECT {
        metrics
            .http_requests_rejected
            .fetch_add(1, Ordering::Relaxed);
        refuse(&mut respond, StatusCode::NOT_IMPLEMENTED);
        return;
    }
    // gRPC keeps both directions of its stream open at once (B-I12/Q5). When
    // the backend speaks HTTP/2 as well, the stream is relayed as-is by
    // `grpc`; every other request keeps the h1 translation below.
    let (request, mut respond) =
        match crate::grpc::serve(request, respond, peer, local, &cfg, &metrics).await {
            Ok(()) => return,
            Err(pair) => pair,
        };
    let body_empty = request.body().is_end_stream();
    let translated = match build_request_head(&method, request.uri(), request.headers(), body_empty)
    {
        Ok(translated) => translated,
        Err(()) => {
            metrics
                .http_requests_rejected
                .fetch_add(1, Ordering::Relaxed);
            refuse(&mut respond, StatusCode::BAD_REQUEST);
            return;
        }
    };
    let head_request = method == Method::HEAD;

    // One h1 exchange on a bounded in-memory pipe. The engine owns the
    // server half; this task writes the request and reads the response.
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

    let (mut pipe_read, mut pipe_write) = tokio::io::split(pipe_ours);
    if pipe_write.write_all(&translated.head).await.is_err() {
        engine.abort();
        refuse(&mut respond, StatusCode::BAD_GATEWAY);
        return;
    }
    let framing = translated.framing;
    let idle = cfg.idle_timeout;
    let mut body = tokio::spawn(async move {
        let mut recv = request.into_body();
        let result = forward_request_body(&mut recv, &mut pipe_write, framing, idle).await;
        if result.is_ok() {
            // The shutdown is only the EOF signal the engine waits for; a
            // pipe that is already gone has nothing left to signal.
            let _ = pipe_write.shutdown().await;
        }
        result
    });

    let reader = BufReader::new(&mut pipe_read);
    let relayed = relay_response(reader, &mut respond, head_request, &cfg).await;
    if relayed.is_err() {
        respond.send_reset(h2::Reason::INTERNAL_ERROR);
    }
    // The engine finishes on its own once the pipe reaches EOF (the body
    // task shuts it down); bounded wait so no task outlives its stream.
    if tokio::time::timeout(Duration::from_secs(1), &mut body)
        .await
        .is_err()
    {
        body.abort();
    }
    if tokio::time::timeout(Duration::from_secs(1), &mut engine)
        .await
        .is_err()
    {
        engine.abort();
    }
}

/// Answers a stream that never reaches the backend.
fn refuse(respond: &mut h2::server::SendResponse<Bytes>, status: StatusCode) {
    let mut response = Response::new(());
    *response.status_mut() = status;
    if let Ok(length) = HeaderValue::from_str("0") {
        response.headers_mut().insert("content-length", length);
    }
    // A client that already reset the stream has nobody to refuse: the
    // refusal is still attempted, and the send error is the client's.
    let _ = respond.send_response(response, true);
}

/// HTTP/1.1 head + framing for one h2 request. Pseudo-headers are required
/// to be complete (`:path` mandatory for a non-CONNECT request); anything
/// that cannot be translated refuses the stream (`Err`) instead of guessing.
pub(crate) fn build_request_head(
    method: &Method,
    uri: &http::Uri,
    headers: &HeaderMap,
    body_empty: bool,
) -> Result<H1Request, ()> {
    let path = uri.path_and_query().map_or("/", |pq| pq.as_str());
    let path = if path.is_empty() { "/" } else { path };
    if !path.starts_with('/') {
        // origin-form only: absolute-form/authority-form belongs to CONNECT
        // or to a client that is not talking to a reverse proxy.
        return Err(());
    }
    let mut head = Vec::with_capacity(256);
    head.extend_from_slice(method.as_str().as_bytes());
    head.push(b' ');
    head.extend_from_slice(path.as_bytes());
    head.extend_from_slice(b" HTTP/1.1\r\n");
    if let Some(authority) = uri.authority() {
        head.extend_from_slice(b"host: ");
        head.extend_from_slice(authority.as_str().as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    for (name, value) in headers {
        let name_str = name.as_str();
        if name_str == "host" || name_str == "content-length" || is_hop_by_hop(name_str) {
            continue;
        }
        let raw = value.as_bytes();
        if raw.iter().any(|b| *b == b'\r' || *b == b'\n' || *b == 0) {
            return Err(());
        }
        head.extend_from_slice(name_str.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(raw);
        head.extend_from_slice(b"\r\n");
    }
    let declared = match headers.get(http::header::CONTENT_LENGTH) {
        Some(value) => Some(
            value
                .to_str()
                .ok()
                .and_then(|text| text.parse::<u64>().ok())
                .ok_or(())?,
        ),
        None => None,
    };
    let framing = match (declared, body_empty) {
        (Some(len), _) => ClientBody::Length(len),
        (None, true) => ClientBody::None,
        (None, false) => ClientBody::Chunked,
    };
    match framing {
        ClientBody::Length(len) => {
            head.extend_from_slice(format!("content-length: {len}\r\n").as_bytes());
        }
        ClientBody::Chunked => head.extend_from_slice(b"transfer-encoding: chunked\r\n"),
        ClientBody::None => {}
    }
    head.extend_from_slice(b"\r\n");
    Ok(H1Request { head, framing })
}

/// Copies the h2 request body into the h1 message, honoring its framing and
/// releasing flow-control capacity as it goes (never an unbounded buffer).
async fn forward_request_body<W>(
    recv: &mut h2::RecvStream,
    out: &mut W,
    framing: ClientBody,
    idle: Duration,
) -> Result<(), StreamError>
where
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    loop {
        let chunk = match tokio::time::timeout(idle, recv.data()).await {
            Err(_) => return Err(StreamError::Io),
            Ok(None) => break,
            Ok(Some(Err(_))) => return Err(StreamError::H2),
            Ok(Some(Ok(chunk))) => chunk,
        };
        if chunk.is_empty() {
            continue;
        }
        match framing {
            ClientBody::None => return Err(StreamError::Framing),
            ClientBody::Length(len) if total + chunk.len() as u64 > len => {
                return Err(StreamError::Framing);
            }
            ClientBody::Length(_) => {}
            ClientBody::Chunked => {
                let header = format!("{:x}\r\n", chunk.len());
                out.write_all(header.as_bytes())
                    .await
                    .map_err(|_| StreamError::Io)?;
            }
        }
        out.write_all(&chunk).await.map_err(|_| StreamError::Io)?;
        if framing == ClientBody::Chunked {
            out.write_all(b"\r\n").await.map_err(|_| StreamError::Io)?;
        }
        total += chunk.len() as u64;
        let released = recv.flow_control().release_capacity(chunk.len());
        if released.is_err() {
            return Err(StreamError::H2);
        }
    }
    match framing {
        ClientBody::Chunked => {
            let trailers = match tokio::time::timeout(idle, recv.trailers()).await {
                Err(_) => return Err(StreamError::Io),
                Ok(Err(_)) => return Err(StreamError::H2),
                // `None` is "the client sent no trailers", not a failure.
                Ok(Ok(Some(trailers))) => trailers,
                Ok(Ok(None)) => HeaderMap::new(),
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
    Ok(())
}

/// Reads the h1 answer and writes it back as h2 frames.
pub(crate) async fn relay_response<R>(
    mut reader: BufReader<R>,
    respond: &mut h2::server::SendResponse<Bytes>,
    head_request: bool,
    cfg: &ResolvedListener,
) -> Result<(), StreamError>
where
    R: AsyncRead + Unpin,
{
    let idle = cfg.idle_timeout;
    let mut carry: Vec<u8> = Vec::new();
    let mut interim = 0u32;
    let (head, response) = loop {
        let mut source = Prefixed {
            prefix: std::mem::take(&mut carry),
            pos: 0,
            inner: &mut reader,
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
                    "WARN [{}] invalid response head for HTTP/2 stream: {}",
                    cfg.name, reject.reason
                );
                return Err(StreamError::Framing);
            }
        };
        if response.status >= 200 {
            break (head, response);
        }
        if response.status == 101 {
            // A protocol switch is h1-only: h2 has no 101. Never mask it.
            eprintln!(
                "WARN [{}] backend offered a protocol switch (101) on an HTTP/2 stream; refused",
                cfg.name
            );
            return Err(StreamError::Framing);
        }
        interim += 1;
        if interim > 8 {
            return Err(StreamError::Framing);
        }
        let informational = informational_response(response.status);
        if respond.send_informational(informational).is_err() {
            return Err(StreamError::H2);
        }
    };

    let status = StatusCode::from_u16(response.status).map_err(|_| StreamError::Framing)?;
    let mut out = Response::new(());
    *out.status_mut() = status;
    *out.headers_mut() = response_headers(&head);
    let end_of_stream = response.framing == BodyFraming::None;
    let mut send = match respond.send_response(out, end_of_stream) {
        Ok(send) => send,
        Err(_) => return Err(StreamError::H2),
    };
    if end_of_stream {
        return Ok(());
    }

    let mut body = Prefixed {
        prefix: carry,
        pos: 0,
        inner: &mut reader,
    };
    let mut buf = vec![0u8; DATA_CHUNK];
    let relayed = match response.framing {
        BodyFraming::ContentLength(len) => {
            let mut remaining = len;
            while remaining > 0 {
                let capacity = capacity(&mut send, DATA_CHUNK, idle).await?;
                let want = capacity.min(DATA_CHUNK).min(remaining as usize);
                let got = read_some(&mut body, &mut buf[..want], idle).await?;
                if got == 0 {
                    send.send_reset(h2::Reason::INTERNAL_ERROR);
                    return Err(StreamError::Truncated);
                }
                send.send_data(Bytes::copy_from_slice(&buf[..got]), false)
                    .map_err(|_| StreamError::H2)?;
                remaining -= got as u64;
            }
            send.send_data(Bytes::new(), true)
                .map_err(|_| StreamError::H2)
        }
        BodyFraming::Chunked => relay_chunked(&mut body, &mut send, &mut buf, idle).await,
        BodyFraming::UntilEof => loop {
            let capacity = capacity(&mut send, DATA_CHUNK, idle).await?;
            let want = capacity.min(DATA_CHUNK);
            let got = read_some(&mut body, &mut buf[..want], idle).await?;
            if got == 0 {
                break send
                    .send_data(Bytes::new(), true)
                    .map_err(|_| StreamError::H2);
            }
            send.send_data(Bytes::copy_from_slice(&buf[..got]), false)
                .map_err(|_| StreamError::H2)?;
        },
        BodyFraming::None => Ok(()),
    };
    match relayed {
        Ok(()) => Ok(()),
        Err(err) => {
            send.send_reset(h2::Reason::INTERNAL_ERROR);
            Err(err)
        }
    }
}

/// Relays a `chunked` h1 body as h2 DATA, ending the stream with the h1
/// trailers when the backend sent any.
async fn relay_chunked<R>(
    body: &mut Prefixed<R>,
    send: &mut h2::SendStream<Bytes>,
    buf: &mut [u8],
    idle: Duration,
) -> Result<(), StreamError>
where
    R: AsyncRead + Unpin,
{
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
            let end = if trailers.is_empty() {
                send.send_data(Bytes::new(), true)
            } else {
                send.send_trailers(trailers)
            };
            return end.map_err(|_| StreamError::H2);
        }
        let mut remaining = size;
        while remaining > 0 {
            let capacity = capacity(send, DATA_CHUNK, idle).await?;
            let want = capacity.min(DATA_CHUNK).min(remaining as usize);
            let got = read_some(body, &mut buf[..want], idle).await?;
            if got == 0 {
                return Err(StreamError::Truncated);
            }
            send.send_data(Bytes::copy_from_slice(&buf[..got]), false)
                .map_err(|_| StreamError::H2)?;
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
    }
}

/// Waits until the h2 stream can accept more DATA and returns the capacity
/// available now (bounded buffering: never `send_data` without capacity).
pub(crate) async fn capacity(
    send: &mut h2::SendStream<Bytes>,
    want: usize,
    idle: Duration,
) -> Result<usize, StreamError> {
    loop {
        let available = send.capacity();
        if available > 0 {
            return Ok(available);
        }
        send.reserve_capacity(want);
        let polled =
            tokio::time::timeout(idle, std::future::poll_fn(|cx| send.poll_capacity(cx))).await;
        match polled {
            Err(_) => return Err(StreamError::Io),
            Ok(Some(Ok(capacity))) if capacity > 0 => return Ok(capacity),
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(_))) | Ok(None) => return Err(StreamError::H2),
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

/// h2 informational response (1xx other than 101) for an h1 interim head.
fn informational_response(status: u16) -> Response<()> {
    let mut response = Response::new(());
    *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::CONTINUE);
    response
}

/// h2 headers from an already validated h1 response head: names lowercased,
/// hop-by-hop and h1 framing headers removed, everything else preserved.
pub(crate) fn response_headers(head: &[u8]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (index, line) in head.split(|byte| *byte == b'\n').enumerate() {
        if index == 0 {
            continue;
        }
        let line = line.strip_suffix(&b"\r"[..]).unwrap_or(line);
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let name = line[..colon].to_ascii_lowercase();
        let value = line[colon + 1..].trim_ascii();
        let name = match std::str::from_utf8(&name) {
            Ok(name) if !is_hop_by_hop(name) => name,
            _ => continue,
        };
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_bytes(value),
        ) {
            headers.append(name, value);
        }
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head_of(translated: &H1Request) -> String {
        String::from_utf8_lossy(&translated.head).to_ascii_lowercase()
    }

    #[test]
    fn get_builds_origin_form_with_authority_as_host() {
        let uri: http::Uri = "https://api.example.com:8443/v1/items?q=2".parse().unwrap();
        let translated = build_request_head(&Method::GET, &uri, &HeaderMap::new(), true).unwrap();
        assert_eq!(translated.framing, ClientBody::None);
        let head = head_of(&translated);
        assert!(
            head.starts_with("get /v1/items?q=2 http/1.1\r\n"),
            "unexpected request line: {head}"
        );
        assert!(head.contains("host: api.example.com:8443\r\n"), "{head}");
        assert!(!head.contains("content-length"), "{head}");
        assert!(!head.contains("transfer-encoding"), "{head}");
    }

    #[test]
    fn declared_length_is_kept_and_frame_headers_are_rebuilt() {
        let uri: http::Uri = "https://api.example.com/upload".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("content-length", HeaderValue::from_static("5"));
        let translated = build_request_head(&Method::POST, &uri, &headers, false).unwrap();
        assert_eq!(translated.framing, ClientBody::Length(5));
        let head = head_of(&translated);
        assert_eq!(head.matches("content-length").count(), 1, "{head}");
        assert!(head.contains("content-length: 5\r\n"), "{head}");
        assert!(!head.contains("transfer-encoding"), "{head}");
    }

    #[test]
    fn body_without_length_becomes_chunked() {
        let uri: http::Uri = "https://api.example.com/stream".parse().unwrap();
        let translated = build_request_head(&Method::POST, &uri, &HeaderMap::new(), false).unwrap();
        assert_eq!(translated.framing, ClientBody::Chunked);
        let head = head_of(&translated);
        assert!(head.contains("transfer-encoding: chunked\r\n"), "{head}");
        assert!(!head.contains("content-length"), "{head}");
    }

    #[test]
    fn hop_by_hop_headers_never_cross_the_translation() {
        let uri: http::Uri = "https://api.example.com/".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("keep-alive"));
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        headers.insert("te", HeaderValue::from_static("trailers"));
        headers.insert("upgrade", HeaderValue::from_static("websocket"));
        headers.insert("x-request-id", HeaderValue::from_static("abc"));
        let translated = build_request_head(&Method::GET, &uri, &headers, true).unwrap();
        let head = head_of(&translated);
        for gone in ["connection:", "transfer-encoding:", "te:", "upgrade:"] {
            assert!(!head.contains(gone), "{gone} leaked: {head}");
        }
        assert!(head.contains("x-request-id: abc\r\n"), "{head}");
    }

    #[test]
    fn only_origin_form_survives_the_translation() {
        let uri: http::Uri = "/relative".parse().unwrap();
        // A path-only URI has no authority and is still origin-form.
        assert!(build_request_head(&Method::GET, &uri, &HeaderMap::new(), true).is_ok());

        // An empty path means "/" (RFC 9113 §8.3.1): the head carries it.
        let authority_only: http::Uri = "api.example.com:443".parse().unwrap();
        let translated =
            build_request_head(&Method::GET, &authority_only, &HeaderMap::new(), true).unwrap();
        assert!(head_of(&translated).starts_with("get / http/1.1\r\n"));

        // `OPTIONS *` has no h1 origin-form equivalent here: refused.
        let asterisk: http::Uri = "*".parse().unwrap();
        assert!(
            build_request_head(&Method::OPTIONS, &asterisk, &HeaderMap::new(), true).is_err(),
            "OPTIONS * has no origin-form translation"
        );
    }

    #[test]
    fn response_headers_lowercase_and_drop_hop_by_hop() {
        let head = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nTransfer-Encoding: chunked\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n";
        let headers = response_headers(head);
        assert_eq!(headers.get("server").unwrap(), "nginx");
        assert_eq!(headers.get("content-type").unwrap(), "text/plain");
        assert!(headers.get("transfer-encoding").is_none());
        assert!(headers.get("connection").is_none());
    }

    #[test]
    fn response_headers_keep_the_application_framing_it_can_carry() {
        let head =
            b"HTTP/1.1 302 Found\r\nLocation: https://elsewhere.test/\r\nContent-Length: 0\r\n\r\n";
        let headers = response_headers(head);
        assert_eq!(headers.get("location").unwrap(), "https://elsewhere.test/");
        assert_eq!(headers.get("content-length").unwrap(), "0");
    }

    #[test]
    fn the_preface_is_the_only_plaintext_signal() {
        assert_eq!(&CLIENT_PREFACE[..3], b"PRI");
        assert!(CLIENT_PREFACE.ends_with(b"SM\r\n\r\n"));
        assert_eq!(CLIENT_PREFACE.len(), 24);
    }
}
