//! WebSockets over HTTP/2 (RFC 8441 extended CONNECT, B-I18).
//!
//! A client keeps using `WebSocket` after perfecting the h2 handshake: it
//! sends `CONNECT` with `:protocol = websocket`, `:scheme`, `:authority` and
//! `:path`, and the stream becomes the socket. This module turns that stream
//! into a **real** WebSocket handshake towards the backend over HTTP/1.1 and
//! then relays bytes in both directions.
//!
//! Why the h1 engine: routing rules, authentication, rate limiting, header
//! actions, rewrites, `forwarded_headers`, the connection pool and the
//! upgrade tunnel with its idle timeout already exist in `http1::serve_http`.
//! The h2 stream is rendered as the h1 request the same client would have
//! sent (`GET`, `Upgrade: websocket`, a proxy-generated
//! `Sec-WebSocket-Key`), handed to that engine over a bounded pipe, and the
//! rest is a byte relay — no second routing implementation, and no second
//! tunnel implementation either.
//!
//! Deliberate limits, all explicit:
//! - The backend side is HTTP/1.1: a backend that speaks **only** h2 cannot
//!   serve an extended CONNECT through this slice (it keeps the existing h1
//!   WebSocket path when the client itself speaks h1).
//! - `Sec-WebSocket-Accept` is validated by the h1 engine's peer (our backend
//!   handshake); the client of the h2 side never sees it, per RFC 8441 §5.
//! - A non-`101` backend answer is relayed as a normal h2 response (status,
//!   headers, body): the client learns the handshake was refused instead of
//!   receiving an empty stream.
//! - `idle_timeout` closes a silent tunnel, exactly like the h1 tunnel.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use eqproxy_core::Metrics;

use crate::http1::{Prefixed, parse_response_head, read_head};
use crate::http2::{capacity, is_hop_by_hop, relay_response, response_headers};
use crate::proxy::ResolvedListener;

/// In-memory pipe between the client stream and the h1 engine. Bounded: a
/// slow peer applies backpressure instead of buffering.
const PIPE_BUFFER: usize = 64 * 1024;

/// The RFC 8441 protocol token this slice implements.
const WEBSOCKET: &str = "websocket";

/// Source of the (non-secret) `Sec-WebSocket-Key` we generate for the h1
/// handshake. The key only has to be unique per handshake: the backend echoes
/// its digest, and the h1 engine's peer is the one that answers us.
static KEY_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Serves one extended CONNECT, or hands the pair back when the stream is not
/// a WebSocket request (the caller keeps the classic CONNECT refusal).
pub(crate) async fn serve(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    peer: SocketAddr,
    local: SocketAddr,
    cfg: &Arc<ResolvedListener>,
    metrics: &Arc<Metrics>,
) -> Result<(), (Request<RecvStream>, SendResponse<Bytes>)> {
    if request.method() != Method::CONNECT {
        return Err((request, respond));
    }
    let protocol = match request.extensions().get::<h2::ext::Protocol>() {
        None => return Err((request, respond)),
        Some(protocol) => protocol.as_str().to_owned(),
    };
    if protocol != WEBSOCKET {
        // RFC 8441 §5: a server that does not implement the requested
        // protocol answers 501 instead of opening a stream it cannot use.
        metrics
            .http_requests_rejected
            .fetch_add(1, Ordering::Relaxed);
        refuse(&mut respond, StatusCode::NOT_IMPLEMENTED);
        return Ok(());
    }
    if request.uri().authority().is_none() || request.uri().path().is_empty() {
        // An extended CONNECT without `:authority`/`:path` has no target to
        // forward; never guess one.
        metrics
            .http_requests_rejected
            .fetch_add(1, Ordering::Relaxed);
        refuse(&mut respond, StatusCode::BAD_REQUEST);
        return Ok(());
    }

    let key = websocket_key();
    let head = match build_head(request.uri(), request.headers(), &key) {
        Some(head) => head,
        None => {
            metrics
                .http_requests_rejected
                .fetch_add(1, Ordering::Relaxed);
            refuse(&mut respond, StatusCode::BAD_REQUEST);
            return Ok(());
        }
    };

    // One h1 exchange on a bounded pipe: the engine owns the server half,
    // this task writes the handshake and then relays the tunnel.
    let (pipe_ours, pipe_engine) = tokio::io::duplex(PIPE_BUFFER);
    let (engine_read, engine_write) = tokio::io::split(pipe_engine);
    let engine_cfg = Arc::clone(cfg);
    let engine_metrics = Arc::clone(metrics);
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
    if pipe_write.write_all(&head).await.is_err() {
        engine.abort();
        metrics.ws_failures.fetch_add(1, Ordering::Relaxed);
        refuse(&mut respond, StatusCode::BAD_GATEWAY);
        return Ok(());
    }

    let idle = cfg.idle_timeout;
    let mut reader = BufReader::new(pipe_read);
    let mut source = Prefixed {
        prefix: Vec::new(),
        pos: 0,
        inner: &mut reader,
    };
    let (head_bytes, mut carry) = match read_head(&mut source, cfg.server_header_timeout).await {
        Ok(pair) => pair,
        Err(_) => {
            engine.abort();
            metrics.ws_failures.fetch_add(1, Ordering::Relaxed);
            metrics.header_timeouts.fetch_add(1, Ordering::Relaxed);
            refuse(&mut respond, StatusCode::GATEWAY_TIMEOUT);
            return Ok(());
        }
    };
    carry.extend(source.prefix.split_off(source.pos));
    let response = match parse_response_head(&head_bytes, false) {
        Ok(response) => response,
        Err(reject) => {
            eprintln!(
                "WARN [{}] invalid handshake answer for a WebSocket stream: {}",
                cfg.name, reject.reason
            );
            engine.abort();
            metrics.ws_failures.fetch_add(1, Ordering::Relaxed);
            refuse(&mut respond, StatusCode::BAD_GATEWAY);
            return Ok(());
        }
    };

    if response.status != 101 {
        // The backend refused the switch: relay its answer (and body) as a
        // normal HTTP/2 response, so a 401/404/502 is visible, never an
        // empty tunnel.
        // `read_head` returns the head without its terminating blank line:
        // put it back so the relay parses the same bytes the backend sent.
        let mut buffered = Vec::with_capacity(head_bytes.len() + carry.len() + 4);
        buffered.extend_from_slice(&head_bytes);
        buffered.extend_from_slice(b"\r\n\r\n");
        buffered.extend_from_slice(&carry);
        let resumed = Prefixed {
            prefix: buffered,
            pos: 0,
            inner: reader,
        };
        let relayed = relay_response(BufReader::new(resumed), &mut respond, false, cfg).await;
        if let Err(err) = relayed {
            eprintln!(
                "WARN [{}] WebSocket refusal could not be relayed: {err:?}",
                cfg.name
            );
            respond.send_reset(h2::Reason::INTERNAL_ERROR);
        }
        metrics.ws_failures.fetch_add(1, Ordering::Relaxed);
        if tokio::time::timeout(Duration::from_secs(1), &mut engine)
            .await
            .is_err()
        {
            engine.abort();
        }
        return Ok(());
    }

    // RFC 8441 §5: a successful switch is `200`, not `101`, and the
    // `Sec-WebSocket-Accept` of the internal handshake is not forwarded.
    let mut out = Response::new(());
    *out.status_mut() = StatusCode::OK;
    *out.headers_mut() = response_headers(&head_bytes);
    out.headers_mut().remove("sec-websocket-accept");
    out.headers_mut().remove("upgrade");
    out.headers_mut().remove("connection");
    let mut send = match respond.send_response(out, false) {
        Ok(send) => send,
        Err(_) => {
            engine.abort();
            metrics.ws_failures.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    };
    metrics.ws_tunnels.fetch_add(1, Ordering::Relaxed);
    metrics
        .http_requests_proxied
        .fetch_add(1, Ordering::Relaxed);
    if !carry.is_empty() {
        // Bytes the backend sent right after its `101` head.
        if capacity(&mut send, carry.len(), idle).await.is_err()
            || send.send_data(Bytes::from(carry), false).is_err()
        {
            engine.abort();
            metrics.ws_failures.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    }

    let up_metrics = Arc::clone(metrics);
    let mut up = tokio::spawn(async move {
        let result =
            client_to_backend(request.into_body(), &mut pipe_write, idle, &up_metrics).await;
        // EOF towards the engine: a clean half-close of the client side.
        let _ = pipe_write.shutdown().await;
        result
    });
    let down_metrics = Arc::clone(metrics);
    let mut down =
        tokio::spawn(
            async move { backend_to_client(reader, &mut send, idle, &down_metrics).await },
        );
    let first = tokio::select! {
        upstream = &mut up => First::Upstream(upstream),
        downstream = &mut down => First::Downstream(downstream),
    };
    match first {
        // The backend closed the socket: the tunnel is over. The client gets
        // a clean end of stream, and the request direction is dropped.
        First::Downstream(downstream) => {
            up.abort();
            match downstream {
                Ok(Ok(())) => {}
                _ => {
                    metrics.ws_failures.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        // The client half-closed: drain what the backend still has.
        First::Upstream(Ok(Ok(()))) => match down.await {
            Ok(Ok(())) => {}
            _ => {
                metrics.ws_failures.fetch_add(1, Ordering::Relaxed);
            }
        },
        // The client direction failed: the tunnel cannot continue.
        First::Upstream(_) => {
            up.abort();
            down.abort();
            metrics.ws_failures.fetch_add(1, Ordering::Relaxed);
        }
    }
    if tokio::time::timeout(Duration::from_secs(1), &mut engine)
        .await
        .is_err()
    {
        engine.abort();
    }
    Ok(())
}

/// Which direction finished first; both are joined above.
enum First {
    Upstream(Result<Result<(), StreamError>, tokio::task::JoinError>),
    Downstream(Result<Result<(), StreamError>, tokio::task::JoinError>),
}

/// Same reasons the h2 translation uses; the enum is local so this module
/// does not leak its internals into the public API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamError {
    Io,
    H2,
}

/// Answers a stream that never opens a tunnel.
fn refuse(respond: &mut SendResponse<Bytes>, status: StatusCode) {
    let mut response = Response::new(());
    *response.status_mut() = status;
    let _ = respond.send_response(response, true);
}

/// The h1 handshake the backend sees: the client's own request, rewritten as
/// the upgrade the h1 engine understands.
fn build_head(uri: &Uri, headers: &HeaderMap, key: &str) -> Option<Vec<u8>> {
    let authority = uri.authority()?.as_str();
    let path = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    if !path.starts_with('/') {
        return None;
    }
    let mut head = Vec::with_capacity(256);
    head.extend_from_slice(b"GET ");
    head.extend_from_slice(path.as_bytes());
    head.extend_from_slice(b" HTTP/1.1\r\nhost: ");
    head.extend_from_slice(authority.as_bytes());
    head.extend_from_slice(b"\r\n");
    for (name, value) in headers {
        let name = name.as_str();
        // The h1 engine adds its own `Upgrade`/`Connection`; the key and the
        // version belong to the handshake we generate. Everything else the
        // client asked for crosses untouched (subprotocols included).
        if name == "host"
            || name == "content-length"
            || name == "connection"
            || name == "upgrade"
            || name == "sec-websocket-key"
            || name == "sec-websocket-version"
            || is_hop_by_hop(name)
        {
            continue;
        }
        let raw = value.as_bytes();
        if raw
            .iter()
            .any(|byte| *byte == b'\r' || *byte == b'\n' || *byte == 0)
        {
            return None;
        }
        head.extend_from_slice(name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(raw);
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"upgrade: websocket\r\nconnection: Upgrade\r\n");
    head.extend_from_slice(b"sec-websocket-version: 13\r\nsec-websocket-key: ");
    head.extend_from_slice(key.as_bytes());
    head.extend_from_slice(b"\r\n\r\n");
    Some(head)
}

/// A fresh, RFC 6455-shaped key: 16 bytes, base64.
fn websocket_key() -> String {
    let counter = KEY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    // Nanoseconds since the epoch fit in 64 bits for the next five centuries;
    // if that ever stops being true the fallback still yields a valid key.
    let stamp = u64::try_from(nanos).unwrap_or(u64::MAX);
    let mut bytes = [0u8; 16];
    let (timestamp, sequence) = bytes.split_at_mut(8);
    timestamp.copy_from_slice(&stamp.to_le_bytes());
    sequence.copy_from_slice(&counter.to_le_bytes());
    base64(&bytes)
}

/// Minimal base64 (RFC 4648, padded) for the 16-byte key: one dependency
/// would be worth it for a general encoder, not for 24 characters here.
fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = u32::from(chunk.first().copied().unwrap_or(0));
        let second = u32::from(chunk.get(1).copied().unwrap_or(0));
        let third = u32::from(chunk.get(2).copied().unwrap_or(0));
        let bits = (first << 16) | (second << 8) | third;
        // Every digit is masked to six bits, so the table lookup cannot miss;
        // `get` keeps that proof in the code instead of in an index.
        let digit = |shift: u32| usize::try_from((bits >> shift) & 63).unwrap_or(0);
        let symbol = |index: usize| char::from(*TABLE.get(index).unwrap_or(&b'A'));
        out.push(symbol(digit(18)));
        out.push(symbol(digit(12)));
        out.push(if chunk.len() > 1 {
            symbol(digit(6))
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            symbol(digit(0))
        } else {
            '='
        });
    }
    out
}

/// Client DATA frames become bytes on the backend socket; flow-control
/// capacity is released only after the backend accepted the chunk.
async fn client_to_backend<W>(
    mut client: RecvStream,
    backend: &mut W,
    idle: Duration,
    metrics: &Metrics,
) -> Result<(), StreamError>
where
    W: AsyncWrite + Unpin,
{
    loop {
        let chunk = match tokio::time::timeout(idle, client.data()).await {
            Err(_) => {
                metrics.idle_timeouts.fetch_add(1, Ordering::Relaxed);
                return Err(StreamError::Io);
            }
            Ok(None) => return Ok(()),
            Ok(Some(Err(_))) => return Err(StreamError::H2),
            Ok(Some(Ok(chunk))) => chunk,
        };
        if chunk.is_empty() {
            continue;
        }
        backend
            .write_all(&chunk)
            .await
            .map_err(|_| StreamError::Io)?;
        client
            .flow_control()
            .release_capacity(chunk.len())
            .map_err(|_| StreamError::H2)?;
    }
}

/// Backend bytes become DATA frames, bounded by the client's flow-control
/// window (the window is the only buffer).
async fn backend_to_client<R>(
    mut backend: BufReader<R>,
    send: &mut SendStream<Bytes>,
    idle: Duration,
    metrics: &Metrics,
) -> Result<(), StreamError>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; crate::http2::DATA_CHUNK];
    loop {
        let window = capacity(send, buf.len(), idle)
            .await
            .map_err(|_| StreamError::H2)?;
        let want = window.min(buf.len());
        let got = match tokio::time::timeout(idle, backend.read(&mut buf[..want])).await {
            Err(_) => {
                // A tunnel with nothing to say in either direction is idle:
                // the same cap applies to both pumps.
                metrics.idle_timeouts.fetch_add(1, Ordering::Relaxed);
                return Err(StreamError::Io);
            }
            Ok(Ok(0)) => {
                send.send_data(Bytes::new(), true)
                    .map_err(|_| StreamError::H2)?;
                return Ok(());
            }
            Ok(Ok(got)) => got,
            Ok(Err(_)) => return Err(StreamError::Io),
        };
        send.send_data(Bytes::copy_from_slice(&buf[..got]), false)
            .map_err(|_| StreamError::H2)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_rfc_vector() {
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64(&[0u8; 16]), "AAAAAAAAAAAAAAAAAAAAAA==");
    }

    #[test]
    fn the_generated_key_is_sixteen_bytes_of_base64() {
        let key = websocket_key();
        assert_eq!(key.len(), 24);
        assert!(key.ends_with("=="));
        let other = websocket_key();
        assert_ne!(key, other, "two handshakes never share a key");
    }

    #[test]
    fn head_adds_the_upgrade_and_drops_what_it_must() {
        let uri: Uri = "http://api.test/chat?room=1".parse().expect("uri");
        let mut headers = HeaderMap::new();
        headers.insert("sec-websocket-protocol", "chat, superchat".parse().unwrap());
        headers.insert("connection", "keep-alive, Upgrade".parse().unwrap());
        headers.insert("upgrade", "h2c".parse().unwrap());
        headers.insert("te", "trailers".parse().unwrap());
        headers.insert("x-request-id", "abc".parse().unwrap());
        headers.insert("sec-websocket-key", "client-key".parse().unwrap());
        let head = build_head(&uri, &headers, "proxy-key").expect("head");
        let text = String::from_utf8(head).expect("utf8");
        assert!(text.starts_with("GET /chat?room=1 HTTP/1.1\r\nhost: api.test\r\n"));
        assert!(text.contains("upgrade: websocket\r\n"));
        assert!(text.contains("connection: Upgrade\r\n"));
        assert!(text.contains("sec-websocket-key: proxy-key\r\n"));
        assert!(text.contains("sec-websocket-version: 13\r\n"));
        assert!(text.contains("sec-websocket-protocol: chat, superchat\r\n"));
        assert!(text.contains("x-request-id: abc\r\n"));
        assert!(!text.contains("client-key"));
        assert!(!text.contains("te:"));
        assert!(!text.contains("h2c"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn a_target_that_is_not_a_path_is_refused() {
        let uri: Uri = "http://api.test".parse().expect("uri");
        let headers = HeaderMap::new();
        let head = build_head(&uri, &headers, "k").expect("defaults to /");
        assert!(
            String::from_utf8(head)
                .unwrap()
                .starts_with("GET / HTTP/1.1\r\n")
        );
        assert!(build_head(&Uri::from_static("*"), &headers, "k").is_none());
    }
}
