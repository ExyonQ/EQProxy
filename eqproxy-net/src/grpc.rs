//! gRPC over HTTP/2, end to end (B-I12/Q5).
//!
//! A gRPC exchange is one long-lived HTTP/2 stream whose two directions are
//! independent: the client keeps sending messages while the server answers,
//! and the final status travels in **trailers**. The generic h2 front end
//! translates every stream to one HTTP/1.1 message for the single exchange
//! engine, which is right for request/response traffic and wrong for this
//! one: that engine forwards the whole request body before it reads the
//! response head, so a bidi stream would never see its first answer before
//! the client half-closes.
//!
//! When both ends speak HTTP/2 this module relays the stream itself:
//! HEADERS + DATA + trailers in both directions at once, with HTTP/2 flow
//! control as the only buffer. What to do with the request is still decided
//! by the proxy's one routing path: the h1 head is built from the h2 request,
//! run through the same helpers the h1 engine uses (rule header actions,
//! forwarded headers, rewrite), and translated back — never a second
//! implementation of the rules.
//!
//! Deliberate limits of this slice, all explicit:
//! - Pass-through requires a gRPC `content-type`, a `POST`, and a backend
//!   that negotiated ALPN `h2`. Anything else keeps the h1 translation
//!   (never a half-broken pass-through).
//! - Compression is not applied: gRPC has its own message compression.
//! - Mirroring is not applied to gRPC streams (the copy needs a finished
//!   body; a stream has none).
//! - A stream the peer refuses after opening it is not replayed: a gRPC
//!   exchange is not idempotent.
//! - `max_stream_duration` ends a running stream with `grpc-status: 4`
//!   (DEADLINE_EXCEEDED) trailers; `idle_timeout` cuts a silent one with a
//!   stream reset.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use h2::RecvStream;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};

use eqproxy_core::Metrics;

/// The request pair handed back untouched when the stream is not gRPC. Boxed:
/// the pair is 264 bytes and returning it inline trips
/// `clippy::result_large_err` on current toolchains.
pub(crate) type Unserved = Box<(Request<RecvStream>, h2::server::SendResponse<Bytes>)>;

use crate::http1::{
    BodyFraming, RequestHead, apply_forwarded, apply_header_actions, apply_rewrite, cookie_value,
    parse_request_head,
};
use crate::http2::{DATA_CHUNK, StreamError, build_request_head, capacity};
use crate::proxy::{
    AffinityMode, OutboundError, ResolvedBackend, ResolvedListener, RouteDecision, open_grpc_stream,
};

/// Headers that must never cross to the backend h2 stream (RFC 9113 §8.2.2).
/// `te` is *not* here: gRPC requires `te: trailers`, added explicitly.
const H1_ONLY: [&str; 7] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

/// Connection-specific response headers: dropped when the backend's HEADERS
/// are relayed to the client. Everything else (including `content-length`)
/// is passed through untouched.
const CONNECTION_SPECIFIC: [&str; 7] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
];

/// Why one gRPC attempt could not be relayed, at the point of a read.
enum ReadError {
    Stream(StreamError),
    /// No DATA within `idle_timeout`: the stream is silent, not dead.
    Idle,
    Deadline,
}

/// Serves one gRPC stream end to end, or hands the request back untouched
/// when this is not the pass-through's case (the caller then keeps the h1
/// translation it always had).
pub(crate) async fn serve(
    request: Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    peer: SocketAddr,
    local: SocketAddr,
    cfg: &Arc<ResolvedListener>,
    metrics: &Arc<Metrics>,
) -> Result<(), Unserved> {
    if request.method() != Method::POST || !is_grpc(request.headers()) {
        return Err(Box::new((request, respond)));
    }
    let body_empty = request.body().is_end_stream();
    let Ok(h1) = build_request_head(
        request.method(),
        request.uri(),
        request.headers(),
        body_empty,
    ) else {
        // The h1 translation answers this with the precise refusal.
        return Err(Box::new((request, respond)));
    };
    let Ok(head) = parse_head(&h1.head) else {
        return Err(Box::new((request, respond)));
    };
    let path = eqproxy_core::rules::path_of(&head.target).to_owned();
    let facts = eqproxy_core::rules::RequestFacts {
        method: &head.method,
        host: &head.host,
        path: &path,
        headers: &head.headers,
        peer: peer.ip(),
        maps: cfg.maps.as_ref(),
    };
    let (decision, route_name) = cfg.decide_routed(&facts);
    if let Some(limiter) = decision.rate_limiter()
        && !limiter.try_acquire(peer.ip())
    {
        metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
        let _ = local_answer(
            &mut respond,
            StatusCode::TOO_MANY_REQUESTS,
            &[],
            b"too many requests",
        );
        return Ok(());
    }
    if let Some(auth) = decision.auth() {
        match crate::auth::check(auth, &head, cfg.connect_timeout, cfg.server_header_timeout).await
        {
            crate::auth::AuthOutcome::Allow => {}
            crate::auth::AuthOutcome::Deny(deny) => {
                metrics.auth_denied.fetch_add(1, Ordering::Relaxed);
                let _ = local_deny(&mut respond, &deny);
                return Ok(());
            }
            crate::auth::AuthOutcome::Error(deny) => {
                metrics.auth_service_errors.fetch_add(1, Ordering::Relaxed);
                let _ = local_deny(&mut respond, &deny);
                return Ok(());
            }
        }
    }
    let (backend, rewrite, actions) = match decision {
        RouteDecision::Proxy {
            backend,
            rewrite,
            headers,
        } => (backend, rewrite, headers),
        // A redirect or a direct answer is a local response, not a stream:
        // the h1 translation already serves them with their exact semantics.
        RouteDecision::Redirect { .. } | RouteDecision::Direct { .. } => {
            return Err(Box::new((request, respond)));
        }
    };
    if backend.h2.is_none() {
        // No HTTP/2 to this backend: gRPC cannot be spoken there. Keep the
        // existing translation instead of inventing a second failure mode.
        return Err(Box::new((request, respond)));
    }

    let scheme = if cfg.server_tls.is_some() {
        "https"
    } else {
        "http"
    };
    // The helpers below work on the head **without** its blank line, exactly
    // as `read_head` hands it to the h1 engine (they append headers at the
    // end, which would land after the terminator otherwise).
    let mut base_head = h1.head.as_slice();
    while let Some(stripped) = base_head.strip_suffix(b"\r\n") {
        base_head = stripped;
    }
    // Exactly the head the h1 engine would forward: rule header actions first,
    // then the forwarded-headers policy, then the path rewrite.
    let acted =
        actions.map(|actions| apply_header_actions(base_head, actions, peer, &head.host, scheme));
    let base = acted.as_deref().unwrap_or(base_head);
    let forwarded = apply_forwarded(base, peer, cfg.forwarded_headers, scheme);
    let forwarded = match rewrite {
        Some(rewrite) => apply_rewrite(&forwarded, rewrite, &head.target),
        None => forwarded,
    };
    let forwarded = match parse_head(&forwarded) {
        Ok(forwarded) => forwarded,
        Err(_) => {
            metrics
                .http_requests_rejected
                .fetch_add(1, Ordering::Relaxed);
            let _ = local_answer(
                &mut respond,
                StatusCode::BAD_REQUEST,
                &[],
                b"untranslatable request head",
            );
            return Ok(());
        }
    };
    let outbound = match outbound_request(&forwarded, scheme) {
        Ok(outbound) => outbound,
        Err(()) => {
            metrics
                .http_requests_rejected
                .fetch_add(1, Ordering::Relaxed);
            let _ = local_answer(
                &mut respond,
                StatusCode::BAD_REQUEST,
                &[],
                b"untranslatable request target",
            );
            return Ok(());
        }
    };
    let affinity_cookie = backend.affinity.as_ref().and_then(|affinity| {
        (affinity.mode == AffinityMode::Cookie)
            .then(|| cookie_value(&head.headers, &affinity.cookie))
            .flatten()
    });
    let end_of_stream = forwarded.framing == BodyFraming::None;
    let stream = match open_grpc_stream(
        cfg,
        backend,
        peer,
        local,
        metrics,
        outbound,
        end_of_stream,
        affinity_cookie.as_deref(),
    )
    .await
    {
        Ok(stream) => stream,
        Err(OutboundError::NoServer)
        | Err(OutboundError::QueueFull)
        | Err(OutboundError::QueueTimeout) => {
            write_no_server(&mut respond, cfg, metrics);
            return Ok(());
        }
        Err(OutboundError::Connect) => {
            metrics.grpc_stream_errors.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "WARN [{}] gRPC stream to backend {} failed before it reached the server (peer {peer})",
                cfg.name, backend.name
            );
            let _ = local_answer(&mut respond, StatusCode::BAD_GATEWAY, &[], b"bad gateway");
            return Ok(());
        }
    };

    metrics.grpc_streams.fetch_add(1, Ordering::Relaxed);
    // The stream outlives the borrow below: remember which server carries it
    // while the struct is still whole (CE4).
    let served_addr = stream.addr;
    let idle = cfg.idle_timeout;
    let deadline = (cfg.max_stream_duration > Duration::ZERO)
        .then(|| tokio::time::Instant::now() + cfg.max_stream_duration);
    let label = cfg.name.clone();
    let client_body = request.into_body();
    let up_metrics = Arc::clone(metrics);
    let mut up = tokio::spawn(async move {
        let result = forward_request(client_body, stream.send, idle, &up_metrics, deadline).await;
        if let Err(err) = result {
            eprintln!(
                "WARN [{label}] gRPC request direction ended: {}",
                describe(err)
            );
        }
        result
    });

    // The backend answers HEADERS as soon as it decides; waiting on them is
    // the server-header phase, capped by the overall stream deadline too.
    let header_wait = cfg.server_header_timeout;
    let now = tokio::time::Instant::now();
    let head_at = match deadline {
        Some(deadline) => deadline.min(now + header_wait),
        None => now + header_wait,
    };
    let response = match tokio::time::timeout_at(head_at, stream.response).await {
        Err(_) => {
            metrics.header_timeouts.fetch_add(1, Ordering::Relaxed);
            metrics.grpc_stream_errors.fetch_add(1, Ordering::Relaxed);
            up.abort();
            let _ = local_answer(
                &mut respond,
                StatusCode::GATEWAY_TIMEOUT,
                &[],
                b"gateway timeout",
            );
            return Ok(());
        }
        Ok(Err(_)) => {
            metrics.grpc_stream_errors.fetch_add(1, Ordering::Relaxed);
            up.abort();
            let _ = local_answer(&mut respond, StatusCode::BAD_GATEWAY, &[], b"bad gateway");
            return Ok(());
        }
        Ok(Ok(response)) => response,
    };

    let failed = response.status().is_server_error();
    let mut out = Response::new(());
    *out.status_mut() = response.status();
    for (name, value) in response.headers() {
        if CONNECTION_SPECIFIC.contains(&name.as_str()) {
            continue;
        }
        out.headers_mut().append(name.clone(), value.clone());
    }
    let end = response.body().is_end_stream();
    let client = match respond.send_response(out, end) {
        Ok(client) => client,
        Err(_) => {
            up.abort();
            return Ok(());
        }
    };
    if end {
        // A trailers-only answer (gRPC's immediate status): nothing to relay.
        up.abort();
        metrics
            .http_requests_proxied
            .fetch_add(1, Ordering::Relaxed);
        record_detail(metrics, cfg, backend, served_addr, route_name, failed);
        return Ok(());
    }

    let down_metrics = Arc::clone(metrics);
    let mut down = tokio::spawn(async move {
        relay_response(response.into_body(), client, idle, deadline, &down_metrics).await
    });
    let first = tokio::select! {
        upstream = &mut up => First::Upstream(upstream),
        downstream = &mut down => First::Downstream(downstream),
    };
    match first {
        // The server finished the stream: the request direction has no reader
        // any more. Aborting it drops the backend stream (cancelled), and the
        // client already received its final trailers.
        First::Downstream(downstream) => {
            up.abort();
            match downstream {
                Ok(Ok(())) => {
                    metrics
                        .http_requests_proxied
                        .fetch_add(1, Ordering::Relaxed);
                    record_detail(metrics, cfg, backend, served_addr, route_name, failed);
                }
                _ => {
                    metrics.grpc_stream_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        // The client half-closed first: keep relaying the answer.
        First::Upstream(Ok(Ok(()))) => match down.await {
            Ok(Ok(())) => {
                metrics
                    .http_requests_proxied
                    .fetch_add(1, Ordering::Relaxed);
                record_detail(metrics, cfg, backend, served_addr, route_name, failed);
            }
            _ => {
                metrics.grpc_stream_errors.fetch_add(1, Ordering::Relaxed);
            }
        },
        // The request direction failed: the answer cannot be completed, so
        // the client stream is cancelled instead of being left half-open.
        First::Upstream(_) => {
            up.abort();
            down.abort();
            metrics.grpc_stream_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
    Ok(())
}

/// Which direction finished first; both are joined below.
enum First {
    Upstream(Result<Result<(), StreamError>, tokio::task::JoinError>),
    Downstream(Result<Result<(), StreamError>, tokio::task::JoinError>),
}

/// Parses a head produced by the h1 renderer (which terminates the last line
/// with CRLF) with the strict request parser (which expects no blank line).
fn parse_head(head: &[u8]) -> Result<RequestHead, crate::http1::Reject> {
    let mut head = head;
    while let Some(stripped) = head.strip_suffix(b"\r\n") {
        head = stripped;
    }
    parse_request_head(head)
}

/// `application/grpc`, `application/grpc+proto`, `application/grpc+json`, …
/// but never `application/grpc-web` (that is a different wire protocol).
fn is_grpc(headers: &HeaderMap) -> bool {
    headers.get_all("content-type").iter().any(|value| {
        let Ok(text) = value.to_str() else {
            return false;
        };
        let mime = text
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        mime == "application/grpc" || mime.starts_with("application/grpc+")
    })
}

/// The h2 request sent to the backend: the forwarded h1 head translated back,
/// with `te: trailers` (gRPC requires it) and without the h1 framing headers.
fn outbound_request(head: &RequestHead, scheme: &str) -> Result<Request<()>, ()> {
    if head.host.trim().is_empty() {
        return Err(());
    }
    let uri: http::Uri =
        if head.target.starts_with("http://") || head.target.starts_with("https://") {
            head.target.parse().map_err(|_| ())?
        } else {
            format!("{}://{}{}", scheme, head.host, head.target)
                .parse()
                .map_err(|_| ())?
        };
    let mut builder = Request::builder()
        .method(head.method.as_str())
        .uri(uri)
        .version(http::Version::HTTP_2);
    for (name, value) in &head.headers {
        if H1_ONLY.contains(&name.as_str()) || name == "te" || name == "trailer" {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_str());
    }
    if let BodyFraming::ContentLength(len) = head.framing {
        builder = builder.header("content-length", len);
    }
    builder = builder.header("te", "trailers");
    builder.body(()).map_err(|_| ())
}

/// Relays the client's DATA and trailers into the backend stream. Flow
/// control is the buffer: capacity is released only after the chunk was
/// accepted by the backend.
async fn forward_request(
    mut client: RecvStream,
    mut backend: h2::SendStream<Bytes>,
    idle: Duration,
    metrics: &Metrics,
    deadline: Option<tokio::time::Instant>,
) -> Result<(), StreamError> {
    loop {
        let chunk = match next_data(&mut client, idle, None).await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(ReadError::Stream(err)) => return Err(err),
            Err(ReadError::Idle) => {
                metrics.idle_timeouts.fetch_add(1, Ordering::Relaxed);
                return Err(StreamError::Io);
            }
            Err(ReadError::Deadline) => return Err(StreamError::Io),
        };
        if !chunk.is_empty() {
            send_chunk(&mut backend, &chunk, idle).await?;
            metrics
                .bytes_client_to_backend
                .fetch_add(chunk.len() as u64, Ordering::Relaxed);
            client
                .flow_control()
                .release_capacity(chunk.len())
                .map_err(|_| StreamError::H2)?;
        }
        if let Some(deadline) = deadline
            && tokio::time::Instant::now() >= deadline
        {
            return Err(StreamError::Io);
        }
    }
    let trailers = match tokio::time::timeout(idle, client.trailers()).await {
        Err(_) => return Err(StreamError::Io),
        Ok(Err(_)) => return Err(StreamError::H2),
        Ok(Ok(Some(trailers))) => trailers,
        Ok(Ok(None)) => HeaderMap::new(),
    };
    if trailers.is_empty() {
        backend
            .send_data(Bytes::new(), true)
            .map_err(|_| StreamError::H2)
    } else {
        backend.send_trailers(trailers).map_err(|_| StreamError::H2)
    }
}

/// Relays the backend's DATA and trailers into the client stream. The final
/// trailers carry gRPC's status; a `max_stream_duration` cut sends
/// `grpc-status: 4` (DEADLINE_EXCEEDED) instead of hiding the reason.
async fn relay_response(
    mut backend: RecvStream,
    mut client: h2::SendStream<Bytes>,
    idle: Duration,
    deadline: Option<tokio::time::Instant>,
    metrics: &Metrics,
) -> Result<(), StreamError> {
    loop {
        let chunk = match next_data(&mut backend, idle, deadline).await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(ReadError::Deadline) => {
                let mut trailers = HeaderMap::new();
                trailers.insert("grpc-status", HeaderValue::from_static("4"));
                trailers.insert(
                    "grpc-message",
                    HeaderValue::from_static("max stream duration exceeded"),
                );
                return client.send_trailers(trailers).map_err(|_| StreamError::H2);
            }
            Err(ReadError::Idle) => {
                metrics.idle_timeouts.fetch_add(1, Ordering::Relaxed);
                return Err(StreamError::Io);
            }
            Err(ReadError::Stream(err)) => return Err(err),
        };
        if !chunk.is_empty() {
            send_chunk(&mut client, &chunk, idle).await?;
            metrics
                .bytes_backend_to_client
                .fetch_add(chunk.len() as u64, Ordering::Relaxed);
            backend
                .flow_control()
                .release_capacity(chunk.len())
                .map_err(|_| StreamError::H2)?;
        }
    }
    let trailers = match tokio::time::timeout(idle, backend.trailers()).await {
        Err(_) => return Err(StreamError::Io),
        Ok(Err(_)) => return Err(StreamError::H2),
        Ok(Ok(Some(trailers))) => trailers,
        Ok(Ok(None)) => HeaderMap::new(),
    };
    if trailers.is_empty() {
        client
            .send_data(Bytes::new(), true)
            .map_err(|_| StreamError::H2)
    } else {
        client.send_trailers(trailers).map_err(|_| StreamError::H2)
    }
}

/// Next DATA payload, bounded by inactivity and (optionally) the total
/// stream deadline.
async fn next_data(
    recv: &mut RecvStream,
    idle: Duration,
    deadline: Option<tokio::time::Instant>,
) -> Result<Option<Bytes>, ReadError> {
    let read = tokio::time::timeout(idle, recv.data());
    let got = match deadline {
        Some(at) => tokio::select! {
            _ = tokio::time::sleep_until(at) => return Err(ReadError::Deadline),
            got = read => got,
        },
        None => read.await,
    };
    match got {
        Err(_) => Err(ReadError::Idle),
        Ok(None) => Ok(None),
        Ok(Some(Err(_))) => Err(ReadError::Stream(StreamError::H2)),
        Ok(Some(Ok(chunk))) => Ok(Some(chunk)),
    }
}

/// Sends one DATA payload honoring the peer's available capacity.
async fn send_chunk(
    send: &mut h2::SendStream<Bytes>,
    chunk: &[u8],
    idle: Duration,
) -> Result<(), StreamError> {
    let mut offset = 0;
    while offset < chunk.len() {
        let want = (chunk.len() - offset).min(DATA_CHUNK);
        let available = capacity(send, want, idle).await?;
        let take = available.min(chunk.len() - offset);
        send.send_data(Bytes::copy_from_slice(&chunk[offset..offset + take]), false)
            .map_err(|_| StreamError::H2)?;
        offset += take;
    }
    Ok(())
}

fn describe(err: StreamError) -> &'static str {
    match err {
        StreamError::Truncated => "body shorter than its declared length",
        StreamError::Framing => "framing that has no HTTP/2 translation",
        StreamError::Io => "I/O, timeout or stream deadline",
        StreamError::H2 => "HTTP/2 protocol error",
        StreamError::H3 => "HTTP/3 stream error",
        StreamError::Refused => "refused by a GOAWAY and not replayable",
        StreamError::StreamRefused => "reset with REFUSED_STREAM and not replayable",
    }
}

/// Local answer for a stream that never becomes a backend exchange.
fn local_answer(
    respond: &mut h2::server::SendResponse<Bytes>,
    status: StatusCode,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<(), ()> {
    let mut response = Response::new(());
    *response.status_mut() = status;
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            response.headers_mut().append(name, value);
        }
    }
    if let Ok(length) = HeaderValue::from_str(&body.len().to_string()) {
        response.headers_mut().insert("content-length", length);
    }
    let mut send = respond
        .send_response(response, body.is_empty())
        .map_err(|_| ())?;
    if !body.is_empty() {
        send.send_data(Bytes::copy_from_slice(body), true)
            .map_err(|_| ())?;
    }
    Ok(())
}

fn local_deny(
    respond: &mut h2::server::SendResponse<Bytes>,
    deny: &crate::auth::DenyResponse,
) -> Result<(), ()> {
    let status = StatusCode::from_u16(deny.status).unwrap_or(StatusCode::FORBIDDEN);
    local_answer(respond, status, &deny.headers, deny.body.as_bytes())
}

/// Attributes a completed gRPC stream to the server that carried it and to the
/// rule that matched (CE4). A disabled registry costs one relaxed load.
fn record_detail(
    metrics: &Metrics,
    cfg: &ResolvedListener,
    backend: &ResolvedBackend,
    served: SocketAddr,
    route: Option<&str>,
    failed: bool,
) {
    if !metrics.detail.enabled() {
        return;
    }
    metrics
        .detail
        .record_server(&backend.name, &served.to_string(), failed);
    if let Some(route) = route {
        metrics.detail.record_route(&cfg.name, route, failed);
    }
}

/// `503` for the whole "no server available" class, honoring the listener's
/// custom local response (C9) exactly like the h1 engine does.
fn write_no_server(
    respond: &mut h2::server::SendResponse<Bytes>,
    cfg: &ResolvedListener,
    metrics: &Metrics,
) {
    if let Some(local_response) = &cfg.local_response {
        metrics
            .local_responses_served
            .fetch_add(1, Ordering::Relaxed);
        let status =
            StatusCode::from_u16(local_response.status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
        let headers = [(
            "content-type".to_owned(),
            local_response.content_type.clone(),
        )];
        let _ = local_answer(respond, status, &headers, local_response.body.as_bytes());
        return;
    }
    let _ = local_answer(
        respond,
        StatusCode::SERVICE_UNAVAILABLE,
        &[],
        b"service unavailable",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(content_type: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            HeaderValue::from_str(content_type).expect("value"),
        );
        headers
    }

    #[test]
    fn grpc_content_types_are_recognized_and_grpc_web_is_not() {
        assert!(is_grpc(&head("application/grpc")));
        assert!(is_grpc(&head("application/grpc+proto")));
        assert!(is_grpc(&head("application/grpc+json; charset=utf-8")));
        assert!(!is_grpc(&head("application/grpc-web")));
        assert!(!is_grpc(&head("application/grpc-web+proto")));
        assert!(!is_grpc(&head("text/plain")));
        assert!(!is_grpc(&HeaderMap::new()));
    }

    fn request_head(target: &str, extra: &str) -> RequestHead {
        let raw = format!(
            "POST {target} HTTP/1.1\r\nhost: api.example.test\r\ncontent-type: application/grpc\r\ntransfer-encoding: chunked\r\nx-trace: 42\r\n{extra}"
        );
        parse_request_head(raw.as_bytes()).expect("valid head")
    }

    #[test]
    fn outbound_request_carries_te_trailers_and_no_h1_framing() {
        let head = request_head("/pkg.Service/Stream", "");
        let out = outbound_request(&head, "https").expect("outbound");
        assert_eq!(out.method(), Method::POST);
        assert_eq!(
            out.uri().to_string(),
            "https://api.example.test/pkg.Service/Stream"
        );
        assert_eq!(out.version(), http::Version::HTTP_2);
        assert_eq!(out.headers()["te"], "trailers");
        assert_eq!(out.headers()["content-type"], "application/grpc");
        assert_eq!(out.headers()["x-trace"], "42");
        assert!(
            !out.headers().contains_key("transfer-encoding"),
            "h1 framing must not cross into h2"
        );
        assert!(
            !out.headers().contains_key("host"),
            ":authority replaces host in h2"
        );
    }

    #[test]
    fn outbound_request_keeps_a_declared_length_only() {
        let head = parse_request_head(
            b"POST /pkg.Service/Unary HTTP/1.1\r\nhost: api\r\ncontent-type: application/grpc\r\ncontent-length: 12\r\n",
        )
        .expect("head");
        let out = outbound_request(&head, "http").expect("outbound");
        assert_eq!(out.headers()["content-length"], "12");
        assert!(
            !out.headers().contains_key("transfer-encoding"),
            "a declared length is never chunked"
        );
    }

    #[test]
    fn outbound_request_refuses_a_missing_authority() {
        let head = parse_request_head(
            b"POST /pkg.Service/Stream HTTP/1.0\r\ncontent-type: application/grpc\r\n",
        )
        .expect("head");
        assert!(outbound_request(&head, "https").is_err());
    }
}
