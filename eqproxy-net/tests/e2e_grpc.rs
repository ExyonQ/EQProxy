//! gRPC end to end over real sockets (B-I12/Q5).
//!
//! The origin is a real TLS HTTP/2 server that speaks the gRPC wire protocol
//! (length-prefixed messages, `te: trailers`, status in trailers); the client
//! is the same `h2` implementation a production gRPC stack uses. The journeys
//! prove what the pass-through promises: both directions advance at once (an
//! answer arrives before the client half-closes), large messages cross HTTP/2
//! flow control, concurrent streams share one backend session, a silent
//! stream is cut by `idle_timeout` instead of hanging, `max_stream_duration`
//! ends a running stream with `grpc-status: 4`, and a backend that is not
//! HTTP/2 keeps the h1 translation instead of a half-broken pass-through.

use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use eqproxy_core::Metrics;
use eqproxy_core::shutdown;
use eqproxy_net::proxy::ForwardedMode;
use eqproxy_net::tls::{self, TlsVersion};
use eqproxy_net::{
    BoundProxy, ProxyMode, ResolvedBackend, ResolvedListener, ResolvedServer, ServerAddr, bind,
};

const WAIT: Duration = Duration::from_secs(10);
const CERT: &[u8] = include_bytes!("fixtures/cert.pem");
const KEY: &[u8] = include_bytes!("fixtures/key.pem");

/// What the origin saw for one stream.
#[derive(Debug, Clone)]
struct Seen {
    path: String,
    te: String,
    content_type: String,
    forwarded_for: String,
    trailers: Option<HeaderMap>,
}

struct Origin {
    addr: SocketAddr,
    /// Accepted backend TCP connections (one shared h2 session must be one).
    connections: Arc<AtomicUsize>,
    /// Maximum streams in flight at the same time.
    max_inflight: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

fn seen(origin: &Origin) -> Vec<Seen> {
    origin.seen.lock().expect("seen lock").clone()
}

fn header(request: &Request<h2::RecvStream>, name: &str) -> String {
    request
        .headers()
        .get(name)
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .unwrap_or_default()
}

/// A TLS HTTP/2 origin that speaks gRPC: every message is echoed as it
/// arrives, and the stream ends with `grpc-status: 0` trailers. `/Barrier`
/// only proceeds once two streams are inside the origin at once.
async fn start_grpc_origin() -> Origin {
    let server = tls::server_config(CERT, KEY, None, &["h2".to_owned()], TlsVersion::V1_2)
        .expect("server tls");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    let connections = Arc::new(AtomicUsize::new(0));
    let inflight = Arc::new(AtomicUsize::new(0));
    let max_inflight = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let accepted = Arc::clone(&connections);
    let active = Arc::clone(&inflight);
    let peak = Arc::clone(&max_inflight);
    let recorded = Arc::clone(&seen);
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            accepted.fetch_add(1, Ordering::SeqCst);
            let acceptor = server.clone();
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            let recorded = Arc::clone(&recorded);
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                let Ok(stream) = acceptor.acceptor.accept(socket).await else {
                    return;
                };
                assert_eq!(
                    stream.get_ref().1.alpn_protocol(),
                    Some(&b"h2"[..]),
                    "the proxy must negotiate h2 with a gRPC backend"
                );
                let Ok(mut connection) = h2::server::handshake(stream).await else {
                    return;
                };
                while let Some(accepted) = connection.accept().await {
                    let Ok((request, respond)) = accepted else {
                        break;
                    };
                    tokio::spawn(serve_stream(
                        request,
                        respond,
                        Arc::clone(&recorded),
                        Arc::clone(&active),
                        Arc::clone(&peak),
                        Arc::clone(&barrier),
                    ));
                }
            });
        }
    });
    Origin {
        addr,
        connections,
        max_inflight,
        seen,
    }
}

async fn serve_stream(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    seen: Arc<Mutex<Vec<Seen>>>,
    inflight: Arc<AtomicUsize>,
    max_inflight: Arc<AtomicUsize>,
    barrier: Arc<tokio::sync::Barrier>,
) {
    let path = request.uri().path().to_owned();
    let entry = Seen {
        path: path.clone(),
        te: header(&request, "te"),
        content_type: header(&request, "content-type"),
        forwarded_for: header(&request, "x-forwarded-for"),
        trailers: None,
    };
    let index = {
        let mut seen = seen.lock().expect("seen lock");
        seen.push(entry);
        seen.len() - 1
    };
    let now = inflight.fetch_add(1, Ordering::SeqCst) + 1;
    max_inflight.fetch_max(now, Ordering::SeqCst);
    let mut body = request.into_body();

    let mut response = Response::new(());
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert("content-type", HeaderValue::from_static("application/grpc"));
    let Ok(mut send) = respond.send_response(response, false) else {
        inflight.fetch_sub(1, Ordering::SeqCst);
        return;
    };

    if path == "/pkg.Service/Barrier" && tokio::time::timeout(WAIT, barrier.wait()).await.is_err() {
        // The proxy serialized the two streams: the test fails on this side.
        inflight.fetch_sub(1, Ordering::SeqCst);
        return;
    }

    // Echo every DATA payload as it arrives: the bytes are genuine gRPC
    // frames and the client is still allowed to send more.
    while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else { break };
        if send_all(&mut send, &chunk).await.is_err() {
            break;
        }
        let _ = body.flow_control().release_capacity(chunk.len());
    }
    let trailers = body.trailers().await.ok().flatten();
    seen.lock().expect("seen lock")[index].trailers = trailers;

    let mut status = HeaderMap::new();
    status.insert("grpc-status", HeaderValue::from_static("0"));
    let _ = send.send_trailers(status);
    inflight.fetch_sub(1, Ordering::SeqCst);
}

/// Sends bytes honoring the peer's flow-control window (the same discipline
/// the proxy applies).
async fn send_all(send: &mut h2::SendStream<Bytes>, data: &[u8]) -> Result<(), ()> {
    let mut offset = 0;
    while offset < data.len() {
        send.reserve_capacity((data.len() - offset).min(16 * 1024));
        let capacity = loop {
            match poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(Ok(available)) if available > 0 => break available,
                Some(Ok(_)) => continue,
                Some(Err(_)) | None => return Err(()),
            }
        };
        let take = capacity.min(data.len() - offset);
        if send
            .send_data(Bytes::copy_from_slice(&data[offset..offset + take]), false)
            .is_err()
        {
            return Err(());
        }
        offset += take;
    }
    Ok(())
}

fn backend_tls(alpn: &[&str]) -> tls::ClientTls {
    let alpn: Vec<String> = alpn.iter().map(|proto| (*proto).to_owned()).collect();
    tls::client_config(Some(CERT), true, Some("localhost"), &alpn, TlsVersion::V1_2)
        .expect("backend tls")
}

fn http_listener(server: SocketAddr) -> ResolvedListener {
    ResolvedListener::new(
        "web",
        "127.0.0.1:0".parse().expect("addr"),
        "api",
        server,
        ProxyMode::Http,
        64,
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
}

fn proxy_with_h2_backend(origin: SocketAddr) -> ResolvedListener {
    let backend = Arc::new(ResolvedBackend::single("api", origin).with_tls(backend_tls(&["h2"])));
    http_listener(origin).with_backend(backend)
}

async fn start_proxy(
    cfg: ResolvedListener,
) -> (
    SocketAddr,
    Arc<Metrics>,
    shutdown::ShutdownHandle,
    JoinHandle<()>,
) {
    let metrics = Arc::new(Metrics::default());
    let bound: BoundProxy = bind(vec![cfg], Arc::clone(&metrics))
        .await
        .expect("bind proxy");
    let addr = bound.local_addrs()[0].1;
    let (handle, signal) = shutdown::channel();
    let serve = tokio::spawn(async move {
        bound.serve(signal, WAIT).await.expect("serve");
    });
    (addr, metrics, handle, serve)
}

async fn stop_proxy(handle: shutdown::ShutdownHandle, serve: JoinHandle<()>) {
    handle.trigger();
    tokio::time::timeout(WAIT + Duration::from_secs(5), serve)
        .await
        .expect("serve must finish")
        .expect("join");
}

async fn h2_connect(addr: SocketAddr) -> h2::client::SendRequest<Bytes> {
    let socket = TcpStream::connect(addr).await.expect("connect proxy");
    let (send, connection) = tokio::time::timeout(WAIT, h2::client::handshake(socket))
        .await
        .expect("h2 handshake in time")
        .expect("h2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    send
}

async fn grpc_open(
    client: &mut h2::client::SendRequest<Bytes>,
    path: &str,
) -> (h2::client::ResponseFuture, h2::SendStream<Bytes>) {
    let request = Request::builder()
        .method("POST")
        .uri(format!("https://grpc.test{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .expect("request");
    client.send_request(request, false).expect("send request")
}

/// One gRPC message: compression flag, 4-byte big-endian length, payload.
fn frame(payload: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0);
    out.extend_from_slice(&u32::try_from(payload.len()).expect("length").to_be_bytes());
    out.extend_from_slice(payload);
    Bytes::from(out)
}

/// Reads exactly one gRPC message, releasing flow-control capacity for every
/// DATA frame consumed.
async fn read_message(recv: &mut h2::RecvStream, buffer: &mut Vec<u8>) -> Vec<u8> {
    loop {
        if buffer.len() >= 5 {
            let len = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
            if buffer.len() >= 5 + len {
                let message = buffer[5..5 + len].to_vec();
                buffer.drain(..5 + len);
                return message;
            }
        }
        let chunk = tokio::time::timeout(WAIT, recv.data())
            .await
            .expect("DATA in time")
            .expect("stream ended before the message")
            .expect("DATA frame");
        recv.flow_control()
            .release_capacity(chunk.len())
            .expect("release capacity");
        buffer.extend_from_slice(&chunk);
    }
}

async fn drain(recv: &mut h2::RecvStream) {
    while let Some(chunk) = tokio::time::timeout(WAIT, recv.data())
        .await
        .expect("end in time")
    {
        let chunk = chunk.expect("DATA frame");
        let _ = recv.flow_control().release_capacity(chunk.len());
    }
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_bidi_answers_before_the_client_half_closes() {
    let origin = start_grpc_origin().await;
    let (addr, metrics, handle, serve) = start_proxy(proxy_with_h2_backend(origin.addr)).await;
    let mut client = h2_connect(addr).await;
    let (response, mut send) = grpc_open(&mut client, "/pkg.Service/Bidi").await;

    let first = frame(b"first-message");
    send_all(&mut send, &first).await.expect("first message");
    let response = tokio::time::timeout(WAIT, response)
        .await
        .expect("headers in time")
        .expect("headers");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/grpc");
    let mut recv = response.into_body();
    let mut buffer = Vec::new();
    assert_eq!(
        read_message(&mut recv, &mut buffer).await,
        b"first-message",
        "the answer must arrive while the request stream is still open"
    );
    let second = frame(b"second-message");
    send_all(&mut send, &second).await.expect("second message");
    assert_eq!(
        read_message(&mut recv, &mut buffer).await,
        b"second-message"
    );

    send.send_data(Bytes::new(), true).expect("half close");
    drain(&mut recv).await;
    let trailers = tokio::time::timeout(WAIT, recv.trailers())
        .await
        .expect("trailers in time")
        .expect("trailers")
        .expect("trailing headers");
    assert_eq!(trailers["grpc-status"], "0");
    assert_eq!(
        metrics.grpc_streams.load(Ordering::SeqCst),
        1,
        "the stream must have taken the pass-through"
    );
    assert_eq!(metrics.grpc_stream_errors.load(Ordering::SeqCst), 0);

    let recorded = seen(&origin);
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].path, "/pkg.Service/Bidi");
    assert_eq!(
        recorded[0].te, "trailers",
        "gRPC requires te: trailers towards the backend"
    );
    assert_eq!(recorded[0].content_type, "application/grpc");
    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_large_messages_cross_flow_control() {
    let origin = start_grpc_origin().await;
    let (addr, _metrics, handle, serve) = start_proxy(proxy_with_h2_backend(origin.addr)).await;
    let mut client = h2_connect(addr).await;
    let (response, mut send) = grpc_open(&mut client, "/pkg.Service/Bulk").await;
    // Bigger than the default 64 KiB stream window on both sides.
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let message = frame(&payload);
    let writer = tokio::spawn(async move {
        send_all(&mut send, &message).await.expect("bulk message");
        send.send_data(Bytes::new(), true).expect("half close");
    });
    let response = tokio::time::timeout(WAIT, response)
        .await
        .expect("headers in time")
        .expect("headers");
    let mut recv = response.into_body();
    let mut buffer = Vec::new();
    assert_eq!(
        read_message(&mut recv, &mut buffer).await,
        payload,
        "the whole message must cross both flow-control windows"
    );
    writer.await.expect("writer");
    drain(&mut recv).await;
    let trailers = recv.trailers().await.expect("trailers").expect("status");
    assert_eq!(trailers["grpc-status"], "0");
    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_concurrent_streams_share_one_backend_session() {
    let origin = start_grpc_origin().await;
    let (addr, _metrics, handle, serve) = start_proxy(proxy_with_h2_backend(origin.addr)).await;
    let mut one = h2_connect(addr).await;
    let mut two = h2_connect(addr).await;
    let (response_one, mut send_one) = grpc_open(&mut one, "/pkg.Service/Barrier").await;
    let (response_two, mut send_two) = grpc_open(&mut two, "/pkg.Service/Barrier").await;
    let message = frame(b"both");
    send_all(&mut send_one, &message).await.expect("one");
    send_all(&mut send_two, &message).await.expect("two");

    let response_one = tokio::time::timeout(WAIT, response_one)
        .await
        .expect("one in time")
        .expect("one");
    let response_two = tokio::time::timeout(WAIT, response_two)
        .await
        .expect("two in time")
        .expect("two");
    let mut recv_one = response_one.into_body();
    let mut recv_two = response_two.into_body();
    let mut buffer_one = Vec::new();
    let mut buffer_two = Vec::new();
    assert_eq!(read_message(&mut recv_one, &mut buffer_one).await, b"both");
    assert_eq!(read_message(&mut recv_two, &mut buffer_two).await, b"both");
    assert!(
        origin.max_inflight.load(Ordering::SeqCst) >= 2,
        "both streams must be inside the origin at the same time"
    );
    assert_eq!(
        origin.connections.load(Ordering::SeqCst),
        1,
        "the two streams must share one backend HTTP/2 session"
    );
    stop_proxy(handle, serve).await;
}

/// B8 over gRPC: the pass-through uses the same selection. A primary owns the
/// tier, the backup origin receives the streams only when every primary is
/// down, and the recovered primary takes them back. The two origins are told
/// apart by what each one saw.
#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_backup_serves_grpc_streams_when_every_primary_is_down() {
    let primary = start_grpc_origin().await;
    let backup = start_grpc_origin().await;
    let backend = Arc::new(
        ResolvedBackend::new(
            "api",
            vec![
                ResolvedServer {
                    addr: ServerAddr::Ip(primary.addr),
                    weight: 1,
                    backup: false,
                    priority: 0,
                },
                ResolvedServer {
                    addr: ServerAddr::Ip(backup.addr),
                    weight: 1,
                    backup: true,
                    priority: 0,
                },
            ],
            1,
            1,
        )
        .with_tls(backend_tls(&["h2"])),
    );
    let (addr, _metrics, handle, serve) =
        start_proxy(http_listener(primary.addr).with_backend(Arc::clone(&backend))).await;
    let mut client = h2_connect(addr).await;

    // One stream: one frame in, its echo out, half close, status trailers.
    async fn call(client: &mut h2::client::SendRequest<Bytes>, message: &'static [u8]) -> Vec<u8> {
        let (response, mut send) = grpc_open(client, "/pkg.Service/Echo").await;
        send_all(&mut send, &frame(message))
            .await
            .expect("request message");
        let response = tokio::time::timeout(WAIT, response)
            .await
            .expect("headers in time")
            .expect("headers");
        let mut recv = response.into_body();
        let mut buffer = Vec::new();
        let echo = read_message(&mut recv, &mut buffer).await;
        send.send_data(Bytes::new(), true).expect("half close");
        drain(&mut recv).await;
        let trailers = tokio::time::timeout(WAIT, recv.trailers())
            .await
            .expect("trailers in time")
            .expect("trailers")
            .expect("trailing headers");
        assert_eq!(trailers["grpc-status"], "0");
        echo
    }

    // A primary owns the tier.
    assert_eq!(call(&mut client, b"one").await, b"one");
    assert_eq!(seen(&primary).len(), 1);
    assert!(seen(&backup).is_empty());

    // Every primary down: the backup origin serves the stream.
    backend.balancer.report_fail(primary.addr);
    assert_eq!(call(&mut client, b"two").await, b"two");
    assert_eq!(
        seen(&backup).len(),
        1,
        "the backup must serve the gRPC stream"
    );
    assert_eq!(
        seen(&primary).len(),
        1,
        "a primary marked down receives nothing"
    );

    // The recovered primary takes it back.
    backend.balancer.report_ok(primary.addr);
    assert_eq!(call(&mut client, b"three").await, b"three");
    assert_eq!(seen(&primary).len(), 2);
    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_silent_stream_is_cut_by_the_idle_timeout() {
    let origin = start_grpc_origin().await;
    let mut cfg = proxy_with_h2_backend(origin.addr);
    cfg.idle_timeout = Duration::from_millis(200);
    let (addr, metrics, handle, serve) = start_proxy(cfg).await;
    let mut client = h2_connect(addr).await;
    let (response, _send) = grpc_open(&mut client, "/pkg.Service/Bidi").await;
    let response = tokio::time::timeout(WAIT, response)
        .await
        .expect("headers in time")
        .expect("headers");
    let mut recv = response.into_body();
    let outcome = tokio::time::timeout(Duration::from_secs(3), recv.data())
        .await
        .expect("the idle window must cut the stream, not hang");
    assert!(
        matches!(outcome, Some(Err(_)) | None),
        "a silent stream must end explicitly, got {outcome:?}"
    );
    assert!(
        metrics.idle_timeouts.load(Ordering::SeqCst) >= 1,
        "the cut must be counted as inactivity"
    );
    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_max_stream_duration_ends_with_deadline_status() {
    let origin = start_grpc_origin().await;
    let mut cfg = proxy_with_h2_backend(origin.addr);
    cfg.max_stream_duration = Duration::from_millis(300);
    let (addr, metrics, handle, serve) = start_proxy(cfg).await;
    let mut client = h2_connect(addr).await;
    let (response, _send) = grpc_open(&mut client, "/pkg.Service/Bidi").await;
    let response = tokio::time::timeout(WAIT, response)
        .await
        .expect("headers in time")
        .expect("headers");
    let mut recv = response.into_body();
    drain(&mut recv).await;
    let trailers = tokio::time::timeout(WAIT, recv.trailers())
        .await
        .expect("trailers in time")
        .expect("trailers")
        .expect("the deadline status must be trailers");
    assert_eq!(
        trailers["grpc-status"], "4",
        "a stream cut by max_stream_duration must report DEADLINE_EXCEEDED"
    );
    assert_eq!(trailers["grpc-message"], "max stream duration exceeded");
    assert_eq!(metrics.grpc_streams.load(Ordering::SeqCst), 1);
    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_forwarded_headers_cross_the_pass_through() {
    let origin = start_grpc_origin().await;
    let mut cfg = proxy_with_h2_backend(origin.addr);
    cfg.forwarded_headers = ForwardedMode::Append;
    let (addr, _metrics, handle, serve) = start_proxy(cfg).await;
    let mut client = h2_connect(addr).await;
    let (response, mut send) = grpc_open(&mut client, "/pkg.Service/Bidi").await;
    send_all(&mut send, &frame(b"headers")).await.expect("send");
    let response = tokio::time::timeout(WAIT, response)
        .await
        .expect("headers in time")
        .expect("headers");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "local answer: headers {:?}",
        response.headers()
    );
    let mut recv = response.into_body();
    let mut buffer = Vec::new();
    assert_eq!(read_message(&mut recv, &mut buffer).await, b"headers");
    let recorded = seen(&origin);
    assert_eq!(
        recorded[0].forwarded_for, "127.0.0.1",
        "the same forwarded-headers policy as h1 must apply to a gRPC stream"
    );
    stop_proxy(handle, serve).await;
}

/// End of a chunked body (or of a request without one) once the head and the
/// `0` chunk are present.
fn find_body_end(bytes: &[u8]) -> Option<usize> {
    let head_end = bytes.windows(4).position(|window| window == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&bytes[..head_end]).to_ascii_lowercase();
    if head.contains("transfer-encoding: chunked") {
        return bytes[head_end..]
            .windows(7)
            .position(|window| window.eq_ignore_ascii_case(b"\r\n0\r\n\r\n"))
            .map(|pos| head_end + pos + 7);
    }
    head.lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .map(|length| head_end + length)
        .or(Some(head_end))
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_without_an_h2_backend_keeps_the_h1_translation() {
    // A plain h1 origin: the pass-through must not apply, and the existing
    // translation must still answer (never a half-broken h2 exchange).
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind h1");
    let origin = listener.local_addr().expect("h1 addr");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                // Read the whole chunked gRPC body before answering: a
                // half-read request would reset the connection under the
                // response.
                let mut received = Vec::new();
                let mut buffer = [0u8; 8192];
                loop {
                    match socket.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => received.extend_from_slice(&buffer[..n]),
                    }
                    if let Some(end) = find_body_end(&received) {
                        let _ = end;
                        break;
                    }
                }
                let response = b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 10\r\nconnection: close\r\n\r\nh1-backend";
                let _ = tokio::io::AsyncWriteExt::write_all(&mut socket, response).await;
                let _ = tokio::io::AsyncWriteExt::shutdown(&mut socket).await;
            });
        }
    });
    let (addr, _metrics, handle, serve) = start_proxy(http_listener(origin)).await;
    let mut client = h2_connect(addr).await;
    let (response, mut send) = grpc_open(&mut client, "/pkg.Service/Unary").await;
    send_all(&mut send, &frame(b"one")).await.expect("send");
    send.send_data(Bytes::new(), true).expect("half close");
    let response = tokio::time::timeout(WAIT, response)
        .await
        .expect("headers in time")
        .expect("headers");
    assert_eq!(response.status(), StatusCode::OK);
    let mut recv = response.into_body();
    let mut body = Vec::new();
    while let Some(chunk) = tokio::time::timeout(WAIT, recv.data())
        .await
        .expect("body in time")
    {
        let chunk = chunk.expect("body chunk");
        let _ = recv.flow_control().release_capacity(chunk.len());
        body.extend_from_slice(&chunk);
    }
    assert_eq!(body, b"h1-backend");
    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_dead_backend_is_an_explicit_502() {
    // A port nobody listens on: the TLS handshake cannot even start.
    let dead = TcpListener::bind("127.0.0.1:0").await.expect("bind dead");
    let dead_addr = dead.local_addr().expect("dead addr");
    drop(dead);
    let (addr, metrics, handle, serve) = start_proxy(proxy_with_h2_backend(dead_addr)).await;
    let mut client = h2_connect(addr).await;
    let (response, mut send) = grpc_open(&mut client, "/pkg.Service/Bidi").await;
    // The dead backend makes the proxy answer 502 and reset the stream; under
    // nextest's scheduling that reset can reach the client before this first
    // DATA frame is flushed. The contract under test is the explicit 502 (and
    // the counted dial), not a successful send into a stream the server is
    // already closing.
    if let Err(err) = send_all(&mut send, &frame(b"lost")).await {
        eprintln!("first DATA frame reached a stream already closed by the 502: {err:?}");
    }
    let response = tokio::time::timeout(WAIT, response)
        .await
        .expect("answer in time")
        .expect("502 response");
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(
        metrics.connect_failures.load(Ordering::SeqCst) >= 1,
        "the failed dial must be counted"
    );
    stop_proxy(handle, serve).await;
}
