//! WebSockets over HTTP/2 (RFC 8441 extended CONNECT) with **real sockets**:
//! a real `h2` client to the proxy and a real HTTP/1.1 WebSocket origin behind
//! it. These journeys prove the tunnel both ways, the h2 `200` success
//! (never a `101`), the relayed refusal, the routing decisions applied by the
//! h1 engine, the explicit `501` for unknown protocols and the idle cut.
//!
//! The client advertises nothing special: it sends `CONNECT` with
//! `:protocol = websocket`, exactly what a browser or `grpcurl`-style client
//! does after the proxy's SETTINGS say extended CONNECT is understood.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use eqproxy_core::rules::RuleSpec;
use eqproxy_core::{Metrics, shutdown};
use eqproxy_net::{BoundProxy, ProxyMode, ResolvedListener, ResolvedRoute, RouteAction, bind};

const WAIT: Duration = Duration::from_secs(10);

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

fn listener_with_rules(server: SocketAddr, routes: Vec<ResolvedRoute>) -> ResolvedListener {
    http_listener(server).with_routes(routes)
}

/// Listener with a short idle window, for the silent-tunnel cut.
fn listener_with_idle(server: SocketAddr, idle: Duration) -> ResolvedListener {
    ResolvedListener::new(
        "web",
        "127.0.0.1:0".parse().expect("addr"),
        "api",
        server,
        ProxyMode::Http,
        64,
        Duration::from_secs(2),
        idle,
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
}

async fn start_proxy(
    cfg: ResolvedListener,
    metrics: Arc<Metrics>,
) -> (SocketAddr, shutdown::ShutdownHandle, JoinHandle<()>) {
    let bound: BoundProxy = bind(vec![cfg], Arc::clone(&metrics))
        .await
        .expect("bind proxy");
    let addr = bound.local_addrs()[0].1;
    let (handle, signal) = shutdown::channel();
    let serve = tokio::spawn(async move {
        bound.serve(signal, WAIT).await.expect("serve");
    });
    (addr, handle, serve)
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

/// What the origin recorded about the handshake it received.
#[derive(Default)]
struct Seen {
    head: std::sync::Mutex<String>,
    connections: AtomicUsize,
    client_closed: AtomicBool,
}

/// A real WebSocket origin: validates the h1 upgrade, answers `101` and then
/// echoes bytes until either side closes.
async fn start_ws_origin(protocol: Option<&'static str>) -> (SocketAddr, Arc<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("addr origin");
    let seen = Arc::new(Seen::default());
    let recorded = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            recorded.connections.fetch_add(1, Ordering::Relaxed);
            let recorded = Arc::clone(&recorded);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let mut total = 0usize;
                let head_end = loop {
                    match socket.read(&mut buf[total..]).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => total += n,
                    }
                    if let Some(pos) = buf[..total].windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                    if total == buf.len() {
                        return;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                *recorded.head.lock().expect("lock") = head.clone();
                let lower = head.to_ascii_lowercase();
                assert!(
                    lower.starts_with("get /")
                        && lower.contains("\r\nupgrade: websocket\r\n")
                        && lower.contains("\r\nconnection: upgrade\r\n")
                        && lower.contains("\r\nsec-websocket-version: 13\r\n")
                        && lower.contains("\r\nsec-websocket-key: "),
                    "origin received an unshaped handshake: {head}"
                );
                let mut response = String::from(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
                );
                if let Some(protocol) = protocol {
                    response.push_str(&format!("Sec-WebSocket-Protocol: {protocol}\r\n"));
                }
                response.push_str("\r\n");
                if socket.write_all(response.as_bytes()).await.is_err() {
                    return;
                }
                // Echo everything until the peer closes.
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => {
                            recorded.client_closed.store(true, Ordering::Relaxed);
                            return;
                        }
                        Ok(n) => {
                            if socket.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, seen)
}

/// An origin that refuses the switch with a normal HTTP response.
async fn start_refusing_origin(status: &'static str, body: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("addr origin");
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let response = response.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let mut total = 0usize;
                loop {
                    match socket.read(&mut buf[total..]).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => total += n,
                    }
                    if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    addr
}

/// Starts the extended CONNECT: `CONNECT` + `:protocol = websocket`.
async fn open_ws(
    send: &mut h2::client::SendRequest<Bytes>,
    uri: &str,
    protocol: &'static str,
    extra: &[(&'static str, &'static str)],
) -> (http::Response<h2::RecvStream>, h2::SendStream<Bytes>) {
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .body(())
        .expect("request");
    for (name, value) in extra {
        request
            .headers_mut()
            .insert(*name, value.parse().expect("header value"));
    }
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static(protocol));
    let (response, stream) = send.send_request(request, false).expect("send CONNECT");
    let response = tokio::time::timeout(WAIT, response)
        .await
        .expect("response in time")
        .expect("response");
    (response, stream)
}

async fn next_chunk(body: &mut h2::RecvStream) -> Option<Bytes> {
    let chunk = tokio::time::timeout(WAIT, body.data())
        .await
        .expect("DATA in time");
    chunk.map(|chunk| {
        let chunk = chunk.expect("DATA frame");
        let _ = body.flow_control().release_capacity(chunk.len());
        chunk
    })
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_extended_connect_tunnels_bytes_both_ways() {
    let (origin, seen) = start_ws_origin(Some("chat")).await;
    let metrics = Arc::new(Metrics::default());
    let (addr, handle, serve) = start_proxy(http_listener(origin), Arc::clone(&metrics)).await;
    let mut send = h2_connect(addr).await;

    let (response, mut upstream) = open_ws(
        &mut send,
        "http://ws.test/chat?room=7",
        "websocket",
        &[("sec-websocket-protocol", "chat, superchat")],
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "RFC 8441 answers 200, never 101"
    );
    let headers = response.headers().clone();
    assert_eq!(
        headers.get("sec-websocket-protocol").expect("protocol"),
        "chat"
    );
    assert!(
        headers.get("sec-websocket-accept").is_none(),
        "the internal handshake digest is not the client's business"
    );
    assert!(
        headers.get("upgrade").is_none() && headers.get("connection").is_none(),
        "h1 upgrade headers do not cross into h2"
    );

    // The origin saw the request reshaped as a real h1 WebSocket handshake.
    let head = seen.head.lock().expect("lock").to_ascii_lowercase();
    assert!(head.starts_with("get /chat?room=7 http/1.1\r\n"), "{head}");
    assert!(head.contains("\r\nhost: ws.test\r\n"), "{head}");
    assert!(
        head.contains("\r\nsec-websocket-protocol: chat, superchat\r\n"),
        "{head}"
    );
    assert!(head.contains("\r\nsec-websocket-key: "), "{head}");

    // Client -> backend -> client, twice, on the same stream.
    let mut body = response.into_body();
    for message in [b"hello".as_slice(), b"world".as_slice()] {
        upstream
            .send_data(Bytes::copy_from_slice(message), false)
            .expect("send DATA");
        let echoed = next_chunk(&mut body).await.expect("an echoed chunk");
        assert_eq!(&echoed[..], message);
    }
    assert_eq!(metrics.snapshot().ws_tunnels, 1);
    assert_eq!(metrics.snapshot().ws_failures, 0);

    // A clean client half-close ends the backend socket.
    upstream.send_data(Bytes::new(), true).expect("end stream");
    let deadline = tokio::time::Instant::now() + WAIT;
    while !seen.client_closed.load(Ordering::Relaxed) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        seen.client_closed.load(Ordering::Relaxed),
        "the origin must see the tunnel close"
    );

    stop_proxy(handle, serve).await;
}

#[cfg_attr(miri, ignore = "needs TCP sockets")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_refused_handshake_is_relayed_as_a_normal_response() {
    let origin = start_refusing_origin("404 Not Found", "no tunnel here").await;
    let metrics = Arc::new(Metrics::default());
    let (addr, handle, serve) = start_proxy(http_listener(origin), Arc::clone(&metrics)).await;
    let mut send = h2_connect(addr).await;

    let (response, _stream) = open_ws(&mut send, "http://ws.test/chat", "websocket", &[]).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = next_chunk(&mut body).await {
        bytes.extend_from_slice(&chunk);
    }
    assert_eq!(bytes, b"no tunnel here");
    assert_eq!(metrics.snapshot().ws_tunnels, 0);
    assert_eq!(metrics.snapshot().ws_failures, 1);

    stop_proxy(handle, serve).await;
}

#[cfg_attr(miri, ignore = "needs TCP sockets")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_route_denial_answers_before_any_backend_contact() {
    let (origin, seen) = start_ws_origin(None).await;
    let rule = ResolvedRoute {
        rule: eqproxy_core::rules::Rule::compile(&RuleSpec {
            name: "block-chat".to_owned(),
            path_prefix: Some("/blocked".to_owned()),
            ..RuleSpec::default()
        })
        .expect("rule"),
        action: RouteAction::Direct {
            status: 403,
            content_type: "text/plain".to_owned(),
            body: "route says no".to_owned(),
        },
        headers: None,
    };
    let metrics = Arc::new(Metrics::default());
    let (addr, handle, serve) = start_proxy(
        listener_with_rules(origin, vec![rule]),
        Arc::clone(&metrics),
    )
    .await;
    let mut send = h2_connect(addr).await;

    let (response, _stream) = open_ws(&mut send, "http://ws.test/blocked", "websocket", &[]).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = next_chunk(&mut body).await {
        bytes.extend_from_slice(&chunk);
    }
    assert_eq!(bytes, b"route says no");
    assert_eq!(
        seen.connections.load(Ordering::Relaxed),
        0,
        "a locally answered rule never reaches the backend"
    );

    stop_proxy(handle, serve).await;
}

#[cfg_attr(miri, ignore = "needs TCP sockets")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_unknown_protocol_is_refused_with_501() {
    let (origin, seen) = start_ws_origin(None).await;
    let metrics = Arc::new(Metrics::default());
    let (addr, handle, serve) = start_proxy(http_listener(origin), Arc::clone(&metrics)).await;
    let mut send = h2_connect(addr).await;

    let (response, _stream) =
        open_ws(&mut send, "http://ws.test/chat", "not-a-protocol", &[]).await;
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(seen.connections.load(Ordering::Relaxed), 0);

    stop_proxy(handle, serve).await;
}

#[cfg_attr(miri, ignore = "needs TCP sockets")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_classic_connect_keeps_its_501() {
    let (origin, seen) = start_ws_origin(None).await;
    let metrics = Arc::new(Metrics::default());
    let (addr, handle, serve) = start_proxy(http_listener(origin), Arc::clone(&metrics)).await;
    let mut send = h2_connect(addr).await;

    // Authority-form CONNECT, no `:protocol`: the h2 tunnel that this slice
    // does not implement stays an explicit 501.
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri("ws.test:80")
        .body(())
        .expect("request");
    let (response, _stream) = send.send_request(request, true).expect("send CONNECT");
    let response = tokio::time::timeout(WAIT, response)
        .await
        .expect("response in time")
        .expect("response");
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(
        seen.connections.load(Ordering::Relaxed),
        0,
        "a refused CONNECT never reaches the backend"
    );

    stop_proxy(handle, serve).await;
}

#[cfg_attr(miri, ignore = "needs TCP sockets")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_silent_tunnel_is_cut_by_the_idle_timeout() {
    let (origin, seen) = start_ws_origin(None).await;
    let metrics = Arc::new(Metrics::default());
    let (addr, handle, serve) = start_proxy(
        listener_with_idle(origin, Duration::from_millis(250)),
        Arc::clone(&metrics),
    )
    .await;
    let mut send = h2_connect(addr).await;

    let (response, _stream) = open_ws(&mut send, "http://ws.test/chat", "websocket", &[]).await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    // No DATA for longer than the idle window: the tunnel is cut — by the
    // proxy's own pump or by the h1 tunnel it is attached to, whichever
    // reaches the cap first. What matters is that the stream ends instead of
    // staying open forever, and that the origin sees its socket close.
    loop {
        match tokio::time::timeout(Duration::from_secs(3), body.data()).await {
            Ok(Some(Ok(chunk))) if chunk.is_empty() => continue,
            Ok(Some(Ok(_))) => panic!("a silent tunnel must not receive payload"),
            Ok(None) | Ok(Some(Err(_))) | Err(_) => break,
        }
    }
    let deadline = tokio::time::Instant::now() + WAIT;
    while !seen.client_closed.load(Ordering::Relaxed) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        seen.client_closed.load(Ordering::Relaxed),
        "the origin must see the tunnel close"
    );

    stop_proxy(handle, serve).await;
}
