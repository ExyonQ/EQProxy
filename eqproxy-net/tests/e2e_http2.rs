//! HTTP/2 E2E tests with **real sockets and a real h2 client** (the same
//! `h2` implementation a production client uses, over loopback TCP).
//!
//! These journeys prove the behaviour the roadmap asks for: h2c with prior
//! knowledge, TLS with ALPN `h2`, multiplexed streams advancing in parallel,
//! request bodies without `content-length` translated to `chunked` upstream,
//! chunked responses and trailers translated back into DATA/trailing
//! HEADERS, and the explicit failures (truncated body, dead backend) never
//! turning into a clean-looking success.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Request, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use eqproxy_core::rules::{Rule, RuleSpec};
use eqproxy_core::{Metrics, shutdown};
use eqproxy_net::tls::{self, TlsVersion};
use eqproxy_net::{
    BoundProxy, ProxyMode, ResolvedHeaders, ResolvedListener, ResolvedRoute, RouteAction, bind,
};

const WAIT: Duration = Duration::from_secs(10);
const CERT: &[u8] = include_bytes!("fixtures/cert.pem");
const KEY: &[u8] = include_bytes!("fixtures/key.pem");

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

async fn start_proxy(
    cfg: ResolvedListener,
) -> (SocketAddr, shutdown::ShutdownHandle, JoinHandle<()>) {
    let metrics = Arc::new(Metrics::default());
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
    // Established h2 connections drain within the shutdown grace, exactly
    // like keep-alive h1 ones: give the harness a margin over the grace.
    tokio::time::timeout(WAIT + Duration::from_secs(5), serve)
        .await
        .expect("serve must finish")
        .expect("join");
}

/// Real h2 client over a plaintext socket (h2c with prior knowledge).
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

/// Collects one full response: status, headers, decoded body and trailers.
async fn read_response(
    response: http::Response<h2::RecvStream>,
) -> (StatusCode, HeaderMap, Vec<u8>, Option<HeaderMap>) {
    let status = response.status();
    let headers = response.headers().clone();
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("DATA frame");
        let _ = body.flow_control().release_capacity(chunk.len());
        bytes.extend_from_slice(&chunk);
    }
    let trailers = body.trailers().await.expect("trailers");
    (status, headers, bytes, trailers)
}

/// GET through the proxy on an open h2 connection.
async fn h2_get(
    send: &mut h2::client::SendRequest<Bytes>,
    path: &str,
) -> http::Response<h2::RecvStream> {
    let request = Request::builder()
        .uri(format!("https://h2.test{path}"))
        .body(())
        .expect("request");
    let (response, _stream) = send.send_request(request, true).expect("send request");
    tokio::time::timeout(WAIT, response)
        .await
        .expect("response in time")
        .expect("response")
}

/// Origin that reads one request and answers with a fixed raw h1 response.
async fn start_raw_origin(response: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("addr origin");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
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
                let _ = socket.write_all(response).await;
            });
        }
    });
    addr
}

/// Origin that records the exact request head it received (so the test can
/// assert what the translation sent upstream) and answers with `body`.
async fn start_recording_origin(body: &'static str) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("addr origin");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
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
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
                let chunked = head.contains("transfer-encoding: chunked");
                let needed = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if needed > 0 {
                    while total < head_end + needed {
                        match socket.read(&mut buf[total..]).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => total += n,
                        }
                    }
                }
                if chunked {
                    // Up to and including the terminal chunk.
                    while !buf[..total].ends_with(b"0\r\n\r\n") {
                        match socket.read(&mut buf[total..]).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => total += n,
                        }
                        if total == buf.len() {
                            return;
                        }
                    }
                }
                // Whole message (head + body) so the test can assert the
                // translated framing and payload exactly as they went out.
                recorded
                    .lock()
                    .expect("record lock")
                    .push(String::from_utf8_lossy(&buf[..total]).into_owned());
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    (addr, seen)
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2c_multiplexes_streams_that_must_advance_together() {
    // The origin only answers once three streams are inside it at the same
    // time: a proxy that serializes streams can never finish the requests.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let origin = listener.local_addr().expect("addr origin");
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
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
                barrier.wait().await;
                let response =
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = socket.write_all(response).await;
            });
        }
    });

    let (proxy, handle, serve) = start_proxy(http_listener(origin)).await;
    let mut send = h2_connect(proxy).await;
    let mut waiting = Vec::new();
    for index in 0..3 {
        let request = Request::builder()
            .uri(format!("https://h2.test/stream/{index}"))
            .body(())
            .expect("request");
        let (response, _stream) = send.send_request(request, true).expect("send");
        waiting.push(response);
    }
    for response in waiting {
        let response = tokio::time::timeout(WAIT, response)
            .await
            .expect("all three streams in flight at once (serialized proxy would deadlock)")
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let (status, _headers, body, _trailers) = read_response(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"ok");
    }
    drop(send);
    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_request_without_content_length_goes_upstream_as_chunked() {
    let (origin, seen) = start_recording_origin("received").await;
    let (proxy, handle, serve) = start_proxy(http_listener(origin)).await;
    let mut send = h2_connect(proxy).await;

    let request = Request::builder()
        .method("POST")
        .uri("https://h2.test/upload")
        .body(())
        .expect("request");
    let (response, mut stream) = send.send_request(request, false).expect("send");
    stream
        .send_data(Bytes::from_static(b"chunk-me"), false)
        .expect("data");
    stream.send_data(Bytes::new(), true).expect("end");

    let response = tokio::time::timeout(WAIT, response)
        .await
        .expect("response in time")
        .expect("response");
    let (status, headers, body, _trailers) = read_response(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"received");
    assert!(
        headers.get("transfer-encoding").is_none(),
        "h2 responses never carry chunked framing"
    );

    let head = {
        let heads = seen.lock().expect("record lock");
        heads.first().cloned().expect("upstream request recorded")
    };
    assert!(
        head.contains("transfer-encoding: chunked"),
        "h2 body without content-length must become chunked upstream: {head}"
    );
    assert!(!head.contains("content-length"), "{head}");
    assert!(head.contains("chunk-me"), "body not forwarded: {head}");
    drop(send);
    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_decodes_chunked_responses_and_keeps_trailers() {
    let origin = start_raw_origin(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Origin: h1\r\n\r\n\
          5\r\nhello\r\n6\r\n world\r\n0\r\nx-checksum: abc123\r\n\r\n",
    )
    .await;
    let (proxy, handle, serve) = start_proxy(http_listener(origin)).await;
    let mut send = h2_connect(proxy).await;

    let response = tokio::time::timeout(WAIT, h2_get(&mut send, "/chunked"))
        .await
        .expect("response in time");
    let (status, headers, body, trailers) = read_response(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"hello world", "chunk framing must not leak into h2");
    assert_eq!(headers.get("x-origin").expect("origin header"), "h1");
    assert!(
        headers.get("transfer-encoding").is_none(),
        "the h2 side must never see chunked framing"
    );
    let trailers = trailers.expect("h1 trailers must arrive as h2 trailers");
    assert_eq!(trailers.get("x-checksum").expect("trailer"), "abc123");
    drop(send);
    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_truncated_backend_body_resets_the_stream() {
    // Declares 10 bytes, sends 3 and closes: the client must see a reset,
    // never a clean end of a short body.
    let origin = start_raw_origin(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc").await;
    let (proxy, handle, serve) = start_proxy(http_listener(origin)).await;
    let mut send = h2_connect(proxy).await;

    let request = Request::builder()
        .uri("https://h2.test/truncated")
        .body(())
        .expect("request");
    let (response, _stream) = send.send_request(request, true).expect("send request");
    let response = tokio::time::timeout(WAIT, response)
        .await
        .expect("request must complete with an explicit failure, not hang");
    // Either the response fails to materialise or its body errors; a clean
    // 3-byte body would be a silent truncation.
    match response {
        Err(_) => {}
        Ok(response) => {
            let status = response.status();
            let mut body = response.into_body();
            let mut failed = status.is_server_error();
            let mut collected = Vec::new();
            while let Some(chunk) = body.data().await {
                match chunk {
                    Ok(chunk) => {
                        let _ = body.flow_control().release_capacity(chunk.len());
                        collected.extend_from_slice(&chunk);
                    }
                    Err(_) => {
                        failed = true;
                        break;
                    }
                }
            }
            assert!(
                failed,
                "a truncated body must not look complete: status {status}, body {collected:?}"
            );
        }
    }
    drop(send);
    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_dead_backend_answers_502_and_a_redirect_answers_locally() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let dead = listener.local_addr().expect("addr");
    drop(listener);
    let (proxy, handle, serve) = start_proxy(http_listener(dead)).await;
    let mut send = h2_connect(proxy).await;

    let response = tokio::time::timeout(WAIT, h2_get(&mut send, "/down"))
        .await
        .expect("response in time");
    let (status, _headers, _body, _trailers) = read_response(response).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "a dead backend is a 502");
    stop_proxy(handle, serve).await;

    // Local answers go through the same exchange engine: a rule redirect must
    // reach an h2 client with its Location intact and no backend contact.
    let routes = vec![ResolvedRoute {
        rule: Rule::compile(&RuleSpec {
            name: "canonical".to_owned(),
            path_prefix: Some("/old".to_owned()),
            ..RuleSpec::default()
        })
        .expect("rule compiles"),
        action: RouteAction::Redirect {
            status: 308,
            location: "https://$host$request_uri".to_owned(),
        },
        headers: Some(ResolvedHeaders {
            set: Vec::new(),
            add: Vec::new(),
            del: Vec::new(),
            response: Vec::new(),
            cors: None,
            rate_limit: None,
            auth: None,
            mirror: None,
        }),
    }];
    let cfg = http_listener(dead).with_routes(routes);
    let (proxy, handle, serve) = start_proxy(cfg).await;
    let mut send = h2_connect(proxy).await;
    let response = tokio::time::timeout(WAIT, h2_get(&mut send, "/old/page"))
        .await
        .expect("response in time");
    let (status, headers, _body, _trailers) = read_response(response).await;
    assert_eq!(status, StatusCode::PERMANENT_REDIRECT);
    assert_eq!(
        headers.get("location").expect("location"),
        "https://h2.test/old/page"
    );
    drop(send);
    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_alpn_h2_terminates_a_real_http2_connection() {
    let origin = start_raw_origin(
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ntls-h2",
    )
    .await;
    let server = tls::server_config(
        CERT,
        KEY,
        None,
        &["h2".to_owned(), "http/1.1".to_owned()],
        TlsVersion::V1_2,
    )
    .expect("server tls");
    let cfg = http_listener(origin).with_server_tls(server);
    let (proxy, handle, serve) = start_proxy(cfg).await;

    let client = tls::client_config(
        Some(CERT),
        true,
        Some("localhost"),
        &["h2".to_owned()],
        TlsVersion::V1_2,
    )
    .expect("client tls");
    let name = tls::server_name_for(&client, proxy);
    let stream = client
        .connector
        .connect(name, TcpStream::connect(proxy).await.expect("connect"))
        .await
        .expect("TLS handshake");
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(&b"h2"[..]),
        "the listener must negotiate h2 when the client offers it"
    );
    let (mut send, connection) = tokio::time::timeout(WAIT, h2::client::handshake(stream))
        .await
        .expect("h2 handshake in time")
        .expect("h2 over TLS");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = tokio::time::timeout(WAIT, h2_get(&mut send, "/secure"))
        .await
        .expect("response in time");
    let (status, _headers, body, _trailers) = read_response(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"tls-h2");
    drop(send);
    stop_proxy(handle, serve).await;
}
