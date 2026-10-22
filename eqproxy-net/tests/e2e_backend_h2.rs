//! HTTP/2 **to the backend** (B-H1/B-N1/B-I1/B-E2) with real sockets: a real
//! TLS backend that negotiates ALPN `h2` and speaks the `h2` server protocol,
//! and a real proxy in front of it.
//!
//! The journeys prove what the opt-in promises: an h1 client reaches an h2
//! backend through a genuine h2 session (the backend sees HTTP/2 frames, not
//! h1 bytes), an h2 client reaches it end to end, bodies and trailers cross in
//! both directions, one pooled backend session serves consecutive requests,
//! `HEAD`/`content-length` stay honest, and a backend that cannot negotiate
//! `h2` is an explicit `502` instead of garbage on the wire.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Request, StatusCode};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use eqproxy_core::Metrics;
use eqproxy_core::shutdown;
use eqproxy_net::tls::{self, TlsVersion};
use eqproxy_net::{BoundProxy, ProxyMode, ResolvedBackend, ResolvedListener, bind};

const WAIT: Duration = Duration::from_secs(10);
const CERT: &[u8] = include_bytes!("fixtures/cert.pem");
const KEY: &[u8] = include_bytes!("fixtures/key.pem");

/// Everything the h2 backend saw for one stream.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    authority: String,
    version: http::Version,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    trailers: Option<HeaderMap>,
}

/// A real h2-over-TLS origin. `connections` counts accepted TCP sockets, so a
/// test can prove the proxy reused one h2 session for consecutive requests.
struct Origin {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

/// Snapshot of what the backend received (the guard never crosses an await).
fn seen_requests(origin: &Origin) -> Vec<Seen> {
    origin.seen.lock().expect("seen lock").clone()
}

fn h2_listener(server: SocketAddr) -> ResolvedListener {
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

/// Backend TLS trusting the test CA, offering exactly the protocols a test
/// needs (the proxy's opt-in lives in this list).
fn backend_tls(alpn: &[&str]) -> tls::ClientTls {
    let alpn: Vec<String> = alpn.iter().map(|proto| (*proto).to_owned()).collect();
    tls::client_config(Some(CERT), true, Some("localhost"), &alpn, TlsVersion::V1_2)
        .expect("backend tls")
}

/// Starts the h2 origin. Its answers are chosen by path so one server serves
/// every journey:
/// - `/echo`: 200, body = request body, `content-length` set.
/// - `/trailers`: 200 chunked with a trailing header.
/// - `/teapot`: 418 with a short body.
/// - `/head`: 200 with `content-length: 5` and no body (a HEAD answer).
async fn start_h2_origin(alpn: &[&str]) -> Origin {
    let server = tls::server_config(CERT, KEY, None, &alpn_strings(alpn), TlsVersion::V1_2)
        .expect("server tls");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("addr origin");
    let connections = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let accepted = Arc::clone(&connections);
    let recorded = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            accepted.fetch_add(1, Ordering::Relaxed);
            let acceptor = server.clone();
            let recorded = Arc::clone(&recorded);
            tokio::spawn(async move {
                // A refused handshake (no common ALPN) is a legit journey:
                // the negative test relies on the proxy failing here.
                let Ok(stream) = acceptor.acceptor.accept(socket).await else {
                    return;
                };
                assert_eq!(
                    stream.get_ref().1.alpn_protocol(),
                    Some(&b"h2"[..]),
                    "the proxy must negotiate h2 with this backend"
                );
                let mut connection = h2::server::handshake(stream)
                    .await
                    .expect("h2 server handshake");
                while let Some(request) = connection.accept().await {
                    let Ok((request, respond)) = request else {
                        break;
                    };
                    let recorded = Arc::clone(&recorded);
                    tokio::spawn(async move {
                        answer(request, respond, recorded).await;
                    });
                }
            });
        }
    });
    Origin {
        addr,
        connections,
        seen,
    }
}

fn alpn_strings(alpn: &[&str]) -> Vec<String> {
    alpn.iter().map(|proto| (*proto).to_owned()).collect()
}

async fn answer(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    seen: Arc<Mutex<Vec<Seen>>>,
) {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let authority = request
        .uri()
        .authority()
        .map(|value| value.to_string())
        .unwrap_or_default();
    let version = request.version();
    let headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect();
    let mut body = request.into_body();
    let mut payload = Vec::new();
    while let Some(chunk) = body.data().await {
        let Ok(chunk) = chunk else { return };
        payload.extend_from_slice(&chunk);
        let _ = body.flow_control().release_capacity(chunk.len());
    }
    let trailers = body.trailers().await.ok().flatten();
    seen.lock().expect("seen lock").push(Seen {
        method: method.to_string(),
        path: path.clone(),
        authority,
        version,
        headers,
        body: payload.clone(),
        trailers,
    });

    let body: Vec<u8> = match path.as_str() {
        "/teapot" => b"short and stout".to_vec(),
        // `HEAD` semantics: a declared length, no body bytes.
        "/head" => Vec::new(),
        _ => payload.clone(),
    };
    let declared = if path == "/head" { 5usize } else { body.len() };
    let mut out = http::Response::new(());
    *out.status_mut() = if path == "/teapot" {
        StatusCode::IM_A_TEAPOT
    } else {
        StatusCode::OK
    };
    out.headers_mut()
        .insert("x-origin", http::HeaderValue::from_static("h2"));
    if path != "/trailers" {
        out.headers_mut().insert(
            "content-length",
            http::HeaderValue::from_str(&declared.to_string()).expect("length header"),
        );
    }
    let mut send = match respond.send_response(out, false) {
        Ok(send) => send,
        Err(_) => return,
    };
    if path == "/trailers" {
        // A chunked h2 answer: DATA followed by trailing HEADERS.
        let _ = send.send_data(Bytes::from_static(b"trailed"), false);
        let mut trailers = HeaderMap::new();
        trailers.insert("x-checksum", http::HeaderValue::from_static("abc123"));
        let _ = send.send_trailers(trailers);
        return;
    }
    let _ = send.send_data(Bytes::from(body), true);
}

/// One response read from the h1 side: status line, headers and body.
struct H1Response {
    status: u16,
    head: String,
    body: Vec<u8>,
    trailer: String,
}

async fn read_h1_response(reader: &mut BufReader<TcpStream>, head_request: bool) -> H1Response {
    let mut head = String::new();
    let mut status = 0u16;
    loop {
        let mut line = String::new();
        let got = tokio::time::timeout(WAIT, reader.read_line(&mut line))
            .await
            .expect("head line in time")
            .expect("head line");
        assert!(got > 0, "EOF inside the response head");
        if line == "\r\n" {
            break;
        }
        if status == 0 {
            status = line
                .split_whitespace()
                .nth(1)
                .and_then(|code| code.parse().ok())
                .expect("status code");
        }
        head.push_str(&line);
    }
    let lower = head.to_ascii_lowercase();
    let length = lower
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|_| !head_request);
    let chunked = lower.contains("transfer-encoding: chunked");
    let mut body = Vec::new();
    let mut trailer = String::new();
    if let Some(length) = length {
        body.resize(length, 0);
        tokio::time::timeout(WAIT, reader.read_exact(&mut body))
            .await
            .expect("body in time")
            .expect("body");
    } else if chunked {
        loop {
            let mut size_line = String::new();
            reader.read_line(&mut size_line).await.expect("chunk size");
            let size = usize::from_str_radix(size_line.trim(), 16).expect("hex chunk size");
            if size == 0 {
                loop {
                    let mut line = String::new();
                    let got = reader.read_line(&mut line).await.expect("trailer line");
                    assert!(got > 0, "EOF inside trailers");
                    if line == "\r\n" {
                        break;
                    }
                    trailer.push_str(&line);
                }
                break;
            }
            let mut chunk = vec![0u8; size];
            reader.read_exact(&mut chunk).await.expect("chunk data");
            body.extend_from_slice(&chunk);
            let mut crlf = [0u8; 2];
            reader.read_exact(&mut crlf).await.expect("chunk crlf");
        }
    }
    H1Response {
        status,
        head,
        body,
        trailer,
    }
}

fn proxy_with_h2_backend(origin: SocketAddr, alpn: &[&str]) -> ResolvedListener {
    let backend = Arc::new(ResolvedBackend::single("api", origin).with_tls(backend_tls(alpn)));
    h2_listener(origin).with_backend(backend)
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h1_client_reaches_an_h2_backend_through_a_real_h2_session() {
    let origin = start_h2_origin(&["h2"]).await;
    let metrics = Arc::new(Metrics::default());
    let (proxy, handle, serve) = start_proxy(
        proxy_with_h2_backend(origin.addr, &["h2"]),
        Arc::clone(&metrics),
    )
    .await;

    let mut client = TcpStream::connect(proxy).await.expect("connect proxy");
    client
        .write_all(
            b"POST /echo HTTP/1.1\r\nHost: api.test\r\nContent-Length: 11\r\n\
              X-Custom: kept\r\nConnection: close\r\n\r\nhello world",
        )
        .await
        .expect("write request");
    let mut reader = BufReader::new(client);
    let response = read_h1_response(&mut reader, false).await;
    assert_eq!(response.status, 200);
    assert_eq!(
        response.body, b"hello world",
        "the h2 answer must flow back"
    );
    assert_eq!(
        response
            .head
            .to_ascii_lowercase()
            .matches("x-origin: h2")
            .count(),
        1,
        "head: {}",
        response.head
    );

    let seen = seen_requests(&origin);
    let request = seen.first().expect("backend saw the request");
    assert_eq!(
        request.version,
        http::Version::HTTP_2,
        "the backend must see HTTP/2, not h1 bytes"
    );
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/echo");
    assert_eq!(request.authority, "api.test", ":authority from Host");
    assert_eq!(request.body, b"hello world");
    let names: Vec<&str> = request
        .headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(
        !names.contains(&"host") && !names.contains(&"connection"),
        "h1-only headers must not cross: {names:?}"
    );
    assert!(
        request
            .headers
            .iter()
            .any(|(name, value)| name == "x-custom" && value == "kept"),
        "application headers must survive: {:?}",
        request.headers
    );
    assert_eq!(metrics.snapshot().connect_failures, 0);
    drop(reader);
    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_client_reaches_an_h2_backend_end_to_end() {
    let origin = start_h2_origin(&["h2"]).await;
    let server = tls::server_config(CERT, KEY, None, &["h2".to_owned()], TlsVersion::V1_2)
        .expect("listener tls");
    let cfg = proxy_with_h2_backend(origin.addr, &["h2"]).with_server_tls(server);
    let (proxy, handle, serve) = start_proxy(cfg, Arc::new(Metrics::default())).await;

    // h2 to the listener, h2 to the backend: HTTP/2 from end to end.
    let listener_tls = tls::client_config(
        Some(CERT),
        true,
        Some("localhost"),
        &["h2".to_owned()],
        TlsVersion::V1_2,
    )
    .expect("client tls");
    let name = tls::server_name_for(&listener_tls, proxy);
    let stream = listener_tls
        .connector
        .connect(name, TcpStream::connect(proxy).await.expect("connect"))
        .await
        .expect("TLS to the proxy");
    let (mut send, connection) = h2::client::handshake(stream)
        .await
        .expect("h2 to the proxy");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method("PUT")
        .uri("https://api.test/echo")
        .body(())
        .expect("request");
    let (response, mut body) = send.send_request(request, false).expect("send");
    body.send_data(Bytes::from_static(b"end-to-end"), true)
        .expect("request body");
    let response = tokio::time::timeout(WAIT, response)
        .await
        .expect("response in time")
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), http::Version::HTTP_2);
    let mut recv = response.into_body();
    let mut payload = Vec::new();
    while let Some(chunk) = recv.data().await {
        let chunk = chunk.expect("DATA");
        payload.extend_from_slice(&chunk);
        let _ = recv.flow_control().release_capacity(chunk.len());
    }
    assert_eq!(payload, b"end-to-end");

    let seen = seen_requests(&origin);
    let request = seen.first().expect("backend saw the request");
    assert_eq!(request.version, http::Version::HTTP_2);
    assert_eq!(request.method, "PUT");
    assert_eq!(request.path, "/echo");
    assert_eq!(request.body, b"end-to-end");
    drop(send);
    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_pooled_h2_session_serves_consecutive_requests() {
    let origin = start_h2_origin(&["h2"]).await;
    let (proxy, handle, serve) = start_proxy(
        proxy_with_h2_backend(origin.addr, &["h2"]),
        Arc::new(Metrics::default()),
    )
    .await;

    let mut client = TcpStream::connect(proxy).await.expect("connect proxy");
    client
        .write_all(b"GET /echo HTTP/1.1\r\nHost: api.test\r\n\r\n")
        .await
        .expect("first request");
    let mut reader = BufReader::new(client);
    let first = read_h1_response(&mut reader, false).await;
    assert_eq!(first.status, 200);

    // Same client connection: the backend connection goes back to the pool
    // and the next exchange must reuse the *same* h2 session.
    reader
        .get_mut()
        .write_all(b"GET /teapot HTTP/1.1\r\nHost: api.test\r\nConnection: close\r\n\r\n")
        .await
        .expect("second request");
    let second = read_h1_response(&mut reader, false).await;
    assert_eq!(second.status, 418, "head: {}", second.head);
    assert_eq!(second.body, b"short and stout");

    assert_eq!(
        origin.connections.load(Ordering::Relaxed),
        1,
        "consecutive exchanges must share one h2 backend session"
    );
    assert_eq!(origin.seen.lock().expect("seen lock").len(), 2);
    drop(reader);
    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trailers_and_chunked_bodies_cross_in_both_directions() {
    let origin = start_h2_origin(&["h2"]).await;
    let (proxy, handle, serve) = start_proxy(
        proxy_with_h2_backend(origin.addr, &["h2"]),
        Arc::new(Metrics::default()),
    )
    .await;

    // h2c client: the chunked h1 message the engine builds carries trailers,
    // which must arrive at the h2 backend as trailing HEADERS.
    let socket = TcpStream::connect(proxy).await.expect("connect proxy");
    let (mut send, connection) = h2::client::handshake(socket).await.expect("h2c");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method("POST")
        .uri("https://api.test/trailers")
        .body(())
        .expect("request");
    let (response, mut stream) = send.send_request(request, false).expect("send");
    stream
        .send_data(Bytes::from_static(b"with-trailers"), false)
        .expect("DATA");
    let mut trailers = HeaderMap::new();
    trailers.insert("x-request-tag", http::HeaderValue::from_static("t-1"));
    stream.send_trailers(trailers).expect("request trailers");

    let response = tokio::time::timeout(WAIT, response)
        .await
        .expect("response in time")
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let mut recv = response.into_body();
    let mut payload = Vec::new();
    while let Some(chunk) = recv.data().await {
        let chunk = chunk.expect("DATA");
        payload.extend_from_slice(&chunk);
        let _ = recv.flow_control().release_capacity(chunk.len());
    }
    assert_eq!(payload, b"trailed");
    let response_trailers = recv
        .trailers()
        .await
        .expect("trailers")
        .expect("the backend's trailing header must survive");
    assert_eq!(
        response_trailers.get("x-checksum").expect("trailer"),
        "abc123"
    );

    let seen = seen_requests(&origin);
    let request = seen.first().expect("backend saw the request");
    assert_eq!(request.body, b"with-trailers");
    let trailers = request
        .trailers
        .as_ref()
        .expect("request trailers must reach the h2 backend");
    assert_eq!(trailers.get("x-request-tag").expect("trailer"), "t-1");
    drop(send);

    // The same journey with an HTTP/1.1 client: a chunked request with a
    // trailer goes up as DATA + trailing HEADERS, and the h2 trailing header
    // comes back as an h1 trailer.
    let mut client = TcpStream::connect(proxy).await.expect("connect proxy");
    client
        .write_all(
            b"POST /trailers HTTP/1.1\r\nHost: api.test\r\nTransfer-Encoding: chunked\r\n\
              Connection: close\r\n\r\n\
              9\r\nh1-trail!\r\n\
              0\r\nx-h1-tag: h-1\r\n\r\n",
        )
        .await
        .expect("chunked request");
    let mut reader = BufReader::new(client);
    let response = read_h1_response(&mut reader, false).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"trailed");
    assert!(
        response.trailer.contains("x-checksum: abc123"),
        "the h2 trailing header must arrive as an h1 trailer: {:?}",
        response.trailer
    );
    let seen = seen_requests(&origin);
    let last = seen.last().expect("backend saw the h1 request");
    assert_eq!(last.body, b"h1-trail!");
    assert_eq!(
        last.trailers
            .as_ref()
            .and_then(|trailers| trailers.get("x-h1-tag"))
            .expect("h1 trailer must reach the h2 backend"),
        "h-1"
    );
    drop(reader);
    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn head_keeps_its_declared_length_and_the_session_stays_usable() {
    let origin = start_h2_origin(&["h2"]).await;
    let (proxy, handle, serve) = start_proxy(
        proxy_with_h2_backend(origin.addr, &["h2"]),
        Arc::new(Metrics::default()),
    )
    .await;

    let mut client = TcpStream::connect(proxy).await.expect("connect proxy");
    client
        .write_all(b"HEAD /head HTTP/1.1\r\nHost: api.test\r\n\r\n")
        .await
        .expect("HEAD");
    let mut reader = BufReader::new(client);
    let head = read_h1_response(&mut reader, true).await;
    assert_eq!(head.status, 200);
    assert!(
        head.head.to_ascii_lowercase().contains("content-length: 5"),
        "a HEAD answer keeps its declared length: {}",
        head.head
    );
    assert!(head.body.is_empty(), "HEAD never carries a body");

    // The same client connection: the h2 session must still be aligned.
    reader
        .get_mut()
        .write_all(b"GET /echo HTTP/1.1\r\nHost: api.test\r\nConnection: close\r\n\r\n")
        .await
        .expect("GET after HEAD");
    let next = read_h1_response(&mut reader, false).await;
    assert_eq!(next.status, 200);
    assert_eq!(
        origin.connections.load(Ordering::Relaxed),
        1,
        "HEAD must not cost the pooled h2 session"
    );
    drop(reader);
    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_through_an_h2_backend_is_refused_not_half_forwarded() {
    // h2 has no `101`: a CONNECT tunnel cannot be translated. The explicit
    // 502 is the contract, and the backend sees no stream at all.
    let origin = start_h2_origin(&["h2"]).await;
    let (proxy, handle, serve) = start_proxy(
        proxy_with_h2_backend(origin.addr, &["h2"]),
        Arc::new(Metrics::default()),
    )
    .await;

    let mut client = TcpStream::connect(proxy).await.expect("connect proxy");
    client
        .write_all(b"CONNECT api.test:443 HTTP/1.1\r\nHost: api.test:443\r\n\r\n")
        .await
        .expect("CONNECT");
    let mut reader = BufReader::new(client);
    let response = read_h1_response(&mut reader, false).await;
    assert_eq!(response.status, 502, "head: {}", response.head);
    assert!(
        origin.seen.lock().expect("seen lock").is_empty(),
        "a CONNECT must never become an h2 stream"
    );
    drop(reader);
    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_backend_that_cannot_negotiate_h2_is_an_explicit_502() {
    // The opt-in says h2, the backend only offers HTTP/1.1: the TLS handshake
    // has no common protocol, so the exchange fails in the connect phase and
    // the client sees 502 — never h1 bytes written into a TLS session.
    let origin = start_h2_origin(&["http/1.1"]).await;
    let metrics = Arc::new(Metrics::default());
    let (proxy, handle, serve) = start_proxy(
        proxy_with_h2_backend(origin.addr, &["h2"]),
        Arc::clone(&metrics),
    )
    .await;

    let mut client = TcpStream::connect(proxy).await.expect("connect proxy");
    client
        .write_all(b"GET /echo HTTP/1.1\r\nHost: api.test\r\nConnection: close\r\n\r\n")
        .await
        .expect("request");
    let mut reader = BufReader::new(client);
    let response = read_h1_response(&mut reader, false).await;
    assert_eq!(response.status, 502, "head: {}", response.head);
    assert_eq!(origin.connections.load(Ordering::Relaxed), 1);
    assert!(
        metrics.snapshot().tls_handshake_failures >= 1,
        "a failed ALPN negotiation is a counted handshake failure"
    );
    assert!(origin.seen.lock().expect("seen lock").is_empty());
    drop(reader);
    stop_proxy(handle, serve).await;
}
