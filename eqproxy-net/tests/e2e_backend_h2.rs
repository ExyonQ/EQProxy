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
    /// Incremented when a session's h2 loop ends (the proxy closed it).
    closed: Arc<AtomicUsize>,
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
/// - `/barrier`: answers only when **two** streams are inside the origin at
///   the same time (a proxy that serializes them can never finish).
async fn start_h2_origin(alpn: &[&str]) -> Origin {
    let server = tls::server_config(CERT, KEY, None, &alpn_strings(alpn), TlsVersion::V1_2)
        .expect("server tls");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("addr origin");
    let connections = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let accepted = Arc::clone(&connections);
    let finished = Arc::clone(&closed);
    let recorded = Arc::clone(&seen);
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            accepted.fetch_add(1, Ordering::Relaxed);
            let acceptor = server.clone();
            let recorded = Arc::clone(&recorded);
            let barrier = Arc::clone(&barrier);
            let finished = Arc::clone(&finished);
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
                    let barrier = Arc::clone(&barrier);
                    tokio::spawn(async move {
                        answer(request, respond, recorded, barrier).await;
                    });
                }
                finished.fetch_add(1, Ordering::Relaxed);
            });
        }
    });
    Origin {
        addr,
        connections,
        closed,
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
    barrier: Arc<tokio::sync::Barrier>,
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
    if path == "/barrier" {
        // Only answers when both in-flight streams are here: a backend that
        // serializes the two exchanges never gets past this point.
        if tokio::time::timeout(WAIT, barrier.wait()).await.is_err() {
            return;
        }
    }
    seen.lock().expect("seen lock").push(Seen {
        method: method.to_string(),
        path: path.clone(),
        authority,
        version,
        headers,
        body: payload.clone(),
        trailers,
    });

    if path == "/drip" {
        // An exchange that lives longer than the session's idle window while
        // never leaving a single operation idle: five DATA frames 120 ms
        // apart (and no `content-length`, so the h1 side streams chunked).
        let mut out = http::Response::new(());
        *out.status_mut() = StatusCode::OK;
        out.headers_mut()
            .insert("x-origin", http::HeaderValue::from_static("h2"));
        let Ok(mut send) = respond.send_response(out, false) else {
            return;
        };
        for byte in b"drip!" {
            if send.send_data(Bytes::from(vec![*byte]), false).is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(120)).await;
        }
        let _ = send.send_data(Bytes::new(), true);
        return;
    }

    let body: Vec<u8> = match path.as_str() {
        "/teapot" => b"short and stout".to_vec(),
        // `HEAD` semantics: a declared length, no body bytes.
        "/head" => Vec::new(),
        // Slow enough to outlive the idle window of the session test.
        "/slow" => {
            tokio::time::sleep(Duration::from_millis(500)).await;
            b"slow-done".to_vec()
        }
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
async fn consecutive_exchanges_share_one_backend_session() {
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

    // Same client connection: the next exchange must take a stream on the
    // *same* h2 session (the pipe itself is never pooled).
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

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_exchanges_multiplex_one_backend_session() {
    // The origin's `/barrier` answer is only produced when two streams are
    // inside it at the same time: a proxy that queues the second exchange
    // behind the first one deadlocks here, and one that dials a second
    // connection instead of multiplexing is caught by the connection count.
    let origin = start_h2_origin(&["h2"]).await;
    let (proxy, handle, serve) = start_proxy(
        proxy_with_h2_backend(origin.addr, &["h2"]),
        Arc::new(Metrics::default()),
    )
    .await;

    let first = tokio::spawn(async move {
        let mut client = TcpStream::connect(proxy).await.expect("connect proxy");
        client
            .write_all(b"GET /barrier HTTP/1.1\r\nHost: api.test\r\nConnection: close\r\n\r\n")
            .await
            .expect("first request");
        let mut reader = BufReader::new(client);
        read_h1_response(&mut reader, false).await
    });
    let second = tokio::spawn(async move {
        let mut client = TcpStream::connect(proxy).await.expect("connect proxy");
        client
            .write_all(b"GET /barrier HTTP/1.1\r\nHost: api.test\r\nConnection: close\r\n\r\n")
            .await
            .expect("second request");
        let mut reader = BufReader::new(client);
        read_h1_response(&mut reader, false).await
    });

    let (first, second) = tokio::join!(first, second);
    let first = first.expect("first exchange task");
    let second = second.expect("second exchange task");
    assert_eq!(first.status, 200, "head: {}", first.head);
    assert_eq!(second.status, 200, "head: {}", second.head);
    assert_eq!(
        origin.connections.load(Ordering::Relaxed),
        1,
        "two in-flight exchanges must share one h2 session, not dial twice"
    );
    let seen = seen_requests(&origin);
    assert_eq!(seen.len(), 2);
    assert!(
        seen.iter()
            .all(|request| request.path == "/barrier" && request.version == http::Version::HTTP_2),
        "both streams must reach the backend over HTTP/2: {seen:?}"
    );
    stop_proxy(handle, serve).await;
}

/// Origin that serves exactly one stream per TCP connection and then hangs
/// up, so a test can force the backend session to die.
struct OneShotOrigin {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    /// Incremented when a connection task is about to close its TCP socket.
    closed: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

async fn start_one_shot_h2_origin() -> OneShotOrigin {
    let server = tls::server_config(CERT, KEY, None, &alpn_strings(&["h2"]), TlsVersion::V1_2)
        .expect("server tls");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("addr origin");
    let connections = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let accepted = Arc::clone(&connections);
    let finished = Arc::clone(&closed);
    let recorded = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            accepted.fetch_add(1, Ordering::Relaxed);
            let acceptor = server.clone();
            let recorded = Arc::clone(&recorded);
            let finished = Arc::clone(&finished);
            tokio::spawn(async move {
                let Ok(stream) = acceptor.acceptor.accept(socket).await else {
                    finished.fetch_add(1, Ordering::Relaxed);
                    return;
                };
                let mut connection = h2::server::handshake(stream)
                    .await
                    .expect("h2 server handshake");
                let Some(Ok((request, respond))) = connection.accept().await else {
                    finished.fetch_add(1, Ordering::Relaxed);
                    return;
                };
                let mut answer = tokio::spawn(answer(
                    request,
                    respond,
                    recorded,
                    Arc::new(tokio::sync::Barrier::new(2)),
                ));
                // The connection must keep being polled while the answer runs:
                // reading the body and writing the response both need it, and
                // this task owns the only poller. Answering inline deadlocks
                // whenever the request body arrives in a later read than the
                // head (a real server runs both concurrently).
                loop {
                    tokio::select! {
                        _ = &mut answer => break,
                        _ = connection.accept() => {}
                    }
                }
                // Poll briefly so the answer is flushed, then drop the
                // session: the proxy's session must become unusable.
                let _ = tokio::time::timeout(Duration::from_millis(100), connection.accept()).await;
                finished.fetch_add(1, Ordering::Relaxed);
            });
        }
    });
    OneShotOrigin {
        addr,
        connections,
        closed,
        seen,
    }
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dead_session_is_replaced_by_a_fresh_one() {
    let origin = start_one_shot_h2_origin().await;
    let backend =
        Arc::new(ResolvedBackend::single("api", origin.addr).with_tls(backend_tls(&["h2"])));
    let cfg = h2_listener(origin.addr).with_backend(backend);
    let (proxy, handle, serve) = start_proxy(cfg, Arc::new(Metrics::default())).await;

    let mut client = TcpStream::connect(proxy).await.expect("connect proxy");
    client
        .write_all(b"POST /echo HTTP/1.1\r\nHost: api.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\none!")
        .await
        .expect("first request");
    let mut reader = BufReader::new(client);
    let first = read_h1_response(&mut reader, false).await;
    assert_eq!(first.status, 200, "head: {}", first.head);
    assert_eq!(first.body, b"one!");
    drop(reader);

    // Wait for the origin to actually hang up, then for the proxy to see it.
    let _ = tokio::time::timeout(WAIT, async {
        while origin.closed.load(Ordering::Relaxed) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        origin.closed.load(Ordering::Relaxed) >= 1,
        "the one-shot origin must have closed its session"
    );

    // A request that races the death (the hub still believes the session is
    // alive, `send_request` fails) is a `502`: no bytes were sent, so nothing
    // was delivered twice. The next attempt must dial a fresh session and be
    // served; this is the documented fail-explicit behaviour, and the loop
    // bounds how long the proxy may take to notice.
    let mut statuses = Vec::new();
    let outcome = tokio::time::timeout(WAIT, async {
        loop {
            let mut client = TcpStream::connect(proxy).await.expect("connect proxy");
            client
                .write_all(b"GET /echo HTTP/1.1\r\nHost: api.test\r\nConnection: close\r\n\r\n")
                .await
                .expect("retry request");
            let mut reader = BufReader::new(client);
            let response = read_h1_response(&mut reader, false).await;
            statuses.push(response.status);
            drop(reader);
            if response.status == 200 {
                return response;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let served = match outcome {
        Ok(response) => response,
        Err(_) => panic!("no request was served within the bound; statuses {statuses:?}"),
    };
    assert!(
        served.body.is_empty(),
        "a GET /echo has no body to echo: {:?}",
        served.body
    );
    assert_eq!(
        origin.connections.load(Ordering::Relaxed),
        2,
        "exactly one replacement session: a stale session is never retried in a storm"
    );
    // Neither the failed attempt nor the recovery delivered the request
    // twice: the origin saw the first exchange and the served one only.
    assert_eq!(origin.seen.lock().expect("seen lock").len(), 2);
    stop_proxy(handle, serve).await;
}

/// A TLS origin that echoes the bytes it receives and records the ALPN its
/// handshake selected.
async fn start_tls_echo(alpn: &[&str]) -> (SocketAddr, Arc<Mutex<Vec<Option<Vec<u8>>>>>) {
    let server = tls::server_config(CERT, KEY, None, &alpn_strings(alpn), TlsVersion::V1_2)
        .expect("server tls");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("addr echo");
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&recorded);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = server.clone();
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let Ok(stream) = acceptor.acceptor.accept(socket).await else {
                    return;
                };
                let alpn = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
                log.lock().expect("alpn log").push(alpn);
                let (mut read, mut write) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    (addr, recorded)
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tcp_listener_relays_bytes_even_when_the_backend_negotiates_h2() {
    // `mode = "tcp"` is a byte tunnel: even a backend that answers ALPN `h2`
    // must be relayed verbatim, never spoken to in h2 frames.
    let (origin, alpn_seen) = start_tls_echo(&["h2"]).await;
    let backend = Arc::new(ResolvedBackend::single("api", origin).with_tls(backend_tls(&["h2"])));
    let cfg = ResolvedListener::new(
        "tunnel",
        "127.0.0.1:0".parse().expect("addr"),
        "api",
        origin,
        ProxyMode::Tcp,
        64,
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .with_backend(backend);
    let (proxy, handle, serve) = start_proxy(cfg, Arc::new(Metrics::default())).await;

    let mut client = TcpStream::connect(proxy).await.expect("connect proxy");
    let payload = b"raw-bytes-through-a-tunnel";
    client.write_all(payload).await.expect("write");
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(WAIT, client.read_exact(&mut echoed))
        .await
        .expect("echo in time")
        .expect("echo");
    assert_eq!(echoed, payload, "a TCP tunnel must never rewrite bytes");
    assert_eq!(
        alpn_seen
            .lock()
            .expect("alpn log")
            .first()
            .cloned()
            .flatten(),
        Some(b"h2".to_vec()),
        "the backend did negotiate h2; the tunnel still relays bytes"
    );
    drop(client);
    stop_proxy(handle, serve).await;
}

/// A listener whose idle window is short enough to observe in a test.
fn h2_listener_with_idle(server: SocketAddr, idle: Duration) -> ResolvedListener {
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

/// Listener with an h2 backend and an explicit session idle window.
fn h2_backend_with_idle(origin: SocketAddr, idle: Duration) -> ResolvedListener {
    let backend = Arc::new(ResolvedBackend::single("api", origin).with_tls(backend_tls(&["h2"])));
    h2_listener_with_idle(origin, idle).with_backend(backend)
}

/// One `Connection: close` exchange through the proxy.
async fn one_exchange(proxy: SocketAddr, request: &[u8]) -> H1Response {
    let mut client = TcpStream::connect(proxy).await.expect("connect proxy");
    client.write_all(request).await.expect("write request");
    let mut reader = BufReader::new(client);
    read_h1_response(&mut reader, false).await
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_session_is_closed_and_the_next_exchange_dials_again() {
    // `idle_timeout` bounds the *session*, not only the exchange pipe: a
    // backend nobody uses must not keep a TLS+h2 session for the process
    // lifetime, and an exchange in flight must not be cut by that close.
    let origin = start_h2_origin(&["h2"]).await;
    let metrics = Arc::new(Metrics::default());
    let (proxy, handle, serve) = start_proxy(
        h2_backend_with_idle(origin.addr, Duration::from_millis(300)),
        Arc::clone(&metrics),
    )
    .await;

    // An exchange that outlives the idle window (480 ms of DATA 120 ms
    // apart, window 300 ms) is never cut: the session counts in-flight work,
    // so only a session nobody uses closes.
    let slow = one_exchange(
        proxy,
        b"GET /drip HTTP/1.1\r\nHost: api.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(slow.status, 200, "head: {}", slow.head);
    assert_eq!(slow.body, b"drip!");
    assert_eq!(origin.connections.load(Ordering::Relaxed), 1);
    assert_eq!(
        metrics.snapshot().h2_sessions_idle_closed,
        0,
        "an in-flight exchange keeps its session"
    );

    // Nothing in flight: the session closes within the window (the monitor
    // ticks at a quarter of it) and the origin sees its connection end.
    let ended = tokio::time::timeout(WAIT, async {
        while origin.closed.load(Ordering::Relaxed) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        ended.is_ok(),
        "an idle backend session must be closed, not kept for the process lifetime"
    );
    assert_eq!(metrics.snapshot().h2_sessions_idle_closed, 1);

    // The next exchange has no session to reuse: a fresh one is dialed.
    let again = one_exchange(
        proxy,
        b"GET /echo HTTP/1.1\r\nHost: api.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(again.status, 200, "head: {}", again.head);
    assert_eq!(
        origin.connections.load(Ordering::Relaxed),
        2,
        "an idle-closed session is replaced by a fresh one"
    );
    stop_proxy(handle, serve).await;
}

/// Origin that announces a graceful GOAWAY while its first stream is still
/// being answered: the stream must finish on the old session and the next
/// exchange must land on a new one.
struct DrainingOrigin {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    /// Notified once the first connection has started its GOAWAY.
    draining: Arc<tokio::sync::Notify>,
}

async fn start_draining_origin() -> DrainingOrigin {
    let server = tls::server_config(CERT, KEY, None, &alpn_strings(&["h2"]), TlsVersion::V1_2)
        .expect("server tls");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("addr origin");
    let connections = Arc::new(AtomicUsize::new(0));
    let draining = Arc::new(tokio::sync::Notify::new());
    let accepted = Arc::clone(&connections);
    let announced = Arc::clone(&draining);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let first = accepted.fetch_add(1, Ordering::Relaxed) == 0;
            let acceptor = server.clone();
            let announced = Arc::clone(&announced);
            tokio::spawn(async move {
                let Ok(stream) = acceptor.acceptor.accept(socket).await else {
                    return;
                };
                let mut connection = h2::server::handshake(stream)
                    .await
                    .expect("h2 server handshake");
                if !first {
                    while let Some(request) = connection.accept().await {
                        let Ok((request, respond)) = request else {
                            break;
                        };
                        tokio::spawn(async move {
                            answer(
                                request,
                                respond,
                                Arc::new(Mutex::new(Vec::new())),
                                Arc::new(tokio::sync::Barrier::new(2)),
                            )
                            .await;
                        });
                    }
                    return;
                }
                // First connection: take the stream that is in flight, then
                // announce GOAWAY while it is still being answered.
                let Some(Ok((request, respond))) = connection.accept().await else {
                    return;
                };
                connection.graceful_shutdown();
                announced.notify_one();
                tokio::spawn(async move {
                    answer(
                        request,
                        respond,
                        Arc::new(Mutex::new(Vec::new())),
                        Arc::new(tokio::sync::Barrier::new(2)),
                    )
                    .await;
                });
                // Keep driving the connection: the drain lasts until the
                // accepted stream has been answered.
                while connection.accept().await.is_some() {}
            });
        }
    });
    DrainingOrigin {
        addr,
        connections,
        draining,
    }
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_goaway_drains_in_flight_streams_and_the_next_exchange_dials_a_fresh_one() {
    let origin = start_draining_origin().await;
    let metrics = Arc::new(Metrics::default());
    let (proxy, handle, serve) = start_proxy(
        h2_backend_with_idle(origin.addr, Duration::from_secs(5)),
        Arc::clone(&metrics),
    )
    .await;

    // The slow exchange is in flight when the peer announces GOAWAY.
    let in_flight = tokio::spawn(async move {
        one_exchange(
            proxy,
            b"GET /slow HTTP/1.1\r\nHost: api.test\r\nConnection: close\r\n\r\n",
        )
        .await
    });
    tokio::time::timeout(WAIT, origin.draining.notified())
        .await
        .expect("the origin announces GOAWAY");

    let next = one_exchange(
        proxy,
        b"GET /echo HTTP/1.1\r\nHost: api.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(next.status, 200, "head: {}", next.head);

    let slow = in_flight.await.expect("in-flight exchange task");
    assert_eq!(
        slow.status, 200,
        "a GOAWAY must not cut a stream the peer accepted: {}",
        slow.head
    );
    assert_eq!(slow.body, b"slow-done");
    assert_eq!(
        origin.connections.load(Ordering::Relaxed),
        2,
        "after a GOAWAY the next exchange must dial a fresh session"
    );
    assert_eq!(metrics.snapshot().h2_goaway_received, 1);
    stop_proxy(handle, serve).await;
}

/// Origin whose first connection serves one stream, then refuses the next one
/// with `RST_STREAM(REFUSED_STREAM)` without processing it. Later connections
/// answer normally.
struct RefusingOrigin {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    /// Notified once the first connection is about to refuse new streams.
    ready: Arc<tokio::sync::Notify>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

async fn start_refusing_origin() -> RefusingOrigin {
    let server = tls::server_config(CERT, KEY, None, &alpn_strings(&["h2"]), TlsVersion::V1_2)
        .expect("server tls");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("addr origin");
    let connections = Arc::new(AtomicUsize::new(0));
    let ready = Arc::new(tokio::sync::Notify::new());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let accepted = Arc::clone(&connections);
    let announced = Arc::clone(&ready);
    let recorded = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let first = accepted.fetch_add(1, Ordering::Relaxed) == 0;
            let acceptor = server.clone();
            let recorded = Arc::clone(&recorded);
            let announced = Arc::clone(&announced);
            tokio::spawn(async move {
                let Ok(stream) = acceptor.acceptor.accept(socket).await else {
                    return;
                };
                let mut connection = h2::server::handshake(stream)
                    .await
                    .expect("h2 server handshake");
                if first {
                    // Serve one stream so the client has a live session, then
                    // refuse whatever arrives next: those streams are never
                    // accepted, so the GOAWAY's last processed stream is the
                    // served one and a replay cannot duplicate any work.
                    let Some(Ok((request, respond))) = connection.accept().await else {
                        return;
                    };
                    answer(
                        request,
                        respond,
                        Arc::clone(&recorded),
                        Arc::new(tokio::sync::Barrier::new(2)),
                    )
                    .await;
                    announced.notify_one();
                    // Refuse the next stream without reading or answering it:
                    // REFUSED_STREAM states that it was never processed, so a
                    // replay cannot duplicate work.
                    if let Some(Ok((_, mut respond))) = connection.accept().await {
                        respond.send_reset(h2::Reason::REFUSED_STREAM);
                    }
                    let _ =
                        tokio::time::timeout(Duration::from_millis(300), connection.accept()).await;
                    return;
                }
                while let Some(request) = connection.accept().await {
                    let Ok((request, respond)) = request else {
                        break;
                    };
                    let recorded = Arc::clone(&recorded);
                    tokio::spawn(async move {
                        answer(
                            request,
                            respond,
                            recorded,
                            Arc::new(tokio::sync::Barrier::new(2)),
                        )
                        .await;
                    });
                }
            });
        }
    });
    RefusingOrigin {
        addr,
        connections,
        ready,
        seen,
    }
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_the_peer_refuses_is_replayed_once_on_a_fresh_session() {
    let origin = start_refusing_origin().await;
    let metrics = Arc::new(Metrics::default());
    let (proxy, handle, serve) = start_proxy(
        h2_backend_with_idle(origin.addr, Duration::from_secs(5)),
        Arc::clone(&metrics),
    )
    .await;

    // Establish the session the origin is about to take away.
    let warm = one_exchange(
        proxy,
        b"GET /echo HTTP/1.1\r\nHost: api.test\r\nX-Warm: 1\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(warm.status, 200, "head: {}", warm.head);
    tokio::time::timeout(WAIT, origin.ready.notified())
        .await
        .expect("the origin refuses new streams after its first answer");

    // This stream is refused (GOAWAY names the earlier one) and must be
    // replayed on a fresh session, with the same request head.
    let response = one_exchange(
        proxy,
        b"GET /echo HTTP/1.1\r\nHost: api.test\r\nX-Replay: kept\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        response.status, 200,
        "a refused stream must be replayed, not failed: {}",
        response.head
    );

    let seen = origin.seen.lock().expect("seen lock").clone();
    assert_eq!(
        seen.len(),
        2,
        "the refused attempt delivered nothing: exactly the warm request and the replay reached the origin"
    );
    assert_eq!(seen[0].path, "/echo");
    assert!(
        seen[1]
            .headers
            .iter()
            .any(|(name, value)| name == "x-replay" && value == "kept"),
        "the replay must carry the same request head: {:?}",
        seen[1].headers
    );
    assert_eq!(
        origin.connections.load(Ordering::Relaxed),
        2,
        "the replay needs a fresh session, dialed exactly once"
    );
    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.h2_goaway_received, 0,
        "REFUSED_STREAM is per stream, not a session GOAWAY"
    );
    assert_eq!(snapshot.h2_refused_retried, 1);
    stop_proxy(handle, serve).await;
}
