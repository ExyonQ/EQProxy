//! HTTP/3 (QUIC) E2E tests with **real sockets and a real h3 client**: a
//! `quinn` endpoint speaking `h3` to the proxy over UDP, and a real HTTP/1.1
//! origin behind it.
//!
//! These journeys prove what the roadmap asks for B-H2: TLS 1.3 + ALPN `h3`
//! over QUIC on the listener's own port, a GET/response relayed end to end,
//! request bodies streamed without `content-length`, chunked responses with
//! trailers, the h1 engine's decisions (rules and compression) applied to h3
//! requests, explicit refusals (CONNECT, no server), `maxconn` refusing a
//! QUIC connection, and the reload lifecycle of the UDP endpoint.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::{Buf, Bytes};
use http::{HeaderMap, Request, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use eqproxy_core::Metrics;
use eqproxy_core::rules::{Rule, RuleSpec};
use eqproxy_net::tls::{self, TlsVersion};
use eqproxy_net::{
    BoundProxy, ProxyMode, ResolvedBackend, ResolvedListener, ResolvedRoute, ResolvedServer,
    RouteAction, ServerAddr, bind,
};

mod common;

const WAIT: Duration = Duration::from_secs(10);
const CERT: &[u8] = include_bytes!("fixtures/cert.pem");
const KEY: &[u8] = include_bytes!("fixtures/key.pem");
// Rotation target: a different chain (and root) for the same name.
const MTLS_SERVER: &[u8] = include_bytes!("fixtures/mtls-server.pem");
const MTLS_SERVER_KEY: &[u8] = include_bytes!("fixtures/mtls-server.key");
const MTLS_CA: &[u8] = include_bytes!("fixtures/mtls-ca.pem");

// ---------------------------------------------------------------- harness ---

fn listener(server: SocketAddr) -> ResolvedListener {
    ResolvedListener::new(
        "h3",
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

fn tls_config(alpn: &[&str]) -> tls::ServerTls {
    server_tls(CERT, KEY, alpn)
}

fn server_tls(cert: &[u8], key: &[u8], alpn: &[&str]) -> tls::ServerTls {
    let alpn: Vec<String> = alpn.iter().map(|p| (*p).to_owned()).collect();
    tls::server_config_with_sni(cert, key, &[], None, &alpn, TlsVersion::V1_3).expect("server tls")
}

fn quic_listener(server: SocketAddr) -> ResolvedListener {
    listener(server)
        .with_server_tls(tls_config(&[]))
        .with_quic(true)
}

/// `bind` starts every accept loop (TCP and QUIC) itself; the returned
/// `BoundProxy` is the owner, and dropping it stops them.
async fn start_proxy(cfg: ResolvedListener, metrics: Arc<Metrics>) -> (BoundProxy, SocketAddr) {
    let bound = bind(vec![cfg], Arc::clone(&metrics))
        .await
        .expect("bind proxy");
    let addr = bound.local_addrs()[0].1;
    (bound, addr)
}

/// Head + decoded body of every request the origin served.
type SeenRequests = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// Records what the origin received.
#[derive(Clone, Default)]
struct Origin {
    seen: SeenRequests,
}

async fn start_origin() -> (SocketAddr, Origin) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    let origin = Origin::default();
    let seen = Arc::clone(&origin.seen);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let Some((head, body)) = read_message(&mut socket).await else {
                    return;
                };
                let path = head
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_owned();
                seen.lock().await.push((head.clone(), body.clone()));
                let response = match path.as_str() {
                    "/hello" => response(200, "text/plain", b"hello from origin"),
                    "/echo" => {
                        let body = format!("{} bytes", body.len()).into_bytes();
                        response(200, "text/plain", &body)
                    }
                    "/compress" => response(200, "text/plain", &vec![b'a'; 8192]),
                    "/chunked" => {
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n8\r\n chunked\r\n0\r\nx-origin: yes\r\n\r\n".to_vec()
                    }
                    "/slow" => {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        response(200, "text/plain", b"slow")
                    }
                    _ => response(200, "text/plain", b"ok"),
                };
                let _ = socket.write_all(&response).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (addr, origin)
}

fn response(status: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Reads one full h1 request (head + content-length or chunked body).
async fn read_message(socket: &mut tokio::net::TcpStream) -> Option<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 16 * 1024];
    let head_end = loop {
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        let got = socket.read(&mut tmp).await.ok()?;
        if got == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..got]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let lower = head.to_ascii_lowercase();
    if lower.contains("transfer-encoding: chunked") {
        let body_start = head_end;
        loop {
            if let Some((body, _used)) = decode_chunked(&buf[body_start..]) {
                return Some((head, body));
            }
            let got = socket.read(&mut tmp).await.ok()?;
            if got == 0 {
                return None;
            }
            buf.extend_from_slice(&tmp[..got]);
        }
    }
    let declared = lower
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while buf.len() < head_end + declared {
        let got = socket.read(&mut tmp).await.ok()?;
        if got == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..got]);
    }
    let body = buf[head_end..(head_end + declared).min(buf.len())].to_vec();
    Some((head, body))
}

/// Parses a chunked body; `None` when the terminal chunk (and trailers) has
/// not arrived yet.
fn decode_chunked(data: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut pos = 0;
    let mut out = Vec::new();
    loop {
        let line_end = pos + find(&data[pos..], b"\r\n")?;
        let size =
            usize::from_str_radix(std::str::from_utf8(&data[pos..line_end]).ok()?.trim(), 16)
                .ok()?;
        pos = line_end + 2;
        if size == 0 {
            loop {
                let end = pos + find(&data[pos..], b"\r\n")?;
                if end == pos {
                    return Some((out, pos + 2));
                }
                pos = end + 2;
            }
        }
        if data.len() < pos + size + 2 {
            return None;
        }
        out.extend_from_slice(&data[pos..pos + size]);
        pos += size + 2;
    }
}

// ------------------------------------------------------------- h3 client ---

struct Client {
    endpoint: quinn::Endpoint,
    send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    drive: JoinHandle<()>,
}

impl Drop for Client {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"test done");
        self.drive.abort();
    }
}

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
    trailers: Option<HeaderMap>,
}

fn client_config() -> quinn::ClientConfig {
    client_config_with_root(CERT)
}

/// A client trusting exactly `root_pem` (rotation tests: the root is what
/// distinguishes the old certificate from the new one).
fn client_config_with_root(root_pem: &[u8]) -> quinn::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in tls::parse_certs(root_pem).expect("fixture certificates") {
        roots.add(certificate).expect("fixture root");
    }
    let mut config =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(config).expect("quic client");
    quinn::ClientConfig::new(Arc::new(crypto))
}

async fn try_connect(addr: SocketAddr) -> Result<Client, String> {
    try_connect_with(addr, client_config(), "localhost").await
}

async fn try_connect_with(
    addr: SocketAddr,
    config: quinn::ClientConfig,
    name: &str,
) -> Result<Client, String> {
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("client addr"))
        .map_err(|err| format!("client endpoint: {err}"))?;
    endpoint.set_default_client_config(config);
    let connection = endpoint
        .connect(addr, name)
        .map_err(|err| format!("connect: {err}"))?
        .await
        .map_err(|err| format!("quic handshake: {err}"))?;
    let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .map_err(|err| format!("h3 client: {err}"))?;
    let drive = tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });
    Ok(Client {
        endpoint,
        send,
        drive,
    })
}

async fn connect(addr: SocketAddr) -> Client {
    tokio::time::timeout(WAIT, try_connect(addr))
        .await
        .expect("connect in time")
        .expect("h3 connection")
}

impl Client {
    /// Closes the QUIC connection with an application code, the way a real
    /// client ends a session (`0`), signals a protocol error (`0x0101`+) or
    /// uses `H3_NO_ERROR` (`0x0100`). The `Drop` close afterwards is a no-op.
    fn close_with(&self, code: u32, reason: &'static [u8]) {
        self.endpoint.close(quinn::VarInt::from_u32(code), reason);
    }

    async fn request(
        &mut self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Answer {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("https://localhost{path}"));
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let request = builder.body(()).expect("request");
        let mut stream = tokio::time::timeout(WAIT, self.send.send_request(request))
            .await
            .expect("request sent in time")
            .expect("send request");
        if let Some(body) = body {
            stream
                .send_data(Bytes::copy_from_slice(body))
                .await
                .expect("send body");
        }
        // An explicit 502 (or a CONNECT refusal) can close the request stream
        // before this FIN is flushed: the server answered, so the contract is
        // the response asserted below, not a successful write into a stream it
        // is already closing.
        if let Err(err) = stream.finish().await {
            eprintln!("request FIN raced the server's answer: {err:?}");
        }
        let response = tokio::time::timeout(WAIT, stream.recv_response())
            .await
            .expect("response in time")
            .expect("response");
        let mut collected = Vec::new();
        loop {
            let chunk = tokio::time::timeout(WAIT, stream.recv_data())
                .await
                .expect("data in time")
                .expect("data");
            match chunk {
                Some(mut chunk) => {
                    let bytes = chunk.copy_to_bytes(chunk.remaining());
                    collected.extend_from_slice(&bytes);
                }
                None => break,
            }
        }
        let trailers = tokio::time::timeout(WAIT, stream.recv_trailers())
            .await
            .expect("trailers in time")
            .expect("trailers");
        Answer {
            status: response.status(),
            headers: response.headers().clone(),
            body: collected,
            trailers,
        }
    }
}

// ---------------------------------------------------------------- journeys ---

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http3_get_is_terminated_and_relayed_to_the_h1_origin() {
    let (origin, seen) = start_origin().await;
    let metrics = Arc::new(Metrics::default());
    let (proxy, addr) = start_proxy(quic_listener(origin), Arc::clone(&metrics)).await;
    let mut client = connect(addr).await;

    let answer = client.request("GET", "/hello", &[], None).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body, b"hello from origin");
    assert_eq!(
        answer.headers.get("content-type").expect("content type"),
        "text/plain"
    );

    let requests = seen.seen.lock().await;
    assert_eq!(requests.len(), 1, "exactly one backend exchange");
    let head = &requests[0].0;
    assert!(
        head.starts_with("GET /hello HTTP/1.1\r\n"),
        "origin saw: {head}"
    );
    assert!(
        head.to_ascii_lowercase().contains("host: localhost"),
        "h3 :authority becomes host: {head}"
    );
    assert!(
        !head.to_ascii_lowercase().contains("connection:"),
        "a hop-by-hop header crossed the translation: {head}"
    );
    common::wait_for_counter("http_requests_proxied", 1, || {
        metrics.http_requests_proxied.load(Ordering::Relaxed)
    })
    .await;
    assert_eq!(
        metrics.http_requests_proxied.load(Ordering::Relaxed),
        1,
        "the h1 engine counted the h3 exchange"
    );
    assert_eq!(metrics.connections_accepted.load(Ordering::Relaxed), 1);

    drop(requests);
    drop(client);
    drop(proxy);
}

/// B8 over HTTP/3: the h3 engine feeds the same selection. The primary owns
/// the tier, the backup origin serves only when every primary is down, and
/// the recovered primary takes it back. The origins are told apart by what
/// each one saw.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http3_fails_over_to_the_backup_when_every_primary_is_down() {
    let (primary, primary_origin) = start_origin().await;
    let (backup, backup_origin) = start_origin().await;
    let metrics = Arc::new(Metrics::default());
    let backend = Arc::new(ResolvedBackend::new(
        "api",
        vec![
            ResolvedServer {
                addr: ServerAddr::Ip(primary),
                weight: 1,
                backup: false,
                priority: 0,
                maxconn: 0,
            },
            ResolvedServer {
                addr: ServerAddr::Ip(backup),
                weight: 1,
                backup: true,
                priority: 0,
                maxconn: 0,
            },
        ],
        1,
        1,
    ));
    let (proxy, addr) = start_proxy(
        quic_listener(primary).with_backend(Arc::clone(&backend)),
        Arc::clone(&metrics),
    )
    .await;
    let mut client = connect(addr).await;

    let answer = client.request("GET", "/hello", &[], None).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body, b"hello from origin");
    assert_eq!(primary_origin.seen.lock().await.len(), 1);
    assert!(backup_origin.seen.lock().await.is_empty());

    // Every primary down: the backup origin serves the h3 request.
    backend.balancer.report_fail(primary);
    let answer = client.request("GET", "/hello", &[], None).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body, b"hello from origin");
    assert_eq!(
        backup_origin.seen.lock().await.len(),
        1,
        "the backup must serve the h3 request"
    );
    assert_eq!(
        primary_origin.seen.lock().await.len(),
        1,
        "a primary marked down receives nothing"
    );

    // The recovered primary takes it back.
    backend.balancer.report_ok(primary);
    let answer = client.request("GET", "/hello", &[], None).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(primary_origin.seen.lock().await.len(), 2);
    drop(client);
    drop(proxy);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http3_request_body_without_length_streams_as_chunked_upstream() {
    let (origin, seen) = start_origin().await;
    let (proxy, addr) = start_proxy(quic_listener(origin), Arc::new(Metrics::default())).await;
    let mut client = connect(addr).await;

    // 256 KiB without `content-length`: the translation must choose chunked
    // and stream it, never buffer the whole body in the proxy.
    let body: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    let answer = client.request("POST", "/echo", &[], Some(&body)).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body, format!("{} bytes", body.len()).into_bytes());

    let requests = seen.seen.lock().await;
    let (head, received) = &requests[0];
    assert!(
        head.to_ascii_lowercase()
            .contains("transfer-encoding: chunked"),
        "body without length must be chunked upstream: {head}"
    );
    assert_eq!(received, &body, "the origin received every byte, in order");

    drop(requests);
    drop(client);
    drop(proxy);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http3_chunked_response_and_trailers_cross_the_translation() {
    let (origin, _seen) = start_origin().await;
    let (proxy, addr) = start_proxy(quic_listener(origin), Arc::new(Metrics::default())).await;
    let mut client = connect(addr).await;

    let answer = client.request("GET", "/chunked", &[], None).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body, b"hello chunked");
    let trailers = answer.trailers.expect("trailers reach the h3 client");
    assert_eq!(trailers.get("x-origin").expect("origin trailer"), "yes");
    // The h1 framing header never crosses: h3 has DATA frames.
    assert!(answer.headers.get("transfer-encoding").is_none());

    drop(client);
    drop(proxy);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http3_requests_get_the_h1_engine_decisions_rules_and_compression() {
    let (origin, seen) = start_origin().await;
    // A direct-response rule and a compressing listener: both live in the h1
    // engine the h3 path reuses, so the client must see their effects.
    let direct = ResolvedRoute {
        rule: Rule::compile(&RuleSpec {
            name: "shed".to_owned(),
            path: Some("/shed".to_owned()),
            ..RuleSpec::default()
        })
        .expect("rule compiles"),
        action: RouteAction::Direct {
            status: 418,
            content_type: "application/json".to_owned(),
            body: "{\"shed\":true}".to_owned(),
        },
        headers: None,
    };
    let compression = eqproxy_net::compression::ResolvedCompression::new(
        true,
        false,
        6,
        5,
        0,
        &["text/*".to_owned()],
    )
    .expect("compression");
    let cfg = quic_listener(origin)
        .with_routes(vec![direct])
        .with_compression(compression);
    let (proxy, addr) = start_proxy(cfg, Arc::new(Metrics::default())).await;
    let mut client = connect(addr).await;

    let shed = client.request("GET", "/shed", &[], None).await;
    assert_eq!(shed.status, StatusCode::IM_A_TEAPOT);
    assert_eq!(shed.body, b"{\"shed\":true}");
    assert!(
        seen.seen.lock().await.is_empty(),
        "a direct answer never dials"
    );

    let compressed = client
        .request("GET", "/compress", &[("accept-encoding", "gzip")], None)
        .await;
    assert_eq!(compressed.status, StatusCode::OK);
    assert_eq!(
        compressed
            .headers
            .get("content-encoding")
            .expect("encoding"),
        "gzip",
        "the h3 response is compressed by the same engine"
    );
    let mut gunzip = flate2::read::GzDecoder::new(compressed.body.as_slice());
    let mut plain = Vec::new();
    std::io::Read::read_to_end(&mut gunzip, &mut plain).expect("gunzip");
    assert_eq!(plain, vec![b'a'; 8192]);

    drop(client);
    drop(proxy);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http3_connect_is_refused_and_a_dead_backend_is_an_explicit_502() {
    // Nothing listens on this address: the engine's "no server" class.
    let dead = {
        let socket = TcpListener::bind("127.0.0.1:0").await.expect("bind dead");
        socket.local_addr().expect("addr dead")
    };
    let cfg = quic_listener(dead);
    let metrics = Arc::new(Metrics::default());
    let (proxy, addr) = start_proxy(cfg, Arc::clone(&metrics)).await;
    let mut client = connect(addr).await;

    // Nothing listening on the backend: the exchange fails explicitly as
    // 502 (the chosen server could not be reached), never as a hang or an
    // empty 200.
    let unavailable = client.request("GET", "/down", &[], None).await;
    assert_eq!(unavailable.status, StatusCode::BAD_GATEWAY);
    assert!(
        unavailable.body.is_empty(),
        "a gateway error has no body: {:?}",
        unavailable.body
    );

    let connect = client.request("CONNECT", "/tunnel", &[], None).await;
    assert_eq!(connect.status, StatusCode::NOT_IMPLEMENTED);
    assert!(metrics.http_requests_rejected.load(Ordering::Relaxed) >= 1);

    drop(client);
    drop(proxy);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http3_maxconn_refuses_a_second_quic_connection() {
    let (origin, _seen) = start_origin().await;
    let cfg = ResolvedListener::new(
        "h3",
        "127.0.0.1:0".parse().expect("addr"),
        "api",
        origin,
        ProxyMode::Http,
        1,
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .with_server_tls(tls_config(&[]))
    .with_quic(true);
    let metrics = Arc::new(Metrics::default());
    let (proxy, addr) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let first = connect(addr).await;
    let refused = tokio::time::timeout(WAIT, try_connect(addr)).await;
    match refused {
        Ok(Err(_)) => {}
        Ok(Ok(_)) => panic!("a second QUIC connection must be refused at maxconn=1"),
        Err(_) => panic!("the refusal must be immediate, not a hang"),
    }
    assert!(
        metrics.connections_rejected.load(Ordering::Relaxed) >= 1,
        "the refusal is counted"
    );

    drop(first);
    drop(proxy);
}

/// Certificate rotation on a **live** HTTP/3 endpoint (D7): a QUIC endpoint
/// freezes its TLS at creation, so the swap rebuilds it on the socket it
/// already holds. The port never closes, the new material answers h3 and the
/// rotated-out root fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http3_reload_applies_new_tls_on_the_same_socket() {
    let (origin, _seen) = start_origin().await;
    let metrics = Arc::new(Metrics::default());
    let mut proxy = bind(vec![quic_listener(origin)], Arc::clone(&metrics))
        .await
        .expect("bind proxy");
    let addr = proxy.local_addrs()[0].1;

    let mut client = connect(addr).await;
    assert_eq!(
        client.request("GET", "/hello", &[], None).await.status,
        StatusCode::OK
    );

    // Same name and address, new certificate + key (`mtls-server`, issued by
    // the CA the new client trusts).
    let rotated = listener(origin)
        .with_server_tls(server_tls(MTLS_SERVER, MTLS_SERVER_KEY, &[]))
        .with_quic(true);
    let summary = proxy
        .apply(vec![rotated])
        .await
        .expect("the rotation is applied, not refused");
    assert_eq!(summary.kept, 1, "the TCP socket is kept");

    // No connection was cut: the session opened before the renewal still
    // serves, because the rotation changed the certificate a *new* handshake
    // sees, not the endpoint.
    assert_eq!(
        client.request("GET", "/hello", &[], None).await.status,
        StatusCode::OK,
        "the connection opened before the rotation must keep serving"
    );
    drop(client);

    // The rotated-out root no longer authenticates the listener; the new one
    // speaks h3 on the same address.
    let stale = tokio::time::timeout(WAIT, try_connect(addr)).await;
    assert!(
        matches!(stale, Ok(Err(_))),
        "a client trusting the rotated-out root must be refused its handshake"
    );
    let mut fresh = tokio::time::timeout(
        WAIT,
        try_connect_with(addr, client_config_with_root(MTLS_CA), "localhost"),
    )
    .await
    .expect("connect in time")
    .expect("h3 handshake with the new certificate");
    assert_eq!(
        fresh.request("GET", "/hello", &[], None).await.status,
        StatusCode::OK
    );
    drop(fresh);

    // Turning QUIC off is still a supported hot swap: the UDP endpoint closes
    // and new h3 connections are refused while the TCP socket stays.
    let tcp_only = listener(origin).with_server_tls(server_tls(MTLS_SERVER, MTLS_SERVER_KEY, &[]));
    let summary = proxy.apply(vec![tcp_only]).await.expect("apply quic=false");
    assert_eq!(summary.kept, 1);
    let refused = tokio::time::timeout(WAIT, try_connect(addr)).await;
    assert!(
        matches!(refused, Ok(Err(_))),
        "an h3 connection must fail after quic = false"
    );
    // The TCP listener is still there and still speaks TLS, with the
    // certificate it was renewed to.
    let connector = tls::client_config(
        Some(MTLS_CA),
        true,
        None,
        &["http/1.1".into()],
        TlsVersion::V1_3,
    )
    .expect("client tls");
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let name = tls::server_name_for(&connector, addr);
    let mut stream = connector
        .connector
        .connect(name, tcp)
        .await
        .expect("tls handshake after quic off");
    stream
        .write_all(b"GET /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write h1");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("read h1");
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 200 "), "{text}");
    assert!(text.ends_with("hello from origin"), "{text}");
}

// ------------------------------------------------- connection close paths ---

/// Polls the h3 close counters until both thresholds are met (the accept loop
/// observes the peer's CONNECTION_CLOSE asynchronously).
async fn wait_for_closes(metrics: &Metrics, clean: u64, errors: u64) {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let seen_clean = metrics.h3_clean_closes.load(Ordering::Relaxed);
        let seen_errors = metrics.h3_connection_errors.load(Ordering::Relaxed);
        if seen_clean >= clean && seen_errors >= errors {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "clean_closes={seen_clean} connection_errors={seen_errors}, \
             wanted >= {clean} and >= {errors}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A normal close (QUIC application code `0`, what aioquic and quic-go send)
/// is the end of a session: it is counted as clean and never as an error, so
/// no `WARN` line is produced.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_normal_quic_close_is_counted_clean_and_never_an_error() {
    let (origin, _seen) = start_origin().await;
    let metrics = Arc::new(Metrics::default());
    let (proxy, addr) = start_proxy(quic_listener(origin), Arc::clone(&metrics)).await;
    let mut client = connect(addr).await;
    let answer = client.request("GET", "/hello", &[], None).await;
    assert_eq!(answer.status, StatusCode::OK);

    client.close_with(0, b"done");
    wait_for_closes(&metrics, 1, 0).await;

    assert_eq!(
        metrics.h3_connection_errors.load(Ordering::Relaxed),
        0,
        "a clean close must never increment the error counter (no WARN)"
    );
    drop(client);
    drop(proxy);
}

/// `H3_NO_ERROR` (`0x0100`, RFC 9114 §8.1) is the other normal close and is
/// classified the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_h3_no_error_close_is_counted_clean() {
    let (origin, _seen) = start_origin().await;
    let metrics = Arc::new(Metrics::default());
    let (proxy, addr) = start_proxy(quic_listener(origin), Arc::clone(&metrics)).await;
    let client = connect(addr).await;

    client.close_with(0x0100, b"bye");
    wait_for_closes(&metrics, 1, 0).await;

    assert_eq!(
        metrics.h3_connection_errors.load(Ordering::Relaxed),
        0,
        "H3_NO_ERROR must never increment the error counter"
    );
    drop(client);
    drop(proxy);
}

/// A real error is never swallowed: a peer close with an HTTP/3 protocol
/// error code increments the error counter (the same branch that emits the
/// `WARN`), is not counted as clean, and the listener keeps serving.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_protocol_error_close_is_counted_and_the_proxy_keeps_serving() {
    let (origin, _seen) = start_origin().await;
    let metrics = Arc::new(Metrics::default());
    let (proxy, addr) = start_proxy(quic_listener(origin), Arc::clone(&metrics)).await;
    let first = connect(addr).await;

    first.close_with(0x0101, b"protocol error");
    wait_for_closes(&metrics, 0, 1).await;

    assert_eq!(
        metrics.h3_clean_closes.load(Ordering::Relaxed),
        0,
        "H3_GENERAL_PROTOCOL_ERROR must never count as a clean close"
    );

    // The connection is gone, the listener is not: a fresh client is served.
    let mut second = connect(addr).await;
    let answer = second.request("GET", "/hello", &[], None).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body, b"hello from origin");
    assert_eq!(metrics.connections_accepted.load(Ordering::Relaxed), 2);

    drop(first);
    drop(second);
    drop(proxy);
}
