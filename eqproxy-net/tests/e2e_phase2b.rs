//! Phase 2b E2E tests with **real sockets**: TLS termination (A11),
//! TLS to backends (A12), ALPN (A14), weighted RR balancing (B1/B7), TCP
//! health checks (B11) and PROXY protocol v1 (A9). One test per
//! PARITY_MATRIX row + error and limit cases.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use eqproxy_core::{Metrics, shutdown};
use eqproxy_net::health::HealthCheck;
use eqproxy_net::tls::{self, ClientTls, TlsVersion};
use eqproxy_net::{
    Balancer, BoundProxy, ProxyMode, ProxyProtocolMode, ResolvedBackend, ResolvedListener,
    ResolvedServer, bind,
};

const WAIT: Duration = Duration::from_secs(5);
const CERT: &[u8] = include_bytes!("fixtures/cert.pem");
const KEY: &[u8] = include_bytes!("fixtures/key.pem");

// ---------------------------------------------------------------- helpers ---

/// Pure echo backend (no identification byte).
async fn start_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("addr echo");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if socket.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// Backend that writes its `id` on accept and echoes the rest.
async fn start_marker_echo(id: u8) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("addr echo");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = socket.write_all(&[id]).await;
                let mut buf = vec![0u8; 4096];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if socket.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// TLS echo backend (A12 as origin server).
async fn start_tls_echo() -> SocketAddr {
    let server = tls::server_config(CERT, KEY, &[], TlsVersion::V1_2).expect("server tls");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("addr echo");
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let server = server.clone();
            tokio::spawn(async move {
                let Ok(stream) = server.acceptor.accept(socket).await else {
                    return;
                };
                let (mut read, mut write) = tokio::io::split(stream);
                let mut buf = vec![0u8; 4096];
                loop {
                    match read.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if write.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// Puerto de loopback libre (sin listener): los connects fallan al instante.
async fn free_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    addr
}

fn base_listener(name: &str, backend: Arc<ResolvedBackend>) -> ResolvedListener {
    ResolvedListener::new(
        name,
        "127.0.0.1:0".parse().expect("addr"),
        backend.name.clone(),
        backend.servers[0].addr,
        ProxyMode::Tcp,
        64,
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(30),
    )
    .with_backend(backend)
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
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve must finish")
        .expect("join");
}

fn test_client(server_name: Option<&str>, alpn: &[&str]) -> ClientTls {
    let alpn: Vec<String> = alpn.iter().map(|p| (*p).to_owned()).collect();
    tls::client_config(Some(CERT), true, server_name, &alpn, TlsVersion::V1_2)
        .expect("cliente tls de test")
}

async fn tls_roundtrip(stream: &mut tokio_rustls::client::TlsStream<TcpStream>, payload: &[u8]) {
    stream.write_all(payload).await.expect("write tls");
    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(WAIT, stream.read_exact(&mut received))
        .await
        .expect("eco tls a tiempo")
        .expect("eco tls completo");
    assert_eq!(received, payload, "TLS echo must be byte for byte");
}

// ----------------------------------------------------------- A11 / A14 -----

#[cfg_attr(
    miri,
    ignore = "requiere sockets TCP: miri no soporta red (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_termination_e2e() {
    let backend = start_echo().await;
    let metrics = Arc::new(Metrics::default());
    let server = tls::server_config(CERT, KEY, &["http/1.1".to_owned()], TlsVersion::V1_2)
        .expect("server tls");
    let cfg = base_listener("web", Arc::new(ResolvedBackend::single("api", backend)))
        .with_server_tls(server);
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let client = test_client(Some("localhost"), &["http/1.1"]);
    let name = tls::server_name_for(&client, proxy_addr);
    let stream = tokio::time::timeout(
        WAIT,
        client
            .connector
            .connect(name, TcpStream::connect(proxy_addr).await.expect("connect")),
    )
    .await
    .expect("handshake a tiempo")
    .expect("handshake TLS contra el listener");
    let mut stream = stream;
    tls_roundtrip(&mut stream, &vec![0xABu8; 4096]).await;
    drop(stream);

    tokio::time::sleep(Duration::from_millis(100)).await;
    let snap = metrics.snapshot();
    assert_eq!(snap.connections_accepted, 1);
    assert_eq!(snap.tls_handshake_failures, 0);
    assert_eq!(snap.bytes_client_to_backend, 4096);
    assert_eq!(snap.bytes_backend_to_client, 4096);

    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "requiere sockets TCP: miri no soporta red (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alpn_negotiation() {
    let backend = start_marker_echo(b'X').await;
    let server = tls::server_config(CERT, KEY, &["http/1.1".to_owned()], TlsVersion::V1_2)
        .expect("server tls");
    let cfg = base_listener("web", Arc::new(ResolvedBackend::single("api", backend)))
        .with_server_tls(server);
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::new(Metrics::default())).await;

    // Client offering h2 and http/1.1: negotiates http/1.1 (the only one supported).
    let client = test_client(Some("localhost"), &["h2", "http/1.1"]);
    let name = tls::server_name_for(&client, proxy_addr);
    let stream = tokio::time::timeout(
        WAIT,
        client
            .connector
            .connect(name, TcpStream::connect(proxy_addr).await.expect("connect")),
    )
    .await
    .expect("handshake a tiempo")
    .expect("handshake TLS");
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(&b"http/1.1"[..]),
        "must negotiate http/1.1"
    );
    drop(stream);

    // Client offering only h2: the handshake must fail (no common protocol).
    let h2_only = test_client(Some("localhost"), &["h2"]);
    let name = tls::server_name_for(&h2_only, proxy_addr);
    let result = tokio::time::timeout(
        WAIT,
        h2_only
            .connector
            .connect(name, TcpStream::connect(proxy_addr).await.expect("connect")),
    )
    .await
    .expect("handshake a tiempo");
    assert!(
        result.is_err(),
        "h2-only must not negotiate against an h1 listener"
    );

    stop_proxy(handle, serve).await;
}

// ------------------------------------------------------------- A12 ---------

#[cfg_attr(
    miri,
    ignore = "requiere sockets TCP: miri no soporta red (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_backend_e2e() {
    let backend_addr = start_tls_echo().await;
    let metrics = Arc::new(Metrics::default());
    let backend_tls =
        tls::client_config(Some(CERT), true, None, &[], TlsVersion::V1_2).expect("client tls");
    let backend = ResolvedBackend::single("api", backend_addr).with_tls(backend_tls);
    let cfg = base_listener("web", Arc::new(backend));
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
    let payload = vec![0xCDu8; 1024];
    client.write_all(&payload).await.expect("write");
    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(WAIT, client.read_exact(&mut received))
        .await
        .expect("eco a tiempo")
        .expect("eco completo");
    assert_eq!(received, payload, "backend TLS echo must be intact");

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(metrics.snapshot().tls_handshake_failures, 0);

    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "requiere sockets TCP: miri no soporta red (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_backend_verification_failure_is_counted_and_rejected() {
    // The backend uses the test cert; without `ca_file` it is not in the
    // Mozilla roots → verification (on by default) must reject.
    let backend_addr = start_tls_echo().await;
    let metrics = Arc::new(Metrics::default());
    let backend_tls = tls::client_config(None, true, None, &[], TlsVersion::V1_2).expect("tls");
    let backend = ResolvedBackend::single("api", backend_addr).with_tls(backend_tls);
    let cfg = base_listener("web", Arc::new(backend));
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
    client.write_all(b"ping").await.expect("write");
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(WAIT, client.read(&mut buf)).await;
    // EOF o RST (con datos sin leer en el buffer el SO responde RST), pero
    // never echo data: TLS to the backend failed, there is no tunnel.
    match read {
        Ok(Ok(0)) => {}
        Ok(Err(err)) if err.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("the tunnel must close without data when TLS fails: {other:?}"),
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
    let snap = metrics.snapshot();
    assert_eq!(snap.tls_handshake_failures, 1, "snap: {snap}");

    stop_proxy(handle, serve).await;
}

// ------------------------------------------------- B1 / B7 / B11 / A9 ------

#[cfg_attr(
    miri,
    ignore = "requiere sockets TCP: miri no soporta red (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn balancer_roundrobin() {
    let a = start_marker_echo(b'A').await;
    let b = start_marker_echo(b'B').await;
    let c = start_marker_echo(b'C').await;
    let backend = ResolvedBackend::new(
        "api",
        vec![
            ResolvedServer { addr: a, weight: 1 },
            ResolvedServer { addr: b, weight: 1 },
            ResolvedServer { addr: c, weight: 1 },
        ],
        3,
        2,
    );
    let cfg = base_listener("web", Arc::new(backend));
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::new(Metrics::default())).await;

    let mut seen = Vec::new();
    for _ in 0..6 {
        let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
        let mut id = [0u8; 1];
        tokio::time::timeout(WAIT, client.read_exact(&mut id))
            .await
            .expect("id a tiempo")
            .expect("id");
        seen.push(id[0] as char);
    }

    assert_eq!(
        seen,
        vec!['A', 'B', 'C', 'A', 'B', 'C'],
        "RR with equal weights must rotate in configuration order"
    );
    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "requiere sockets TCP: miri no soporta red (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn balancer_weights() {
    let a = start_marker_echo(b'A').await;
    let b = start_marker_echo(b'B').await;
    let backend = ResolvedBackend::new(
        "api",
        vec![
            ResolvedServer { addr: a, weight: 1 },
            ResolvedServer { addr: b, weight: 3 },
        ],
        3,
        2,
    );
    let cfg = base_listener("web", Arc::new(backend));
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::new(Metrics::default())).await;

    let mut counts = [0u32; 2];
    for _ in 0..8 {
        let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
        let mut id = [0u8; 1];
        tokio::time::timeout(WAIT, client.read_exact(&mut id))
            .await
            .expect("id a tiempo")
            .expect("id");
        counts[usize::from(id[0] - b'A')] += 1;
    }

    assert_eq!(counts, [2, 6], "weights 1:3 → 2:6 ratio over two cycles");
    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "requiere sockets TCP: miri no soporta red (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn healthchecks_e2e() {
    let a = start_marker_echo(b'A').await;
    let b_addr = free_port().await; // sin listener: los checks fallan
    let metrics = Arc::new(Metrics::default());
    let backend = ResolvedBackend::new(
        "api",
        vec![
            ResolvedServer { addr: a, weight: 1 },
            ResolvedServer {
                addr: b_addr,
                weight: 1,
            },
        ],
        2,
        2,
    )
    .with_health_check(HealthCheck {
        interval: Duration::from_millis(80),
        timeout: Duration::from_millis(80),
    });
    let cfg = base_listener("web", Arc::new(backend));
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    // With B dead, `fall = 2` drops it in ~2 cycles; traffic goes only to A.
    tokio::time::sleep(Duration::from_millis(600)).await;
    for _ in 0..6 {
        let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
        let mut id = [0u8; 1];
        tokio::time::timeout(WAIT, client.read_exact(&mut id))
            .await
            .expect("id a tiempo")
            .expect("id");
        assert_eq!(id[0], b'A', "with B down all traffic goes to A");
    }

    // We raise B at its same address: `rise = 2` recovers it in ~2 cycles.
    let listener = TcpListener::bind(b_addr).await.expect("rebind de B");
    let acceptor = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = socket.write_all(b"B").await;
                let mut buf = vec![0u8; 1024];
                while matches!(socket.read(&mut buf).await, Ok(n) if n > 0) {}
            });
        }
    });
    tokio::time::sleep(Duration::from_millis(600)).await;
    let mut seen_b = false;
    for _ in 0..8 {
        let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
        let mut id = [0u8; 1];
        tokio::time::timeout(WAIT, client.read_exact(&mut id))
            .await
            .expect("id a tiempo")
            .expect("id");
        if id[0] == b'B' {
            seen_b = true;
        }
    }
    assert!(seen_b, "with B operational it must receive traffic again");
    acceptor.abort();

    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "requiere sockets TCP: miri no soporta red (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_protocol_v1() {
    // Backend que espera la cabecera PROXY v1 y responde con ella.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let backend_addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut header = Vec::new();
                let mut byte = [0u8; 1];
                while matches!(socket.read(&mut byte).await, Ok(1)) {
                    header.push(byte[0]);
                    if header.ends_with(b"\r\n") {
                        break;
                    }
                }
                let mut payload = [0u8; 4];
                let _ = socket.read_exact(&mut payload).await;
                let _ = socket.write_all(&header).await;
                let _ = socket.write_all(b"pong").await;
            });
        }
    });

    let backend =
        ResolvedBackend::single("api", backend_addr).with_proxy_protocol(ProxyProtocolMode::V1);
    let cfg = base_listener("web", Arc::new(backend));
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::new(Metrics::default())).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
    let client_port = client.local_addr().expect("local").port();
    client.write_all(b"ping").await.expect("write");
    let expected = format!(
        "PROXY TCP4 127.0.0.1 127.0.0.1 {client_port} {}\r\npong",
        proxy_addr.port()
    );
    let mut response = vec![0u8; expected.len()];
    tokio::time::timeout(WAIT, client.read_exact(&mut response))
        .await
        .expect("respuesta a tiempo")
        .expect("respuesta completa");
    assert_eq!(
        response,
        expected.as_bytes(),
        "the PROXY v1 header must reflect the real peer and destination"
    );

    drop(client); // without this, `serve` waits for the live tunnel to drain
    stop_proxy(handle, serve).await;
}

// --------------------------------------------------- errors and limits -----

#[cfg_attr(
    miri,
    ignore = "requiere sockets TCP: miri no soporta red (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_servers_down_returns_503_in_http_mode() {
    let dead = free_port().await;
    let metrics = Arc::new(Metrics::default());
    let backend = ResolvedBackend::new(
        "api",
        vec![ResolvedServer {
            addr: dead,
            weight: 1,
        }],
        1,
        1,
    )
    .with_health_check(HealthCheck {
        interval: Duration::from_millis(50),
        timeout: Duration::from_millis(50),
    });
    let mut cfg = base_listener("web", Arc::new(backend));
    cfg.mode = ProxyMode::Http;
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    // We wait for the health check to drop the single server (fall = 1).
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
    client
        .write_all(b"GET / HTTP/1.1\r\nhost: test\r\n\r\n")
        .await
        .expect("write");
    let mut response = vec![0u8; 2048];
    let n = tokio::time::timeout(WAIT, client.read(&mut response))
        .await
        .expect("respuesta a tiempo")
        .expect("read");
    let text = String::from_utf8_lossy(&response[..n]).to_string();
    assert!(
        text.starts_with("HTTP/1.1 503"),
        "with no servers it must be 503: {text}"
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(metrics.snapshot().no_available_server >= 1);

    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "requiere sockets TCP: miri no soporta red (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_servers_down_closes_connection_in_tcp_mode() {
    let dead = free_port().await;
    let metrics = Arc::new(Metrics::default());
    let backend = ResolvedBackend::new(
        "api",
        vec![ResolvedServer {
            addr: dead,
            weight: 1,
        }],
        1,
        1,
    )
    .with_health_check(HealthCheck {
        interval: Duration::from_millis(50),
        timeout: Duration::from_millis(50),
    });
    let cfg = base_listener("web", Arc::new(backend));
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
    let mut buf = [0u8; 8];
    let read = tokio::time::timeout(WAIT, client.read(&mut buf))
        .await
        .expect("cierre a tiempo")
        .expect("read");
    assert_eq!(read, 0, "TCP mode must close without data");

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(metrics.snapshot().no_available_server >= 1);

    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "requiere sockets TCP: miri no soporta red (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drained_server_is_skipped() {
    let a = start_marker_echo(b'A').await;
    let drained = start_marker_echo(b'D').await;
    let backend = ResolvedBackend::new(
        "api",
        vec![
            ResolvedServer { addr: a, weight: 1 },
            ResolvedServer {
                addr: drained,
                weight: 0,
            },
        ],
        3,
        2,
    );
    let cfg = base_listener("web", Arc::new(backend));
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::new(Metrics::default())).await;

    for _ in 0..4 {
        let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
        let mut id = [0u8; 1];
        tokio::time::timeout(WAIT, client.read_exact(&mut id))
            .await
            .expect("id a tiempo")
            .expect("id");
        assert_eq!(id[0], b'A', "weight = 0 must never receive traffic");
    }

    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "requiere sockets TCP: miri no soporta red (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_garbage_handshake_is_counted_as_tls_failure() {
    let backend = start_marker_echo(b'X').await;
    let metrics = Arc::new(Metrics::default());
    let server = tls::server_config(CERT, KEY, &[], TlsVersion::V1_2).expect("server tls");
    let cfg = base_listener("web", Arc::new(ResolvedBackend::single("api", backend)))
        .with_server_tls(server);
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
    client.write_all(b"this is not TLS").await.expect("write");
    let mut buf = [0u8; 8];
    let _ = tokio::time::timeout(WAIT, client.read(&mut buf)).await;

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        metrics.snapshot().tls_handshake_failures >= 1,
        "the garbage handshake must be counted"
    );

    stop_proxy(handle, serve).await;
}

// Tell the compiler Balancer is used in the module (public helpers).
#[allow(dead_code)]
fn _balancer_is_exported() -> Balancer {
    Balancer::new(vec![], 3, 2)
}
