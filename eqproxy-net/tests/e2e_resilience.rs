//! E2E tests with **real sockets** for the v0.5 resilience features:
//! connect-phase retries with idempotence gate (B-H7), bounded backend
//! queue with explicit rejection (B-H7/B-E7), PROXY v1 reception with
//! allowlisted origins (B-H9/B-E10), forwarded headers (B-N4), custom
//! local responses (C9) and mTLS client certificates (A15).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use eqproxy_core::expectation::IpAllowlist;
use eqproxy_core::{Metrics, shutdown};
use eqproxy_net::proxy::{ForwardedMode, LocalResponse, QueueSettings, RetryPolicy};
use eqproxy_net::tls::{self, TlsVersion};
use eqproxy_net::{
    BoundProxy, ProxyMode, ProxyProtocolMode, ResolvedBackend, ResolvedListener, ResolvedServer,
    bind,
};

const WAIT: Duration = Duration::from_secs(5);
const MTLS_CA: &[u8] = include_bytes!("fixtures/mtls-ca.pem");
const MTLS_SERVER: &[u8] = include_bytes!("fixtures/mtls-server.pem");
const MTLS_SERVER_KEY: &[u8] = include_bytes!("fixtures/mtls-server.key");
const MTLS_CLIENT: &[u8] = include_bytes!("fixtures/mtls-client.pem");
const MTLS_CLIENT_KEY: &[u8] = include_bytes!("fixtures/mtls-client.key");

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

/// Minimal HTTP backend: reads each full request (head + `Content-Length`
/// body) and answers `200 OK` with an empty body (keep-alive).
async fn start_ok_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ok backend");
    let addr = listener.local_addr().expect("addr ok backend");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
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
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
                    let body_needed = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    while total < head_end + body_needed {
                        match socket.read(&mut buf[total..]).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => total += n,
                        }
                    }
                    if socket
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// HTTP backend answering `status` with `marker` as body (keep-alive).
async fn start_status_backend(status: u16, marker: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind status backend");
    let addr = listener.local_addr().expect("addr status backend");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
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
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
                    let body_needed = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    while total < head_end + body_needed {
                        match socket.read(&mut buf[total..]).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => total += n,
                        }
                    }
                    let reason = if status == 500 {
                        "Internal Server Error"
                    } else {
                        "OK"
                    };
                    // A closing server announces it in the response
                    // (RFC 9112 §9.6): `Connection: close` must appear in
                    // the head so proxies never pool this connection.
                    let close = head.contains("connection: close");
                    let response = if close {
                        format!(
                            "HTTP/1.1 {status} {reason}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{marker}",
                            marker.len()
                        )
                    } else {
                        format!(
                            "HTTP/1.1 {status} {reason}\r\ncontent-length: {}\r\n\r\n{marker}",
                            marker.len()
                        )
                    };
                    if socket.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                    if close {
                        let _ = socket.shutdown().await;
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// HTTP backend that answers `200` with the **received request head** as
/// body and `connection: close` (one exchange per connection).
async fn start_head_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind head echo");
    let addr = listener.local_addr().expect("addr head echo");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
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
                let head = &buf[..head_end];
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    head.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.write_all(head).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    addr
}

/// Free loopback port (no listener): connects fail instantly.
async fn free_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    addr
}

fn http_listener(name: &str, backend: Arc<ResolvedBackend>) -> ResolvedListener {
    ResolvedListener::new(
        name,
        "127.0.0.1:0".parse().expect("addr"),
        backend.name.clone(),
        backend.servers[0].addr.clone(),
        ProxyMode::Http,
        64,
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(30),
    )
    .with_backend(backend)
}

fn tcp_listener(name: &str, backend: Arc<ResolvedBackend>) -> ResolvedListener {
    let mut cfg = http_listener(name, backend);
    cfg.mode = ProxyMode::Tcp;
    cfg
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

/// One HTTP exchange: writes the raw request, reads to EOF (bounded).
async fn http_exchange(proxy: SocketAddr, request: &str) -> String {
    let mut client = TcpStream::connect(proxy).await.expect("connect proxy");
    client.write_all(request.as_bytes()).await.expect("write");
    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let got = tokio::time::timeout(WAIT, client.read(&mut buf))
            .await
            .expect("response in time")
            .expect("read");
        if got == 0 {
            break;
        }
        response.extend_from_slice(&buf[..got]);
    }
    String::from_utf8_lossy(&response).into_owned()
}

fn get_request() -> &'static str {
    "GET /x HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n"
}

fn post_request() -> &'static str {
    "POST /x HTTP/1.1\r\nhost: t\r\ncontent-length: 3\r\nconnection: close\r\n\r\nabc"
}

/// Response body of a head-echo exchange (after the `\r\n\r\n` split).
fn response_body(response: &str) -> &str {
    response.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}

// ------------------------------------------------------- B-H7: retries ------

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retry_saves_idempotent_get_from_dead_server() {
    let dead = free_port().await;
    let live = start_ok_backend().await;
    let metrics = Arc::new(Metrics::default());
    let backend = ResolvedBackend::new(
        "api",
        vec![
            ResolvedServer {
                addr: dead.into(),
                weight: 1,
            },
            ResolvedServer {
                addr: live.into(),
                weight: 1,
            },
        ],
        3,
        2,
    )
    .with_retries(RetryPolicy {
        max: 1,
        non_idempotent: false,
    });
    let cfg = http_listener("web", Arc::new(backend));
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    // Whatever the RR order, the dead pick must be saved by the redial.
    for i in 0..6 {
        let response = http_exchange(proxy_addr, get_request()).await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "GET {i} must succeed via retry, got: {response:?}"
        );
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let snap = metrics.snapshot();
    assert!(
        snap.retry_attempts >= 1,
        "the redial must be counted: {snap:?}"
    );
    assert_eq!(
        snap.http_requests_proxied, 6,
        "all six exchanges complete: {snap:?}"
    );

    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_idempotent_post_is_never_retried_without_opt_in() {
    let dead = free_port().await;
    let live = start_ok_backend().await;
    let metrics = Arc::new(Metrics::default());
    let backend = ResolvedBackend::new(
        "api",
        vec![
            ResolvedServer {
                addr: dead.into(),
                weight: 1,
            },
            ResolvedServer {
                addr: live.into(),
                weight: 1,
            },
        ],
        3,
        2,
    )
    .with_retries(RetryPolicy {
        max: 1,
        non_idempotent: false,
    });
    let cfg = http_listener("web", Arc::new(backend));
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let mut ok = 0;
    let mut bad_gateway = 0;
    for _ in 0..6 {
        let response = http_exchange(proxy_addr, post_request()).await;
        if response.starts_with("HTTP/1.1 200") {
            ok += 1;
        } else if response.starts_with("HTTP/1.1 502") {
            bad_gateway += 1;
        } else {
            panic!("unexpected response: {response:?}");
        }
    }
    assert!(ok >= 1, "the live server must serve its share");
    assert!(
        bad_gateway >= 1,
        "the dead pick must NOT be saved for POST without opt-in"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        metrics.snapshot().retry_attempts,
        0,
        "non-idempotent exchanges must never redial without the opt-in"
    );

    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_idempotent_opt_in_allows_post_retry() {
    let dead = free_port().await;
    let live = start_ok_backend().await;
    let metrics = Arc::new(Metrics::default());
    let backend = ResolvedBackend::new(
        "api",
        vec![
            ResolvedServer {
                addr: dead.into(),
                weight: 1,
            },
            ResolvedServer {
                addr: live.into(),
                weight: 1,
            },
        ],
        3,
        2,
    )
    .with_retries(RetryPolicy {
        max: 1,
        non_idempotent: true,
    });
    let cfg = http_listener("web", Arc::new(backend));
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    for i in 0..6 {
        let response = http_exchange(proxy_addr, post_request()).await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "POST {i} must succeed via explicit opt-in retry, got: {response:?}"
        );
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        metrics.snapshot().retry_attempts >= 1,
        "the opt-in redial must be counted"
    );

    stop_proxy(handle, serve).await;
}

// -------------------------------------------------------- B-H7: queue -------

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_queue_rejects_explicitly_and_waiters_time_out() {
    // All servers drained (weight 0): the queue path is deterministic.
    let drained = free_port().await;
    let metrics = Arc::new(Metrics::default());
    let backend = ResolvedBackend::new(
        "api",
        vec![ResolvedServer {
            addr: drained.into(),
            weight: 0,
        }],
        3,
        2,
    )
    .with_queue(QueueSettings {
        maxqueue: 1,
        timeout: Duration::from_millis(600),
    });
    let cfg = http_listener("web", Arc::new(backend));
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    // Waiter A occupies the only queue slot and waits for a server.
    let first = tokio::spawn({
        let request = get_request().to_owned();
        async move { http_exchange(proxy_addr, &request).await }
    });
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Waiter B arrives to a full queue: explicit 503, never a silent hang.
    let started = std::time::Instant::now();
    let second = http_exchange(proxy_addr, get_request()).await;
    assert!(
        second.starts_with("HTTP/1.1 503"),
        "full queue must reject with 503, got: {second:?}"
    );
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "full-queue rejection must be immediate, took {:?}",
        started.elapsed()
    );

    // Waiter A expires at the queue timeout: explicit 503 too.
    let first = tokio::time::timeout(WAIT, first)
        .await
        .expect("first request must finish")
        .expect("join");
    assert!(
        first.starts_with("HTTP/1.1 503"),
        "queue timeout must answer 503, got: {first:?}"
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    let snap = metrics.snapshot();
    assert!(snap.queue_full >= 1, "queue_full must be counted: {snap:?}");
    assert!(
        snap.queue_timeout >= 1,
        "queue_timeout must be counted: {snap:?}"
    );

    stop_proxy(handle, serve).await;
}

// ------------------------------------------------------ C9: local reply -----

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_response_serves_the_configured_body() {
    let drained = free_port().await;
    let metrics = Arc::new(Metrics::default());
    let backend = ResolvedBackend::new(
        "api",
        vec![ResolvedServer {
            addr: drained.into(),
            weight: 0,
        }],
        3,
        2,
    );
    let cfg = http_listener("web", Arc::new(backend)).with_local_response(LocalResponse {
        status: 503,
        content_type: "text/plain".to_owned(),
        body: "maintenance mode".to_owned(),
    });
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let response = http_exchange(proxy_addr, get_request()).await;
    assert!(
        response.starts_with("HTTP/1.1 503"),
        "must answer the configured status, got: {response:?}"
    );
    assert!(
        response.contains("content-type: text/plain"),
        "must carry the configured content type: {response:?}"
    );
    assert!(
        response.ends_with("maintenance mode"),
        "must carry the configured body: {response:?}"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        metrics.snapshot().local_responses_served >= 1,
        "the custom reply must be counted"
    );

    stop_proxy(handle, serve).await;
}

// --------------------------------------------- B-H9: PROXY v1 reception -----

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_receive_forwards_the_claimed_peer() {
    let echo = start_echo().await;
    let metrics = Arc::new(Metrics::default());
    let backend = ResolvedBackend::new(
        "api",
        vec![ResolvedServer {
            addr: echo.into(),
            weight: 1,
        }],
        3,
        2,
    )
    .with_proxy_protocol(ProxyProtocolMode::V1);
    let cfg = tcp_listener("edge", Arc::new(backend))
        .with_proxy_receive(IpAllowlist::parse(&["127.0.0.1".to_owned()]).expect("allowlist"));
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
    client
        .write_all(b"PROXY TCP4 192.0.2.1 192.0.2.2 443 8443\r\nping")
        .await
        .expect("write");
    let mut echoed = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let got = tokio::time::timeout(WAIT, client.read(&mut buf))
            .await
            .expect("echo in time")
            .expect("read");
        if got == 0 {
            break;
        }
        echoed.extend_from_slice(&buf[..got]);
        if echoed.windows(4).any(|w| w == b"ping") {
            break;
        }
    }
    let echoed = String::from_utf8_lossy(&echoed).into_owned();
    assert!(
        echoed.starts_with("PROXY TCP4 192.0.2.1 127.0.0.1 443 "),
        "the claimed source must reach the backend, got: {echoed:?}"
    );
    assert!(
        echoed.ends_with("ping"),
        "payload must pass, got: {echoed:?}"
    );

    drop(client);
    stop_proxy(handle, serve).await;
}

/// B-H9/B-E10 (A10): the same reception journey with a PROXY v2 binary
/// header — auto-detected by signature; the claimed source reaches the
/// backend and no payload byte is consumed.
#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_receive_accepts_the_v2_header() {
    let echo = start_echo().await;
    let metrics = Arc::new(Metrics::default());
    let backend = ResolvedBackend::new(
        "api",
        vec![ResolvedServer {
            addr: echo.into(),
            weight: 1,
        }],
        3,
        2,
    )
    .with_proxy_protocol(ProxyProtocolMode::V1);
    let cfg = tcp_listener("edge", Arc::new(backend))
        .with_proxy_receive(IpAllowlist::parse(&["127.0.0.1".to_owned()]).expect("allowlist"));
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
    let mut hello = eqproxy_net::proxy_proto::encode_v2(
        "192.0.2.1:443".parse().expect("claimed"),
        "192.0.2.2:8443".parse().expect("dest"),
    );
    hello.extend_from_slice(b"ping");
    client.write_all(&hello).await.expect("write");
    let mut echoed = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let got = tokio::time::timeout(WAIT, client.read(&mut buf))
            .await
            .expect("echo in time")
            .expect("read");
        if got == 0 {
            break;
        }
        echoed.extend_from_slice(&buf[..got]);
        if echoed.windows(4).any(|w| w == b"ping") {
            break;
        }
    }
    let echoed = String::from_utf8_lossy(&echoed).into_owned();
    assert!(
        echoed.starts_with("PROXY TCP4 192.0.2.1 127.0.0.1 443 "),
        "the v2-claimed source must reach the backend, got: {echoed:?}"
    );
    assert!(
        echoed.ends_with("ping"),
        "payload must pass, got: {echoed:?}"
    );

    drop(client);
    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_receive_rejects_non_allowlisted_origin() {
    let echo = start_echo().await;
    let metrics = Arc::new(Metrics::default());
    let backend = ResolvedBackend::new(
        "api",
        vec![ResolvedServer {
            addr: echo.into(),
            weight: 1,
        }],
        3,
        2,
    );
    // The test client comes from 127.0.0.1: not in this allowlist.
    let cfg = tcp_listener("edge", Arc::new(backend))
        .with_proxy_receive(IpAllowlist::parse(&["10.0.0.0/8".to_owned()]).expect("allowlist"));
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
    client
        .write_all(b"PROXY TCP4 192.0.2.1 192.0.2.2 443 8443\r\nping")
        .await
        .expect("write");
    let mut buf = [0u8; 8];
    // The deny path closes without draining the request bytes, so TCP
    // resets the connection instead of a clean EOF — both prove rejection.
    let got = tokio::time::timeout(WAIT, client.read(&mut buf))
        .await
        .expect("close in time");
    assert!(
        matches!(got, Ok(0) | Err(_)),
        "a denied origin must be closed without data, got: {got:?}"
    );

    drop(client);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let snap = metrics.snapshot();
    assert!(
        snap.proxy_protocol_denied >= 1,
        "the denial must be counted: {snap:?}"
    );

    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_receive_rejects_invalid_header() {
    let echo = start_echo().await;
    let metrics = Arc::new(Metrics::default());
    let backend = ResolvedBackend::new(
        "api",
        vec![ResolvedServer {
            addr: echo.into(),
            weight: 1,
        }],
        3,
        2,
    );
    let cfg = tcp_listener("edge", Arc::new(backend))
        .with_proxy_receive(IpAllowlist::parse(&["127.0.0.1".to_owned()]).expect("allowlist"));
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
    client
        .write_all(b"NOT A PROXY LINE\r\n")
        .await
        .expect("write");
    let mut buf = [0u8; 8];
    // The reject path closes at the first non-matching byte without
    // draining the request bytes, so TCP may reset instead of a clean
    // EOF — both prove rejection (the deny path above documents the
    // same artifact).
    let got = tokio::time::timeout(WAIT, client.read(&mut buf))
        .await
        .expect("close in time");
    assert!(
        matches!(got, Ok(0) | Err(_)),
        "an invalid PROXY header must be closed without data: {got:?}"
    );

    drop(client);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let snap = metrics.snapshot();
    assert!(
        snap.proxy_protocol_invalid >= 1,
        "the invalid header must be counted: {snap:?}"
    );

    stop_proxy(handle, serve).await;
}

// -------------------------------------------------- B-N4: forwarded IPs -----

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forwarded_headers_append_and_replace() {
    let echo = start_head_echo().await;

    // Append: the chain keeps the client-provided hops.
    let metrics = Arc::new(Metrics::default());
    let backend = ResolvedBackend::new(
        "api",
        vec![ResolvedServer {
            addr: echo.into(),
            weight: 1,
        }],
        3,
        2,
    );
    let cfg = http_listener("web", Arc::new(backend)).with_forwarded_headers(ForwardedMode::Append);
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;
    let response = http_exchange(
        proxy_addr,
        "GET /x HTTP/1.1\r\nhost: t\r\nx-forwarded-for: 203.0.113.9\r\nx-real-ip: 203.0.113.8\r\nconnection: close\r\n\r\n",
    )
    .await;
    let body = response_body(&response).to_ascii_lowercase();
    assert!(
        body.contains("x-forwarded-for: 203.0.113.9, 127.0.0.1"),
        "append must extend the chain: {body:?}"
    );
    assert!(
        body.contains("x-real-ip: 203.0.113.8"),
        "append must keep an existing x-real-ip: {body:?}"
    );
    stop_proxy(handle, serve).await;

    // Replace: only the real client address survives.
    let metrics = Arc::new(Metrics::default());
    let backend = ResolvedBackend::new(
        "api",
        vec![ResolvedServer {
            addr: echo.into(),
            weight: 1,
        }],
        3,
        2,
    );
    let cfg =
        http_listener("web", Arc::new(backend)).with_forwarded_headers(ForwardedMode::Replace);
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;
    let response = http_exchange(
        proxy_addr,
        "GET /x HTTP/1.1\r\nhost: t\r\nx-forwarded-for: 203.0.113.9, 203.0.113.7\r\nx-real-ip: 203.0.113.8\r\nconnection: close\r\n\r\n",
    )
    .await;
    let body = response_body(&response).to_ascii_lowercase();
    assert!(
        body.contains("x-forwarded-for: 127.0.0.1\r\n")
            || body.trim_end().ends_with("x-forwarded-for: 127.0.0.1"),
        "replace must reset the chain: {body:?}"
    );
    assert!(
        !body.contains("203.0.113"),
        "replace must drop spoofed hops: {body:?}"
    );
    assert!(
        body.contains("x-real-ip: 127.0.0.1"),
        "replace must reset x-real-ip: {body:?}"
    );
    stop_proxy(handle, serve).await;

    // Off (default): the proxy touches nothing.
    let metrics = Arc::new(Metrics::default());
    let backend = ResolvedBackend::new(
        "api",
        vec![ResolvedServer {
            addr: echo.into(),
            weight: 1,
        }],
        3,
        2,
    );
    let cfg = http_listener("web", Arc::new(backend));
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;
    let response = http_exchange(
        proxy_addr,
        "GET /x HTTP/1.1\r\nhost: t\r\nx-forwarded-for: 203.0.113.9\r\nconnection: close\r\n\r\n",
    )
    .await;
    let body = response_body(&response).to_ascii_lowercase();
    assert!(
        body.contains("x-forwarded-for: 203.0.113.9"),
        "off must pass the header untouched: {body:?}"
    );
    assert!(
        !body.contains("x-real-ip"),
        "off must not create headers: {body:?}"
    );
    stop_proxy(handle, serve).await;
}

// ------------------------------------------------- D7: hot certificates ----

/// TLS client trusting exactly `root_pem` (rotation tests).
fn tls_client_with_root(root_pem: &[u8]) -> tokio_rustls::TlsConnector {
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, pem::PemObject};

    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(root_pem) {
        roots.add(cert.expect("root cert")).expect("add root");
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

/// Full byte-for-byte roundtrip through the proxy over TLS.
async fn tls_roundtrip_ok(proxy: SocketAddr, connector: tokio_rustls::TlsConnector, name: &str) {
    let mut stream = mtls_connect(proxy, connector, name)
        .await
        .expect("handshake must pass");
    stream.write_all(b"ping").await.expect("write");
    let mut echoed = [0u8; 4];
    tokio::time::timeout(WAIT, stream.read_exact(&mut echoed))
        .await
        .expect("echo in time")
        .expect("full echo");
    assert_eq!(&echoed, b"ping", "byte-for-byte echo over TLS");
    drop(stream);
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hot_reload_swaps_tls_material_on_the_kept_socket() {
    const OLD_CERT: &[u8] = include_bytes!("fixtures/cert.pem");
    const OLD_KEY: &[u8] = include_bytes!("fixtures/key.pem");

    let echo = start_echo().await;
    let metrics = Arc::new(Metrics::default());
    let old_tls =
        tls::server_config(OLD_CERT, OLD_KEY, None, &[], TlsVersion::V1_2).expect("old tls");
    let backend = ResolvedBackend::new(
        "api",
        vec![ResolvedServer {
            addr: echo.into(),
            weight: 1,
        }],
        3,
        2,
    );
    let cfg = tcp_listener("secure", Arc::new(backend)).with_server_tls(old_tls);
    let bound = bind(vec![cfg], Arc::clone(&metrics)).await.expect("bind");
    let proxy_addr = bound.local_addrs()[0].1;
    let (handle, signal) = shutdown::channel();
    let (reload_tx, reload_rx) = tokio::sync::mpsc::channel(4);
    let serve = tokio::spawn(async move {
        bound
            .serve_with_reloads(signal, WAIT, reload_rx)
            .await
            .expect("serve");
    });

    // Phase 1: the old material answers.
    tls_roundtrip_ok(proxy_addr, tls_client_with_root(OLD_CERT), "127.0.0.1").await;

    // Rotation (D7): same name + same config address → the socket is
    // kept and only the config (the new TLS material) changes.
    let new_tls = tls::server_config(MTLS_SERVER, MTLS_SERVER_KEY, None, &[], TlsVersion::V1_2)
        .expect("new tls");
    let backend = ResolvedBackend::new(
        "api",
        vec![ResolvedServer {
            addr: echo.into(),
            weight: 1,
        }],
        3,
        2,
    );
    let cfg = tcp_listener("secure", Arc::new(backend)).with_server_tls(new_tls);
    reload_tx.send(vec![cfg]).await.expect("send reload");
    let deadline = tokio::time::Instant::now() + WAIT;
    while metrics.snapshot().config_reloads == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the reload must be applied"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Phase 2: the NEW material is live on the same socket — trusting the
    // rotated-out root must fail, trusting the new root must work.
    assert_no_data_flows(
        proxy_addr,
        tls_client_with_root(OLD_CERT),
        "trusting the rotated-out root",
        "127.0.0.1",
    )
    .await;
    tls_roundtrip_ok(proxy_addr, tls_client_with_root(MTLS_CA), "127.0.0.1").await;

    // The swap latency is measured and recorded (PP-04/05).
    let snap = metrics.snapshot();
    assert_eq!(snap.config_reloads, 1, "exactly one swap: {snap:?}");
    assert!(
        snap.config_reload_duration_us > 0,
        "the swap latency must be recorded: {snap:?}"
    );

    drop(reload_tx);
    stop_proxy(handle, serve).await;
}

// -------------------------------------------- B-N10: passive detection ------

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passive_detection_marks_5xx_server_down() {
    use eqproxy_net::health::HealthCheck;

    let failing = start_status_backend(500, "A").await;
    let healthy = start_status_backend(200, "B").await;
    let metrics = Arc::new(Metrics::default());
    let backend = Arc::new(
        ResolvedBackend::new(
            "api",
            vec![
                ResolvedServer {
                    addr: failing.into(),
                    weight: 1,
                },
                ResolvedServer {
                    addr: healthy.into(),
                    weight: 1,
                },
            ],
            2,
            2,
        )
        .with_health_check(
            // The active checker is effectively parked (1h): the fall
            // machine is fed by live traffic and it is what can restore
            // the server (safe-restart rule).
            HealthCheck::tcp(Duration::from_secs(3600), Duration::from_secs(1)).with_passive(true),
        ),
    );
    let cfg = http_listener("web", Arc::clone(&backend));
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let mut responses = Vec::new();
    for _ in 0..6 {
        responses.push(http_exchange(proxy_addr, get_request()).await);
    }

    // The 5xx server serves (and its 500 reaches the client) before the
    // fall threshold trips.
    assert!(
        responses
            .iter()
            .any(|r| r.starts_with("HTTP/1.1 500") && response_body(r) == "A"),
        "the 500 must reach the client before detection: {responses:?}"
    );
    // After the mark, no request may land on the failing server again.
    let last_a = responses
        .iter()
        .rposition(|r| response_body(r) == "A")
        .expect("the failing server must serve at least once");
    assert!(
        responses[last_a + 1..]
            .iter()
            .all(|r| response_body(r) == "B"),
        "after the mark every request must go to the healthy server: {responses:?}"
    );
    assert!(
        !backend.balancer.is_up(failing),
        "two 5xx exchanges with fall = 2 must mark the server DOWN"
    );
    assert!(
        backend.balancer.is_up(healthy),
        "the healthy server stays up"
    );

    stop_proxy(handle, serve).await;
}

// ------------------------------- B-H6: HTTP expect check (active) ----------

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_expect_check_marks_5xx_server_down() {
    use eqproxy_core::expectation::StatusExpectation;
    use eqproxy_net::health::{HealthCheck, HttpCheck, HttpCheckMethod};

    let failing = start_status_backend(500, "A").await;
    let healthy = start_status_backend(200, "B").await;
    let metrics = Arc::new(Metrics::default());
    let backend = Arc::new(
        ResolvedBackend::new(
            "api",
            vec![
                ResolvedServer {
                    addr: failing.into(),
                    weight: 1,
                },
                ResolvedServer {
                    addr: healthy.into(),
                    weight: 1,
                },
            ],
            1,
            1,
        )
        .with_health_check(
            HealthCheck::tcp(Duration::from_millis(80), Duration::from_millis(80)).with_http(
                HttpCheck {
                    method: HttpCheckMethod::Get,
                    path: "/healthz".to_owned(),
                    host: None,
                    expect_status: StatusExpectation::parse("200").expect("status range"),
                    expect_rstring: None,
                },
            ),
        ),
    );
    let cfg = http_listener("web", Arc::clone(&backend));
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    // With fall = 1 the failing backend is DOWN in ~1 check cycle.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(
        !backend.balancer.is_up(failing),
        "the 500-answering server must be DOWN for the http expect check"
    );
    assert!(backend.balancer.is_up(healthy), "the 200 server stays up");

    // Every request now lands on the healthy server.
    for _ in 0..4 {
        let response = http_exchange(proxy_addr, get_request()).await;
        assert!(
            response.starts_with("HTTP/1.1 200") && response_body(&response) == "B",
            "traffic must go to the healthy server only: {response:?} metrics={:?}",
            metrics.snapshot()
        );
    }

    stop_proxy(handle, serve).await;
}

// --------------------------- B-H6 interop: keep-alive origins --------------

/// Keep-alive origin that **never** closes a connection — the interop
/// hazard for any checker that reads its response to EOF. `/healthz`
/// answers `200` with an `ok` body framed by `Content-Length` (chunked
/// when `chunked_health`); any other path answers `200` with `marker`.
/// `Connection: close` is ignored on purpose.
async fn start_keepalive_origin(marker: &'static str, chunked_health: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind keep-alive origin");
    let addr = listener.local_addr().expect("addr keep-alive origin");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
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
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
                    let response = if head.starts_with("get /healthz ") {
                        if chunked_health {
                            "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"
                                .to_owned()
                        } else {
                            "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok".to_owned()
                        }
                    } else {
                        format!(
                            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{marker}",
                            marker.len()
                        )
                    };
                    if socket.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                    // Never close: the socket stays open forever.
                }
            });
        }
    });
    addr
}

/// HTTP check interop (B-H6): the check completes at the HTTP message
/// boundary (RFC 9112 §6) and never waits for the origin to close, so
/// keep-alive origins stay UP across check cycles instead of flapping
/// to DOWN on every check timeout.
#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_check_interops_with_keep_alive_origins() {
    use eqproxy_core::expectation::{RegexMatcher, StatusExpectation};
    use eqproxy_net::health::{HealthCheck, HttpCheck, HttpCheckMethod};

    // Two keep-alive origins that never close a connection: one delimits
    // its responses with Content-Length, the other with chunked framing.
    // A checker that reads to EOF times out every cycle and flaps both
    // DOWN even though they answer 200 + "ok" on time.
    let cl = start_keepalive_origin("cl", false).await;
    let chunked = start_keepalive_origin("ck", true).await;
    let metrics = Arc::new(Metrics::default());
    let backend = Arc::new(
        ResolvedBackend::new(
            "api",
            vec![
                ResolvedServer {
                    addr: cl.into(),
                    weight: 1,
                },
                ResolvedServer {
                    addr: chunked.into(),
                    weight: 1,
                },
            ],
            1, // fall
            1, // rise
        )
        .with_health_check(
            HealthCheck::tcp(Duration::from_millis(100), Duration::from_millis(150)).with_http(
                HttpCheck {
                    method: HttpCheckMethod::Get,
                    path: "/healthz".to_owned(),
                    host: None,
                    expect_status: StatusExpectation::parse("200").expect("status range"),
                    expect_rstring: Some(RegexMatcher::parse("ok").expect("regex")),
                },
            ),
        ),
    );
    let (proxy_addr, handle, serve) = start_proxy(
        http_listener("web", Arc::clone(&backend)),
        Arc::clone(&metrics),
    )
    .await;

    // Several check cycles pass (interval 100 ms): both origins stay
    // operational — no flapping.
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(
        backend.balancer.is_up(cl),
        "the Content-Length keep-alive origin must stay UP"
    );
    assert!(
        backend.balancer.is_up(chunked),
        "the chunked keep-alive origin must stay UP"
    );

    // And live traffic still reaches both of them (round robin).
    let mut bodies = Vec::new();
    for _ in 0..6 {
        let response = http_exchange(proxy_addr, get_request()).await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "traffic must flow while the checks pass: {response:?}"
        );
        bodies.push(response_body(&response).to_owned());
    }
    assert!(
        bodies.iter().any(|b| b == "cl") && bodies.iter().any(|b| b == "ck"),
        "both keep-alive origins must serve: {bodies:?}"
    );

    stop_proxy(handle, serve).await;
}

// --------------------------------------------------------- A15: mTLS -------

fn mtls_client_connector(with_client_cert: bool, wrong_cert: bool) -> tokio_rustls::TlsConnector {
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(MTLS_CA) {
        roots.add(cert.expect("CA cert")).expect("add root");
    }
    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let mut config = if with_client_cert {
        let (cert_pem, key_pem): (&[u8], &[u8]) = if wrong_cert {
            (
                include_bytes!("fixtures/cert.pem"),
                include_bytes!("fixtures/key.pem"),
            )
        } else {
            (MTLS_CLIENT, MTLS_CLIENT_KEY)
        };
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
            .collect::<Result<_, _>>()
            .expect("client certs");
        let key = PrivateKeyDer::from_pem_slice(key_pem).expect("client key");
        builder
            .with_client_auth_cert(certs, key)
            .expect("client auth")
    } else {
        builder.with_no_client_auth()
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

async fn mtls_connect(
    proxy: SocketAddr,
    connector: tokio_rustls::TlsConnector,
    name: &str,
) -> Option<tokio_rustls::client::TlsStream<TcpStream>> {
    use rustls::pki_types::ServerName;
    let stream = TcpStream::connect(proxy).await.expect("connect proxy");
    let name = ServerName::try_from(name.to_owned()).expect("server name");
    tokio::time::timeout(WAIT, connector.connect(name, stream))
        .await
        .expect("handshake in time")
        .ok()
}

/// Asserts the mTLS exchange dies before any byte flows: either the
/// handshake is rejected outright, or the first read gets the alert/EOF.
async fn assert_no_data_flows(
    proxy: SocketAddr,
    connector: tokio_rustls::TlsConnector,
    case: &str,
    name: &str,
) {
    let Some(mut stream) = mtls_connect(proxy, connector, name).await else {
        return; // rejected during the handshake
    };
    let _ = stream.write_all(b"ping").await;
    let mut buf = [0u8; 4];
    let first_io = tokio::time::timeout(WAIT, stream.read_exact(&mut buf)).await;
    let died = match first_io {
        Ok(Err(_)) => true, // alert or EOF: the exchange is dead
        _ => false,
    };
    assert!(died, "mTLS {case}: no data may flow through the proxy");
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mtls_requires_a_certificate_issued_by_the_client_ca() {
    let echo = start_echo().await;
    let metrics = Arc::new(Metrics::default());
    let server_tls = tls::server_config(
        MTLS_SERVER,
        MTLS_SERVER_KEY,
        Some(MTLS_CA),
        &["http/1.1".to_owned()],
        TlsVersion::V1_2,
    )
    .expect("mTLS server config");
    let backend = ResolvedBackend::new(
        "api",
        vec![ResolvedServer {
            addr: echo.into(),
            weight: 1,
        }],
        3,
        2,
    );
    let cfg = tcp_listener("secure", Arc::new(backend)).with_server_tls(server_tls);
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    // No client certificate: no data may flow (the server rejects with
    // `peer sent no certificates`; the client can finish its own side and
    // only see the alert on the first read).
    assert_no_data_flows(
        proxy_addr,
        mtls_client_connector(false, false),
        "without a client cert",
        "localhost",
    )
    .await;

    // A certificate from another CA: rejected too.
    assert_no_data_flows(
        proxy_addr,
        mtls_client_connector(true, true),
        "with a foreign cert",
        "localhost",
    )
    .await;

    // The certificate issued by the client CA: full roundtrip.
    let mut stream = mtls_connect(proxy_addr, mtls_client_connector(true, false), "localhost")
        .await
        .expect("handshake with the right cert must pass");
    stream.write_all(b"ping").await.expect("write");
    let mut echoed = [0u8; 4];
    tokio::time::timeout(WAIT, stream.read_exact(&mut echoed))
        .await
        .expect("echo in time")
        .expect("full echo");
    assert_eq!(&echoed, b"ping", "byte-for-byte echo over mTLS");

    drop(stream);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let snap = metrics.snapshot();
    assert!(
        snap.tls_handshake_failures >= 2,
        "both rejected handshakes must be counted: {snap:?}"
    );

    stop_proxy(handle, serve).await;
}
