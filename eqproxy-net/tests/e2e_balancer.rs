//! E2E tests of advanced balancing over real sockets (v0.6,
//! B-H5/B-N12/B-E6 + B14).
//!
//! Journeys under test (observable traffic, not internal state):
//!
//! - `leastconn_routes_new_exchanges_to_the_least_loaded_server`: while one
//!   server holds an exchange open, every new request lands on the other.
//! - leastconn_weights_share_in_flight_load_by_conns_over_weight`: with
//!   weights 2:1 and everything held, 6 in-flight exchanges split 4:2.
//! - `slow_start_ramps_the_recovered_server_up`: a server that returns from
//!   DOWN gets a tiny share at first (dynamic weighting) and exactly its
//!   fair share once the slow-start window is over.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use eqproxy_core::expectation::StatusExpectation;
use eqproxy_core::{Metrics, shutdown};
use eqproxy_net::health::{HealthCheck, HttpCheck, HttpCheckMethod};
use eqproxy_net::{
    Balance, BoundProxy, ProxyMode, ResolvedBackend, ResolvedListener, ResolvedServer, bind,
};

const WAIT: Duration = Duration::from_secs(10);

/// Real HTTP origin: answers `200` with `marker` as body (keep-alive).
/// `/healthz` answers `200`/`500` per `healthy` (not counted). With
/// `hold` the response waits until the channel flips to `true`, so a test
/// can keep an exchange in flight on purpose.
struct Origin {
    addr: SocketAddr,
    /// Marker responses served (health checks excluded).
    served: Arc<AtomicUsize>,
    /// Release the held responses.
    release: Option<watch::Sender<bool>>,
    /// Health status for `/healthz`.
    healthy: Option<Arc<AtomicBool>>,
}

async fn start_origin(marker: &'static str, hold: bool, unhealthy: bool) -> Origin {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("addr origin");
    let served = Arc::new(AtomicUsize::new(0));
    let healthy = Arc::new(AtomicBool::new(!unhealthy));
    let health = Arc::clone(&healthy);
    let (release, hold_rx) = if hold {
        let (tx, rx) = watch::channel(false);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let served_task = Arc::clone(&served);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let served = Arc::clone(&served_task);
            let health = health.clone();
            let hold_rx = hold_rx.clone();
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
                    // `Connection: close` is honored (RFC 9112 §9.6).
                    let close = head.contains("connection: close");
                    let is_health = head.starts_with("get /healthz ");
                    if is_health {
                        // Health-check answer: 200 or 500 per the flag.
                        let ok = health.load(Ordering::SeqCst);
                        let response = if ok {
                            "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"
                                .to_owned()
                        } else {
                            "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                                .to_owned()
                        };
                        if socket.write_all(response.as_bytes()).await.is_err() {
                            return;
                        }
                        let _ = socket.shutdown().await;
                        return;
                    }
                    served.fetch_add(1, Ordering::SeqCst);
                    // Hold the response until the test releases it.
                    if let Some(rx) = &hold_rx {
                        let mut rx = rx.clone();
                        while !*rx.borrow() {
                            if rx.changed().await.is_err() {
                                break;
                            }
                        }
                    }
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n{}\r\n\r\n{marker}",
                        marker.len(),
                        if close {
                            "connection: close"
                        } else {
                            "connection: keep-alive"
                        }
                    );
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
    Origin {
        addr,
        served,
        release,
        healthy: Some(healthy),
    }
}

impl Origin {
    fn release(&self) {
        if let Some(tx) = &self.release {
            let _ = tx.send(true);
        }
    }

    fn set_healthy(&self, value: bool) {
        if let Some(flag) = &self.healthy {
            flag.store(value, Ordering::SeqCst);
        }
    }
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

/// One complete HTTP exchange on its own connection (bodies identified by
/// the origin marker).
async fn get_body(proxy: SocketAddr) -> String {
    let mut client = TcpStream::connect(proxy).await.expect("connect proxy");
    client
        .write_all(b"GET /x HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n")
        .await
        .expect("write");
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
    let response = String::from_utf8_lossy(&response).into_owned();
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected 200, got {response:?}"
    );
    response
        .split_once("\r\n\r\n")
        .map_or("", |(_, body)| body)
        .to_owned()
}

/// Polls `cond` until true (bounded).
async fn eventually(mut cond: impl FnMut() -> bool, what: &str) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !cond() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// --------------------------------------------- B-H5: least-connections ----

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leastconn_routes_new_exchanges_to_the_least_loaded_server() {
    // A holds its first exchange open (active = 1); every new request
    // must land on B until A's exchange finishes.
    let a = start_origin("a", true, false).await;
    let b = start_origin("b", false, false).await;
    let metrics = Arc::new(Metrics::default());
    let backend = Arc::new(
        ResolvedBackend::new(
            "api",
            vec![
                ResolvedServer {
                    addr: a.addr.into(),
                    weight: 1,
                    backup: false,
                    priority: 0,
                },
                ResolvedServer {
                    addr: b.addr.into(),
                    weight: 1,
                    backup: false,
                    priority: 0,
                },
            ],
            3,
            2,
        )
        .with_balance(Balance::LeastConn, Duration::ZERO),
    );
    let (proxy_addr, handle, serve) = start_proxy(
        http_listener("web", Arc::clone(&backend)),
        Arc::clone(&metrics),
    )
    .await;

    // First request: both servers idle (tie) -> A (config order), held.
    let held_proxy = proxy_addr;
    let held = tokio::spawn(async move { get_body(held_proxy).await });
    eventually(
        || a.served.load(Ordering::SeqCst) == 1,
        "the first request to reach origin A",
    )
    .await;
    assert_eq!(
        backend.balancer.active_count(a.addr),
        1,
        "the held exchange counts as in-flight load on A"
    );

    // Sequential requests: A is loaded (1), B is idle (0) -> all to B.
    for expected in 0..3 {
        let body = get_body(proxy_addr).await;
        assert_eq!(
            body,
            "b",
            "request {} must go to the idle server",
            expected + 1
        );
    }
    assert_eq!(
        a.served.load(Ordering::SeqCst),
        1,
        "no new request may land on the loaded server"
    );
    assert_eq!(b.served.load(Ordering::SeqCst), 3);

    // Release A: its exchange completes and the slot frees up.
    a.release();
    let body = tokio::time::timeout(WAIT, held)
        .await
        .expect("held exchange on time")
        .expect("join");
    assert_eq!(body, "a", "the held exchange was served by A");
    eventually(
        || backend.balancer.active_count(a.addr) == 0,
        "the in-flight slot released at exchange end",
    )
    .await;

    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leastconn_weights_share_in_flight_load_by_conns_over_weight() {
    // Weights 2:1, all responses held: 6 in-flight exchanges must split
    // 4:2 (`active / weight` equalizes), whatever the arrival order.
    let a = start_origin("a", true, false).await;
    let b = start_origin("b", true, false).await;
    let metrics = Arc::new(Metrics::default());
    let backend = Arc::new(
        ResolvedBackend::new(
            "api",
            vec![
                ResolvedServer {
                    addr: a.addr.into(),
                    weight: 2,
                    backup: false,
                    priority: 0,
                },
                ResolvedServer {
                    addr: b.addr.into(),
                    weight: 1,
                    backup: false,
                    priority: 0,
                },
            ],
            3,
            2,
        )
        .with_balance(Balance::LeastConn, Duration::ZERO),
    );
    let (proxy_addr, handle, serve) = start_proxy(
        http_listener("web", Arc::clone(&backend)),
        Arc::clone(&metrics),
    )
    .await;

    let mut held = Vec::new();
    for _ in 0..6 {
        let proxy = proxy_addr;
        held.push(tokio::spawn(async move { get_body(proxy).await }));
    }
    // Every request reached its origin => every pick is done and held.
    eventually(
        || a.served.load(Ordering::SeqCst) + b.served.load(Ordering::SeqCst) == 6,
        "all six requests in flight",
    )
    .await;
    assert_eq!(
        (
            a.served.load(Ordering::SeqCst),
            b.served.load(Ordering::SeqCst)
        ),
        (4, 2),
        "in-flight split follows the 2:1 weights (conns/weight)"
    );

    a.release();
    b.release();
    let mut bodies = Vec::new();
    for task in held {
        bodies.push(
            tokio::time::timeout(WAIT, task)
                .await
                .expect("exchange on time")
                .expect("join"),
        );
    }
    let from_a = bodies.iter().filter(|body| *body == "a").count();
    let from_b = bodies.iter().filter(|body| *body == "b").count();
    assert_eq!(
        (from_a, from_b),
        (4, 2),
        "the served responses match the weighted split: {bodies:?}"
    );

    stop_proxy(handle, serve).await;
}

// ---------------------------------------------------- B14: slow start ----

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_start_ramps_the_recovered_server_up() {
    // Round-robin + slow start (2s). B starts unhealthy (DOWN after the
    // first check); when it recovers, its effective weight ramps from
    // ~0 to full over the window: almost no traffic at first, exactly
    // its 1:1 fair share once the ramp is over.
    let a = start_origin("a", false, false).await;
    let b = start_origin("b", false, true).await;
    let metrics = Arc::new(Metrics::default());
    let slow_start = Duration::from_millis(2000);
    let backend = Arc::new(
        ResolvedBackend::new(
            "api",
            vec![
                ResolvedServer {
                    addr: a.addr.into(),
                    weight: 1,
                    backup: false,
                    priority: 0,
                },
                ResolvedServer {
                    addr: b.addr.into(),
                    weight: 1,
                    backup: false,
                    priority: 0,
                },
            ],
            1,
            1,
        )
        .with_health_check(
            // B answers 500 at once; the 1 s timeout is scheduler headroom,
            // not a wait for the origin.
            HealthCheck::tcp(Duration::from_millis(150), Duration::from_secs(1)).with_http(
                HttpCheck {
                    method: HttpCheckMethod::Get,
                    path: "/healthz".to_owned(),
                    host: None,
                    expect_status: StatusExpectation::parse("200").expect("status range"),
                    expect_rstring: None,
                },
            ),
        )
        .with_balance(Balance::RoundRobin, slow_start),
    );
    let (proxy_addr, handle, serve) = start_proxy(
        http_listener("web", Arc::clone(&backend)),
        Arc::clone(&metrics),
    )
    .await;

    // Phase 0: the health check drops the unhealthy server (fall = 1).
    eventually(
        || !backend.balancer.is_up(b.addr),
        "B marked DOWN by the health check",
    )
    .await;

    // Phase 1 (B down): every request goes to A.
    for _ in 0..20 {
        assert_eq!(get_body(proxy_addr).await, "a");
    }

    // Let A's own slow-start window (from startup) finish before the
    // comparison, then recover B.
    tokio::time::sleep(Duration::from_millis(2100)).await;
    b.set_healthy(true);
    eventually(
        || backend.balancer.is_up(b.addr),
        "B marked UP again (rise = 1)",
    )
    .await;

    // Phase 2 (ramp): the recovered server is nearly invisible next to
    // the fully ramped one.
    let eff_a = backend.balancer.effective_weight(a.addr);
    let eff_b = backend.balancer.effective_weight(b.addr);
    assert!(
        eff_b < eff_a / 10,
        "the recovered server starts with a tiny weight: eff_a={eff_a} eff_b={eff_b}"
    );
    let mut early = (0usize, 0usize);
    for _ in 0..20 {
        match get_body(proxy_addr).await.as_str() {
            "a" => early.0 += 1,
            "b" => early.1 += 1,
            other => panic!("unexpected origin body {other:?}"),
        }
    }
    assert!(
        early.1 <= 5 && early.0 >= 15,
        "during the ramp the recovered server gets a small share (a={}, b={})",
        early.0,
        early.1
    );

    // Phase 3 (ramp over): the split is exactly fair.
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let mut late = (0usize, 0usize);
    for _ in 0..20 {
        match get_body(proxy_addr).await.as_str() {
            "a" => late.0 += 1,
            "b" => late.1 += 1,
            other => panic!("unexpected origin body {other:?}"),
        }
    }
    assert_eq!(
        late,
        (10, 10),
        "after the slow-start window the split is exactly 1:1"
    );

    stop_proxy(handle, serve).await;
}
