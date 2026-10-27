//! E2E tests of non-blocking dynamic DNS (B-H13/B-N18/B-E15) over real
//! sockets: the dataplane serves from the first moment whatever DNS does.
//!
//! Journeys under test (observable traffic, not internal state):
//!
//! - `re_resolution_swaps_the_backend_address_in_hot`: a `HOSTNAME:PORT`
//!   backend keeps serving while the resolver's answer changes — the new
//!   address takes traffic without a restart.
//! - `hung_dns_serves_explicit_503_never_blocks`: with DNS hung from the
//!   start the listener binds and answers immediately (explicit 503 +
//!   `no_available_server` metric), and traffic starts flowing when DNS
//!   recovers — no restart, no silent blocking (CE7).
//!
//! The resolver itself is the injected seam (`Resolved` trait): these
//! tests exercise the scheduling and the dataplane behaviour around it;
//! the real-binary journeys in `eqproxy-cli` use the OS resolver.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use eqproxy_core::{Metrics, shutdown};
use eqproxy_net::dns::Resolving;
use eqproxy_net::{
    Balance, BoundProxy, ProxyMode, ResolvedBackend, ResolvedListener, ResolvedServer, ServerAddr,
    bind,
};

const WAIT: Duration = Duration::from_secs(5);

/// What the stub resolver answers (the seam under test).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    Addrs(Vec<SocketAddr>),
    Hang,
}

#[derive(Debug)]
struct Stub {
    answer: Mutex<Answer>,
}

impl Stub {
    fn new(answer: Answer) -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(answer),
        })
    }

    fn set(&self, answer: Answer) {
        *self.answer.lock().expect("answer lock") = answer;
    }
}

impl Resolving for Stub {
    fn resolve(
        &self,
        _host: String,
        _port: u16,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
        let answer = self.answer.lock().expect("answer lock").clone();
        Box::pin(async move {
            match answer {
                Answer::Addrs(addrs) => Ok(addrs),
                Answer::Hang => std::future::pending().await,
            }
        })
    }
}

/// Real origin answering `200` with `marker` as body (keep-alive).
async fn start_origin(marker: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("addr origin");
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
                    let close = head.contains("connection: close");
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
    addr
}

fn named_backend(host: &str, port: u16, interval: Duration) -> Arc<ResolvedBackend> {
    Arc::new(
        ResolvedBackend::new(
            "api",
            vec![ResolvedServer {
                addr: ServerAddr::Name {
                    host: host.to_owned(),
                    port,
                },
                weight: 1,
                backup: false,
                priority: 0,
            }],
            1,
            1,
        )
        .with_balance(Balance::RoundRobin, Duration::ZERO)
        .with_resolve_interval(interval)
        // Bounded attempts: the tests keep the hung-DNS windows tight.
        .with_resolve_timeout(Duration::from_millis(200)),
    )
}

async fn start_proxy(
    backend: Arc<ResolvedBackend>,
    metrics: Arc<Metrics>,
    resolver: Arc<Stub>,
) -> (SocketAddr, shutdown::ShutdownHandle, JoinHandle<()>) {
    let cfg = ResolvedListener::new(
        "web",
        "127.0.0.1:0".parse().expect("addr"),
        "api",
        ServerAddr::Name {
            host: "api.internal".to_owned(),
            port: 9000,
        },
        ProxyMode::Http,
        64,
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .with_backend(backend);
    let bound: BoundProxy = bind(vec![cfg], Arc::clone(&metrics))
        .await
        .expect("bind proxy");
    // The seam is injected before serving: production keeps SystemResolver.
    let bound = bound.with_resolver(resolver);
    let addr = bound.local_addrs()[0].1;
    let (handle, signal) = shutdown::channel();
    let serve = tokio::spawn(async move {
        bound.serve(signal, WAIT).await.expect("serve");
    });
    (addr, handle, serve)
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

async fn stop_proxy(handle: shutdown::ShutdownHandle, serve: JoinHandle<()>) {
    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve must finish")
        .expect("join");
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn re_resolution_swaps_the_backend_address_in_hot() {
    // One HOSTNAME:PORT backend; the resolver's answer moves from origin
    // A to origin B while traffic flows. No restart: the swap happens in
    // the background (B-H13/B-N18/B-E15).
    let a = start_origin("a").await;
    let b = start_origin("b").await;
    let stub = Stub::new(Answer::Addrs(vec![a]));
    let metrics = Arc::new(Metrics::default());
    let backend = named_backend("api.internal", 9000, Duration::from_millis(50));
    let (proxy_addr, handle, serve) =
        start_proxy(backend, Arc::clone(&metrics), Arc::clone(&stub)).await;

    // The first round resolves immediately: traffic reaches A.
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let response = http_exchange(proxy_addr, get_request()).await;
        if response.starts_with("HTTP/1.1 200") && response.ends_with("a") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "traffic never reached A: {response:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Re-resolution lands: the new address takes the traffic (hot).
    stub.set(Answer::Addrs(vec![b]));
    let mut saw_b = false;
    let deadline = tokio::time::Instant::now() + WAIT;
    while !saw_b {
        let response = http_exchange(proxy_addr, get_request()).await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "the backend keeps serving during the swap: {response:?}"
        );
        saw_b = response.ends_with("b");
        assert!(
            tokio::time::Instant::now() < deadline,
            "the re-resolved address never took traffic"
        );
    }
    let snap = metrics.snapshot();
    assert!(snap.dns_resolutions_ok >= 2, "{snap:?}");
    assert!(snap.dns_address_updates >= 1, "{snap:?}");

    stop_proxy(handle, serve).await;
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hung_dns_serves_explicit_503_never_blocks() {
    // CE7: startup with DNS hung. The listener must be up instantly and
    // answer an explicit 503 (counted in `no_available_server`) — never
    // a silent block. When DNS recovers, traffic flows without restart.
    let stub = Stub::new(Answer::Hang);
    let metrics = Arc::new(Metrics::default());
    let backend = named_backend("api.internal", 9000, Duration::from_millis(50));
    let (proxy_addr, handle, serve) =
        start_proxy(backend, Arc::clone(&metrics), Arc::clone(&stub)).await;

    // The exchange completes promptly even though DNS hangs forever.
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        http_exchange(proxy_addr, get_request()),
    )
    .await
    .expect("the request must never wait for DNS");
    assert!(
        response.starts_with("HTTP/1.1 503"),
        "unresolved backend = explicit 503, got: {response:?}"
    );
    assert!(
        metrics.snapshot().no_available_server >= 1,
        "the 503 is counted: {:?}",
        metrics.snapshot()
    );

    // DNS recovers: the same listener serves real traffic (no restart).
    let origin = start_origin("ok").await;
    stub.set(Answer::Addrs(vec![origin]));
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let response = http_exchange(proxy_addr, get_request()).await;
        if response.starts_with("HTTP/1.1 200") && response.ends_with("ok") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "traffic never recovered after DNS came back: {response:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let snap = metrics.snapshot();
    assert!(snap.dns_resolutions_ok >= 1, "{snap:?}");

    stop_proxy(handle, serve).await;
}
