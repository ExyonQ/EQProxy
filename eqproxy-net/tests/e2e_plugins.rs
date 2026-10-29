//! WASM plugin E2E journeys (B-I5/B-E4, ADR-0031) with real sockets.
//!
//! Fixtures are real `.wasm` modules committed next to their `.wat` source in
//! `tests/fixtures/plugins/`; the proxy loads exactly the bytes the runtime
//! loads in production. The origin is a real TCP server, so "never dialed" is
//! a fact about the socket, not a mock.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use http::{Request, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use eqproxy_core::Metrics;
use eqproxy_core::shutdown;
use eqproxy_net::{
    BoundProxy, FailurePolicy, PluginHost, PluginSettings, ProxyMode, ResolvedListener, bind,
};

const WAIT: Duration = Duration::from_secs(10);

fn plugin(
    name: &str,
    fuel: u64,
    timeout: Duration,
    memory_bytes: usize,
    on_error: FailurePolicy,
) -> Arc<PluginHost> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/plugins")
        .join(name);
    Arc::new(
        PluginHost::load(
            PluginSettings {
                path,
                fuel,
                timeout,
                memory_bytes,
                max_header_ops: 16,
                on_error,
            },
            Path::new("."),
        )
        .expect("plugin loads"),
    )
}

struct Origin {
    addr: SocketAddr,
    dials: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Origin {
    fn dials(&self) -> usize {
        self.dials.load(Ordering::Relaxed)
    }

    fn heads(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// Real TCP origin: records each request head and answers `200 ok`.
async fn start_origin() -> Origin {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    let dials = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let task_dials = Arc::clone(&dials);
    let task_seen = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            task_dials.fetch_add(1, Ordering::Relaxed);
            let seen = Arc::clone(&task_seen);
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    let Ok(read) = socket.read(&mut chunk).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    head.extend_from_slice(&chunk[..read]);
                    if head.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                seen.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(String::from_utf8_lossy(&head).into_owned());
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                    .await;
                let _ = socket.shutdown().await;
            });
        }
    });
    Origin { addr, dials, seen }
}

async fn start_proxy(
    origin: SocketAddr,
    plugin: Arc<PluginHost>,
) -> (
    SocketAddr,
    Arc<Metrics>,
    shutdown::ShutdownHandle,
    tokio::task::JoinHandle<()>,
) {
    let cfg = ResolvedListener::new(
        "web",
        "127.0.0.1:0".parse().expect("listen"),
        "api",
        origin,
        ProxyMode::Http,
        64,
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .with_plugin(plugin);
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

/// Sends one request with `connection: close` and returns the raw response.
async fn request_close(addr: SocketAddr, method: &str, path: &str) -> Vec<u8> {
    let mut socket = TcpStream::connect(addr).await.expect("connect proxy");
    let request = format!("{method} {path} HTTP/1.1\r\nhost: api\r\nconnection: close\r\n\r\n");
    socket
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    tokio::time::timeout(WAIT, socket.read_to_end(&mut response))
        .await
        .expect("response in time")
        .expect("read response");
    response
}

fn head(response: &[u8]) -> String {
    let end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map_or(response.len(), |pos| pos + 4);
    String::from_utf8_lossy(&response[..end]).into_owned()
}

fn status(response: &[u8]) -> u16 {
    head(response)
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .expect("status line")
}

#[tokio::test]
async fn plugin_adds_a_header_the_backend_receives() {
    let origin = start_origin().await;
    let host = plugin(
        "add_header.wasm",
        10_000_000,
        Duration::from_millis(50),
        16 << 20,
        FailurePolicy::Closed,
    );
    let (addr, metrics, stop, serve) = start_proxy(origin.addr, host).await;

    let response = request_close(addr, "GET", "/hello").await;
    assert_eq!(status(&response), 200, "{}", head(&response));
    let heads = origin.heads();
    assert_eq!(heads.len(), 1);
    assert!(
        heads[0].to_ascii_lowercase().contains("x-plugin: on"),
        "the backend must see the plugin header: {}",
        heads[0]
    );
    assert_eq!(metrics.snapshot().plugin_requests, 1);
    assert_eq!(metrics.snapshot().plugin_denied, 0);
    assert_eq!(metrics.snapshot().plugin_errors, 0);

    stop.trigger();
    let _ = tokio::time::timeout(WAIT, serve).await;
}

#[tokio::test]
async fn plugin_denial_never_dials_the_backend() {
    let origin = start_origin().await;
    let host = plugin(
        "deny_403.wasm",
        10_000_000,
        Duration::from_millis(50),
        16 << 20,
        FailurePolicy::Closed,
    );
    let (addr, metrics, stop, serve) = start_proxy(origin.addr, host).await;

    let response = request_close(addr, "GET", "/blocked").await;
    assert_eq!(status(&response), 403, "{}", head(&response));
    assert_eq!(
        origin.dials(),
        0,
        "a plugin denial must not open a backend connection"
    );
    assert!(origin.heads().is_empty());
    assert_eq!(metrics.snapshot().plugin_requests, 1);
    assert_eq!(metrics.snapshot().plugin_denied, 1);

    stop.trigger();
    let _ = tokio::time::timeout(WAIT, serve).await;
}

#[tokio::test]
async fn plugin_sees_the_request_head_and_can_deny_by_method() {
    let origin = start_origin().await;
    let host = plugin(
        "deny_get.wasm",
        10_000_000,
        Duration::from_millis(50),
        16 << 20,
        FailurePolicy::Closed,
    );
    let (addr, metrics, stop, serve) = start_proxy(origin.addr, host).await;

    let denied = request_close(addr, "GET", "/x").await;
    assert_eq!(status(&denied), 403, "GET must reach the plugin as GET");
    let allowed = request_close(addr, "POST", "/x").await;
    assert_eq!(status(&allowed), 200, "POST must not match the GET verdict");
    assert_eq!(origin.dials(), 1);
    assert!(origin.heads()[0].starts_with("POST /x"));
    assert_eq!(metrics.snapshot().plugin_denied, 1);

    stop.trigger();
    let _ = tokio::time::timeout(WAIT, serve).await;
}

#[tokio::test]
async fn fuel_exhaustion_fails_closed_by_default() {
    let origin = start_origin().await;
    let host = plugin(
        "spin.wasm",
        10_000,
        Duration::from_secs(5),
        16 << 20,
        FailurePolicy::Closed,
    );
    let (addr, metrics, stop, serve) = start_proxy(origin.addr, host).await;

    let response = request_close(addr, "GET", "/").await;
    assert_eq!(status(&response), 503, "{}", head(&response));
    assert_eq!(origin.dials(), 0);
    assert_eq!(metrics.snapshot().plugin_errors, 1);

    stop.trigger();
    let _ = tokio::time::timeout(WAIT, serve).await;
}

#[tokio::test]
async fn the_deadline_fails_closed_even_with_plenty_of_fuel() {
    let origin = start_origin().await;
    let host = plugin(
        "spin.wasm",
        100_000_000,
        Duration::from_millis(5),
        16 << 20,
        FailurePolicy::Closed,
    );
    let (addr, metrics, stop, serve) = start_proxy(origin.addr, host).await;

    let response = request_close(addr, "GET", "/").await;
    assert_eq!(status(&response), 503, "{}", head(&response));
    assert_eq!(origin.dials(), 0);
    assert_eq!(metrics.snapshot().plugin_errors, 1);

    stop.trigger();
    let _ = tokio::time::timeout(WAIT, serve).await;
}

#[tokio::test]
async fn fail_open_forwards_the_request_unchanged() {
    let origin = start_origin().await;
    let host = plugin(
        "spin.wasm",
        10_000,
        Duration::from_secs(5),
        16 << 20,
        FailurePolicy::Open,
    );
    let (addr, metrics, stop, serve) = start_proxy(origin.addr, host).await;

    let response = request_close(addr, "GET", "/").await;
    assert_eq!(status(&response), 200, "{}", head(&response));
    assert_eq!(origin.dials(), 1);
    assert!(!origin.heads()[0].to_ascii_lowercase().contains("x-plugin"));
    assert_eq!(metrics.snapshot().plugin_errors, 1);

    stop.trigger();
    let _ = tokio::time::timeout(WAIT, serve).await;
}

#[tokio::test]
async fn memory_growth_over_the_bound_fails_closed() {
    let origin = start_origin().await;
    let host = plugin(
        "grow.wasm",
        10_000_000,
        Duration::from_millis(50),
        1 << 20,
        FailurePolicy::Closed,
    );
    let (addr, metrics, stop, serve) = start_proxy(origin.addr, host).await;

    let response = request_close(addr, "GET", "/").await;
    assert_eq!(status(&response), 503, "{}", head(&response));
    assert_eq!(origin.dials(), 0);
    assert_eq!(metrics.snapshot().plugin_errors, 1);

    stop.trigger();
    let _ = tokio::time::timeout(WAIT, serve).await;
}

#[tokio::test]
async fn a_reserved_framing_header_from_the_plugin_fails_closed() {
    let origin = start_origin().await;
    let host = plugin(
        "reserved_header.wasm",
        10_000_000,
        Duration::from_millis(50),
        16 << 20,
        FailurePolicy::Closed,
    );
    let (addr, metrics, stop, serve) = start_proxy(origin.addr, host).await;

    let response = request_close(addr, "GET", "/").await;
    assert_eq!(status(&response), 503, "{}", head(&response));
    assert_eq!(origin.dials(), 0);
    assert_eq!(metrics.snapshot().plugin_errors, 1);

    stop.trigger();
    let _ = tokio::time::timeout(WAIT, serve).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plugin_denial_is_enforced_on_http2_streams() {
    let origin = start_origin().await;
    let host = plugin(
        "deny_403.wasm",
        10_000_000,
        Duration::from_millis(50),
        16 << 20,
        FailurePolicy::Closed,
    );
    let (addr, metrics, stop, serve) = start_proxy(origin.addr, host).await;

    let socket = TcpStream::connect(addr).await.expect("connect proxy");
    let (send, connection) = tokio::time::timeout(WAIT, h2::client::handshake(socket))
        .await
        .expect("h2 handshake in time")
        .expect("h2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut send = send;
    let request = Request::builder()
        .uri("https://h2.test/blocked")
        .body(())
        .expect("request");
    let (response, _stream) = send.send_request(request, true).expect("send");
    let response = tokio::time::timeout(WAIT, response)
        .await
        .expect("response in time")
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(origin.dials(), 0);
    assert_eq!(metrics.snapshot().plugin_denied, 1);

    stop.trigger();
    let _ = tokio::time::timeout(WAIT, serve).await;
}
