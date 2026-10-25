//! E2E of the administration plane with **real sockets**: both bearer tokens
//! gate their routes, the status JSON names the live topology, the Prometheus
//! export reflects the live counters with a fixed number of series, a
//! `PUT .../state` drains a server under traffic (new requests skip it, the
//! in-flight one finishes), and the dataplane keeps serving after the admin
//! task dies (SPEC §9: the panel is not required to operate the proxy).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use eqproxy_core::Metrics;
use eqproxy_net::admin::{self, AdminHandle, AdminState, AdminTopology, ListenerInfo};
use eqproxy_net::{
    ProxyMode, ResolvedBackend, ResolvedListener, ResolvedServer, ServerAddr, ServerMode,
    ServerModes, bind,
};

const TOKEN: &str = "e2e-admin-token-0123456789";
const WRITE: &str = "e2e-admin-write-token-9876543210";
const WAIT: Duration = Duration::from_secs(5);
const BACKEND: &str = "api";
const SERVER_A: &str = "127.0.0.1:19000";
const SERVER_B: &str = "127.0.0.1:19001";

fn backend(modes: &Arc<ServerModes>) -> Arc<ResolvedBackend> {
    Arc::new(
        ResolvedBackend::new(
            BACKEND,
            vec![
                ResolvedServer {
                    addr: ServerAddr::Ip(SERVER_A.parse().expect("addr a")),
                    weight: 1,
                },
                ResolvedServer {
                    addr: ServerAddr::Ip(SERVER_B.parse().expect("addr b")),
                    weight: 1,
                },
            ],
            3,
            2,
        )
        .with_server_modes(Arc::clone(modes)),
    )
}

fn state(
    metrics: Arc<Metrics>,
    modes: Arc<ServerModes>,
    backends: Vec<Arc<ResolvedBackend>>,
) -> AdminState {
    AdminState {
        version: "0.0.0-test",
        started: std::time::Instant::now(),
        topology: Arc::new(std::sync::RwLock::new(AdminTopology {
            revision: "v1".to_owned(),
            listeners: vec![ListenerInfo {
                name: "web".to_owned(),
                listen: "127.0.0.1:18080".to_owned(),
                mode: "http".to_owned(),
                backend: BACKEND.to_owned(),
                maxconn: 2048,
            }],
            backends,
        })),
        modes,
        metrics,
        metrics_detailed: false,
        apply: None,
    }
}

async fn start_admin_with(
    token: &str,
    write: Option<&str>,
) -> (SocketAddr, AdminHandle, Arc<Metrics>, Arc<ServerModes>) {
    let metrics = Arc::new(Metrics::default());
    let modes = Arc::new(ServerModes::new());
    let handle = start_admin_for(
        token,
        write,
        Arc::clone(&metrics),
        Arc::clone(&modes),
        vec![backend(&modes)],
    )
    .await;
    (handle.0, handle.1, metrics, modes)
}

/// Admin plane that reports **the same** backend instance the dataplane uses
/// (the drain test needs the write key to name the proxy's configured
/// targets).
async fn start_admin_for(
    token: &str,
    write: Option<&str>,
    metrics: Arc<Metrics>,
    modes: Arc<ServerModes>,
    backends: Vec<Arc<ResolvedBackend>>,
) -> (SocketAddr, AdminHandle) {
    let cfg = admin::ResolvedAdmin {
        listen: "127.0.0.1:0".parse().expect("addr"),
        token: Arc::from(token),
        write_token: write.map(Arc::from),
    };
    let handle = admin::bind(cfg, Arc::new(state(metrics, modes, backends)))
        .await
        .expect("bind admin");
    let addr = handle.local_addr();
    (addr, handle)
}

async fn start_admin(token: &str) -> (SocketAddr, AdminHandle, Arc<Metrics>) {
    let (addr, handle, metrics, _modes) = start_admin_with(token, Some(WRITE)).await;
    (addr, handle, metrics)
}

/// Sends a raw head and reads the whole answer (the server closes).
async fn request(addr: SocketAddr, head: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("connect admin");
    stream.write_all(head.as_bytes()).await.expect("write head");
    let mut answer = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut answer))
        .await
        .expect("answer before the deadline")
        .expect("read answer");
    String::from_utf8_lossy(&answer).into_owned()
}

fn get(path: &str, authorization: Option<&str>) -> String {
    let mut head = format!("GET {path} HTTP/1.1\r\nhost: admin\r\n");
    if let Some(value) = authorization {
        head.push_str(&format!("authorization: {value}\r\n"));
    }
    head.push_str("\r\n");
    head
}

fn put_state(path: &str, secret: &str, state: &str) -> String {
    let body = format!("{{\"state\":\"{state}\"}}");
    format!(
        "PUT {path} HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {secret}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    )
}

fn status_line(answer: &str) -> &str {
    answer.lines().next().unwrap_or("")
}

fn body(answer: &str) -> &str {
    answer
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("")
}

/// HTTP origin that answers after `delay_ms` with `body` and closes.
async fn start_origin(body: &'static str, delay_ms: u64) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    match socket.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            head.extend_from_slice(&chunk[..n]);
                            if head.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                if delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    addr
}

async fn start_proxy(
    backend: Arc<ResolvedBackend>,
) -> (
    SocketAddr,
    eqproxy_core::shutdown::ShutdownHandle,
    tokio::task::JoinHandle<Result<(), eqproxy_net::ProxyError>>,
) {
    let cfg = ResolvedListener::new(
        "web",
        "127.0.0.1:0".parse().expect("addr"),
        BACKEND,
        backend.servers[0].addr.clone(),
        ProxyMode::Http,
        64,
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(30),
    )
    .with_backend(backend);
    let bound = bind(vec![cfg], Arc::new(Metrics::default()))
        .await
        .expect("bind dataplane");
    let proxy_addr = bound.local_addrs()[0].1;
    let (stop, signal) = eqproxy_core::shutdown::channel();
    let serving = tokio::spawn(async move { bound.serve(signal, WAIT).await });
    (proxy_addr, stop, serving)
}

async fn http_get(addr: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("connect proxy");
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .expect("write request");
    let mut raw = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut raw))
        .await
        .expect("answer before the deadline")
        .expect("read answer");
    let answer = String::from_utf8_lossy(&raw).into_owned();
    body(&answer).trim().to_owned()
}

#[tokio::test]
async fn the_token_gates_every_route() {
    let (addr, handle, _metrics) = start_admin(TOKEN).await;

    let anonymous = request(addr, &get("/api/v1/status", None)).await;
    assert_eq!(status_line(&anonymous), "HTTP/1.1 401 Unauthorized");
    assert!(
        anonymous
            .to_ascii_lowercase()
            .contains("www-authenticate: bearer")
    );
    assert!(
        !body(&anonymous).contains("listeners"),
        "an unauthorized caller learns nothing about the topology"
    );

    for wrong in [
        "Bearer nope",
        "Bearer e2e-admin-token-012345678",
        "Basic abc",
    ] {
        let answer = request(addr, &get("/api/v1/status", Some(wrong))).await;
        assert_eq!(status_line(&answer), "HTTP/1.1 401 Unauthorized", "{wrong}");
    }

    let authorized = request(addr, &get("/metrics", Some(&format!("Bearer {TOKEN}")))).await;
    assert_eq!(status_line(&authorized), "HTTP/1.1 200 OK");

    // The write token reads too (more privileged, never less).
    let written = request(
        addr,
        &get("/api/v1/status", Some(&format!("Bearer {WRITE}"))),
    )
    .await;
    assert_eq!(status_line(&written), "HTTP/1.1 200 OK");

    handle.shutdown().await;
}

#[tokio::test]
async fn status_reports_topology_and_live_counters() {
    let (addr, handle, metrics) = start_admin(TOKEN).await;
    metrics
        .http_requests_proxied
        .fetch_add(11, std::sync::atomic::Ordering::Relaxed);

    let answer = request(
        addr,
        &get("/api/v1/status", Some(&format!("Bearer {TOKEN}"))),
    )
    .await;
    assert_eq!(status_line(&answer), "HTTP/1.1 200 OK");
    assert!(
        answer
            .to_ascii_lowercase()
            .contains("content-type: application/json")
    );

    let parsed: serde_json::Value = serde_json::from_str(body(&answer)).expect("valid JSON");
    assert_eq!(parsed["version"], "0.0.0-test");
    assert_eq!(parsed["listeners"][0]["name"], "web");
    assert_eq!(parsed["listeners"][0]["maxconn"], 2048);
    assert_eq!(parsed["backends"][0]["name"], BACKEND);
    assert_eq!(
        parsed["backends"][0]["servers"][0]["addr"], SERVER_A,
        "the configured target is the write key"
    );
    assert_eq!(parsed["backends"][0]["servers"][0]["resolved"], SERVER_A);
    assert_eq!(parsed["backends"][0]["servers"][0]["state"], "ready");
    assert_eq!(parsed["backends"][0]["servers"][0]["weight"], 1);
    assert_eq!(parsed["backends"][0]["servers"][0]["active"], 0);
    assert_eq!(parsed["metrics_detailed"], false);
    assert_eq!(parsed["counters"]["http_requests_proxied"], 11);
    assert!(
        !body(&answer).contains(TOKEN) && !body(&answer).contains(WRITE),
        "the status never echoes a secret"
    );

    handle.shutdown().await;
}

#[tokio::test]
async fn metrics_export_is_prometheus_with_a_fixed_series_count() {
    let (addr, handle, metrics) = start_admin(TOKEN).await;
    metrics
        .connections_accepted
        .fetch_add(2, std::sync::atomic::Ordering::Relaxed);

    let answer = request(addr, &get("/metrics", Some(&format!("Bearer {TOKEN}")))).await;
    assert_eq!(status_line(&answer), "HTTP/1.1 200 OK");
    assert!(
        answer
            .to_ascii_lowercase()
            .contains("content-type: text/plain; version=0.0.4")
    );
    let text = body(&answer);
    assert!(text.contains("# TYPE eqproxy_connections_accepted_total counter"));
    assert!(text.contains("eqproxy_connections_accepted_total 2"));
    assert!(
        text.contains(&format!(
            "eqproxy_build_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION")
        )),
        "the build info carries the crate version"
    );

    // Cardinality is fixed: the series set is the same before and after a
    // scrape, and only build-info carries a label.
    let series: Vec<&str> = text
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .collect();
    assert!(!series.is_empty());
    for line in &series {
        assert_eq!(
            line.matches('{').count(),
            usize::from(line.starts_with("eqproxy_build_info")),
            "{line}"
        );
        let value = line.rsplit(' ').next().expect("value");
        assert!(
            value.parse::<f64>().is_ok(),
            "prometheus value must be numeric: {line}"
        );
    }

    let second = request(addr, &get("/metrics", Some(&format!("Bearer {TOKEN}")))).await;
    let second_series: Vec<&str> = body(&second)
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .collect();
    assert_eq!(series.len(), second_series.len(), "the series set is fixed");

    handle.shutdown().await;
}

#[tokio::test]
async fn malformed_and_oversized_heads_are_refused_without_killing_the_plane() {
    let (addr, handle, _metrics) = start_admin(TOKEN).await;

    let oversized = format!(
        "GET /metrics HTTP/1.1\r\nhost: admin\r\nx-pad: {}\r\n\r\n",
        "a".repeat(9 * 1024)
    );
    let answer = request(addr, &oversized).await;
    assert_eq!(
        status_line(&answer),
        "HTTP/1.1 431 Request Header Fields Too Large"
    );

    let unknown = request(addr, &get("/nope", Some(&format!("Bearer {TOKEN}")))).await;
    assert_eq!(status_line(&unknown), "HTTP/1.1 404 Not Found");

    let post = request(
        addr,
        &format!("POST /metrics HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {TOKEN}\r\n\r\n"),
    )
    .await;
    assert_eq!(status_line(&post), "HTTP/1.1 405 Method Not Allowed");
    assert!(
        post.to_ascii_lowercase().contains("allow: get, put"),
        "{post}"
    );

    // The plane still answers after the refusals.
    let healthy = request(addr, &get("/metrics", Some(&format!("Bearer {TOKEN}")))).await;
    assert_eq!(status_line(&healthy), "HTTP/1.1 200 OK");

    handle.shutdown().await;
}

#[tokio::test]
async fn write_roles_and_bodies_are_enforced_over_the_wire() {
    let (addr, handle, _metrics) = start_admin(TOKEN).await;
    let path = format!("/api/v1/backends/{BACKEND}/servers/{SERVER_A}/state");

    // Anonymous and read-role writes are refused and change nothing.
    let anonymous = request(addr, &format!("PUT {path} HTTP/1.1\r\nhost: admin\r\ncontent-type: application/json\r\ncontent-length: 17\r\n\r\n{{\"state\":\"drain\"}}")).await;
    assert_eq!(status_line(&anonymous), "HTTP/1.1 401 Unauthorized");
    let read_only = request(addr, &put_state(&path, TOKEN, "drain")).await;
    assert_eq!(status_line(&read_only), "HTTP/1.1 403 Forbidden");
    let parsed: serde_json::Value = serde_json::from_str(body(&read_only)).expect("json");
    assert_eq!(parsed["error"], "forbidden");

    // Missing media type, missing length and an invalid state are explicit.
    let plain = request(
        addr,
        &format!(
            "PUT {path} HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {WRITE}\r\ncontent-type: text/plain\r\ncontent-length: 17\r\n\r\n{{\"state\":\"drain\"}}"
        ),
    )
    .await;
    assert_eq!(status_line(&plain), "HTTP/1.1 415 Unsupported Media Type");
    let no_length = request(
        addr,
        &format!(
            "PUT {path} HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {WRITE}\r\ncontent-type: application/json\r\n\r\n"
        ),
    )
    .await;
    assert_eq!(status_line(&no_length), "HTTP/1.1 411 Length Required");
    let invalid = request(addr, &put_state(&path, WRITE, "maintenance")).await;
    assert_eq!(status_line(&invalid), "HTTP/1.1 400 Bad Request");
    let parsed: serde_json::Value = serde_json::from_str(body(&invalid)).expect("json");
    assert_eq!(parsed["error"], "invalid_state");

    // A browser-originated write is refused even with a valid token.
    let browser = request(
        addr,
        &format!(
            "PUT {path} HTTP/1.1\r\nhost: admin\r\norigin: https://evil.example\r\nauthorization: Bearer {WRITE}\r\ncontent-type: application/json\r\ncontent-length: 17\r\n\r\n{{\"state\":\"drain\"}}"
        ),
    )
    .await;
    assert_eq!(status_line(&browser), "HTTP/1.1 403 Forbidden");
    let parsed: serde_json::Value = serde_json::from_str(body(&browser)).expect("json");
    assert_eq!(parsed["error"], "origin_forbidden");

    // Unknown servers are a 404; nothing was drained by any of the refusals.
    let unknown = request(
        addr,
        &put_state(
            &format!("/api/v1/backends/{BACKEND}/servers/127.0.0.1:19999/state"),
            WRITE,
            "drain",
        ),
    )
    .await;
    assert_eq!(status_line(&unknown), "HTTP/1.1 404 Not Found");
    let status = request(
        addr,
        &get("/api/v1/status", Some(&format!("Bearer {TOKEN}"))),
    )
    .await;
    let parsed: serde_json::Value = serde_json::from_str(body(&status)).expect("json");
    assert_eq!(parsed["backends"][0]["servers"][0]["state"], "ready");

    // The write token drains and the status reflects the live slot.
    let drained = request(addr, &put_state(&path, WRITE, "drain")).await;
    assert_eq!(status_line(&drained), "HTTP/1.1 200 OK");
    let parsed: serde_json::Value = serde_json::from_str(body(&drained)).expect("json");
    assert_eq!(parsed["state"], "drain");
    assert_eq!(parsed["previous"], "ready");
    assert_eq!(parsed["changed"], true);
    let status = request(
        addr,
        &get("/api/v1/status", Some(&format!("Bearer {TOKEN}"))),
    )
    .await;
    let parsed: serde_json::Value = serde_json::from_str(body(&status)).expect("json");
    assert_eq!(parsed["backends"][0]["servers"][0]["state"], "drain");
    assert_eq!(parsed["backends"][0]["servers"][1]["state"], "ready");

    // And ready puts it back.
    let ready = request(addr, &put_state(&path, WRITE, "ready")).await;
    assert_eq!(status_line(&ready), "HTTP/1.1 200 OK");

    handle.shutdown().await;
}

#[tokio::test]
async fn without_a_write_token_the_state_route_stays_read_only() {
    let (addr, handle, _metrics, modes) = start_admin_with(TOKEN, None).await;
    let path = format!("/api/v1/backends/{BACKEND}/servers/{SERVER_A}/state");
    let answer = request(addr, &put_state(&path, TOKEN, "drain")).await;
    assert_eq!(status_line(&answer), "HTTP/1.1 403 Forbidden");
    let parsed: serde_json::Value = serde_json::from_str(body(&answer)).expect("json");
    assert_eq!(parsed["error"], "write_disabled");
    assert_eq!(modes.get(BACKEND, SERVER_A), ServerMode::Ready);
    handle.shutdown().await;
}

/// The slice's acceptance test: drain a server **while one exchange is in
/// flight**. New requests must skip the drained slot, the in-flight exchange
/// must finish on it, and `ready` must return it to the rotation.
#[tokio::test]
async fn drain_skips_new_requests_and_lets_the_in_flight_one_finish() {
    let slow = start_origin("origin-a", 400).await;
    let fast = start_origin("origin-b", 0).await;
    let modes = Arc::new(ServerModes::new());
    let backend = Arc::new(
        ResolvedBackend::new(
            BACKEND,
            vec![
                ResolvedServer {
                    addr: ServerAddr::Ip(slow),
                    weight: 1,
                },
                ResolvedServer {
                    addr: ServerAddr::Ip(fast),
                    weight: 1,
                },
            ],
            3,
            2,
        )
        .with_server_modes(Arc::clone(&modes)),
    );

    // The proxy reports the *configured* targets; the origins live on
    // ephemeral ports, so the admin view and the write key use `slow`/`fast`.
    let targets = backend.balancer.servers_view();
    assert_eq!(targets.len(), 2);
    let slow_target = targets[0].target.clone();
    let fast_target = targets[1].target.clone();

    let (proxy_addr, stop, serving) = start_proxy(Arc::clone(&backend)).await;
    let (admin_addr, admin) = start_admin_for(
        TOKEN,
        Some(WRITE),
        Arc::new(Metrics::default()),
        Arc::clone(&modes),
        vec![Arc::clone(&backend)],
    )
    .await;
    let path = format!("/api/v1/backends/{BACKEND}/servers/{slow_target}/state");

    // First request: round-robin picks the slow origin; leave it unread.
    let mut first = TcpStream::connect(proxy_addr).await.expect("connect proxy");
    first
        .write_all(b"GET /first HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n")
        .await
        .expect("write first request");
    // Give the proxy time to forward it before draining.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let drained = request(admin_addr, &put_state(&path, WRITE, "drain")).await;
    assert_eq!(status_line(&drained), "HTTP/1.1 200 OK");
    assert_eq!(modes.get(BACKEND, &slow_target), ServerMode::Drain);

    // New requests skip the drained slot: the fast origin answers them all.
    for _ in 0..4 {
        assert_eq!(
            http_get(proxy_addr, "/after-drain").await,
            "origin-b",
            "a drained server must not receive new requests"
        );
    }

    // The exchange that was already in flight finishes on the drained slot.
    let mut raw = Vec::new();
    tokio::time::timeout(WAIT, first.read_to_end(&mut raw))
        .await
        .expect("the in-flight exchange must finish")
        .expect("read in-flight answer");
    let answer = String::from_utf8_lossy(&raw).into_owned();
    assert_eq!(
        body(&answer).trim(),
        "origin-a",
        "the drain must not cut the in-flight exchange: {answer}"
    );

    // The fast target keeps its own declared state.
    assert_eq!(modes.get(BACKEND, &fast_target), ServerMode::Ready);

    // Ready returns the drained server to the rotation.
    let ready = request(admin_addr, &put_state(&path, WRITE, "ready")).await;
    assert_eq!(status_line(&ready), "HTTP/1.1 200 OK");
    let mut seen_a = false;
    for _ in 0..6 {
        seen_a |= http_get(proxy_addr, "/after-ready").await == "origin-a";
    }
    assert!(seen_a, "the server must take traffic again after `ready`");

    admin.shutdown().await;
    stop.trigger();
    tokio::time::timeout(WAIT, serving)
        .await
        .expect("dataplane shutdown")
        .expect("join")
        .expect("serve");
}

/// With every server drained the proxy answers an explicit 503 (counted in
/// `no_available_server`), never a hang or a silent reuse of the slot.
#[tokio::test]
async fn draining_every_server_yields_an_explicit_503() {
    let origin = start_origin("only", 0).await;
    let modes = Arc::new(ServerModes::new());
    let metrics = Arc::new(Metrics::default());
    let backend = Arc::new(
        ResolvedBackend::new(
            BACKEND,
            vec![ResolvedServer {
                addr: ServerAddr::Ip(origin),
                weight: 1,
            }],
            3,
            2,
        )
        .with_server_modes(Arc::clone(&modes)),
    );
    let target = backend.balancer.servers_view()[0].target.clone();
    let cfg = ResolvedListener::new(
        "web",
        "127.0.0.1:0".parse().expect("addr"),
        BACKEND,
        backend.servers[0].addr.clone(),
        ProxyMode::Http,
        64,
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(30),
    )
    .with_backend(Arc::clone(&backend));
    let bound = bind(vec![cfg], Arc::clone(&metrics))
        .await
        .expect("bind dataplane");
    let proxy_addr = bound.local_addrs()[0].1;
    let (stop, signal) = eqproxy_core::shutdown::channel();
    let serving = tokio::spawn(async move { bound.serve(signal, WAIT).await });

    assert_eq!(http_get(proxy_addr, "/before").await, "only");
    modes.set(BACKEND, &target, ServerMode::Drain);
    let mut stream = TcpStream::connect(proxy_addr).await.expect("connect proxy");
    stream
        .write_all(b"GET /after HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n")
        .await
        .expect("write request");
    let mut raw = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut raw))
        .await
        .expect("503 before the deadline")
        .expect("read answer");
    let answer = String::from_utf8_lossy(&raw).into_owned();
    assert!(
        answer.starts_with("HTTP/1.1 503"),
        "all servers drained must be an explicit 503: {answer}"
    );
    assert!(
        metrics.snapshot().no_available_server >= 1,
        "the 503 is counted: {:?}",
        metrics.snapshot()
    );

    stop.trigger();
    tokio::time::timeout(WAIT, serving)
        .await
        .expect("dataplane shutdown")
        .expect("join")
        .expect("serve");
}

#[tokio::test]
async fn the_dataplane_keeps_serving_when_the_admin_task_dies() {
    // A real echo backend and a TCP listener through the dataplane.
    let echo = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let echo_addr = echo.local_addr().expect("addr echo");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = echo.accept().await {
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

    let cfg = ResolvedListener::new(
        "web",
        "127.0.0.1:0".parse().expect("addr"),
        "echo",
        echo_addr,
        ProxyMode::Tcp,
        64,
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(30),
    );
    let bound = bind(vec![cfg], Arc::new(Metrics::default()))
        .await
        .expect("bind dataplane");
    let proxy_addr = bound.local_addrs()[0].1;
    let (stop, signal) = eqproxy_core::shutdown::channel();
    let serving = tokio::spawn(async move { bound.serve(signal, WAIT).await });

    let (admin_addr, admin, _metrics) = start_admin(TOKEN).await;

    // A first round-trip through the dataplane.
    async fn roundtrip(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut stream = TcpStream::connect(addr).await.expect("connect proxy");
        stream.write_all(payload).await.expect("write payload");
        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(WAIT, stream.read_exact(&mut echoed))
            .await
            .expect("echo before the deadline")
            .expect("read echo");
        echoed
    }
    assert_eq!(
        roundtrip(proxy_addr, b"before-admin-death").await,
        b"before-admin-death"
    );

    // The panel dies; the proxy must not notice.
    admin.abort();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        TcpStream::connect(admin_addr).await.is_err(),
        "the admin listener is gone once its task is aborted"
    );
    assert_eq!(
        roundtrip(proxy_addr, b"after-admin-death").await,
        b"after-admin-death"
    );

    stop.trigger();
    tokio::time::timeout(WAIT, serving)
        .await
        .expect("dataplane shutdown")
        .expect("join")
        .expect("serve");
}
