//! E2E of the administration plane with **real sockets**: both bearer tokens
//! gate their routes, the status JSON names the live topology, the Prometheus
//! export reflects the live counters with a fixed number of series, a
//! `PUT .../state` drains a server under traffic (new requests skip it, the
//! in-flight one finishes), **every endpoint** answers with the role it
//! declares (anonymous / read / write, route by route), and the dataplane
//! keeps serving after the admin task dies (SPEC §9: the panel is not required
//! to operate the proxy).

use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::net::{TcpListener, TcpStream};

use eqproxy_core::Metrics;
use eqproxy_net::admin::{
    self, AdminEndpoint, AdminHandle, AdminState, AdminTopology, ListenerInfo, UnixSocketOptions,
};
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
                    backup: false,
                    priority: 0,
                },
                ResolvedServer {
                    addr: ServerAddr::Ip(SERVER_B.parse().expect("addr b")),
                    weight: 1,
                    backup: false,
                    priority: 0,
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
                tls_fingerprint: None,
            }],
            backends,
        })),
        modes,
        metrics,
        apply: None,
        panel: None,
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
        endpoint: AdminEndpoint::Tcp("127.0.0.1:0".parse().expect("addr")),
        unix: UnixSocketOptions::default(),
        token: Arc::from(token),
        write_token: write.map(Arc::from),
        panel: false,
    };
    let handle = admin::bind(cfg, Arc::new(state(metrics, modes, backends)))
        .await
        .expect("bind admin");
    let addr = handle.local_addr().expect("tcp admin endpoint");
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
    assert_eq!(parsed["metrics_detail"]["enabled"], false);
    assert_eq!(parsed["metrics_detail"]["series"], 0);
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
    let invalid = request(addr, &put_state(&path, WRITE, "pause")).await;
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

    // `maintenance` is accepted over the wire and published like any other
    // removal state (ADR-0028); the idle-pool closure it performs is
    // asserted where a connection can actually be parked (`admin::tests`
    // over the pool, and the journey over the release binary).
    let maintained = request(addr, &put_state(&path, WRITE, "maintenance")).await;
    assert_eq!(status_line(&maintained), "HTTP/1.1 200 OK");
    let parsed: serde_json::Value = serde_json::from_str(body(&maintained)).expect("json");
    assert_eq!(parsed["state"], "maintenance");
    assert_eq!(parsed["previous"], "ready");
    assert_eq!(parsed["drained"], true);
    let status = request(
        addr,
        &get("/api/v1/status", Some(&format!("Bearer {TOKEN}"))),
    )
    .await;
    let parsed: serde_json::Value = serde_json::from_str(body(&status)).expect("json");
    assert_eq!(parsed["backends"][0]["servers"][0]["state"], "maintenance");
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

/// One request of the authorization matrix, with the assertions every answer
/// must satisfy whatever its status: no secret in it (T17) and, for a refusal
/// issued before routing, no topology either.
async fn expect_status(addr: SocketAddr, raw: &str, expected: &str, label: &str) -> String {
    let answer = request(addr, raw).await;
    assert_eq!(status_line(&answer), expected, "{label}: {answer}");
    assert!(
        !answer.contains(TOKEN) && !answer.contains(WRITE),
        "{label}: a secret reached the answer: {answer}"
    );
    if expected == "HTTP/1.1 401 Unauthorized" {
        assert!(
            answer
                .to_ascii_lowercase()
                .contains("www-authenticate: bearer"),
            "{label}: a 401 must advertise the scheme: {answer}"
        );
        assert!(
            !answer.contains("listeners") && !answer.contains("backends"),
            "{label}: an unauthorized caller learns nothing about the topology: {answer}"
        );
    }
    answer
}

fn put_table(path: &str, secret: &str, table: &str) -> String {
    format!(
        "PUT {path} HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {secret}\r\ncontent-type: application/toml\r\nif-match: \"v1\"\r\ncontent-length: {}\r\n\r\n{table}",
        table.len()
    )
}

fn reload(secret: &str) -> String {
    format!(
        "POST /api/v1/certificates/reload HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {secret}\r\ncontent-length: 0\r\n\r\n"
    )
}

/// The v0.8 gate (SPEC §9): **every endpoint** answers with the role it
/// declares, over real sockets and for all three callers — anonymous, read
/// token, write token. Refusals change nothing, a 401 discloses neither the
/// topology nor the secret, and a write that passes the role gate reaches the
/// applier (here absent, so `503 config_unavailable`, which is not an
/// authorization answer).
#[tokio::test]
async fn every_route_is_authorized_by_the_matrix() {
    let (addr, handle, _metrics, modes) = start_admin_with(TOKEN, Some(WRITE)).await;
    let state_path = format!("/api/v1/backends/{BACKEND}/servers/{SERVER_A}/state");
    let backend_path = format!("/api/v1/backends/{BACKEND}");
    let backend_table = format!("server = \"{SERVER_A}\"\n");
    let listener_path = "/api/v1/listeners/web".to_owned();
    let listener_table = format!("listen = \"127.0.0.1:18080\"\nbackend = \"{BACKEND}\"\n");
    let read = format!("Bearer {TOKEN}");
    let write = format!("Bearer {WRITE}");
    let read = read.as_str();
    let write = write.as_str();

    // Read routes: both roles read, nobody else does.
    for (path, label) in [("/api/v1/status", "status"), ("/metrics", "metrics")] {
        expect_status(addr, &get(path, None), "HTTP/1.1 401 Unauthorized", label).await;
        expect_status(addr, &get(path, Some(read)), "HTTP/1.1 200 OK", label).await;
        expect_status(addr, &get(path, Some(write)), "HTTP/1.1 200 OK", label).await;
    }

    // An unknown route is only disclosed to an authenticated caller.
    expect_status(
        addr,
        &get("/nope", None),
        "HTTP/1.1 401 Unauthorized",
        "unknown anonymous",
    )
    .await;
    expect_status(
        addr,
        &get("/nope", Some(read)),
        "HTTP/1.1 404 Not Found",
        "unknown read",
    )
    .await;
    expect_status(
        addr,
        &get("/nope", Some(write)),
        "HTTP/1.1 404 Not Found",
        "unknown write",
    )
    .await;

    // The state write: anonymous is 401, read is 403, write applies (an
    // idempotent `ready` leaves the slot as it was).
    let anon_body = "{\"state\":\"ready\"}";
    let state_anonymous = format!(
        "PUT {state_path} HTTP/1.1\r\nhost: admin\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{anon_body}",
        anon_body.len()
    );
    expect_status(
        addr,
        &state_anonymous,
        "HTTP/1.1 401 Unauthorized",
        "state anonymous",
    )
    .await;
    expect_status(
        addr,
        &put_state(&state_path, TOKEN, "ready"),
        "HTTP/1.1 403 Forbidden",
        "state read",
    )
    .await;
    expect_status(
        addr,
        &put_state(&state_path, WRITE, "ready"),
        "HTTP/1.1 200 OK",
        "state write",
    )
    .await;

    // The document writes and the certificate action: the read token is
    // refused at the role gate; the write token passes it and finds no
    // applier attached in this test (a 503, never a 200 it cannot back).
    for (path, table, label) in [
        (
            backend_path.as_str(),
            backend_table.as_str(),
            "backend table",
        ),
        (
            listener_path.as_str(),
            listener_table.as_str(),
            "listener table",
        ),
    ] {
        expect_status(
            addr,
            &put_table(path, TOKEN, table),
            "HTTP/1.1 403 Forbidden",
            label,
        )
        .await;
        let unreachable = expect_status(
            addr,
            &put_table(path, WRITE, table),
            "HTTP/1.1 503 Error",
            label,
        )
        .await;
        assert!(
            body(&unreachable).contains("config_unavailable"),
            "{label}: {unreachable}"
        );
    }
    expect_status(
        addr,
        &reload(TOKEN),
        "HTTP/1.1 403 Forbidden",
        "reload read",
    )
    .await;
    let unreachable =
        expect_status(addr, &reload(WRITE), "HTTP/1.1 503 Error", "reload write").await;
    assert!(body(&unreachable).contains("config_unavailable"));

    // Method routing: a method the plane does not serve is `405` with the
    // plane's `Allow` list (configuration-wide: this plane has a write token),
    // and the token still gates it — a caller without one never reaches it.
    expect_status(
        addr,
        "DELETE /api/v1/status HTTP/1.1\r\nhost: admin\r\n\r\n",
        "HTTP/1.1 401 Unauthorized",
        "delete anonymous",
    )
    .await;
    let read_delete = expect_status(
        addr,
        &format!(
            "DELETE /api/v1/status HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {TOKEN}\r\n\r\n"
        ),
        "HTTP/1.1 405 Method Not Allowed",
        "delete read",
    )
    .await;
    assert!(
        read_delete
            .to_ascii_lowercase()
            .contains("allow: get, put, post"),
        "the Allow list names the methods the plane serves: {read_delete}"
    );
    let write_delete = expect_status(
        addr,
        &format!(
            "DELETE /api/v1/status HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {WRITE}\r\n\r\n"
        ),
        "HTTP/1.1 405 Method Not Allowed",
        "delete write",
    )
    .await;
    assert!(
        write_delete
            .to_ascii_lowercase()
            .contains("allow: get, put, post"),
        "a write token is told every method the plane serves: {write_delete}"
    );

    // None of the refusals above changed the running state.
    assert_eq!(modes.get(BACKEND, SERVER_A), ServerMode::Ready);
    assert_eq!(modes.get(BACKEND, SERVER_B), ServerMode::Ready);
    let status = request(addr, &get("/api/v1/status", Some(read))).await;
    let parsed: serde_json::Value = serde_json::from_str(body(&status)).expect("json");
    assert_eq!(parsed["revision"], "v1");
    assert_eq!(parsed["backends"][0]["servers"][0]["state"], "ready");

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
                    backup: false,
                    priority: 0,
                },
                ResolvedServer {
                    addr: ServerAddr::Ip(fast),
                    weight: 1,
                    backup: false,
                    priority: 0,
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
                backup: false,
                priority: 0,
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

/// Unique socket path per test run: parallel test binaries must not share a
/// filesystem name (the admin plane refuses a path that is already served).
#[cfg(unix)]
fn socket_path(tag: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "eqproxy-admin-{tag}-{}-{sequence}.sock",
        std::process::id()
    ))
}

/// The test process's effective uid/gid, read from a file it just created.
/// Using the kernel's answer on a real file avoids guessing how the runner
/// resolves the user (and works the same on macOS and Linux).
#[cfg(unix)]
fn current_ids() -> (u32, u32) {
    use std::os::unix::fs::MetadataExt;

    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "eqproxy-ids-{}-{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, b"x").expect("write id probe");
    let metadata = std::fs::metadata(&path).expect("id probe metadata");
    let ids = (metadata.uid(), metadata.gid());
    std::fs::remove_file(&path).expect("remove id probe");
    ids
}

/// Sends a raw head over the Unix socket and reads the whole answer.
#[cfg(unix)]
async fn unix_request(path: &Path, head: &str) -> String {
    let mut stream = UnixStream::connect(path).await.expect("connect unix admin");
    stream.write_all(head.as_bytes()).await.expect("write head");
    let mut answer = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut answer))
        .await
        .expect("answer before the deadline")
        .expect("read answer");
    String::from_utf8_lossy(&answer).into_owned()
}

#[cfg(unix)]
#[tokio::test]
async fn admin_unix_socket_serves_the_same_routes_and_is_owner_only() {
    let path = socket_path("routes");
    let metrics = Arc::new(Metrics::default());
    let modes = Arc::new(ServerModes::new());
    let cfg = admin::ResolvedAdmin {
        endpoint: AdminEndpoint::Unix(path.clone()),
        unix: UnixSocketOptions::default(),
        token: Arc::from(TOKEN),
        write_token: Some(Arc::from(WRITE)),
        panel: false,
    };
    let handle = admin::bind(
        cfg,
        Arc::new(state(
            Arc::clone(&metrics),
            Arc::clone(&modes),
            vec![backend(&modes)],
        )),
    )
    .await
    .expect("bind admin on a Unix socket");

    assert_eq!(handle.socket_path(), Some(path.as_path()));
    assert!(
        handle.local_addr().is_none(),
        "a Unix plane has no TCP address"
    );
    let mode = std::fs::metadata(&path)
        .expect("socket metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "only the owner may open the admin socket");

    // The bearer token is still required: the filesystem gates *who* can
    // connect, the token gates *what* the caller may do.
    let denied = unix_request(&path, &get("/api/v1/status", None)).await;
    assert!(denied.starts_with("HTTP/1.1 401"), "{denied}");

    let status = unix_request(
        &path,
        &get("/api/v1/status", Some(&format!("Bearer {TOKEN}"))),
    )
    .await;
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert!(status.contains("\"version\":\"0.0.0-test\""), "{status}");
    assert!(status.contains("\"revision\":\"v1\""), "{status}");

    let metrics_body =
        unix_request(&path, &get("/metrics", Some(&format!("Bearer {TOKEN}")))).await;
    assert!(metrics_body.starts_with("HTTP/1.1 200"), "{metrics_body}");
    assert!(
        metrics_body.contains("eqproxy_build_info"),
        "the Prometheus export is served on the Unix socket too: {metrics_body}"
    );

    // Write authorization is unchanged: the read token cannot mutate.
    let forbidden = unix_request(
        &path,
        &format!(
            "PUT /api/v1/backends/{BACKEND} HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {TOKEN}\r\ncontent-type: application/toml\r\nif-match: \"v1\"\r\ncontent-length: 0\r\n\r\n"
        ),
    )
    .await;
    assert!(forbidden.starts_with("HTTP/1.1 403"), "{forbidden}");

    handle.shutdown().await;
    assert!(
        !path.exists(),
        "a clean shutdown removes the socket file it created"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn admin_unix_socket_refuses_live_sockets_and_replaces_stale_ones() {
    let path = socket_path("lifecycle");
    let start = |path: PathBuf| {
        let cfg = admin::ResolvedAdmin {
            endpoint: AdminEndpoint::Unix(path),
            unix: UnixSocketOptions::default(),
            token: Arc::from(TOKEN),
            write_token: None,
            panel: false,
        };
        let metrics = Arc::new(Metrics::default());
        let modes = Arc::new(ServerModes::new());
        admin::bind(
            cfg,
            Arc::new(state(metrics, modes.clone(), vec![backend(&modes)])),
        )
    };

    let first = start(path.clone()).await.expect("first bind");
    let error = start(path.clone())
        .await
        .err()
        .expect("a second process must not steal a live socket");
    assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse, "{error}");
    first.shutdown().await;
    assert!(!path.exists(), "shutdown cleaned the first socket");

    // A crash leaves the file behind with no listener: the next start must
    // replace it instead of refusing to boot forever.
    let stale = std::os::unix::net::UnixListener::bind(&path).expect("stale bind");
    drop(stale);
    assert!(path.exists(), "the crash left a stale socket file");
    let recovered = start(path.clone())
        .await
        .expect("a stale socket is replaced");
    let answer = unix_request(
        &path,
        &get("/api/v1/status", Some(&format!("Bearer {TOKEN}"))),
    )
    .await;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    recovered.shutdown().await;
    assert!(!path.exists());

    // Any other file at that path is preserved: the plane never deletes an
    // operator's file to make room for itself.
    let occupied = socket_path("occupied");
    std::fs::write(&occupied, b"do not delete me").expect("write sentinel");
    let error = start(occupied.clone())
        .await
        .err()
        .expect("a regular file must not be removed");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{error}");
    assert_eq!(
        std::fs::read(&occupied).expect("sentinel still there"),
        b"do not delete me"
    );
    std::fs::remove_file(&occupied).expect("cleanup sentinel");
}

#[tokio::test]
async fn a_tcp_admin_plane_exposes_no_unix_socket_policy() {
    let (_addr, handle, _metrics) = start_admin(TOKEN).await;
    assert!(
        handle.unix_policy().is_none(),
        "a TCP plane has no socket mode, group or peer allowlist to reload"
    );
    handle.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn admin_unix_socket_policy_reloads_without_a_restart() {
    let (uid, gid) = current_ids();
    let path = socket_path("policy-reload");
    let metrics = Arc::new(Metrics::default());
    let modes = Arc::new(ServerModes::new());
    let handle = admin::bind(
        admin::ResolvedAdmin {
            endpoint: AdminEndpoint::Unix(path.clone()),
            unix: UnixSocketOptions::default(),
            token: Arc::from(TOKEN),
            write_token: None,
            panel: false,
        },
        Arc::new(state(metrics, Arc::clone(&modes), vec![backend(&modes)])),
    )
    .await
    .expect("bind unix admin");
    let policy = handle
        .unix_policy()
        .expect("a Unix plane exposes its live policy")
        .clone();
    let authorized = get("/api/v1/status", Some(&format!("Bearer {TOKEN}")));

    let group_policy = UnixSocketOptions {
        mode: 0o660,
        gid: Some(gid),
        allow_uids: vec![uid].into(),
        acl_uids: vec![].into(),
    };
    policy.apply(&group_policy).expect("widen the socket");
    let metadata = std::fs::metadata(&path).expect("socket metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o660);
    assert_eq!(metadata.gid(), gid, "the reloaded group owns the socket");
    assert_eq!(policy.options().mode, 0o660);
    let answer = unix_request(&path, &authorized).await;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");

    // Same listener, same file, stricter list: the **next** peer is refused
    // although the kernel credential has not changed.
    let deny_policy = UnixSocketOptions {
        mode: 0o660,
        gid: Some(gid),
        allow_uids: vec![uid.wrapping_add(1)].into(),
        acl_uids: vec![].into(),
    };
    policy.apply(&deny_policy).expect("narrow the allowlist");
    let mut denied = UnixStream::connect(&path)
        .await
        .expect("the filesystem still allows the owner to connect");
    let _ = denied
        .write_all(b"GET /api/v1/status HTTP/1.1\r\nhost: admin\r\n\r\n")
        .await;
    let mut response = Vec::new();
    let read = tokio::time::timeout(WAIT, denied.read_to_end(&mut response))
        .await
        .expect("the plane closes the now-unauthorized connection")
        .unwrap_or(0);
    assert_eq!(read, 0, "no HTTP bytes for a uid dropped by the reload");
    assert!(response.is_empty(), "{response:?}");

    // Back to owner-only with an empty list: the file shrinks and the owner
    // is admitted again without the listener being rebound.
    policy
        .apply(&UnixSocketOptions::default())
        .expect("restore owner-only");
    let metadata = std::fs::metadata(&path).expect("socket metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let answer = unix_request(&path, &authorized).await;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");

    // A group the process cannot own is an error, and the live policy and the
    // file are exactly as they were: a failed reload never widens anything.
    let refused = UnixSocketOptions {
        mode: 0o660,
        gid: Some(54321),
        allow_uids: Vec::new().into(),
        acl_uids: Vec::new().into(),
    };
    let error = policy
        .apply(&refused)
        .expect_err("an unprivileged chown to a foreign group must fail");
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied,
        "{error}"
    );
    assert_eq!(policy.options().mode, 0o600, "the mode was not changed");
    assert_eq!(policy.options().gid, None, "the group was not changed");
    let metadata = std::fs::metadata(&path).expect("socket metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.gid(), gid, "the file kept the group it had");
    let answer = unix_request(&path, &authorized).await;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");

    handle.shutdown().await;
    assert!(!path.exists(), "shutdown still removes the socket");
}

#[cfg(unix)]
#[tokio::test]
async fn admin_unix_socket_group_mode_and_uid_allowlist() {
    let (uid, gid) = current_ids();
    let metrics = Arc::new(Metrics::default());
    let modes = Arc::new(ServerModes::new());
    let start = |path: PathBuf, allow: Vec<u32>| {
        let cfg = admin::ResolvedAdmin {
            endpoint: AdminEndpoint::Unix(path),
            unix: UnixSocketOptions {
                mode: 0o660,
                gid: Some(gid),
                allow_uids: allow.into(),
                acl_uids: vec![].into(),
            },
            token: Arc::from(TOKEN),
            write_token: None,
            panel: false,
        };
        let metrics = Arc::clone(&metrics);
        let modes = Arc::clone(&modes);
        admin::bind(
            cfg,
            Arc::new(state(metrics, Arc::clone(&modes), vec![backend(&modes)])),
        )
    };

    // The owner's uid is in the list: the real kernel-reported credential
    // passes, the group owns the socket, and the routes answer.
    let path = socket_path("group-allowed");
    let handle = start(path.clone(), vec![uid])
        .await
        .expect("bind group socket");
    let metadata = std::fs::metadata(&path).expect("socket metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o660);
    assert_eq!(metadata.uid(), uid, "the socket stays owned by the process");
    assert_eq!(metadata.gid(), gid, "the configured group owns the socket");
    let answer = unix_request(
        &path,
        &get("/api/v1/status", Some(&format!("Bearer {TOKEN}"))),
    )
    .await;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    handle.shutdown().await;

    // A uid outside the list is refused before any HTTP parsing: the client
    // gets EOF (or a reset), never a status line it could probe.
    let denied_path = socket_path("group-denied");
    let denied = start(denied_path.clone(), vec![uid.wrapping_add(1)])
        .await
        .expect("bind allowlist socket");
    let mut stream = UnixStream::connect(&denied_path)
        .await
        .expect("the filesystem still allows the owner to connect");
    let _ = stream
        .write_all(b"GET /api/v1/status HTTP/1.1\r\nhost: admin\r\n\r\n")
        .await;
    let mut response = Vec::new();
    let read = tokio::time::timeout(WAIT, stream.read_to_end(&mut response))
        .await
        .expect("the plane closes the unauthorized connection")
        .unwrap_or(0);
    assert_eq!(read, 0, "no HTTP bytes for an unauthorized uid");
    assert!(response.is_empty(), "{response:?}");
    denied.shutdown().await;
}

/// POSIX ACL layer (ADR-0023, Linux): a named user is written into
/// `system.posix_acl_access` on the live socket, replaced on reload and
/// removed when the list empties — the kernel, not this process, decides
/// whether that uid may `connect`.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn admin_unix_socket_acl_uids_write_replace_and_clear_the_posix_acl() {
    use eqproxy_net::unix_acl::{ACCESS_XATTR, access_blob};

    fn entries(blob: &[u8]) -> Vec<(u16, u32)> {
        blob[4..]
            .chunks_exact(8)
            .map(|chunk| {
                (
                    u16::from_le_bytes(chunk[0..2].try_into().expect("tag")),
                    u32::from_le_bytes(chunk[4..8].try_into().expect("id")),
                )
            })
            .collect()
    }

    let (uid, gid) = current_ids();
    let named = uid.wrapping_add(1000).max(1);
    let path = socket_path("acl");
    let metrics = Arc::new(Metrics::default());
    let modes = Arc::new(ServerModes::new());
    let policy = |acl: Vec<u32>| UnixSocketOptions {
        mode: 0o660,
        gid: Some(gid),
        allow_uids: vec![].into(),
        acl_uids: acl.into(),
    };
    let handle = admin::bind(
        admin::ResolvedAdmin {
            endpoint: AdminEndpoint::Unix(path.clone()),
            unix: policy(vec![named]),
            token: Arc::from(TOKEN),
            write_token: None,
            panel: false,
        },
        Arc::new(state(metrics, Arc::clone(&modes), vec![backend(&modes)])),
    )
    .await
    .expect("bind with a named ACL user");

    let live = handle
        .unix_policy()
        .expect("a Unix plane exposes its live policy")
        .clone();
    let blob = xattr::get(&path, ACCESS_XATTR)
        .expect("read the access ACL")
        .expect("the ACL exists as soon as the socket is bound");
    assert_eq!(
        blob,
        access_blob(&[named]),
        "the attribute is the canonical kernel layout"
    );
    // Tag 0x02 is ACL_USER, 0x10 is ACL_MASK; the mode's group class is the
    // mask, so both must be present for the named entry to mean anything.
    let decoded = entries(&blob);
    assert_eq!(decoded.iter().filter(|(tag, _)| *tag == 0x02).count(), 1);
    assert!(
        decoded.contains(&(0x02, named)),
        "the named user is an ACL_USER entry: {decoded:?}"
    );
    assert!(
        decoded.contains(&(0x10, u32::MAX)),
        "a named user requires the mask entry: {decoded:?}"
    );
    assert_eq!(
        std::fs::metadata(&path)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777,
        0o660
    );

    // Reload: the named user is replaced, not accumulated.
    let other = named.wrapping_add(1);
    live.apply(&policy(vec![other]))
        .expect("replace the named user");
    assert_eq!(
        xattr::get(&path, ACCESS_XATTR)
            .expect("read after reload")
            .expect("ACL still present"),
        access_blob(&[other])
    );

    // Empty list: the attribute is removed, so no stale named user survives a
    // reload that takes the ACL away. The mode is untouched.
    live.apply(&policy(vec![])).expect("clear the ACL");
    assert!(
        xattr::get(&path, ACCESS_XATTR)
            .expect("read after clearing")
            .is_none(),
        "an emptied list must remove the attribute, not leave it"
    );
    assert_eq!(
        std::fs::metadata(&path)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777,
        0o660,
        "removing the ACL does not change the mode"
    );

    let answer = unix_request(
        &path,
        &get("/api/v1/status", Some(&format!("Bearer {TOKEN}"))),
    )
    .await;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    handle.shutdown().await;
    assert!(!path.exists(), "shutdown removes the socket file");
}
