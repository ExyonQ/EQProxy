//! E2E tests through the **real** `eqproxy` binary (the interface the
//! operator will use), with real sockets and real process signals.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_eqproxy"))
}

/// Test certificates shared with the eqproxy-net e2e tests.
const FIXTURE_CERT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../eqproxy-net/tests/fixtures/cert.pem"
);
const FIXTURE_KEY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../eqproxy-net/tests/fixtures/key.pem"
);
/// Additional SNI certificates (B-I2/B-H10/B-E9): `alpha.example.test`
/// (exact) and `*.beta.example.test` (wildcard).
const FIXTURE_ALPHA_CERT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../eqproxy-net/tests/fixtures/alpha.pem"
);
const FIXTURE_ALPHA_KEY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../eqproxy-net/tests/fixtures/alpha.key"
);
const FIXTURE_BETA_CERT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../eqproxy-net/tests/fixtures/beta.pem"
);
const FIXTURE_BETA_KEY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../eqproxy-net/tests/fixtures/beta.key"
);

fn temp_config(name: &str, contents: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "eqproxy-cli-e2e-{}-{name}.toml",
        std::process::id()
    ));
    std::fs::write(&path, contents).expect("write test config");
    path
}

fn remove_temp(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// Real echo backend on a synchronous thread.
fn start_echo_backend() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
    let addr = listener.local_addr().expect("addr echo");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    use std::io::Read;
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).is_err() {
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

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn validate_accepts_a_good_config() {
    let backend = start_echo_backend();
    let config = temp_config(
        "ok",
        &format!(
            "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\n[backend.api]\nserver = \"{backend}\"\n"
        ),
    );
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&config)
        .output()
        .expect("run eqproxy config validate");
    remove_temp(&config);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("config OK"), "stdout: {stdout}");
    assert!(
        stdout.contains("1 listener(s), 1 backend(s)"),
        "stdout: {stdout}"
    );
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn validate_reports_file_line_field_cause_example() {
    // [listener.web] is on line 3; the referenced backend does not exist.
    let config = temp_config(
        "bad-ref",
        "schema_version = 1\n\n[listener.web]\nlisten = \"127.0.0.1:8080\"\nbackend = \"ghost\"\n",
    );
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&config)
        .output()
        .expect("run eqproxy config validate");
    remove_temp(&config);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "must fail with code 1; stderr: {stderr}"
    );
    for expected in [
        &*format!("{}", config.display()),
        ":3",
        "field `listener.web.backend`",
        "ghost",
        "example:",
        "[backend.ghost]",
    ] {
        assert!(
            stderr.contains(expected),
            "missing {expected:?} in stderr:\n{stderr}"
        );
    }
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn validate_reports_syntax_errors_with_line() {
    let config = temp_config("syntax", "schema_version = 1\n[listener.web\n");
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&config)
        .output()
        .expect("run eqproxy config validate");
    remove_temp(&config);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr.contains("configuration error in"),
        "stderr:\n{stderr}"
    );
    assert!(stderr.contains(":2"), "must locate line 2:\n{stderr}");
    assert!(stderr.contains("example:"), "stderr:\n{stderr}");
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn unimplemented_commands_fail_explicitly_with_exit_2() {
    // `config explain`/`plan`/`apply`/`rollback` and now `doctor` used to
    // be in this list; all are implemented (Phase 3 slices) and covered
    // by explain_*/plan_*/apply_*/rollback_*/doctor_* tests below. Only
    // `config import` (Phase 8) still holds the exit-2 contract.
    let cases: &[(&[&str], &str)] = &[(
        &["config", "import", "--input", "a.cfg", "--output", "b.toml"],
        "config import",
    )];
    for (args, name) in cases {
        let output = bin().args(*args).output().expect("run eqproxy");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{name} must exit with code 2; stderr: {stderr}"
        );
        assert!(
            stderr.contains("not implemented yet"),
            "{name} must fail explicitly; stderr: {stderr}"
        );
    }
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn explain_simulates_routing_with_no_side_effects() {
    let backend = start_echo_backend();
    let config = temp_config(
        "explain",
        &format!(
            "schema_version = 1\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             mode = \"http\"\n\
             backend = \"api\"\n\
             local_response = {{ status = 503, content_type = \"text/plain\", body = \"back soon\" }}\n\
             [backend.api]\n\
             servers = [{{ addr = \"{backend}\", weight = 3 }}]\n\
             maxqueue = 8\n\
             timeout_queue = \"500ms\"\n\
             retries = 1\n"
        ),
    );
    let output = bin()
        .args(["config", "explain", "--config"])
        .arg(&config)
        .args(["--method", "GET", "--host", "example.com", "--path", "/api"])
        .output()
        .expect("run eqproxy config explain");
    remove_temp(&config);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "explain must exit 0; stderr: {stderr}"
    );
    for expected in [
        "simulation: true (no requests issued, no state changed)",
        "request: GET /api host=example.com",
        "listener \"web\"",
        "mode=http",
        "backend \"api\"",
        &format!("server {backend} weight=3 state=UP(initial)"),
        &format!("decision: server {backend}"),
        // `config explain` says what each timeout does when it fires
        // (Q4/H5) and the bounded queue/retry policy of the backend.
        "timeout_on_fire: connect=502 after ",
        "client_header=408(first exchange)/close after ",
        "server_header=504 after ",
        "queue: maxqueue=8 timeout=500ms (full->503; expired->503)",
        "retries: max=1 scope=idempotent-only (connect-phase only; failed server excluded)",
        "local_response: status=503 content_type=\"text/plain\" body_bytes=9 (no-server class)",
    ] {
        assert!(
            stdout.contains(expected),
            "missing {expected:?} in: {stdout}"
        );
    }
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn explain_fails_actionably_on_bad_input() {
    // Missing file -> exit 1 with an actionable error, never exit 2.
    let output = bin()
        .args(["config", "explain", "--config", "x.toml"])
        .output()
        .expect("run eqproxy config explain");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("could not read"), "stderr: {stderr}");

    // Two listeners without --listener -> exit 1 asking for --listener.
    let config = temp_config(
        "explain-ambiguous",
        "schema_version = 1\n[listener.a]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\n[listener.b]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\n[backend.api]\nserver = \"127.0.0.1:9\"\n",
    );
    let output = bin()
        .args(["config", "explain", "--config"])
        .arg(&config)
        .output()
        .expect("run eqproxy config explain");
    remove_temp(&config);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("select one with --listener"),
        "stderr: {stderr}"
    );
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn diff_reports_no_differences_for_identical_configs() {
    let contents = "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\n[backend.api]\nserver = \"127.0.0.1:9\"\n";
    let left = temp_config("diff-same-left", contents);
    let right = temp_config("diff-same-right", contents);
    let output = bin()
        .args(["config", "diff"])
        .arg(&left)
        .arg(&right)
        .output()
        .expect("run eqproxy config diff");
    remove_temp(&left);
    remove_temp(&right);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("no differences"), "stdout: {stdout}");
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn diff_reports_changed_servers_and_added_listener() {
    let left = temp_config(
        "diff-left",
        "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\n[backend.api]\nservers = [{ addr = \"127.0.0.1:9000\", weight = 3 }]\n",
    );
    let right = temp_config(
        "diff-right",
        "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\n[listener.extra]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\n[backend.api]\nservers = [{ addr = \"127.0.0.1:9000\", weight = 1 }, { addr = \"127.0.0.1:9001\" }]\n",
    );
    let output = bin()
        .args(["config", "diff"])
        .arg(&left)
        .arg(&right)
        .output()
        .expect("run eqproxy config diff");
    remove_temp(&left);
    remove_temp(&right);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    for expected in [
        "2 difference(s):",
        "+ listener \"extra\" (only in right)",
        "~ backend \"api\" servers: [127.0.0.1:9000(3)] -> [127.0.0.1:9000(1), 127.0.0.1:9001(1)]",
    ] {
        assert!(
            stdout.contains(expected),
            "missing {expected:?} in: {stdout}"
        );
    }
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn diff_refuses_when_a_side_is_invalid() {
    let good = temp_config(
        "diff-good",
        "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\n[backend.api]\nserver = \"127.0.0.1:9\"\n",
    );
    let output = bin()
        .args(["config", "diff"])
        .arg(&good)
        .arg("no-existe.toml")
        .output()
        .expect("run eqproxy config diff");
    remove_temp(&good);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("could not read"), "stderr: {stderr}");
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn plan_inventories_what_run_would_activate() {
    let config = temp_config(
        "plan",
        "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nmode = \"http\"\nbackend = \"api\"\n[backend.api]\nservers = [{ addr = \"127.0.0.1:9000\", weight = 3 }, { addr = \"127.0.0.1:9001\" }]\n",
    );
    let output = bin()
        .args(["config", "plan", "--config"])
        .arg(&config)
        .output()
        .expect("run eqproxy config plan");
    remove_temp(&config);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    for expected in [
        "plan: 1 listener(s), 1 backend(s) — nothing started (dry run)",
        "listener \"web\": bind 127.0.0.1:0 mode=http",
        "backend=\"api\"",
        "backend \"api\": servers=2 tls=no proxy_protocol=none health_check=none",
        "server 127.0.0.1:9000 weight=3",
        "server 127.0.0.1:9001 weight=1",
    ] {
        assert!(
            stdout.contains(expected),
            "missing {expected:?} in: {stdout}"
        );
    }
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn plan_loads_real_tls_material() {
    let config = temp_config(
        "plan-tls",
        &format!(
            "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nmode = \"http\"\nbackend = \"api\"\n[listener.web.tls]\ncert = \"{FIXTURE_CERT}\"\nkey = \"{FIXTURE_KEY}\"\nalpn = [\"http/1.1\"]\n[backend.api]\nserver = \"127.0.0.1:9\"\n"
        ),
    );
    let output = bin()
        .args(["config", "plan", "--config"])
        .arg(&config)
        .output()
        .expect("run eqproxy config plan");
    remove_temp(&config);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("tls=yes(alpn=[http/1.1])"),
        "TLS material must load and report: {stdout}"
    );
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn plan_fails_actionably_on_bad_input() {
    // Missing file -> exit 1, never a fake plan.
    let output = bin()
        .args(["config", "plan", "--config", "no-existe.toml"])
        .output()
        .expect("run eqproxy config plan");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("could not read"), "stderr: {stderr}");

    // Semantically invalid (server + servers) -> exit 1 with the field.
    let bad = temp_config(
        "plan-bad",
        "schema_version = 1\n[backend.api]\nserver = \"127.0.0.1:9000\"\nservers = [{ addr = \"127.0.0.1:9001\" }]\n",
    );
    let output = bin()
        .args(["config", "plan", "--config"])
        .arg(&bad)
        .output()
        .expect("run eqproxy config plan");
    remove_temp(&bad);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("mutually exclusive"), "stderr: {stderr}");
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_http_mode_proxies_requests_and_rejects_smuggling() {
    // Minimal real HTTP backend: answers 200 with body echo.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend http");
    let backend = listener.local_addr().expect("addr backend");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let mut total = 0usize;
                loop {
                    use std::io::Read;
                    match stream.read(&mut buf[total..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => total += n,
                    }
                    if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let response =
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = stream.write_all(response);
            });
        }
    });

    let config = temp_config(
        "http",
        &format!(
            "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\nmode = \"http\"\n[backend.api]\nserver = \"{backend}\"\n"
        ),
    );

    let mut child = bin()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run (http)");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));

    let mut proxy_addr = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        let read = stderr.read_line(&mut line).expect("leer stderr");
        assert!(read > 0, "eqproxy closed stderr without announcing bind");
        if let Some(addr) = line.split("listening on ").nth(1) {
            proxy_addr = addr.trim().to_owned();
            break;
        }
    }
    assert!(!proxy_addr.is_empty(), "the address was not announced");

    // Real run: proxied GET with observed response.
    let mut client = TcpStream::connect(proxy_addr.as_str()).expect("connect al proxy");
    client
        .write_all(b"GET /x HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        .expect("write GET");
    let mut response = Vec::new();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let _ = client.read_to_end(&mut response);
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 200 OK"), "respuesta: {text}");
    assert!(text.ends_with("ok"), "echoed body: {text}");

    // Error case: CL+TE smuggling rejected with 400 by the real binary.
    let mut evil = TcpStream::connect(proxy_addr.as_str()).expect("connect 2");
    evil.write_all(
        b"POST /x HTTP/1.1\r\nHost: t\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
    )
    .expect("write smuggle");
    let mut rejected = Vec::new();
    evil.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let _ = evil.read_to_end(&mut rejected);
    let rejected = String::from_utf8_lossy(&rejected);
    assert!(
        rejected.starts_with("HTTP/1.1 400"),
        "smuggling must be rejected: {rejected}"
    );

    // Real SIGINT → clean shutdown with code 0.
    let pid = child.id();
    let kill = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .expect("run kill");
    assert!(kill.success(), "kill -INT must be accepted");
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("eqproxy did not finish after SIGINT");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    remove_temp(&config);
    assert_eq!(status.code(), Some(0), "clean shutdown must exit with 0");
}

/// Minimal identity backend: answers `200 OK` with the given body and
/// closes (the routing cases send `Connection: close`).
fn start_identity_backend(body: &'static str) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind identity");
    let addr = listener.local_addr().expect("addr identity");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            std::thread::spawn(move || {
                use std::io::Read;
                let mut buf = [0u8; 8192];
                let mut total = 0usize;
                loop {
                    match stream.read(&mut buf[total..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => total += n,
                    }
                    if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            });
        }
    });
    addr
}

/// One request through the real binary; returns the raw response.
fn proxied(proxy: &str, request: &[u8]) -> String {
    let mut client = TcpStream::connect(proxy).expect("connect proxy");
    client.write_all(request).expect("write request");
    let mut response = Vec::new();
    // 30 s, not 5: a coverage build (`cargo llvm-cov`) of the binary behind
    // a full parallel suite can stall well past five seconds, and a swallowed
    // timeout used to surface as "unexpected origin body" in tests that infer
    // the routing decision from the body. The exchange itself is unchanged;
    // only the budget for this harness read grows.
    client
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("read timeout");
    let _ = client.read_to_end(&mut response);
    assert!(
        response.windows(4).any(|w| w == b"\r\n\r\n"),
        "the proxy never completed a response head before the 30 s deadline: {:?}",
        String::from_utf8_lossy(&response)
    );
    String::from_utf8_lossy(&response).into_owned()
}

fn body_of(response: &str) -> &str {
    response.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}

/// Routing rules through the **real** binary (v0.6, B-H3/B-H4): paths,
/// hosts, methods, headers and source IPs route to their backends; first
/// match wins over later rules, the listener backend is the fallback, and
/// near misses never route. `config explain` reproduces the decisions
/// offline, rule by rule.
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_routes_by_rules_first_match_wins_with_default_fallback() {
    let api = start_identity_backend("api");
    let mgmt = start_identity_backend("mgmt");
    let fallback = start_identity_backend("fallback");
    let config = temp_config(
        "rules",
        &format!(
            "schema_version = 1\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             backend = \"fallback\"\n\
             mode = \"http\"\n\
             \n\
             [[listener.web.rules]]\n\
             name = \"api-v1\"\n\
             path_prefix = \"/v1/\"\n\
             use_backend = \"api\"\n\
             \n\
             [[listener.web.rules]]\n\
             name = \"special-host\"\n\
             host = \"special.example.com\"\n\
             use_backend = \"mgmt\"\n\
             \n\
             [[listener.web.rules]]\n\
             name = \"admin-post\"\n\
             path = \"/admin\"\n\
             methods = [\"POST\"]\n\
             use_backend = \"mgmt\"\n\
             \n\
             [[listener.web.rules]]\n\
             name = \"beta-json\"\n\
             path_regex = \"\\\\.json$\"\n\
             headers = [{{ name = \"x-beta\", exact = \"on\" }}]\n\
             use_backend = \"mgmt\"\n\
             \n\
             [[listener.web.rules]]\n\
             name = \"office-ip\"\n\
             path = \"/office\"\n\
             ip = [\"10.0.0.0/8\"]\n\
             use_backend = \"mgmt\"\n\
             \n\
             [backend.api]\n\
             server = \"{api}\"\n\
             [backend.mgmt]\n\
             server = \"{mgmt}\"\n\
             [backend.fallback]\n\
             server = \"{fallback}\"\n"
        ),
    );

    let mut child = bin()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run (rules)");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let mut proxy_addr = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        let read = stderr.read_line(&mut line).expect("leer stderr");
        assert!(read > 0, "eqproxy closed stderr without announcing bind");
        if let Some(addr) = line.split("listening on ").nth(1) {
            proxy_addr = addr.trim().to_owned();
            break;
        }
    }
    assert!(!proxy_addr.is_empty(), "the address was not announced");

    let cases: &[(&[u8], &str, &str)] = &[
        (
            b"GET /v1/users HTTP/1.1\r\nHost: special.example.com\r\nConnection: close\r\n\r\n",
            "api",
            "first matching rule wins over a later one",
        ),
        (
            b"GET /v1/users HTTP/1.1\r\nHost: other.example.com\r\nConnection: close\r\n\r\n",
            "api",
            "path prefix routes",
        ),
        (
            b"GET /other HTTP/1.1\r\nHost: special.example.com:8443\r\nConnection: close\r\n\r\n",
            "mgmt",
            "host matches ignoring the :port suffix",
        ),
        (
            b"GET /v10 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            "fallback",
            "literal prefix /v1/ must not swallow /v10",
        ),
        (
            b"POST /admin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            "mgmt",
            "method condition matches",
        ),
        (
            b"GET /admin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            "fallback",
            "method near miss must not route",
        ),
        (
            b"GET /data.json HTTP/1.1\r\nHost: x\r\nx-beta: on\r\nConnection: close\r\n\r\n",
            "mgmt",
            "header condition matches",
        ),
        (
            b"GET /data.json HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            "fallback",
            "missing header must not route",
        ),
        (
            b"GET /office HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            "fallback",
            "source IP outside the blocks must not route",
        ),
    ];
    for (request, want, why) in cases {
        let response = proxied(proxy_addr.as_str(), request);
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "{why}: response {response}"
        );
        assert_eq!(body_of(&response), *want, "{why}");
    }

    // `config explain` reproduces the decisions offline (H4): every rule
    // with its verdict, then the fired rule and chosen backend.
    let explain = |args: &[&str]| {
        let out = bin()
            .args(["config", "explain", "--config"])
            .arg(&config)
            .args(args)
            .output()
            .expect("run eqproxy config explain");
        assert!(out.status.success(), "explain exits 0: {:?}", out);
        String::from_utf8_lossy(&out.stdout).into_owned()
    };

    let report = explain(&["--host", "special.example.com", "--path", "/v1/users"]);
    assert!(
        report.contains("rule[0] \"api-v1\": match -> use_backend \"api\""),
        "{report}"
    );
    assert!(
        report.contains("rule[1] \"special-host\": match -> use_backend \"mgmt\""),
        "{report}"
    );
    // Since slice 2 the decision line reports the full action (not just
    // the backend), so actions and routing read identically in `explain`.
    assert!(
        report.contains("route_decision: first matching rule -> use_backend \"api\""),
        "{report}"
    );

    let report = explain(&["--method", "GET", "--host", "x", "--path", "/admin"]);
    assert!(
        report.contains("rule[2] \"admin-post\": no match (method:"),
        "{report}"
    );
    assert!(
        report.contains("route_decision: no rule matched -> default backend \"fallback\""),
        "{report}"
    );

    let report = explain(&[
        "--host",
        "x",
        "--path",
        "/data.json",
        "--header",
        "x-beta=on",
    ]);
    assert!(
        report.contains("rule[3] \"beta-json\": match -> use_backend \"mgmt\""),
        "{report}"
    );

    let report = explain(&[
        "--host",
        "x",
        "--path",
        "/office",
        "--client-ip",
        "10.1.2.3",
    ]);
    assert!(
        report.contains("rule[4] \"office-ip\": match -> use_backend \"mgmt\""),
        "{report}"
    );

    let pid = child.id();
    let kill = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .expect("run kill");
    assert!(kill.success(), "kill -INT must be accepted");
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("eqproxy did not finish after SIGINT");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    remove_temp(&config);
    assert_eq!(status.code(), Some(0), "clean shutdown must exit with 0");
}

/// Auth service for the subrequest gate (real socket): 401 + body for
/// `/ext/bad`, 200 otherwise.
fn start_auth_service() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind auth service");
    let addr = listener.local_addr().expect("addr auth service");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            std::thread::spawn(move || {
                use std::io::Read;
                let mut buf = [0u8; 8192];
                let mut total = 0usize;
                loop {
                    match stream.read(&mut buf[total..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => total += n,
                    }
                    if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf[..total]).into_owned();
                let denied = head.contains("x-original-url: /ext/bad");
                let response = if denied {
                    "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"ext\"\r\nContent-Length: 14\r\nConnection: close\r\n\r\ndenied-by-auth"
                        .to_owned()
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_owned()
                };
                let _ = stream.write_all(response.as_bytes());
            });
        }
    });
    addr
}

/// Authentication through the **real** binary (B-N9/B-I9): Basic
/// htpasswd entries (`type = "basic"`) and the external subrequest
/// (`auth-url`) gate the requests of their rules — explicit 401s with
/// `WWW-Authenticate`/auth body, good credentials reach the backend, and
/// `config explain` names the gate offline.
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_auth_basic_and_subrequest_gate_requests() {
    let backend = start_identity_backend("api");
    let auth = start_auth_service();
    let config = temp_config(
        "auth",
        &format!(
            "schema_version = 1\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             backend = \"api\"\n\
             mode = \"http\"\n\
             \n\
             [[listener.web.rules]]\n\
             name = \"private\"\n\
             path_prefix = \"/private/\"\n\
             use_backend = \"api\"\n\
             [listener.web.rules.auth]\n\
             type = \"basic\"\n\
             realm = \"test\"\n\
             users = [\"alice:$apr1$eqpr0xyS$DDjQzF4.2qDil6v9iW4Xo1\"]\n\
             \n\
             [[listener.web.rules]]\n\
             name = \"ext\"\n\
             path_prefix = \"/ext/\"\n\
             use_backend = \"api\"\n\
             [listener.web.rules.auth]\n\
             url = \"http://{auth}/verify\"\n\
             \n\
             [backend.api]\n\
             server = \"{backend}\"\n"
        ),
    );

    let mut child = bin()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run (auth)");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let mut proxy_addr = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        let read = stderr.read_line(&mut line).expect("read stderr");
        assert!(read > 0, "eqproxy closed stderr without announcing bind");
        if let Some(addr) = line.split("listening on ").nth(1) {
            proxy_addr = addr.trim().to_owned();
            break;
        }
    }
    assert!(!proxy_addr.is_empty(), "the address was not announced");

    // Basic: no credentials -> explicit 401 + WWW-Authenticate.
    let response = proxied(
        proxy_addr.as_str(),
        b"GET /private/x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(response.starts_with("HTTP/1.1 401 "), "{response}");
    assert!(
        response.contains("www-authenticate: Basic realm=\"test\""),
        "{response}"
    );
    // Wrong password -> 401 again.
    let response = proxied(
        proxy_addr.as_str(),
        b"GET /private/x HTTP/1.1\r\nHost: x\r\nAuthorization: Basic YWxpY2U6d3Jvbmc=\r\nConnection: close\r\n\r\n",
    );
    assert!(response.starts_with("HTTP/1.1 401 "), "{response}");
    // `alice:secret` (apr1 htpasswd entry) -> proxied to the backend.
    let response = proxied(
        proxy_addr.as_str(),
        b"GET /private/x HTTP/1.1\r\nHost: x\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\nConnection: close\r\n\r\n",
    );
    assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
    assert_eq!(body_of(&response), "api");

    // Subrequest: the auth service allows and the backend answers.
    let response = proxied(
        proxy_addr.as_str(),
        b"GET /ext/good HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
    assert_eq!(body_of(&response), "api");
    // Subrequest: the auth service denies and its response reaches the
    // client (status, WWW-Authenticate and body).
    let response = proxied(
        proxy_addr.as_str(),
        b"GET /ext/bad HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(response.starts_with("HTTP/1.1 401 "), "{response}");
    assert!(
        response.contains("www-authenticate: Basic realm=\"ext\""),
        "{response}"
    );
    assert_eq!(body_of(&response), "denied-by-auth");

    // `config explain` names the gate offline (H4).
    let explain = |path: &str| {
        let out = bin()
            .args(["config", "explain", "--config"])
            .arg(&config)
            .args(["--host", "x", "--path", path])
            .output()
            .expect("run eqproxy config explain");
        assert!(out.status.success(), "explain exits 0: {:?}", out);
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let report = explain("/private/x");
    assert!(report.contains("auth basic realm \"test\""), "{report}");
    let report = explain("/ext/good");
    assert!(
        report.contains(&format!("auth subrequest http://{auth}/verify")),
        "{report}"
    );

    let pid = child.id();
    let kill = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .expect("run kill");
    assert!(kill.success(), "kill -INT must be accepted");
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("eqproxy did not finish after SIGINT");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    remove_temp(&config);
    assert_eq!(status.code(), Some(0), "clean shutdown must exit with 0");
}

/// The config gate rejects an `https://` auth-url naming the gap (the
/// subrequest is plain http) instead of failing at request time.
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn validate_rejects_https_auth_url_naming_the_gap() {
    let config = temp_config(
        "auth-https",
        "schema_version = 1\n\
         [listener.web]\n\
         listen = \"127.0.0.1:8080\"\n\
         backend = \"api\"\n\
         mode = \"http\"\n\
         [[listener.web.rules]]\n\
         path = \"/x\"\n\
         use_backend = \"api\"\n\
         [listener.web.rules.auth]\n\
         url = \"https://auth.example/verify\"\n\
         [backend.api]\n\
         server = \"127.0.0.1:9000\"\n",
    );
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&config)
        .output()
        .expect("run eqproxy config validate");
    remove_temp(&config);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "must fail with code 1; stderr: {stderr}"
    );
    assert!(stderr.contains("auth.url"), "stderr: {stderr}");
    assert!(stderr.contains("http:// only"), "stderr: {stderr}");
}

/// Rule errors through the real binary name the field and show an example
/// (Q1: actionable errors, never opaque).
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn validate_names_rule_fields_actionably() {
    let backend = start_identity_backend("x");
    let config = temp_config(
        "rules-bad",
        &format!(
            "schema_version = 1\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             backend = \"api\"\n\
             mode = \"http\"\n\
             \n\
             [[listener.web.rules]]\n\
             use_backend = \"api\"\n\
             host = \"a\"\n\
             host_regex = \"b\"\n\
             \n\
             [backend.api]\n\
             server = \"{backend}\"\n"
        ),
    );
    let out = bin()
        .args(["config", "validate", "--config"])
        .arg(&config)
        .output()
        .expect("run eqproxy config validate");
    remove_temp(&config);
    assert!(!out.status.success(), "ambiguous rule must be rejected");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("rules[0].host"),
        "the error must name the rule field: {err}"
    );
    assert!(
        err.contains("at most one of host, host_prefix, host_regex"),
        "the error must say why: {err}"
    );
}

/// Backend that answers `200 OK` with `body` and records the request
/// line of every request, so tests can observe what the proxy really
/// forwarded (e.g. a rewritten path). Same shape as `start_identity_backend`.
fn start_recording_backend(
    body: &'static str,
) -> (
    std::net::SocketAddr,
    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
) {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind recording");
    let addr = listener.local_addr().expect("addr recording");
    let keep = std::sync::Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let keep = std::sync::Arc::clone(&keep);
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let mut total = 0usize;
                loop {
                    match stream.read(&mut buf[total..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => total += n,
                    }
                    if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let request_line = String::from_utf8_lossy(&buf[..total])
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                keep.lock().expect("record").push(request_line);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            });
        }
    });
    (addr, seen)
}

/// Rule actions through the **real** binary (v0.6 slice 2: B-N5/B-I6 +
/// Envoy `prefix_rewrite`/`redirect`/`direct_response`): `rewrite`
/// reshapes the forwarded request, `redirect` answers a rendered 3xx and
/// `direct_response` serves a body locally — the local actions never
/// contact a backend. `config explain` shows each action offline.
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_rule_actions_rewrite_redirect_and_direct_response() {
    let (api, seen) = start_recording_backend("api");
    let config = temp_config(
        "rules-actions",
        &format!(
            r#"schema_version = 1
[listener.web]
listen = "127.0.0.1:0"
backend = "api"
mode = "http"

[[listener.web.rules]]
name = "rewrite-v1"
path_prefix = "/v1/"
use_backend = "api"
set_headers = [{{ name = "x-beta", value = "on" }}]
response_headers = [{{ name = "x-marker", value = "v06" }}]
[listener.web.rules.rewrite]
path_prefix_rewrite = "/api/"

[[listener.web.rules]]
name = "redirect-old"
path = "/old"
[listener.web.rules.redirect]
status = 301
location = "/new"

[[listener.web.rules]]
name = "direct-health"
path = "/healthz"
[listener.web.rules.direct_response]
status = 200
body = "pong"

[backend.api]
server = "{api}"
"#
        ),
    );

    let mut child = bin()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run (actions)");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let mut proxy_addr = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        let read = stderr.read_line(&mut line).expect("leer stderr");
        assert!(read > 0, "eqproxy closed stderr without announcing bind");
        if let Some(addr) = line.split("listening on ").nth(1) {
            proxy_addr = addr.trim().to_owned();
            break;
        }
    }
    assert!(!proxy_addr.is_empty(), "the address was not announced");

    // direct_response: local body, no backend involved.
    let response = proxied(
        proxy_addr.as_str(),
        b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    // Locally-generated responses use the shared lowercase reason
    // phrases (`phrase()`, same as the C9 503/502 responses).
    assert!(response.starts_with("HTTP/1.1 200 ok"), "{response}");
    assert!(
        response.contains("content-type: text/plain\r\n"),
        "{response}"
    );
    assert_eq!(body_of(&response), "pong", "direct_response body");

    // redirect: 3xx + Location rendered per request.
    let response = proxied(
        proxy_addr.as_str(),
        b"GET /old HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(
        response.starts_with("HTTP/1.1 301 moved permanently"),
        "{response}"
    );
    assert!(response.contains("location: /new\r\n"), "{response}");

    assert!(
        seen.lock().expect("lock").is_empty(),
        "redirect/direct_response must never contact a backend: {:?}",
        seen.lock().expect("lock")
    );

    // rewrite: the backend sees the rewritten target.
    let response = proxied(
        proxy_addr.as_str(),
        b"GET /v1/users HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert_eq!(body_of(&response), "api", "proxied to the rule's backend");
    assert_eq!(
        *seen.lock().expect("lock"),
        ["GET /api/users HTTP/1.1"],
        "the forwarded request must carry the rewritten path"
    );
    // The rule's response header actions reach the client (B-N4/B-I4/B-E17).
    assert!(response.contains("x-marker: v06\r\n"), "{response}");

    // `config explain` reproduces the actions offline.
    let explain = |args: &[&str]| {
        let out = bin()
            .args(["config", "explain", "--config"])
            .arg(&config)
            .args(args)
            .output()
            .expect("run eqproxy config explain");
        assert!(out.status.success(), "explain exits 0: {:?}", out);
        String::from_utf8_lossy(&out.stdout).into_owned()
    };

    let report = explain(&["--host", "x", "--path", "/v1/users"]);
    assert!(
        report.contains(
            "rule[0] \"rewrite-v1\": match -> use_backend \"api\" (rewrite: path_prefix \"/v1/\" -> \"/api/\")"
        ),
        "{report}"
    );
    assert!(
        report.contains("[headers: set x-beta -> \"on\", response set x-marker -> \"v06\"]"),
        "{report}"
    );
    assert!(
        report.contains("route_decision: first matching rule -> use_backend \"api\" (rewrite:"),
        "{report}"
    );

    let report = explain(&["--host", "x", "--path", "/old"]);
    assert!(
        report.contains("rule[1] \"redirect-old\": match -> redirect 301 -> \"/new\""),
        "{report}"
    );
    assert!(
        report.contains("action: local response (no backend contacted)"),
        "{report}"
    );

    let report = explain(&["--host", "x", "--path", "/healthz"]);
    assert!(
        report.contains("rule[2] \"direct-health\": match -> direct_response 200"),
        "{report}"
    );
    assert!(
        report.contains("action: local response (no backend contacted)"),
        "{report}"
    );

    let pid = child.id();
    let kill = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .expect("run kill");
    assert!(kill.success(), "kill -INT must be accepted");
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("eqproxy did not finish after SIGINT");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    remove_temp(&config);
    assert_eq!(status.code(), Some(0), "clean shutdown must exit with 0");
}

/// Rule action errors through the real binary name the exact field and
/// suggest a fix (Q1: actionable errors, never opaque).
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn validate_names_rule_action_fields_actionably() {
    let reject = |rule: &str, want_field: &str, want_why: &str| {
        let config = temp_config(
            "actions-bad",
            &format!(
                r#"schema_version = 1
[listener.web]
listen = "127.0.0.1:0"
backend = "api"
mode = "http"

{rule}

[backend.api]
server = "127.0.0.1:9"
"#
            ),
        );
        let out = bin()
            .args(["config", "validate", "--config"])
            .arg(&config)
            .output()
            .expect("run eqproxy config validate");
        remove_temp(&config);
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success(),
            "must be rejected: {rule}
{err}"
        );
        assert!(
            err.contains(want_field),
            "must name the field {want_field}: {err}"
        );
        assert!(err.contains(want_why), "must say why ({want_why}): {err}");
    };

    reject(
        r#"[[listener.web.rules]]
name = "r"
path = "/x"
[listener.web.rules.redirect]
status = 200
location = "/y""#,
        "rules[0].redirect.status",
        "301, 302, 303, 307, 308",
    );
    reject(
        r#"[[listener.web.rules]]
name = "r"
path = "/x"
[listener.web.rules.redirect]
location = "/new?from=$scheme""#,
        "rules[0].redirect.location",
        "unknown placeholder in location",
    );
    reject(
        r#"[[listener.web.rules]]
name = "r"
path = "/x"
[listener.web.rules.direct_response]
status = 700
body = "x""#,
        "rules[0].direct_response.status",
        "out of range (200-599)",
    );
    reject(
        r#"[[listener.web.rules]]
name = "r"
path = "/x"
use_backend = "api"
[listener.web.rules.rewrite]
path_prefix_rewrite = "/v2/""#,
        "rules[0].rewrite.path_prefix_rewrite",
        "needs the rule's path_prefix to replace",
    );
    reject(
        r#"[[listener.web.rules]]
name = "r"
path = "/x"
use_backend = "api"
[listener.web.rules.redirect]
location = "/y""#,
        "rules[0]",
        "set exactly one of use_backend, split, redirect or direct_response",
    );
    reject(
        r#"[[listener.web.rules]]
name = "r"
path = "/x"
set_headers = [{ name = "x-beta", value = "on" }]"#,
        "rules[0].set_headers",
        "only apply to forwarding rules (use_backend or split)",
    );
    reject(
        r#"[[listener.web.rules]]
name = "r"
path = "/x"
use_backend = "api"
set_headers = [{ name = "x-beta", value = "$request_uri" }]"#,
        "rules[0].set_headers[0].value",
        "unknown placeholder in value",
    );
    reject(
        r#"[[listener.web.rules]]
name = "r"
path = "/x"
use_backend = "api"
del_headers = ["content-length"]"#,
        "rules[0].del_headers[0]",
        "framing header the proxy owns",
    );
    reject(
        r#"[[listener.web.rules]]
name = "r"
path = "/x"
use_backend = "api"
[listener.web.rules.cors]
allow_origin = "*"
allow_credentials = true"#,
        "rules[0].cors.allow_origin",
        "cannot be combined with allow_credentials",
    );
    reject(
        r#"[[listener.web.rules]]
name = "r"
path = "/x"
[listener.web.rules.cors]
allow_origin = "https://app.example""#,
        "rules[0].cors",
        "only applies to forwarding rules (use_backend or split)",
    );
    reject(
        r#"[[listener.web.rules]]
name = "r"
path = "/x"
use_backend = "api"
rate_limit = { rate = 0 }"#,
        "rules[0].rate_limit.rate",
        "rate must be at least 1",
    );
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_proxies_traffic_and_shuts_down_gracefully_on_sigint() {
    let backend = start_echo_backend();
    let config = temp_config(
        "run",
        &format!(
            "schema_version = 1\nshutdown_grace = \"5s\"\n[listener.web]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\nconnect_timeout = \"2s\"\nidle_timeout = \"30s\"\n[backend.api]\nserver = \"{backend}\"\n"
        ),
    );

    let mut child = bin()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));

    // Waits for the bind line to learn the real ephemeral port.
    let mut proxy_addr = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        let read = stderr.read_line(&mut line).expect("leer stderr");
        assert!(read > 0, "eqproxy closed stderr without announcing bind");
        if let Some(addr) = line.split("listening on ").nth(1) {
            proxy_addr = addr.trim().to_owned();
            break;
        }
    }
    assert!(
        !proxy_addr.is_empty(),
        "the listen address was not announced"
    );

    // Real traffic through the proxy.
    let mut client = TcpStream::connect(proxy_addr.as_str()).expect("connect al proxy");
    client.write_all(b"ping").expect("write");
    let mut buf = [0u8; 4];
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    client.read_exact(&mut buf).expect("read eco");
    assert_eq!(&buf, b"ping", "echo must be byte for byte");

    // Real SIGINT → graceful shutdown.
    let pid = child.id();
    let kill = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .expect("run kill");
    assert!(kill.success(), "kill -INT must be accepted");

    // The in-flight connection must be able to finish after the signal.
    client.write_all(b"fin").expect("write after SIGINT");
    let mut tail = [0u8; 3];
    client.read_exact(&mut tail).expect("echo after SIGINT");
    assert_eq!(&tail, b"fin");
    drop(client);

    // The process must exit on its own, with code 0.
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("eqproxy did not finish after SIGINT");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    remove_temp(&config);

    assert_eq!(status.code(), Some(0), "clean shutdown must exit with 0");
    let mut rest = String::new();
    let _ = stderr.read_line(&mut rest);
    let mut remainder = String::new();
    for line in stderr.lines().map_while(Result::ok) {
        remainder.push_str(&line);
        remainder.push('\n');
    }
    let all = format!("{rest}{remainder}");
    assert!(all.contains("shutdown complete"), "stderr final:\n{all}");
    assert!(all.contains("METRICS"), "must report metrics:\n{all}");
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn validate_accepts_phase2b_config_with_tls_servers_and_health_checks() {
    let config = temp_config(
        "phase2b",
        &format!(
            "schema_version = 1\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             backend = \"api\"\n\
             [listener.web.tls]\n\
             cert = \"{FIXTURE_CERT}\"\n\
             key = \"{FIXTURE_KEY}\"\n\
             alpn = [\"http/1.1\"]\n\
             min_version = \"1.2\"\n\
             [backend.api]\n\
             servers = [{{ addr = \"127.0.0.1:9000\", weight = 2 }}, {{ addr = \"127.0.0.1:9001\" }}]\n\
             balance = \"roundrobin\"\n\
             proxy_protocol = \"v1\"\n\
             [backend.api.health_check]\n\
             interval = \"2s\"\n\
             timeout = \"1s\"\n\
             fall = 3\n\
             rise = 2\n\
             [backend.api.tls]\n\
             verify = true\n\
             ca_file = \"{FIXTURE_CERT}\"\n\
             server_name = \"localhost\"\n"
        ),
    );
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&config)
        .output()
        .expect("run eqproxy config validate");
    remove_temp(&config);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the full 2b config must validate; stderr: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("config OK: 1 listener(s), 1 backend(s)"),
        "stdout: {stdout}"
    );
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn validate_rejects_server_and_servers_together() {
    let config = temp_config(
        "both",
        "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\n[backend.api]\nserver = \"127.0.0.1:9000\"\nservers = [{ addr = \"127.0.0.1:9001\" }]\n",
    );
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&config)
        .output()
        .expect("run eqproxy config validate");
    remove_temp(&config);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "server + servers must be rejected; stderr: {stderr}"
    );
    assert!(
        stderr.contains("field `backend.api.servers`"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("mutually exclusive"), "stderr: {stderr}");
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn validate_rejects_invalid_affinity_mode() {
    let config = temp_config(
        "affinity-bad",
        "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\n[backend.api]\nserver = \"127.0.0.1:9\"\naffinity = { mode = \"sticky\" }\n",
    );
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&config)
        .output()
        .expect("run eqproxy config validate");
    remove_temp(&config);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "an unknown affinity mode must be rejected; stderr: {stderr}"
    );
    assert!(
        stderr.contains("backend.api.affinity.mode"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("mode must be"), "stderr: {stderr}");
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn validate_reports_missing_cert_file_with_actionable_error() {
    let config = temp_config(
        "no-cert",
        "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\n[listener.web.tls]\ncert = \"/no/existe/cert.pem\"\nkey = \"/no/existe/key.pem\"\n[backend.api]\nserver = \"127.0.0.1:9000\"\n",
    );
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&config)
        .output()
        .expect("run eqproxy config validate");
    remove_temp(&config);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a missing cert must be rejected; stderr: {stderr}"
    );
    assert!(stderr.contains("listener.web.tls.cert"), "stderr: {stderr}");
    assert!(stderr.contains("could not read"), "stderr: {stderr}");
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_with_tls_termination_proxies_real_traffic() {
    let backend = start_echo_backend();
    let config = temp_config(
        "tls-run",
        &format!(
            "schema_version = 1\nshutdown_grace = \"1s\"\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             backend = \"api\"\n\
             connect_timeout = \"2s\"\n\
             idle_timeout = \"1s\"\n\
             [listener.web.tls]\n\
             cert = \"{FIXTURE_CERT}\"\n\
             key = \"{FIXTURE_KEY}\"\n\
             alpn = [\"http/1.1\"]\n\
             [backend.api]\n\
             server = \"{backend}\"\n"
        ),
    );

    let mut child = bin()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));

    let mut proxy_addr = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        let read = stderr.read_line(&mut line).expect("leer stderr");
        assert!(read > 0, "eqproxy closed stderr without announcing bind");
        if let Some(addr) = line.split("listening on ").nth(1) {
            proxy_addr = addr.trim().to_owned();
            break;
        }
    }
    assert!(!proxy_addr.is_empty(), "the TLS address was not announced");

    // Real TLS client (openssl s_client) against the listener with termination:
    // the echo must come back through the encrypted tunnel.
    let mut client = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            proxy_addr.as_str(),
            "-quiet",
            "-ign_eof",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn openssl s_client (needed for the TLS e2e)");
    client
        .stdin
        .take()
        .expect("TLS client stdin")
        .write_all(b"ping")
        .expect("write TLS");
    let output = client.wait_with_output().expect("wait for s_client");
    let echoed = String::from_utf8_lossy(&output.stdout);
    assert!(
        echoed.contains("ping"),
        "the TLS echo must come back intact; stdout: {echoed}"
    );
    wait_for_sigint_shutdown(&mut child, &config);
}

/// Subject of the certificate a real TLS client receives for `sni`
/// (`openssl s_client -showcerts` piped to `openssl x509`).
fn served_certificate_subject(addr: &str, sni: Option<&str>) -> String {
    let sni = sni.map_or(String::new(), |name| format!("-servername {name} "));
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "openssl s_client -connect {addr} {sni}-showcerts </dev/null 2>/dev/null | openssl x509 -noout -subject"
        ))
        .output()
        .expect("run openssl s_client (needed for the SNI e2e)");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_with_sni_serves_the_certificate_of_the_requested_name() {
    let backend = start_echo_backend();
    let config = temp_config(
        "sni",
        &format!(
            "schema_version = 1\nshutdown_grace = \"1s\"\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             backend = \"api\"\n\
             connect_timeout = \"2s\"\n\
             idle_timeout = \"1s\"\n\
             [listener.web.tls]\n\
             cert = \"{FIXTURE_CERT}\"\n\
             key = \"{FIXTURE_KEY}\"\n\
             [[listener.web.tls.certs]]\n\
             cert = \"{FIXTURE_ALPHA_CERT}\"\n\
             key = \"{FIXTURE_ALPHA_KEY}\"\n\
             names = [\"alpha.example.test\"]\n\
             [[listener.web.tls.certs]]\n\
             cert = \"{FIXTURE_BETA_CERT}\"\n\
             key = \"{FIXTURE_BETA_KEY}\"\n\
             names = [\"*.beta.example.test\"]\n\
             [backend.api]\n\
             server = \"{backend}\"\n"
        ),
    );

    let mut child = bin()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let mut proxy_addr = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        let read = stderr.read_line(&mut line).expect("leer stderr");
        assert!(read > 0, "eqproxy closed stderr without announcing bind");
        if let Some(addr) = line.split("listening on ").nth(1) {
            proxy_addr = addr.trim().to_owned();
            break;
        }
    }
    assert!(!proxy_addr.is_empty(), "the TLS address was not announced");

    // The certificate of each name comes from the handshake itself.
    let alpha = served_certificate_subject(&proxy_addr, Some("alpha.example.test"));
    assert!(
        alpha.contains("alpha.example.test"),
        "exact SNI name must serve its certificate; got {alpha:?}"
    );
    let beta = served_certificate_subject(&proxy_addr, Some("x.beta.example.test"));
    assert!(
        beta.contains("beta.example.test"),
        "wildcard SNI name must serve its certificate; got {beta:?}"
    );
    let unknown = served_certificate_subject(&proxy_addr, Some("unknown.example.test"));
    assert!(
        unknown.contains("localhost"),
        "an unclaimed name must get the default certificate ({FIXTURE_CERT}); got {unknown:?}"
    );
    let no_sni = served_certificate_subject(&proxy_addr, None);
    assert!(
        no_sni.contains("localhost"),
        "a client without SNI must get the default certificate; got {no_sni:?}"
    );

    // Traffic through the SNI tunnel still reaches the backend.
    let mut client = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            proxy_addr.as_str(),
            "-servername",
            "alpha.example.test",
            "-quiet",
            "-ign_eof",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn openssl s_client");
    client
        .stdin
        .take()
        .expect("TLS client stdin")
        .write_all(b"ping-sni")
        .expect("write TLS");
    let output = client.wait_with_output().expect("wait for s_client");
    let echoed = String::from_utf8_lossy(&output.stdout);
    assert!(
        echoed.contains("ping-sni"),
        "the SNI tunnel must carry traffic; stdout: {echoed}"
    );
    wait_for_sigint_shutdown(&mut child, &config);
}

#[cfg_attr(
    miri,
    ignore = "needs processes and the filesystem: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn config_validate_rejects_duplicate_and_invalid_sni_names() {
    // The same name claimed by two certificates.
    let duplicate = temp_config(
        "sni-dupe",
        &format!(
            "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\n\
             [listener.web.tls]\ncert = \"{FIXTURE_CERT}\"\nkey = \"{FIXTURE_KEY}\"\n\
             [[listener.web.tls.certs]]\ncert = \"{FIXTURE_ALPHA_CERT}\"\nkey = \"{FIXTURE_ALPHA_KEY}\"\nnames = [\"same.example.test\"]\n\
             [[listener.web.tls.certs]]\ncert = \"{FIXTURE_BETA_CERT}\"\nkey = \"{FIXTURE_BETA_KEY}\"\nnames = [\"SAME.example.test\"]\n\
             [backend.api]\nserver = \"127.0.0.1:9\"\n"
        ),
    );
    let out = bin()
        .args(["config", "validate", "--config"])
        .arg(&duplicate)
        .output()
        .expect("run config validate");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("listener.web.tls.certs[1].names"),
        "the error must name the field; stderr: {stderr}"
    );
    assert!(
        stderr.contains("already claimed"),
        "the error must name the cause; stderr: {stderr}"
    );

    // Invalid names: an IP literal and a wildcard that is not the
    // leftmost label.
    let invalid = temp_config(
        "sni-invalid",
        &format!(
            "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\n\
             [listener.web.tls]\ncert = \"{FIXTURE_CERT}\"\nkey = \"{FIXTURE_KEY}\"\n\
             [[listener.web.tls.certs]]\ncert = \"{FIXTURE_ALPHA_CERT}\"\nkey = \"{FIXTURE_ALPHA_KEY}\"\nnames = [\"127.0.0.1\", \"api.*.example.test\"]\n\
             [backend.api]\nserver = \"127.0.0.1:9\"\n"
        ),
    );
    let out = bin()
        .args(["config", "validate", "--config"])
        .arg(&invalid)
        .output()
        .expect("run config validate");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("IP literal"),
        "an IP name must be rejected naming the cause; stderr: {stderr}"
    );
    assert!(
        stderr.contains("leftmost label"),
        "a misplaced wildcard must be rejected naming the fix; stderr: {stderr}"
    );
    remove_temp(&duplicate);
    remove_temp(&invalid);
}

// --- `config apply` / `config rollback` (Phase 3, offline) ---
//
// The state (`current.toml` + `history/`) lives in `EQPROXY_STATE_DIR`, so
// parallel tests isolate without touching the process working directory.

/// Isolated state dir for one test (removed first in case of stale runs).
fn fresh_state(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("eqproxy-state-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn remove_state(dir: &PathBuf) {
    let _ = std::fs::remove_dir_all(dir);
}

const APPLY_V1: &str = "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\n[backend.api]\nserver = \"127.0.0.1:9\"\n";
const APPLY_V2: &str = "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\n[backend.api]\nservers = [{ addr = \"127.0.0.1:9\" }, { addr = \"127.0.0.1:10\" }]\n";

fn run_apply(state: &PathBuf, config: &PathBuf) -> std::process::Output {
    bin()
        .env("EQPROXY_STATE_DIR", state)
        .args(["config", "apply", "--config"])
        .arg(config)
        .output()
        .expect("run eqproxy config apply")
}

/// `apply` must gate from a single read: pipes like `/dev/stdin` cannot be
/// read twice (regression test for the audit-found stdin bug).
#[cfg_attr(
    miri,
    ignore = "needs processes and the filesystem: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn apply_reads_piped_stdin_once() {
    let state = fresh_state("stdin");
    let mut child = bin()
        .env("EQPROXY_STATE_DIR", &state)
        .args(["config", "apply", "--config", "/dev/stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy config apply");
    child
        .stdin
        .take()
        .expect("apply stdin")
        .write_all(APPLY_V1.as_bytes())
        .expect("write piped config");
    let output = child.wait_with_output().expect("wait for apply");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "piped apply must exit 0; stderr: {stderr}"
    );
    assert!(
        stdout.contains("(no previous configuration)"),
        "stdout: {stdout}"
    );
    assert_eq!(
        std::fs::read(state.join("current.toml")).expect("current stored"),
        APPLY_V1.as_bytes()
    );
    remove_state(&state);
}

fn run_rollback(state: &PathBuf) -> std::process::Output {
    bin()
        .env("EQPROXY_STATE_DIR", state)
        .args(["config", "rollback"])
        .output()
        .expect("run eqproxy config rollback")
}

#[cfg_attr(
    miri,
    ignore = "needs processes and the filesystem: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn apply_stores_first_configuration_with_inventory() {
    let state = fresh_state("first");
    let config = temp_config("apply-v1", APPLY_V1);
    let output = run_apply(&state, &config);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "apply must exit 0; stderr: {stderr}"
    );
    for expected in [
        "applied:",
        "(no previous configuration)",
        "plan: 1 listener(s), 1 backend(s)",
    ] {
        assert!(
            stdout.contains(expected),
            "missing {expected:?} in: {stdout}"
        );
    }
    assert_eq!(
        std::fs::read(state.join("current.toml")).expect("current stored"),
        APPLY_V1.as_bytes(),
        "current.toml must hold the exact candidate bytes"
    );
    let history: Vec<_> = std::fs::read_dir(state.join("history"))
        .expect("history dir")
        .filter_map(|e| e.ok())
        .collect();
    assert!(history.is_empty(), "first apply records no backup");
    remove_temp(&config);
    remove_state(&state);
}

#[cfg_attr(
    miri,
    ignore = "needs processes and the filesystem: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn apply_reports_diff_and_keeps_backup() {
    let state = fresh_state("diff");
    let v1 = temp_config("apply-d-v1", APPLY_V1);
    let v2 = temp_config("apply-d-v2", APPLY_V2);
    assert!(run_apply(&state, &v1).status.success());
    let output = run_apply(&state, &v2);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "second apply must exit 0; stderr: {stderr}"
    );
    for expected in [
        "applied:",
        "1 difference(s) vs previous",
        "backup 0001-",
        "~ backend \"api\" servers:",
    ] {
        assert!(
            stdout.contains(expected),
            "missing {expected:?} in: {stdout}"
        );
    }
    assert_eq!(
        std::fs::read(state.join("current.toml")).expect("current stored"),
        APPLY_V2.as_bytes()
    );
    let history: Vec<_> = std::fs::read_dir(state.join("history"))
        .expect("history dir")
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(history.len(), 1, "one backup for one superseded current");
    remove_temp(&v1);
    remove_temp(&v2);
    remove_state(&state);
}

#[cfg_attr(
    miri,
    ignore = "needs processes and the filesystem: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn apply_is_idempotent_for_identical_bytes() {
    let state = fresh_state("idem");
    let config = temp_config("apply-idem", APPLY_V1);
    assert!(run_apply(&state, &config).status.success());
    let output = run_apply(&state, &config);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(
        stdout.contains("already applied"),
        "re-apply must be a no-op report; stdout: {stdout}"
    );
    let history: Vec<_> = std::fs::read_dir(state.join("history"))
        .expect("history dir")
        .filter_map(|e| e.ok())
        .collect();
    assert!(history.is_empty(), "idempotent re-apply records no backup");
    remove_temp(&config);
    remove_state(&state);
}

#[cfg_attr(
    miri,
    ignore = "needs processes and the filesystem: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn apply_gate_leaves_state_untouched() {
    let state = fresh_state("gate");
    let good = temp_config("apply-g-good", APPLY_V1);
    assert!(run_apply(&state, &good).status.success());
    // Invalid candidate: exit 1, current and history unchanged.
    let bad = temp_config(
        "apply-g-bad",
        "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nbackend = \"ghost\"\n",
    );
    let output = run_apply(&state, &bad);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "gate failure must exit 1");
    assert!(
        stderr.contains("ghost"),
        "actionable error; stderr: {stderr}"
    );
    assert_eq!(
        std::fs::read(state.join("current.toml")).expect("current kept"),
        APPLY_V1.as_bytes(),
        "failed apply must not touch current"
    );
    let history: Vec<_> = std::fs::read_dir(state.join("history"))
        .expect("history dir")
        .filter_map(|e| e.ok())
        .collect();
    assert!(history.is_empty(), "failed apply records no backup");
    // Missing file: exit 1 without creating any state.
    let missing_state = fresh_state("gate-missing");
    let output = bin()
        .env("EQPROXY_STATE_DIR", &missing_state)
        .args(["config", "apply", "--config", "no-existe.toml"])
        .output()
        .expect("run eqproxy config apply");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr.contains("could not read"), "stderr: {stderr}");
    assert!(
        !missing_state.exists(),
        "a failed gate must not create state"
    );
    remove_temp(&good);
    remove_temp(&bad);
    remove_state(&state);
}

#[cfg_attr(
    miri,
    ignore = "needs processes and the filesystem: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn rollback_restores_previous_current() {
    let state = fresh_state("rb");
    let v1 = temp_config("rb-v1", APPLY_V1);
    let v2 = temp_config("rb-v2", APPLY_V2);
    assert!(run_apply(&state, &v1).status.success());
    assert!(run_apply(&state, &v2).status.success());
    let output = run_rollback(&state);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "rollback must exit 0; stderr: {stderr}"
    );
    for expected in [
        "rolled back:",
        "restored from 0001-",
        "difference(s) vs applied",
    ] {
        assert!(
            stdout.contains(expected),
            "missing {expected:?} in: {stdout}"
        );
    }
    assert_eq!(
        std::fs::read(state.join("current.toml")).expect("current restored"),
        APPLY_V1.as_bytes(),
        "rollback must restore the exact previous bytes"
    );
    let history: Vec<_> = std::fs::read_dir(state.join("history"))
        .expect("history dir")
        .filter_map(|e| e.ok())
        .collect();
    assert!(history.is_empty(), "rollback pops the spent backup");
    remove_temp(&v1);
    remove_temp(&v2);
    remove_state(&state);
}

#[cfg_attr(
    miri,
    ignore = "needs processes and the filesystem: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn rollback_without_history_fails_explicitly() {
    let state = fresh_state("rb-empty");
    let output = run_rollback(&state);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("no previous configuration"),
        "stderr: {stderr}"
    );
    remove_state(&state);
}

#[cfg_attr(
    miri,
    ignore = "needs processes and the filesystem: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn rollback_walks_back_one_apply_at_a_time() {
    let state = fresh_state("rb-walk");
    let v1 = temp_config("rb-w-v1", APPLY_V1);
    let v2 = temp_config("rb-w-v2", APPLY_V2);
    let v3 = temp_config(
        "rb-w-v3",
        "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nmaxconn = 7\nbackend = \"api\"\n[backend.api]\nservers = [{ addr = \"127.0.0.1:9\" }, { addr = \"127.0.0.1:10\" }]\n",
    );
    assert!(run_apply(&state, &v1).status.success());
    assert!(run_apply(&state, &v2).status.success());
    assert!(run_apply(&state, &v3).status.success());
    assert!(run_rollback(&state).status.success());
    assert_eq!(
        std::fs::read(state.join("current.toml")).expect("back to v2"),
        APPLY_V2.as_bytes()
    );
    assert!(run_rollback(&state).status.success());
    assert_eq!(
        std::fs::read(state.join("current.toml")).expect("back to v1"),
        APPLY_V1.as_bytes()
    );
    let output = run_rollback(&state);
    assert_eq!(
        output.status.code(),
        Some(1),
        "empty history must exit 1; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    remove_temp(&v1);
    remove_temp(&v2);
    remove_temp(&v3);
    remove_state(&state);
}

/// Shared SIGINT-shutdown tail: real SIGINT to a live proxy must end it
/// with code 0 (extracted so the apply/rollback suite can sit above it).
fn wait_for_sigint_shutdown(child: &mut std::process::Child, config: &Path) {
    // Real SIGINT → clean shutdown with code 0.
    let pid = child.id();
    let kill = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .expect("run kill");
    assert!(kill.success(), "kill -INT must be accepted");
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("eqproxy did not finish after SIGINT");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    remove_temp(config);
    assert_eq!(status.code(), Some(0), "clean shutdown must exit with 0");
}

// --- `doctor` (Phase 3, environment diagnostics) ---

fn run_doctor(args: &[&str]) -> std::process::Output {
    bin()
        .arg("doctor")
        .args(args)
        .output()
        .expect("run eqproxy doctor")
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn doctor_passes_for_a_free_port() {
    let config = temp_config(
        "doctor-ok",
        "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\n[backend.api]\nserver = \"127.0.0.1:9\"\n",
    );
    let config_str = config.to_string_lossy().into_owned();
    let output = run_doctor(&["--config", &config_str]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    remove_temp(&config);
    assert!(
        output.status.success(),
        "doctor must exit 0; stderr: {stderr}"
    );
    for expected in [
        "doctor checks for",
        "ok: bind 127.0.0.1:0 (listener \"web\")",
        "tls disabled (plain TCP)",
        "doctor: PASS",
    ] {
        assert!(
            stdout.contains(expected),
            "missing {expected:?} in: {stdout}"
        );
    }
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn doctor_fails_on_an_occupied_port() {
    // The echo backend holds its port: doctor's bind probe must fail
    // loudly (exit 1 + FAIL), the way `run` would fail to start.
    let backend = start_echo_backend();
    let config = temp_config(
        "doctor-busy",
        &format!(
            "schema_version = 1\n[listener.web]\nlisten = \"{backend}\"\nbackend = \"api\"\n[backend.api]\nserver = \"127.0.0.1:9\"\n"
        ),
    );
    let config_str = config.to_string_lossy().into_owned();
    let output = run_doctor(&["--config", &config_str]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    remove_temp(&config);
    assert_eq!(output.status.code(), Some(1), "stdout: {stdout}");
    assert!(
        stdout.contains(&format!("err: bind {backend} (listener \"web\")")),
        "stdout: {stdout}"
    );
    for expected in ["run would fail to start", "doctor: FAIL"] {
        assert!(
            stdout.contains(expected),
            "missing {expected:?} in: {stdout}"
        );
    }
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn doctor_reports_missing_config_actionably() {
    let output = run_doctor(&["--config", "no-existe.toml"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("could not read"), "stderr: {stderr}");
}

// --- hot config reload via SIGHUP (S-CFG-01) ---

/// Static-response backend: every request gets `200 OK` with `body`, so
/// the response body reveals **which** backend served it.
fn start_static_backend(body: &'static str) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind static");
    let addr = listener.local_addr().expect("addr static");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let mut total = 0usize;
                loop {
                    match stream.read(&mut buf[total..]) {
                        Ok(0) => break,
                        Ok(n) => {
                            total += n;
                            if buf[..total].windows(4).any(|w| w == b"\r\n\r\n")
                                || total == buf.len()
                            {
                                break;
                            }
                        }
                        Err(_) => return,
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            });
        }
    });
    addr
}

/// GET through the proxy and return the response body.
fn http_body(addr: &str) -> String {
    let mut client = TcpStream::connect(addr).expect("connect proxy");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        .expect("write GET");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let mut response = Vec::new();
    let _ = client.read_to_end(&mut response);
    let text = String::from_utf8_lossy(&response);
    text.split("\r\n\r\n")
        .nth(1)
        .unwrap_or_else(|| panic!("no body in response: {text}"))
        .to_owned()
}

/// Sends a real signal to the child (`"-HUP"`, `"-INT"`, …).
fn send_signal(child: &std::process::Child, signal: &str) {
    let pid = child.id();
    let kill = Command::new("kill")
        .args([signal, &pid.to_string()])
        .status()
        .expect("run kill");
    assert!(kill.success(), "kill {signal} must be accepted");
}

/// Reads stderr lines until one contains `needle` (panic on EOF/timeout).
fn wait_for_stderr(stderr: &mut BufReader<std::process::ChildStderr>, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        let read = stderr.read_line(&mut line).expect("read stderr");
        assert!(read > 0, "eqproxy closed stderr before {needle:?}");
        if line.contains(needle) {
            return line;
        }
    }
    panic!("timeout waiting for {needle:?} in stderr");
}

/// Full operator journey (S-CFG-01): edit the file + `kill -HUP` while
/// serving. New connections follow the new config, established ones drain
/// with theirs, an invalid candidate is rejected without touching the
/// running config, and the final report shows both counters (PP-03).
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn sighup_reloads_the_config_under_traffic() {
    let one = start_static_backend("one");
    let two = start_static_backend("two");
    let config = temp_config(
        "sighup",
        &format!(
            "schema_version = 1\nshutdown_grace = \"1s\"\n\
             [listener.web]\nlisten = \"127.0.0.1:0\"\nmode = \"http\"\nbackend = \"api\"\n\
             [backend.api]\nserver = \"{one}\"\n"
        ),
    );

    let mut child = bin()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run (sighup)");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));

    // The listen address is ephemeral: wait for the announcement.
    let mut proxy_addr = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        let read = stderr.read_line(&mut line).expect("read stderr");
        assert!(read > 0, "eqproxy closed stderr without announcing bind");
        if let Some(addr) = line.split("listening on ").nth(1) {
            proxy_addr = addr.trim().to_owned();
            break;
        }
    }
    assert!(!proxy_addr.is_empty(), "the address was not announced");
    assert_eq!(http_body(&proxy_addr), "one", "initial routing");

    // Journey 1: valid candidate → applied, new connections follow it.
    std::fs::write(
        &config,
        format!(
            "schema_version = 1\nshutdown_grace = \"1s\"\n\
             [listener.web]\nlisten = \"127.0.0.1:0\"\nmode = \"http\"\nbackend = \"api\"\n\
             [backend.api]\nserver = \"{two}\"\n"
        ),
    )
    .expect("write v2");
    send_signal(&child, "-HUP");
    let applied = wait_for_stderr(&mut stderr, "INFO config reload applied");
    assert!(
        applied.contains("listeners kept=1 added=0 removed=0"),
        "swap summary: {applied}"
    );
    assert_eq!(
        http_body(&proxy_addr),
        "two",
        "new connections must follow the applied config"
    );

    // Journey 2: invalid candidate → rejected, running config keeps serving.
    std::fs::write(&config, "schema_version = 1\n[listener.web\n").expect("write broken");
    send_signal(&child, "-HUP");
    let rejected = wait_for_stderr(&mut stderr, "ERROR config reload rejected");
    assert!(
        !rejected.trim().is_empty(),
        "the rejection must be actionable"
    );
    assert_eq!(
        http_body(&proxy_addr),
        "two",
        "the running config must keep serving"
    );

    // Clean shutdown; the final report keeps the counters (no reset).
    wait_for_sigint_shutdown(&mut child, &config);
    let mut rest = String::new();
    let _ = stderr.read_to_string(&mut rest);
    // Format updated for PP-04/05: the metrics line now also reports the
    // measured swap latency (`last_swap_us`), so the exact-format assertion
    // includes the new field.
    assert!(
        rest.contains("cfg[reloads=1 reload_failures=1 last_swap_us="),
        "final METRICS must show the reload counters and the swap latency: {rest}"
    );
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn doctor_without_config_checks_the_environment() {
    let output = run_doctor(&[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "env-only doctor must exit 0; stderr: {stderr}"
    );
    assert!(
        stdout.contains("fd limit=") || stdout.contains("fd limit unreadable"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("doctor: PASS"), "stdout: {stdout}");
}

// --- Advanced balancing through the real binary (B-H5/B-N12/B-E6 + B14) ---

use std::sync::atomic::{AtomicBool, AtomicUsize};

/// Real HTTP origin on a thread: `200` with `marker` as body (keep-alive),
/// `/healthz` answers `200`/`500` per `healthy` and closes (courtesy:
/// the checker completes at the message boundary, not at EOF). With
/// `release` set, every response waits
/// for the flag — a held exchange keeps the server loaded on purpose.
fn start_balancer_origin(
    marker: &'static str,
    healthy: std::sync::Arc<AtomicBool>,
    served: std::sync::Arc<AtomicUsize>,
    release: Option<std::sync::Arc<AtomicBool>>,
) -> std::net::SocketAddr {
    use std::sync::atomic::Ordering;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind balancer origin");
    let addr = listener.local_addr().expect("addr balancer origin");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let healthy = std::sync::Arc::clone(&healthy);
            let served = std::sync::Arc::clone(&served);
            let release = release.clone();
            std::thread::spawn(move || {
                loop {
                    use std::io::Read;
                    let mut buf = [0u8; 8192];
                    let mut total = 0usize;
                    let head_end = loop {
                        match stream.read(&mut buf[total..]) {
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
                    if head.starts_with("get /healthz ") {
                        let ok = healthy.load(Ordering::SeqCst);
                        let response = if ok {
                            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                                .to_owned()
                        } else {
                            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                .to_owned()
                        };
                        let _ = stream.write_all(response.as_bytes());
                        return;
                    }
                    served.fetch_add(1, Ordering::SeqCst);
                    if let Some(flag) = &release {
                        while !flag.load(Ordering::SeqCst) {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                    }
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n{marker}",
                        marker.len(),
                        if close { "close" } else { "keep-alive" }
                    );
                    if stream.write_all(response.as_bytes()).is_err() {
                        return;
                    }
                    if close {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// One request through the real binary; the origin marker as body.
fn marker_body(proxy: &str) -> String {
    body_of(&proxied(
        proxy,
        b"GET /x HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    ))
    .to_owned()
}

/// leastconn (B-H5/B-N12/B-E6) through the **real** binary: while one
/// server holds an exchange open, every new request lands on the other.
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_leastconn_sends_new_requests_to_the_idle_server() {
    use std::sync::atomic::Ordering;
    let served_a = std::sync::Arc::new(AtomicUsize::new(0));
    let served_b = std::sync::Arc::new(AtomicUsize::new(0));
    let healthy = std::sync::Arc::new(AtomicBool::new(true));
    let release = std::sync::Arc::new(AtomicBool::new(false));
    let a = start_balancer_origin(
        "a",
        std::sync::Arc::clone(&healthy),
        std::sync::Arc::clone(&served_a),
        Some(std::sync::Arc::clone(&release)),
    );
    let b = start_balancer_origin(
        "b",
        std::sync::Arc::clone(&healthy),
        std::sync::Arc::clone(&served_b),
        None,
    );
    let config = temp_config(
        "leastconn",
        &format!(
            "schema_version = 1\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             backend = \"api\"\n\
             mode = \"http\"\n\
             [backend.api]\n\
             balance = \"leastconn\"\n\
             servers = [{{ addr = \"{a}\" }}, {{ addr = \"{b}\" }}]\n"
        ),
    );

    let mut child = bin()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run (leastconn)");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let announce = wait_for_stderr(&mut stderr, "listening on ");
    let proxy_addr = announce
        .split("listening on ")
        .nth(1)
        .expect("bind line")
        .trim()
        .to_owned();

    // First request: both servers idle (tie) -> A (config order), held.
    let held_proxy = proxy_addr.clone();
    let held = std::thread::spawn(move || marker_body(&held_proxy));
    let deadline = Instant::now() + Duration::from_secs(10);
    while served_a.load(Ordering::SeqCst) != 1 {
        assert!(
            Instant::now() < deadline,
            "the first request never reached A"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    // Sequential requests: A is loaded (1), B is idle (0) -> all to B.
    for round in 0..3 {
        assert_eq!(
            marker_body(&proxy_addr),
            "b",
            "request {} must go to the idle server",
            round + 1
        );
    }
    assert_eq!(served_a.load(Ordering::SeqCst), 1, "A got no new request");
    assert_eq!(served_b.load(Ordering::SeqCst), 3);

    // Release A: its exchange completes and the load slot frees up.
    release.store(true, Ordering::SeqCst);
    let body = held.join().expect("held exchange thread");
    assert_eq!(body, "a", "the held exchange was served by A");

    wait_for_sigint_shutdown(&mut child, &config);
}

/// Slow start (B14, dynamic weighting) through the **real** binary: a
/// server that returns from DOWN gets almost no traffic at first and
/// exactly its fair share once the window is over.
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_slow_start_ramps_the_recovered_server_up() {
    use std::sync::atomic::Ordering;
    let served_a = std::sync::Arc::new(AtomicUsize::new(0));
    let served_b = std::sync::Arc::new(AtomicUsize::new(0));
    let healthy_a = std::sync::Arc::new(AtomicBool::new(true));
    let healthy_b = std::sync::Arc::new(AtomicBool::new(false));
    let a = start_balancer_origin("a", healthy_a, served_a, None);
    let b = start_balancer_origin("b", std::sync::Arc::clone(&healthy_b), served_b, None);
    let config = temp_config(
        "slowstart",
        &format!(
            "schema_version = 1\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             backend = \"api\"\n\
             mode = \"http\"\n\
             [backend.api]\n\
             balance = \"roundrobin\"\n\
             slow_start = \"2s\"\n\
             servers = [{{ addr = \"{a}\" }}, {{ addr = \"{b}\" }}]\n\
             [backend.api.health_check]\n\
             type = \"http\"\n\
             http_path = \"/healthz\"\n\
             interval = \"150ms\"\n\
             timeout = \"100ms\"\n\
             fall = 1\n\
             rise = 1\n\
             expect_status = \"200\"\n"
        ),
    );

    let mut child = bin()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run (slow start)");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let announce = wait_for_stderr(&mut stderr, "listening on ");
    let proxy_addr = announce
        .split("listening on ")
        .nth(1)
        .expect("bind line")
        .trim()
        .to_owned();

    // Phase 1: the health check drops the unhealthy server (fall = 1).
    // Observable through traffic: 5 consecutive responses from A mean B
    // is out of rotation (with both up, round-robin alternates).
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut streak = 0;
    while streak < 5 {
        assert!(Instant::now() < deadline, "B was never marked DOWN");
        if marker_body(&proxy_addr) == "a" {
            streak += 1;
        } else {
            streak = 0;
        }
    }

    // Phase 2: recover B and watch the ramp — the recovered server is
    // nearly invisible next to the fully ramped one.
    healthy_b.store(true, Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(300));
    let mut early = (0usize, 0usize);
    for _ in 0..10 {
        match marker_body(&proxy_addr).as_str() {
            "a" => early.0 += 1,
            "b" => early.1 += 1,
            other => panic!("unexpected origin body {other:?}"),
        }
    }
    assert!(
        early.1 < 5,
        "during the ramp the recovered server gets less than its fair share: {early:?}"
    );

    // Phase 3: the ramp is over — the split is exactly fair.
    std::thread::sleep(Duration::from_millis(2500));
    let mut late = (0usize, 0usize);
    for _ in 0..10 {
        match marker_body(&proxy_addr).as_str() {
            "a" => late.0 += 1,
            "b" => late.1 += 1,
            other => panic!("unexpected origin body {other:?}"),
        }
    }
    assert_eq!(late, (5, 5), "after the window the split is exactly 1:1");

    wait_for_sigint_shutdown(&mut child, &config);
}

/// Keep-alive origin on a thread that **never** closes a connection —
/// the interop hazard for a checker that reads its response to EOF.
/// `/healthz` answers `200` + `ok` (Content-Length framed); any other
/// path answers `200` with `marker`. `Connection: close` is ignored.
fn start_keepalive_origin(marker: &'static str) -> std::net::SocketAddr {
    use std::io::{Read, Write};
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind keep-alive origin");
    let addr = listener.local_addr().expect("addr keep-alive origin");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                loop {
                    let mut total = 0usize;
                    let head_end = loop {
                        match stream.read(&mut buf[total..]) {
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
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_owned()
                    } else {
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{marker}",
                            marker.len()
                        )
                    };
                    if stream.write_all(response.as_bytes()).is_err() {
                        return;
                    }
                    // Never close: keep serving on the same connection.
                }
            });
        }
    });
    addr
}

/// HTTP health-check interop (B-H6) through the **real** binary: an
/// origin that never closes its connections must stay in rotation
/// across check cycles. The check completes at the Content-Length
/// boundary; a checker waiting for EOF times out every cycle and flaps
/// the server DOWN (503 after the first cycle).
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_http_check_interops_with_keep_alive_origin() {
    let origin = start_keepalive_origin("k");
    let config = temp_config(
        "health-keepalive",
        &format!(
            "schema_version = 1\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             backend = \"api\"\n\
             mode = \"http\"\n\
             [backend.api]\n\
             servers = [{{ addr = \"{origin}\" }}]\n\
             [backend.api.health_check]\n\
             type = \"http\"\n\
             http_path = \"/healthz\"\n\
             interval = \"100ms\"\n\
             timeout = \"150ms\"\n\
             fall = 1\n\
             rise = 1\n\
             expect_status = \"200\"\n\
             expect_rstring = \"ok\"\n"
        ),
    );

    let mut child = bin()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run (health keep-alive)");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let announce = wait_for_stderr(&mut stderr, "listening on ");
    let proxy_addr = announce
        .split("listening on ")
        .nth(1)
        .expect("bind line")
        .trim()
        .to_owned();

    // Journey: many check cycles pass against the keep-alive origin and
    // it stays in rotation the whole time (no flapping to DOWN).
    assert_eq!(
        marker_body(&proxy_addr),
        "k",
        "the first request must be proxied"
    );
    std::thread::sleep(Duration::from_millis(1000)); // >= 6 check cycles
    for round in 0..3 {
        assert_eq!(
            marker_body(&proxy_addr),
            "k",
            "the server must stay UP after check cycle {}",
            round + 1
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    wait_for_sigint_shutdown(&mut child, &config);
}

// --- Non-blocking dynamic DNS through the real binary (B-H13·B-N18·B-E15) ---

/// Value of `key` (e.g. `"failures="`) inside the last `cluster`
/// (e.g. `"dns["`) of the METRICS output.
fn metric_value(rest: &str, cluster: &str, key: &str) -> u64 {
    let Some(at) = rest.rfind(cluster) else {
        return 0;
    };
    rest[at + cluster.len()..]
        .split([']', ' '])
        .find(|token| token.starts_with(key))
        .and_then(|token| token[key.len()..].parse().ok())
        .unwrap_or(0)
}

/// Accept loop for one bound listener: `200` + `marker` (keep-alive).
fn serve_origin_loop(listener: std::net::TcpListener, marker: &'static str) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { break };
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let mut buf = [0u8; 8192];
            loop {
                let mut total = 0usize;
                let head_end = loop {
                    match stream.read(&mut buf[total..]) {
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
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n{marker}",
                    marker.len(),
                    if close { "close" } else { "keep-alive" }
                );
                if stream.write_all(response.as_bytes()).is_err() {
                    return;
                }
                if close {
                    return;
                }
            }
        });
    }
}

/// Real origin on ONE port bound on both loopback families: the OS
/// resolver may hand `localhost` as 127.0.0.1 or ::1 (multi-A reality),
/// and the origin must answer whatever comes.
fn start_dual_stack_origin(marker: &'static str) -> u16 {
    let v4 = std::net::TcpListener::bind("127.0.0.1:0").expect("bind v4 origin");
    let port = v4.local_addr().expect("addr v4 origin").port();
    let v6_addr = std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port));
    let v6 = std::net::TcpListener::bind(v6_addr).expect("bind v6 origin");
    std::thread::spawn(move || serve_origin_loop(v4, marker));
    std::thread::spawn(move || serve_origin_loop(v6, marker));
    port
}

/// Startup with broken DNS (CE7) through the **real** binary: the
/// listener is announced immediately and answers an explicit, counted
/// 503 — never a silent block. The name is RFC 6761 `.invalid` (the OS
/// resolver answers NXDOMAIN; the background resolver keeps retrying at
/// `resolve_interval`). The hung-resolver variant is covered at the
/// dataplane level in `eqproxy-net/tests/e2e_dns.rs`.
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_startup_with_broken_dns_serves_immediately_with_explicit_503() {
    let config = temp_config(
        "dns-broken",
        "schema_version = 1\n\
         [listener.web]\n\
         listen = \"127.0.0.1:0\"\n\
         backend = \"api\"\n\
         mode = \"http\"\n\
         [backend.api]\n\
         servers = [{ addr = \"cold-start.invalid:8080\" }]\n\
         resolve_interval = \"100ms\"\n",
    );

    let started = Instant::now();
    let mut child = bin()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run (broken dns)");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let announce = wait_for_stderr(&mut stderr, "listening on ");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the listener must not wait for DNS (took {:?})",
        started.elapsed()
    );
    let proxy_addr = announce
        .split("listening on ")
        .nth(1)
        .expect("bind line")
        .trim()
        .to_owned();

    // Explicit 503, promptly: the request never waits for DNS.
    let response = proxied(
        &proxy_addr,
        b"GET /x HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    );
    assert!(
        response.starts_with("HTTP/1.1 503"),
        "unresolved backend = explicit 503: {response:?}"
    );

    // Bounded wait for the background resolver to complete several
    // rounds (the first OS lookup lands a few hundred ms after startup;
    // measured: ~400 ms on the maintainer's host).
    std::thread::sleep(Duration::from_millis(1500));

    wait_for_sigint_shutdown(&mut child, &config);
    let mut rest = String::new();
    let _ = stderr.read_to_string(&mut rest);
    assert!(
        metric_value(&rest, "proxy[", "no_server=") >= 1,
        "the 503 must be counted in no_available_server: {rest}"
    );
    assert!(
        metric_value(&rest, "dns[", "failures=") >= 1,
        "the broken resolution rounds must be counted: {rest}"
    );
}

/// A `HOSTNAME:PORT` backend through the **real** binary with the OS
/// resolver (B-H13/B-N18/B-E15): traffic flows to the origin through
/// the name and the periodic re-resolution runs against real DNS
/// (counted in METRICS) — no restart anywhere.
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_hostname_backend_resolves_with_the_os_resolver() {
    let port = start_dual_stack_origin("k");
    let config = temp_config(
        "dns-name",
        &format!(
            "schema_version = 1\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             backend = \"api\"\n\
             mode = \"http\"\n\
             [backend.api]\n\
             servers = [{{ addr = \"localhost:{port}\" }}]\n\
             resolve_interval = \"100ms\"\n"
        ),
    );

    let mut child = bin()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run (hostname backend)");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let announce = wait_for_stderr(&mut stderr, "listening on ");
    let proxy_addr = announce
        .split("listening on ")
        .nth(1)
        .expect("bind line")
        .trim()
        .to_owned();

    // The resolved name serves real traffic.
    let deadline = Instant::now() + Duration::from_secs(10);
    while marker_body(&proxy_addr) != "k" {
        assert!(
            Instant::now() < deadline,
            "traffic never reached the origin through the hostname"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // Several periodic rounds against the real resolver.
    std::thread::sleep(Duration::from_millis(400));

    wait_for_sigint_shutdown(&mut child, &config);
    let mut rest = String::new();
    let _ = stderr.read_to_string(&mut rest);
    assert!(
        metric_value(&rest, "dns[", "ok=") >= 2,
        "initial + periodic resolutions against real DNS: {rest}"
    );
    assert!(
        metric_value(&rest, "dns[", "updates=") >= 1,
        "the resolved address must reach the balancer: {rest}"
    );
}

/// The config gate through the **real** binary (Q1: actionable errors):
/// the reference aliases of `leastconn` are accepted, `slow_start` is
/// bounded, and an unknown algorithm is rejected by name.
#[cfg_attr(
    miri,
    ignore = "needs processes and the filesystem: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn validate_maps_leastconn_aliases_and_bounds_slow_start() {
    // nginx's `least_conn` name + slow start in range: accepted.
    let ok = temp_config(
        "balance-ok",
        "schema_version = 1\n\
         [listener.web]\n\
         listen = \"127.0.0.1:8080\"\n\
         backend = \"api\"\n\
         [backend.api]\n\
         balance = \"least_conn\"\n\
         slow_start = \"30s\"\n\
         servers = [{ addr = \"127.0.0.1:9000\", weight = 2 }]\n",
    );
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&ok)
        .output()
        .expect("run eqproxy config validate");
    remove_temp(&ok);
    assert!(
        output.status.success(),
        "least_conn alias + slow_start must validate; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Envoy's `least_request` name: accepted too.
    let ok = temp_config(
        "balance-alias",
        "schema_version = 1\n\
         [listener.web]\n\
         listen = \"127.0.0.1:8080\"\n\
         backend = \"api\"\n\
         [backend.api]\n\
         balance = \"least_request\"\n\
         servers = [{ addr = \"127.0.0.1:9000\" }]\n",
    );
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&ok)
        .output()
        .expect("run eqproxy config validate");
    remove_temp(&ok);
    assert!(
        output.status.success(),
        "least_request alias must validate; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // slow_start out of range: named field + bounded example.
    let bad = temp_config(
        "balance-slow",
        "schema_version = 1\n\
         [listener.web]\n\
         listen = \"127.0.0.1:8080\"\n\
         backend = \"api\"\n\
         [backend.api]\n\
         slow_start = \"2h\"\n\
         servers = [{ addr = \"127.0.0.1:9000\" }]\n",
    );
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&bad)
        .output()
        .expect("run eqproxy config validate");
    remove_temp(&bad);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "out-of-range slow_start must fail; stderr: {stderr}"
    );
    for expected in ["slow_start", "maximum 1h", "example:"] {
        assert!(
            stderr.contains(expected),
            "missing {expected:?} in:\n{stderr}"
        );
    }

    // Unknown algorithm: rejected by name, never silently defaulted.
    let bad = temp_config(
        "balance-unknown",
        "schema_version = 1\n\
         [listener.web]\n\
         listen = \"127.0.0.1:8080\"\n\
         backend = \"api\"\n\
         [backend.api]\n\
         balance = \"maglev\"\n\
         servers = [{ addr = \"127.0.0.1:9000\" }]\n",
    );
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&bad)
        .output()
        .expect("run eqproxy config validate");
    remove_temp(&bad);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("maglev"),
        "the error must name the rejected value: {stderr}"
    );
}

// --- B-I11 (canary y tráfico ponderado) + C10 (hot maps) ---

/// Identity backend that keeps connections alive (answers every
/// request on the same connection until the client closes): the
/// hot-map test holds one client connection open across data swaps.
fn start_keepalive_identity_backend(body: &'static str) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind keepalive identity");
    let addr = listener.local_addr().expect("addr keepalive identity");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            std::thread::spawn(move || {
                use std::io::Read;
                let mut buf = [0u8; 8192];
                loop {
                    // Read one full request head, then answer it.
                    let mut total = 0usize;
                    loop {
                        match stream.read(&mut buf[total..]) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => total += n,
                        }
                        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    if stream.write_all(response.as_bytes()).is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// One request on a keep-alive connection: writes the head and reads
/// exactly one Content-Length-framed response, leaving the connection
/// open (the hot-map test holds one across data swaps).
fn keepalive_roundtrip(stream: &mut TcpStream, head: &str) -> String {
    stream.write_all(head.as_bytes()).expect("write head");
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).expect("read response");
        assert!(read > 0, "the keep-alive connection closed unexpectedly");
        buf.extend_from_slice(&chunk[..read]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head_text = String::from_utf8_lossy(&buf[..pos]).to_ascii_lowercase();
            let len: usize = head_text
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .map(|value| value.trim().parse().expect("content-length"))
                .unwrap_or(0);
            if buf.len() >= pos + 4 + len {
                return String::from_utf8_lossy(&buf).into_owned();
            }
        }
    }
}

/// Canary y tráfico ponderado through the **real** binary (B-I11): a
/// `split` rule fans requests out across backends by weight (exact
/// shares in rotation), `canary-by-header` and `canary-by-cookie`
/// overrides route 100 % to the canary, and `config explain` shows both
/// offline (H4).
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_canary_split_routes_by_weight_with_header_and_cookie_overrides() {
    let stable = start_identity_backend("stable");
    let canary = start_identity_backend("canary");
    let config = temp_config(
        "canary",
        &format!(
            "schema_version = 1\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             mode = \"http\"\n\
             backend = \"stable\"\n\
             \n\
             [[listener.web.rules]]\n\
             name = \"by-header\"\n\
             path_prefix = \"/h\"\n\
             headers = [{{ name = \"x-canary\", exact = \"always\" }}]\n\
             use_backend = \"canary\"\n\
             \n\
             [[listener.web.rules]]\n\
             name = \"by-cookie\"\n\
             path_prefix = \"/c\"\n\
             cookies = [{{ name = \"canary\", exact = \"always\" }}]\n\
             use_backend = \"canary\"\n\
             \n\
             [[listener.web.rules]]\n\
             name = \"split\"\n\
             path_prefix = \"/s\"\n\
             split = [\
               {{ backend = \"stable\", weight = 3 }},\
               {{ backend = \"canary\", weight = 1 }},\
             ]\n\
             \n\
             [backend.stable]\n\
             server = \"{stable}\"\n\
             [backend.canary]\n\
             server = \"{canary}\"\n"
        ),
    );

    let mut child = bin()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run (canary)");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let mut proxy_addr = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        let read = stderr.read_line(&mut line).expect("read stderr");
        assert!(read > 0, "eqproxy closed stderr without announcing bind");
        if let Some(addr) = line.split("listening on ").nth(1) {
            proxy_addr = addr.trim().to_owned();
            break;
        }
    }
    assert!(!proxy_addr.is_empty(), "the address was not announced");

    // Weighted split: 8 requests over a 3:1 split = 6 stable + 2 canary.
    let mut counts = std::collections::BTreeMap::new();
    for _ in 0..8 {
        let response = proxied(
            proxy_addr.as_str(),
            b"GET /s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        );
        assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
        *counts
            .entry(body_of(&response).to_owned())
            .or_insert(0usize) += 1;
    }
    assert_eq!(
        counts.get("stable"),
        Some(&6),
        "3:1 over 8 requests: {counts:?}"
    );
    assert_eq!(counts.get("canary"), Some(&2), "3:1 over 8: {counts:?}");

    // Canary-by-header: 100 % to the canary when the header matches.
    let response = proxied(
        proxy_addr.as_str(),
        b"GET /h HTTP/1.1\r\nHost: x\r\nx-canary: always\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body_of(&response), "canary", "{response}");
    let response = proxied(
        proxy_addr.as_str(),
        b"GET /h HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body_of(&response), "stable", "{response}");

    // Canary-by-cookie: same, via the Cookie header (RFC 6265 pairs).
    let response = proxied(
        proxy_addr.as_str(),
        b"GET /c HTTP/1.1\r\nHost: x\r\nCookie: sid=1; canary=always\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body_of(&response), "canary", "{response}");
    let response = proxied(
        proxy_addr.as_str(),
        b"GET /c HTTP/1.1\r\nHost: x\r\nCookie: canary=never\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body_of(&response), "stable", "{response}");

    // `config explain` shows the split and the cookie gate offline (H4).
    let explain = |args: &[&str]| {
        let out = bin()
            .args(["config", "explain", "--config"])
            .arg(&config)
            .args(args)
            .output()
            .expect("run eqproxy config explain");
        assert!(out.status.success(), "explain exits 0: {:?}", out);
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let report = explain(&["--path", "/s"]);
    assert!(
        report.contains("split [stable w=3, canary w=1] (smooth weighted round-robin per request)"),
        "{report}"
    );
    let report = explain(&["--path", "/c"]);
    assert!(
        report.contains("no match (cookie \"canary\": not present)"),
        "{report}"
    );
    let report = explain(&["--path", "/c", "--header", "cookie=canary=always"]);
    assert!(
        report.contains("match -> use_backend \"canary\""),
        "{report}"
    );

    let pid = child.id();
    let kill = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .expect("run kill");
    assert!(kill.success(), "kill -INT must be accepted");
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("eqproxy did not finish after SIGINT");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    remove_temp(&config);
    assert_eq!(status.code(), Some(0), "clean shutdown must exit with 0");
}

/// Hot data maps through the **real** binary (C10 / PP-02): a 100 000
/// entry map updates under traffic **without a config reload** and
/// without losing any other state — the modified entries change, the
/// untouched ones keep working and a held keep-alive connection
/// survives the swap. A malformed update is rejected once (counted) and
/// the last good data keeps serving.
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_hot_maps_swap_under_traffic_without_config_reload() {
    fn map_file(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("eqproxy-cli-e2e-{}-{name}", std::process::id()))
    }
    fn write_entries(path: &Path, lines: &[String]) {
        // Atomic replace (write + rename): the watcher never sees a
        // torn file (documented operational rule for map updates).
        let staging = path.with_extension("staging");
        std::fs::write(&staging, lines.join("\n") + "\n").expect("write map file");
        std::fs::rename(&staging, path).expect("replace map file");
    }

    let mapfile = map_file("tiers.map");
    let initial: Vec<String> = (0..100_000).map(|i| format!("user-{i} vip")).collect();
    write_entries(&mapfile, &initial);

    let vip = start_keepalive_identity_backend("vip");
    let free = start_keepalive_identity_backend("free");
    let config = temp_config(
        "hotmaps",
        &format!(
            "schema_version = 1\n\
             [maps.tiers]\n\
             file = \"{}\"\n\
             reload_interval = \"250ms\"\n\
             \n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             mode = \"http\"\n\
             backend = \"free\"\n\
             \n\
             [[listener.web.rules]]\n\
             name = \"vip\"\n\
             map = {{ name = \"tiers\", header = \"x-user\", equals = \"vip\" }}\n\
             use_backend = \"vip\"\n\
             \n\
             [backend.free]\n\
             server = \"{free}\"\n\
             [backend.vip]\n\
             server = \"{vip}\"\n",
            mapfile.display()
        ),
    );

    let mut child = bin()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run (hot maps)");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let mut proxy_addr = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        let read = stderr.read_line(&mut line).expect("read stderr");
        assert!(read > 0, "eqproxy closed stderr without announcing bind");
        if let Some(addr) = line.split("listening on ").nth(1) {
            proxy_addr = addr.trim().to_owned();
            break;
        }
    }
    assert!(!proxy_addr.is_empty(), "the address was not announced");

    let as_user = |user: &str| {
        format!("GET / HTTP/1.1\r\nHost: x\r\nx-user: {user}\r\nConnection: close\r\n\r\n")
    };
    // Baseline: the mapped user is vip, the unknown one is not.
    let response = proxied(proxy_addr.as_str(), as_user("user-99999").as_bytes());
    assert_eq!(body_of(&response), "vip", "{response}");
    let response = proxied(proxy_addr.as_str(), as_user("nobody").as_bytes());
    assert_eq!(body_of(&response), "free", "{response}");

    // One keep-alive connection held across the whole update (PP-02:
    // live state survives the data swap).
    let mut held = TcpStream::connect(proxy_addr.as_str()).expect("connect keepalive");
    let response = keepalive_roundtrip(
        &mut held,
        "GET / HTTP/1.1\r\nHost: x\r\nx-user: user-99999\r\n\r\n",
    );
    assert_eq!(body_of(&response), "vip", "{response}");

    // Hot update: one entry downgraded, one added, 99 999 untouched.
    let mut updated: Vec<String> = (0..100_000)
        .map(|i| {
            if i == 50_000 {
                "user-50000 downgraded".to_owned()
            } else {
                format!("user-{i} vip")
            }
        })
        .collect();
    updated.push("newcomer vip".to_owned());
    write_entries(&mapfile, &updated);

    // The swap lands within a reload window (poll, never a fixed sleep).
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = proxied(proxy_addr.as_str(), as_user("newcomer").as_bytes());
        if body_of(&response) == "vip" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the map reload did not land in time"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    // The modified entry changed…
    let response = proxied(proxy_addr.as_str(), as_user("user-50000").as_bytes());
    assert_eq!(body_of(&response), "free", "{response}");
    // …and the untouched entries kept working (before/after identical
    // except the modified entries: the PP-02 success criterion).
    let response = proxied(proxy_addr.as_str(), as_user("user-99999").as_bytes());
    assert_eq!(body_of(&response), "vip", "{response}");
    // The held connection survived the swap and still routes.
    let response = keepalive_roundtrip(
        &mut held,
        "GET / HTTP/1.1\r\nHost: x\r\nx-user: user-77777\r\n\r\n",
    );
    assert_eq!(body_of(&response), "vip", "{response}");

    // A malformed update (duplicate key) is rejected once and counted;
    // the last good data keeps serving.
    write_entries(&mapfile, &["dup 1".to_owned(), "dup 2".to_owned()]);
    std::thread::sleep(Duration::from_secs(1));
    let response = proxied(proxy_addr.as_str(), as_user("user-99999").as_bytes());
    assert_eq!(
        body_of(&response),
        "vip",
        "a bad update must keep the last good data"
    );

    // Close the held connection so the drain is immediate, then stop.
    drop(held);
    let pid = child.id();
    let kill = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .expect("run kill");
    assert!(kill.success(), "kill -INT must be accepted");
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("eqproxy did not finish after SIGINT");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    // The process has exited: drain the log lines it left in the pipe.
    let mut log = String::new();
    loop {
        line.clear();
        if stderr.read_line(&mut line).expect("read stderr") == 0 {
            break;
        }
        log.push_str(&line);
    }
    remove_temp(&config);
    let _ = std::fs::remove_file(&mapfile);
    assert_eq!(status.code(), Some(0), "clean shutdown must exit with 0");

    // The final METRICS line is the observable of PP-02: data updated
    // in hot (`map_reloads`) with **zero** config reloads (no state was
    // rebuilt) and exactly one rejected bad update (counted once).
    assert!(
        log.contains("map \"tiers\" reloaded: 100001 entries"),
        "the hot reload must be logged: {log}"
    );
    assert!(
        log.contains("maps[reloads=1 failures=1]"),
        "one good swap and one rejected bad update: {log}"
    );
    assert!(
        log.contains("cfg[reloads=0"),
        "no config reload may happen (PP-02: no state rebuilt): {log}"
    );
}

/// The config gate rejects misconfigured splits and maps with field,
/// cause and example — and a missing map file fails at load with the
/// map name (never at request time).
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn validate_rejects_misconfigured_splits_maps_and_missing_files() {
    let reject = |body: &str, want_field: &str, want_why: &str| {
        let config = temp_config("split-map-bad", &format!("schema_version = 1\n{body}"));
        let out = bin()
            .args(["config", "validate", "--config"])
            .arg(&config)
            .output()
            .expect("run eqproxy config validate");
        remove_temp(&config);
        assert!(!out.status.success(), "must be rejected: {body}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains(want_field), "must name {want_field}: {err}");
        assert!(err.contains(want_why), "must say why ({want_why}): {err}");
    };

    // A split naming a ghost backend.
    reject(
        "[listener.web]\n\
         listen = \"127.0.0.1:0\"\n\
         mode = \"http\"\n\
         backend = \"stable\"\n\
         [[listener.web.rules]]\n\
         name = \"s\"\n\
         path_prefix = \"/\"\n\
         split = [{ backend = \"stable\", weight = 1 }, { backend = \"ghost\", weight = 1 }]\n\
         [backend.stable]\n\
         server = \"127.0.0.1:9\"\n",
        "rules[0].split[1].backend",
        "does not exist",
    );
    // A map with both sources (exactly one is required).
    reject(
        "[maps.t]\n\
         file = \"t.map\"\n\
         entries = { a = \"1\" }\n",
        "maps.t",
        "set exactly one of file or entries",
    );
    // A map with an unreadable file fails at load (not at request time).
    reject(
        "[maps.t]\n\
         file = \"/nonexistent/eqproxy-missing.map\"\n",
        "maps.t.file",
        "cannot be read",
    );
}

/// B-H3 through the **real** binary: `hash_policy` keeps a key on its split
/// target and `request_mirror` sends a copy of the matching request to a
/// shadow backend while the client keeps the primary answer. `config
/// explain` shows both decisions offline.
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_hash_policy_and_request_mirror_end_to_end() {
    let api_a = start_static_backend("alpha");
    let api_b = start_static_backend("beta");
    let (shadow, shadow_seen) = start_recording_backend("shadow");
    let config = temp_config(
        "hash-mirror",
        &format!(
            r#"schema_version = 1
[listener.web]
listen = "127.0.0.1:0"
backend = "a"
mode = "http"

[[listener.web.rules]]
name = "hashed"
path_prefix = "/hashed"
split = [{{ backend = "a", weight = 1 }}, {{ backend = "b", weight = 1 }}]
hash_policy = {{ key = "cookie:session" }}

[[listener.web.rules]]
name = "mirrored"
path_prefix = "/api"
use_backend = "a"
request_mirror = {{ backend = "shadow", percentage = 100 }}

[backend.a]
server = "{api_a}"
[backend.b]
server = "{api_b}"
[backend.shadow]
server = "{shadow}"
"#
        ),
    );

    // `config explain` says how the split picks and that a copy goes out,
    // before anything runs.
    let explain = bin()
        .args(["config", "explain", "--config"])
        .arg(&config)
        .args(["--method", "GET", "--host", "svc", "--path", "/hashed"])
        .output()
        .expect("run eqproxy config explain");
    let explained = String::from_utf8_lossy(&explain.stdout);
    assert!(
        explain.status.success(),
        "explain must exit 0; stderr: {}",
        String::from_utf8_lossy(&explain.stderr)
    );
    assert!(
        explained.contains("hash cookie:session"),
        "explain must name the hash key: {explained}"
    );

    // The mirror belongs to the other rule: explain again for its path and
    // check the policy shows up in the matched rule's header summary.
    let explain_mirror = bin()
        .args(["config", "explain", "--config"])
        .arg(&config)
        .args(["--method", "GET", "--host", "svc", "--path", "/api/x"])
        .output()
        .expect("run eqproxy config explain (mirror)");
    let explained_mirror = String::from_utf8_lossy(&explain_mirror.stdout);
    assert!(
        explain_mirror.status.success(),
        "explain must exit 0; stderr: {}",
        String::from_utf8_lossy(&explain_mirror.stderr)
    );
    assert!(
        explained_mirror.contains("mirror 100% -> shadow"),
        "explain must name the mirror policy: {explained_mirror}"
    );

    let mut child = bin()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run (hash/mirror)");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let mut proxy_addr = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        let read = stderr.read_line(&mut line).expect("leer stderr");
        assert!(read > 0, "eqproxy closed stderr without announcing bind");
        if let Some(addr) = line.split("listening on ").nth(1) {
            proxy_addr = addr.trim().to_owned();
            break;
        }
    }
    assert!(!proxy_addr.is_empty(), "the address was not announced");

    let hashed = |key: &str| {
        proxied(
            proxy_addr.as_str(),
            format!(
                "GET /hashed/p HTTP/1.1\r\nHost: svc\r\nCookie: session={key}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
    };

    // One key, many requests: always the same split target.
    let first = hashed("alice");
    assert_eq!(body_of(&first), "alpha", "first key: {first}");
    for _ in 0..5 {
        assert_eq!(
            body_of(&hashed("alice")),
            "alpha",
            "the same key must keep its target on the real binary"
        );
    }
    // Different keys reach both targets (the key really selects).
    let mut bodies = std::collections::BTreeSet::new();
    for i in 0..12 {
        let response = hashed(&format!("user-{i}"));
        bodies.insert(body_of(&response).to_owned());
    }
    assert_eq!(
        bodies,
        ["alpha".to_owned(), "beta".to_owned()]
            .into_iter()
            .collect(),
        "the split must keep every target in rotation: {bodies:?}"
    );

    // Mirror: the client gets the primary answer, the shadow backend
    // receives the copy (observed on its own socket, not assumed).
    let response = proxied(
        proxy_addr.as_str(),
        b"POST /api/orders HTTP/1.1\r\nHost: svc\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody",
    );
    assert_eq!(body_of(&response), "alpha", "primary answer: {response}");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let seen = shadow_seen.lock().expect("record").clone();
        if seen.iter().any(|line| line == "POST /api/orders HTTP/1.1") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the shadow backend never received the mirrored copy: {seen:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    send_signal(&child, "-INT");
    child.wait().expect("eqproxy exits");
    remove_temp(&config);
}

/// Q1/CE1: `config schema` publishes the configuration schema the editors
/// consume — the same document the parser accepts, reproducible into a file.
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn config_schema_publishes_the_generated_json_schema() {
    let output = bin()
        .args(["config", "schema"])
        .output()
        .expect("run eqproxy config schema");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "config schema must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is JSON");
    assert_eq!(
        parsed["$schema"], "https://json-schema.org/draft/2020-12/schema",
        "the schema declares its draft"
    );
    for definition in [
        "ListenerConfig",
        "BackendConfig",
        "RuleConfig",
        "HashPolicyConfig",
        "RequestMirrorConfig",
    ] {
        assert!(
            parsed["$defs"][definition].is_object(),
            "the schema must publish {definition}"
        );
    }

    // `--output` writes exactly what stdout prints (one trailing newline),
    // so the repository copy is regenerated by a single command.
    let path = std::env::temp_dir().join(format!("eqproxy-schema-{}.json", std::process::id()));
    let written = bin()
        .args(["config", "schema", "--output"])
        .arg(&path)
        .output()
        .expect("run eqproxy config schema --output");
    assert!(
        written.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&written.stderr)
    );
    let file = std::fs::read_to_string(&path).expect("read written schema");
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        file, stdout,
        "--output must write exactly what stdout prints (one trailing newline)"
    );

    // The published file in the repository is the one this binary renders.
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../eqproxy.schema.json");
    let committed = std::fs::read_to_string(&repo).expect("read eqproxy.schema.json");
    assert_eq!(
        committed,
        file,
        "{} is stale: run `eqproxy config schema --output eqproxy.schema.json`",
        repo.display()
    );
}
