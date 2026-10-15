//! E2E tests through the **real** `eqproxy` binary (the interface the
//! operator will use), with real sockets and real process signals.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
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

fn temp_config(name: &str, contents: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "eqproxy-cli-e2e-{}-{name}.toml",
        std::process::id()
    ));
    std::fs::write(&path, contents).expect("write test config");
    path
}

fn remove_temp(path: &PathBuf) {
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
    // `config explain`, `config plan` and now `config apply`/`config rollback`
    // used to be in this list; all are implemented (Phase 3 slices) and
    // covered by explain_*/plan_*/apply_*/rollback_* tests below.
    let cases: &[(&[&str], &str)] = &[
        (
            &["config", "import", "--input", "a.cfg", "--output", "b.toml"],
            "config import",
        ),
        (&["doctor"], "eqproxy doctor"),
    ];
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
            "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nmode = \"http\"\nbackend = \"api\"\n[backend.api]\nservers = [{{ addr = \"{backend}\", weight = 3 }}]\n"
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
fn wait_for_sigint_shutdown(child: &mut std::process::Child, config: &PathBuf) {
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
