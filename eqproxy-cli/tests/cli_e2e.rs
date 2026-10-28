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

/// Origin that answers each request with its body, `Content-Length` framed.
fn start_body_echo_origin() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind body echo");
    let addr = listener.local_addr().expect("addr body echo");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            std::thread::spawn(move || {
                use std::io::Read;
                let mut buf = vec![0u8; 8192];
                let mut total = 0usize;
                let head_end = loop {
                    match stream.read(&mut buf[total..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => total += n,
                    }
                    if let Some(pos) = buf[..total].windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
                let needed = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                while total < head_end + needed {
                    match stream.read(&mut buf[total..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => total += n,
                    }
                }
                let body = &buf[head_end..head_end + needed];
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nX-Origin: h1\r\n\r\n",
                    body.len()
                );
                if stream.write_all(response.as_bytes()).is_err() {
                    return;
                }
                let _ = stream.write_all(body);
            });
        }
    });
    addr
}

fn curl_stdout(args: &[&str]) -> String {
    let output = Command::new("curl")
        .args(["-sS", "--max-time", "15", "-D", "-"])
        .args(args)
        .output()
        .expect("run curl (needed for the HTTP/2 e2e)");
    assert!(
        output.status.success(),
        "curl {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// HTTP/2 E2E through the **real binary** with a **real client** (curl,
/// nghttp2): cleartext h2c with prior knowledge and TLS with `h2` ALPN, plus
/// the same TLS listener still serving HTTP/1.1 when the client asks for it.
/// A negotiated `HTTP/2` status line in curl's dump is the proof the proxy
/// spoke h2 on the wire, not just that it answered.
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_serves_http2_to_real_clients_over_tls_and_cleartext() {
    let origin = start_body_echo_origin();
    let config = temp_config(
        "h2-run",
        &format!(
            "schema_version = 1\nshutdown_grace = \"1s\"\n\
             [listener.plain]\n\
             listen = \"127.0.0.1:0\"\n\
             mode = \"http\"\n\
             backend = \"api\"\n\
             connect_timeout = \"2s\"\n\
             [listener.secure]\n\
             listen = \"127.0.0.1:0\"\n\
             mode = \"http\"\n\
             backend = \"api\"\n\
             connect_timeout = \"2s\"\n\
             [listener.secure.tls]\n\
             cert = \"{FIXTURE_CERT}\"\n\
             key = \"{FIXTURE_KEY}\"\n\
             alpn = [\"h2\", \"http/1.1\"]\n\
             [backend.api]\n\
             server = \"{origin}\"\n"
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
    let (mut plain, mut secure) = (String::new(), String::new());
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline && (plain.is_empty() || secure.is_empty()) {
        line.clear();
        let read = stderr.read_line(&mut line).expect("read stderr");
        assert!(read > 0, "eqproxy closed stderr without announcing bind");
        if let Some(addr) = line.split("listener plain listening on ").nth(1) {
            plain = addr.trim().to_owned();
        }
        if let Some(addr) = line.split("listener secure listening on ").nth(1) {
            secure = addr.trim().to_owned();
        }
    }
    assert!(
        !plain.is_empty(),
        "the cleartext listener was not announced"
    );
    assert!(!secure.is_empty(), "the TLS listener was not announced");

    // Cleartext h2c (prior knowledge): curl sends the connection preface.
    let h2c = curl_stdout(&["--http2-prior-knowledge", &format!("http://{plain}/h2c")]);
    assert!(
        h2c.starts_with("HTTP/2 200"),
        "cleartext h2c must negotiate HTTP/2: {h2c}"
    );
    assert!(h2c.contains("x-origin: h1"), "origin header lost: {h2c}");

    // A real request body through the h2 → h1 translation.
    let posted = curl_stdout(&[
        "--http2-prior-knowledge",
        "-d",
        "body-through-h2",
        &format!("http://{plain}/echo"),
    ]);
    assert!(posted.starts_with("HTTP/2 200"), "POST must work: {posted}");
    assert!(
        posted.ends_with("body-through-h2"),
        "the body must round-trip through the proxy: {posted}"
    );

    // TLS with ALPN h2: the client asks for h2 and gets it.
    let tls_h2 = curl_stdout(&["-k", "--http2", &format!("https://{secure}/tls-h2")]);
    assert!(
        tls_h2.starts_with("HTTP/2 200"),
        "TLS + ALPN h2 must negotiate HTTP/2: {tls_h2}"
    );

    // The same listener still serves HTTP/1.1 for clients that ask for it.
    let tls_h1 = curl_stdout(&["-k", "--http1.1", &format!("https://{secure}/tls-h1")]);
    assert!(
        tls_h1.starts_with("HTTP/1.1 200"),
        "the h2 listener must keep HTTP/1.1 alive: {tls_h1}"
    );

    wait_for_sigint_shutdown(&mut child, &config);
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
fn validate_accepts_h2_alpn_on_an_http_listener() {
    // v0.7: `alpn = ["h2"]` used to be rejected because there was no HTTP/2
    // dataplane. It terminates h2 now, so the gate accepts it (alone or
    // alongside `http/1.1`) and resolution must succeed with real certs.
    let backend = start_echo_backend();
    for alpn in ["[\"h2\"]", "[\"h2\", \"http/1.1\"]"] {
        let config = temp_config(
            "h2-alpn",
            &format!(
                "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nmode = \"http\"\nbackend = \"api\"\n[listener.web.tls]\ncert = \"{FIXTURE_CERT}\"\nkey = \"{FIXTURE_KEY}\"\nalpn = {alpn}\n[backend.api]\nserver = \"{backend}\"\n"
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
            "alpn = {alpn} must be accepted; stderr: {stderr}"
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("config OK"),
            "alpn = {alpn} must report config OK"
        );
    }
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn validate_accepts_h2_alpn_on_a_backend() {
    // v0.6.3 rejected `alpn = ["h2"]` on a backend used by an `http`
    // listener because the dataplane only spoke HTTP/1.1 upstream. v0.7
    // opens a real h2 session there, so the gate accepts it and resolution
    // keeps working (CA file + server name included).
    let backend = start_echo_backend();
    let config = temp_config(
        "backend-h2-alpn",
        &format!(
            "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nmode = \"http\"\nbackend = \"api\"\n[backend.api]\nserver = \"{backend}\"\n[backend.api.tls]\nverify = false\nalpn = [\"h2\"]\n"
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
        "backend alpn = [\"h2\"] must be accepted; stderr: {stderr}"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("config OK"),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[cfg(unix)]
#[test]
fn explain_piped_into_head_does_not_panic() {
    // `println!` panics on EPIPE: piping a long report into `head` used to
    // abort with "failed printing to stdout: Broken pipe". A reader that
    // stops early is not an error.
    let config = temp_config(
        "pipe",
        "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\n[backend.api]\nserver = \"127.0.0.1:1\"\n",
    );
    let script = format!(
        "'{}' config explain --config '{}' | head -1",
        env!("CARGO_BIN_EXE_eqproxy"),
        config.display()
    );
    let output = Command::new("sh")
        .args(["-c", &script])
        .output()
        .expect("run piped explain");
    remove_temp(&config);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "pipeline failed: {stderr}; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        !stderr.contains("Broken pipe") && !stderr.contains("panicked"),
        "the closed pipe produced a panic:\n{stderr}"
    );
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

/// Gate an origin holds an exchange on until the test opens it, so one proxy
/// exchange can stay in flight on purpose (H3: drain observability).
struct Gate {
    /// `(request_reached, opened)`.
    state: std::sync::Mutex<(bool, bool)>,
    cv: std::sync::Condvar,
}

impl Gate {
    fn new() -> Self {
        Self {
            state: std::sync::Mutex::new((false, false)),
            cv: std::sync::Condvar::new(),
        }
    }

    fn reached(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.0 = true;
            self.cv.notify_all();
        }
    }

    fn open(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.1 = true;
            self.cv.notify_all();
        }
    }

    /// Waits until the origin holds a request; `false` on timeout.
    fn wait_until_reached(&self, budget: Duration) -> bool {
        let deadline = Instant::now() + budget;
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        while !state.0 {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            let Ok((next, _)) = self.cv.wait_timeout(state, left) else {
                return false;
            };
            state = next;
        }
        true
    }

    fn wait_until_opened(&self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        while !state.1 {
            let Ok(next) = self.cv.wait(state) else {
                return;
            };
            state = next;
        }
    }
}

/// An origin that reads the request head and then waits for the gate: the
/// exchange is real and stays open until the test releases it.
fn start_gated_backend(body: &'static str) -> (std::net::SocketAddr, std::sync::Arc<Gate>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind gated");
    let addr = listener.local_addr().expect("addr gated");
    let gate = std::sync::Arc::new(Gate::new());
    let backend_gate = std::sync::Arc::clone(&gate);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let gate = std::sync::Arc::clone(&backend_gate);
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let mut total = 0usize;
                loop {
                    match stream.read(&mut buf[total..]) {
                        Ok(0) => return,
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
                gate.reached();
                gate.wait_until_opened();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            });
        }
    });
    (addr, gate)
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
///
/// Every journey that runs this origin configures its health check with
/// `timeout = "1s"`, not the 100 ms a *dead* origin would need: the probe
/// shares the machine with the whole suite, and at 100 ms a scheduling
/// hiccup marked the **healthy** origin down (`fall = 1`); the requests then
/// met the built-in `503 service unavailable` with an empty body — the
/// `expected a pool member, got ""` flake recorded on 2026-10-27. The
/// intended failure in these journeys is a status mismatch (`500`), which no
/// timeout can absorb, so the longer timeout takes nothing from the
/// assertion.
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
    marker_response(proxy).0
}

/// One request through the real binary: the marker body plus the raw
/// response, so a routing mismatch can name what the proxy actually
/// answered. The built-in "no server available" answer is a
/// `503 service unavailable` with `content-length: 0`, which is why such a
/// failure used to read as `unexpected origin body ""`.
fn marker_response(proxy: &str) -> (String, String) {
    let raw = proxied(
        proxy,
        b"GET /x HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    );
    (body_of(&raw).to_owned(), raw)
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
    // The check's timeout is 1 s, not the 100 ms a dead origin would need:
    // this harness's probe shares the machine with the whole suite, and at
    // 100 ms a scheduling hiccup under load marked the *healthy* origin down
    // (`fall = 1`); the requests then met the built-in 503 with an empty
    // body — the `unexpected origin body ""` flake recorded on 2026-10-27.
    // B's intentional failure is a status mismatch (500), which no timeout
    // can absorb, so the check still drops B on its first probe.
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
             timeout = \"1s\"\n\
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
    // nearly invisible next to the fully ramped one. The window opens at
    // B's **first byte of traffic**, observed through the dataplane, not at
    // a fixed sleep: the ramp starts at the health checker's tick, and under
    // load that tick can land later than any sleep the harness could pick,
    // so the A-only answers before it are skipped instead of timed.
    healthy_b.store(true, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut early = (0usize, 0usize);
    loop {
        let (body, raw) = marker_response(&proxy_addr);
        if early.0 + early.1 == 0 && body == "a" {
            assert!(
                Instant::now() < deadline,
                "the recovered server never took traffic within 20 s"
            );
            continue; // the tick has not landed yet: not part of the ramp
        }
        match body.as_str() {
            "a" => early.0 += 1,
            "b" => early.1 += 1,
            other => panic!("unexpected origin body {other:?}; the proxy answered {raw:?}"),
        }
        if early.0 + early.1 == 10 {
            break;
        }
    }
    assert!(
        early.1 < 5,
        "during the ramp the recovered server gets less than its fair share: {early:?}"
    );

    // Phase 3: the ramp ends — the split becomes exactly fair. The window
    // this is observed in is polled, not assumed: the ramp starts when the
    // health checker marks B up, and under instrumentation that tick can
    // arrive later than its 150 ms interval, so a fixed sleep is a race.
    // Once the weights are equal SWRR alternates strictly, so every
    // 10-request window is 5:5 from then on.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut window = 0u32;
    let mut late;
    loop {
        window += 1;
        late = (0, 0);
        for _ in 0..10 {
            let (body, raw) = marker_response(&proxy_addr);
            match body.as_str() {
                "a" => late.0 += 1,
                "b" => late.1 += 1,
                other => panic!("unexpected origin body {other:?}; the proxy answered {raw:?}"),
            }
        }
        if late == (5, 5) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the split never became exactly 1:1 after the slow-start window \
             (window {window}: {late:?})"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    wait_for_sigint_shutdown(&mut child, &config);
}

/// Backup servers (B8) through the **real** binary: the backup never sees
/// traffic while the primary is healthy, takes over when the health check
/// drops the primary, and hands the tier back when the primary recovers.
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_backup_server_covers_a_failed_primary_and_returns_on_recovery() {
    use std::sync::atomic::Ordering;
    let served_a = std::sync::Arc::new(AtomicUsize::new(0));
    let served_b = std::sync::Arc::new(AtomicUsize::new(0));
    let healthy_a = std::sync::Arc::new(AtomicBool::new(true));
    let healthy_b = std::sync::Arc::new(AtomicBool::new(true));
    let a = start_balancer_origin(
        "a",
        std::sync::Arc::clone(&healthy_a),
        std::sync::Arc::clone(&served_a),
        None,
    );
    let b = start_balancer_origin(
        "b",
        std::sync::Arc::clone(&healthy_b),
        std::sync::Arc::clone(&served_b),
        None,
    );
    let config = temp_config(
        "backup",
        &format!(
            "schema_version = 1\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             backend = \"api\"\n\
             mode = \"http\"\n\
             [backend.api]\n\
             balance = \"roundrobin\"\n\
             servers = [{{ addr = \"{a}\" }}, {{ addr = \"{b}\", backup = true }}]\n\
             [backend.api.health_check]\n\
             type = \"http\"\n\
             http_path = \"/healthz\"\n\
             interval = \"150ms\"\n\
             timeout = \"1s\"\n\
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
        .expect("spawn eqproxy run (backup)");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let announce = wait_for_stderr(&mut stderr, "listening on ");
    let proxy_addr = announce
        .split("listening on ")
        .nth(1)
        .expect("bind line")
        .trim()
        .to_owned();

    // Phase 1: the primary is healthy, so the backup must stay idle even
    // though it answers health checks and would be ready to serve.
    for _ in 0..10 {
        assert_eq!(marker_body(&proxy_addr), "a");
    }
    assert_eq!(
        served_b.load(Ordering::SeqCst),
        0,
        "the backup must not see traffic while a primary is eligible"
    );
    eprintln!(
        "backup journey phase 1 (primary healthy): primary={} backup={}",
        served_a.load(Ordering::SeqCst),
        served_b.load(Ordering::SeqCst)
    );

    // Phase 2: the primary fails its HTTP check (fall = 1) and the backup
    // takes over. Observable through traffic, not internal state.
    healthy_a.store(false, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut streak = 0;
    while streak < 5 {
        assert!(
            Instant::now() < deadline,
            "the backup never took over after the primary failed"
        );
        if marker_body(&proxy_addr) == "b" {
            streak += 1;
        } else {
            streak = 0;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    eprintln!(
        "backup journey phase 2 (primary down): primary={} backup={}",
        served_a.load(Ordering::SeqCst),
        served_b.load(Ordering::SeqCst)
    );

    // Phase 3: the primary recovers (rise = 1) and owns the tier again; the
    // backup leaves rotation immediately (a backup is never selected while a
    // primary is eligible).
    healthy_a.store(true, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut streak = 0;
    while streak < 5 {
        assert!(
            Instant::now() < deadline,
            "the recovered primary never took the tier back"
        );
        if marker_body(&proxy_addr) == "a" {
            streak += 1;
        } else {
            streak = 0;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let backup_served = served_b.load(Ordering::SeqCst);
    for _ in 0..10 {
        assert_eq!(
            marker_body(&proxy_addr),
            "a",
            "after recovery every new exchange goes to the primary"
        );
    }
    assert_eq!(
        served_b.load(Ordering::SeqCst),
        backup_served,
        "the backup stops serving once a primary is back"
    );
    eprintln!(
        "backup journey: primary={} backup={} failover=ok recovery=ok",
        served_a.load(Ordering::SeqCst),
        served_b.load(Ordering::SeqCst)
    );

    wait_for_sigint_shutdown(&mut child, &config);
}

/// Priority ladder (B7) through the **real** binary: one primary and two
/// backups at different priorities. The backup tier serves its highest rung
/// only; when that rung fails the next one takes over, and a recovered rung
/// (or the primary) takes the traffic back on the next request.
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_priority_ladder_fails_over_between_backups_and_back() {
    use std::sync::atomic::Ordering;
    let served = || std::sync::Arc::new(AtomicUsize::new(0));
    let healthy = || std::sync::Arc::new(AtomicBool::new(true));
    let (served_a, served_h, served_l) = (served(), served(), served());
    let (healthy_a, healthy_h) = (healthy(), healthy());
    let a = start_balancer_origin(
        "a",
        std::sync::Arc::clone(&healthy_a),
        std::sync::Arc::clone(&served_a),
        None,
    );
    let h = start_balancer_origin(
        "h",
        std::sync::Arc::clone(&healthy_h),
        std::sync::Arc::clone(&served_h),
        None,
    );
    let l = start_balancer_origin(
        "l",
        std::sync::Arc::new(AtomicBool::new(true)),
        std::sync::Arc::clone(&served_l),
        None,
    );
    let config = temp_config(
        "priority-ladder",
        &format!(
            "schema_version = 1\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             backend = \"api\"\n\
             mode = \"http\"\n\
             [backend.api]\n\
             balance = \"roundrobin\"\n\
             servers = [{{ addr = \"{a}\" }}, {{ addr = \"{h}\", backup = true, priority = 10 }}, {{ addr = \"{l}\", backup = true, priority = 5 }}]\n\
             [backend.api.health_check]\n\
             type = \"http\"\n\
             http_path = \"/healthz\"\n\
             interval = \"150ms\"\n\
             timeout = \"1s\"\n\
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
        .expect("spawn eqproxy run (priority ladder)");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let announce = wait_for_stderr(&mut stderr, "listening on ");
    let proxy_addr = announce
        .split("listening on ")
        .nth(1)
        .expect("bind line")
        .trim()
        .to_owned();

    let wait_for_marker = |expected: &str, what: &str| {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut streak = 0;
        while streak < 5 {
            assert!(Instant::now() < deadline, "{what}");
            if marker_body(&proxy_addr) == expected {
                streak += 1;
            } else {
                streak = 0;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    };

    // Phase 1: the primary owns the tier; both backups answer health checks
    // and stay idle.
    for _ in 0..10 {
        assert_eq!(marker_body(&proxy_addr), "a");
    }
    assert_eq!(served_h.load(Ordering::SeqCst), 0, "high rung idle");
    assert_eq!(served_l.load(Ordering::SeqCst), 0, "low rung idle");

    // Phase 2: the primary fails; the highest priority rung takes over.
    healthy_a.store(false, Ordering::SeqCst);
    wait_for_marker("h", "the high-priority backup never took over");
    assert_eq!(
        served_l.load(Ordering::SeqCst),
        0,
        "the lower rung stays idle while the high one is up"
    );

    // Phase 3: the high rung fails; the next rung serves.
    healthy_h.store(false, Ordering::SeqCst);
    wait_for_marker("l", "the lower-priority backup never took over");

    // Phase 4: the high rung recovers and takes the traffic back.
    healthy_h.store(true, Ordering::SeqCst);
    wait_for_marker("h", "the recovered high rung never took the tier back");
    let low_served = served_l.load(Ordering::SeqCst);
    for _ in 0..10 {
        assert_eq!(marker_body(&proxy_addr), "h");
    }
    assert_eq!(
        served_l.load(Ordering::SeqCst),
        low_served,
        "the lower rung stops serving when a higher one is operational"
    );

    // Phase 5: the primary recovers and outranks the whole ladder.
    healthy_a.store(true, Ordering::SeqCst);
    wait_for_marker("a", "the recovered primary never took the tier back");
    eprintln!(
        "priority journey: primary={} high={} low={} ladder=ok",
        served_a.load(Ordering::SeqCst),
        served_h.load(Ordering::SeqCst),
        served_l.load(Ordering::SeqCst)
    );

    wait_for_sigint_shutdown(&mut child, &config);
}

/// Backup pooling (`option allbackups`, B8) through the **real** binary:
/// with `all_backups = true` the whole backup tier balances by weight while
/// no primary is eligible, a dead pool member leaves rotation, a recovered
/// one takes its share back, and the primary outranks the pool on its first
/// successful check.
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_all_backups_spreads_traffic_across_the_backup_pool() {
    use std::sync::atomic::Ordering;
    let served = || std::sync::Arc::new(AtomicUsize::new(0));
    let healthy = || std::sync::Arc::new(AtomicBool::new(true));
    let (served_a, served_h, served_l) = (served(), served(), served());
    let (healthy_a, healthy_h) = (healthy(), healthy());
    let a = start_balancer_origin(
        "a",
        std::sync::Arc::clone(&healthy_a),
        std::sync::Arc::clone(&served_a),
        None,
    );
    let h = start_balancer_origin(
        "h",
        std::sync::Arc::clone(&healthy_h),
        std::sync::Arc::clone(&served_h),
        None,
    );
    let l = start_balancer_origin(
        "l",
        std::sync::Arc::new(AtomicBool::new(true)),
        std::sync::Arc::clone(&served_l),
        None,
    );
    let config = temp_config(
        "all-backups",
        &format!(
            "schema_version = 1\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             backend = \"api\"\n\
             mode = \"http\"\n\
             [backend.api]\n\
             balance = \"roundrobin\"\n\
             all_backups = true\n\
             servers = [{{ addr = \"{a}\" }}, {{ addr = \"{h}\", weight = 2, backup = true }}, {{ addr = \"{l}\", weight = 1, backup = true }}]\n\
             [backend.api.health_check]\n\
             type = \"http\"\n\
             http_path = \"/healthz\"\n\
             interval = \"150ms\"\n\
             timeout = \"1s\"\n\
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
        .expect("spawn eqproxy run (all_backups)");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let announce = wait_for_stderr(&mut stderr, "listening on ");
    let proxy_addr = announce
        .split("listening on ")
        .nth(1)
        .expect("bind line")
        .trim()
        .to_owned();

    // A request round whose every answer must come from the pool. The pool
    // weights are 2:1, so a count that is a multiple of the 3-request cycle
    // splits exactly 2:1 whatever the cycle phase is.
    let pool_round = |n: usize| -> (usize, usize) {
        let (mut high, mut low) = (0, 0);
        for _ in 0..n {
            match marker_body(&proxy_addr).as_str() {
                "h" => high += 1,
                "l" => low += 1,
                other => panic!("expected a pool member, got {other:?}"),
            }
        }
        (high, low)
    };

    // Phase 1: the primary owns the tier; both pool members answer health
    // checks and stay idle even though `all_backups` is on.
    for _ in 0..10 {
        assert_eq!(marker_body(&proxy_addr), "a");
    }
    assert_eq!(served_h.load(Ordering::SeqCst), 0, "pool member idle");
    assert_eq!(served_l.load(Ordering::SeqCst), 0, "pool member idle");

    // Phase 2: the primary fails; the whole pool serves, split by weight.
    healthy_a.store(false, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut streak = 0;
    while streak < 3 {
        assert!(
            Instant::now() < deadline,
            "the backup pool never took over after the primary failed"
        );
        if marker_body(&proxy_addr) != "a" {
            streak += 1;
        } else {
            streak = 0;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let primary_before = served_a.load(Ordering::SeqCst);
    let (high, low) = pool_round(30);
    assert_eq!(
        (high, low),
        (20, 10),
        "the pool balances the whole backup tier by weight (2:1)"
    );
    assert_eq!(
        served_a.load(Ordering::SeqCst),
        primary_before,
        "the down primary sees no traffic while the pool serves"
    );
    eprintln!("all_backups phase 2 (pool): high={high} low={low} primary={primary_before}");

    // Phase 3: a pool member fails (fall = 1); the other takes the whole
    // tier, and the dead one leaves rotation.
    healthy_h.store(false, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut streak = 0;
    while streak < 3 {
        assert!(
            Instant::now() < deadline,
            "the surviving pool member never took the tier"
        );
        if marker_body(&proxy_addr) == "l" {
            streak += 1;
        } else {
            streak = 0;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let high_before = served_h.load(Ordering::SeqCst);
    let (survivors, others) = pool_round(20);
    assert_eq!(
        (survivors, others),
        (0, 20),
        "the dead pool member leaves rotation for good"
    );
    assert_eq!(
        served_h.load(Ordering::SeqCst),
        high_before,
        "the failed member sees no traffic after it was marked down"
    );

    // Phase 4: the member recovers (rise = 1) and takes its weighted share
    // back: the pool is balanced again, not handed to one rung.
    healthy_h.store(true, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(10);
    // A single `h` answer already proves the member is back in rotation:
    // only that origin answers `h`, and with weights 2:1 its turn comes at
    // least once every three requests. (Waiting for a longer streak would
    // be wrong: the weighted cycle is `h,h,l`, so three in a row never come.)
    while marker_body(&proxy_addr) != "h" {
        assert!(
            Instant::now() < deadline,
            "the recovered member never rejoined the pool"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let (high, low) = pool_round(21);
    assert_eq!(
        (high, low),
        (14, 7),
        "a recovered member gets its weighted share of the pool back"
    );

    // Phase 5: the primary recovers and outranks the whole pool again.
    healthy_a.store(true, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut streak = 0;
    while streak < 3 {
        assert!(
            Instant::now() < deadline,
            "the recovered primary never took the tier back"
        );
        if marker_body(&proxy_addr) == "a" {
            streak += 1;
        } else {
            streak = 0;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let pool_served = served_h.load(Ordering::SeqCst) + served_l.load(Ordering::SeqCst);
    for _ in 0..10 {
        assert_eq!(
            marker_body(&proxy_addr),
            "a",
            "the pool is idle while a primary is eligible"
        );
    }
    assert_eq!(
        served_h.load(Ordering::SeqCst) + served_l.load(Ordering::SeqCst),
        pool_served,
        "the pool stops serving once a primary is back"
    );
    eprintln!(
        "all_backups journey: primary={} high={} low={} pool=ok failover=ok recovery=ok",
        served_a.load(Ordering::SeqCst),
        served_h.load(Ordering::SeqCst),
        served_l.load(Ordering::SeqCst)
    );

    wait_for_sigint_shutdown(&mut child, &config);
}

/// `option allbackups` switched on **while serving** (Q1): the document `PUT`
/// turns a single-primary backend into a weighted pool, the pool takes over
/// on the next failure, a contradicting candidate is refused without touching
/// the running revision, and the flip back retires the pool — all of it
/// invisible to clients that never stop asking.
#[cfg_attr(
    miri,
    ignore = "needs processes and the filesystem: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_document_put_flips_the_backup_pool_live() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let served = || std::sync::Arc::new(AtomicUsize::new(0));
    let healthy = || std::sync::Arc::new(AtomicBool::new(true));
    let (served_a, served_h, served_l) = (served(), served(), served());
    let (healthy_a, healthy_h) = (healthy(), healthy());
    let a = start_balancer_origin(
        "a",
        std::sync::Arc::clone(&healthy_a),
        std::sync::Arc::clone(&served_a),
        None,
    );
    let h = start_balancer_origin(
        "h",
        std::sync::Arc::clone(&healthy_h),
        std::sync::Arc::clone(&served_h),
        None,
    );
    let l = start_balancer_origin(
        "l",
        std::sync::Arc::new(AtomicBool::new(true)),
        std::sync::Arc::clone(&served_l),
        None,
    );
    let read_token = "d4c1b7a09e3f26851b7c0a4d9e6f3a82";
    let write_token = "7e2f9b3c6d1a84052f3e7b9c1d4a6083";
    let tag = format!("eqproxy-cli-e2e-{}-flip-live", std::process::id());
    let read_path = std::env::temp_dir().join(format!("{tag}.read"));
    let write_path = std::env::temp_dir().join(format!("{tag}.write"));
    std::fs::write(&read_path, format!("{read_token}\n")).expect("write read token");
    std::fs::write(&write_path, format!("{write_token}\n")).expect("write write token");
    let config = temp_config(
        "flip-live",
        &format!(
            "schema_version = 1\nshutdown_grace = \"1s\"\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             mode = \"http\"\n\
             backend = \"api\"\n\
             connect_timeout = \"2s\"\n\
             [backend.api]\n\
             balance = \"roundrobin\"\n\
             server = \"{a}\"\n\
             [backend.api.health_check]\n\
             type = \"http\"\n\
             http_path = \"/healthz\"\n\
             interval = \"150ms\"\n\
             timeout = \"1s\"\n\
             fall = 1\n\
             rise = 1\n\
             expect_status = \"200\"\n\
             [admin]\n\
             listen = \"127.0.0.1:0\"\n\
             token_file = \"{}\"\n\
             write_token_file = \"{}\"\n",
            read_path.display(),
            write_path.display()
        ),
    );

    let mut child = ReapOnDrop(
        bin()
            .args(["run", "--config"])
            .arg(&config)
            .args(["--metrics-interval", "1h"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn eqproxy run (flip live)"),
    );
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let log = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let mut proxy_addr = String::new();
    let mut admin_addr = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline && (proxy_addr.is_empty() || admin_addr.is_empty()) {
        line.clear();
        let read = stderr.read_line(&mut line).expect("read stderr");
        assert!(
            read > 0,
            "eqproxy closed stderr without announcing both binds"
        );
        if let Ok(mut log) = log.lock() {
            log.push_str(&line);
        }
        if proxy_addr.is_empty()
            && let Some(addr) = line.split("listening on ").nth(1)
        {
            proxy_addr = addr.trim().to_owned();
        }
        if let Some(rest) = line.split("admin listening on ").nth(1) {
            admin_addr = rest
                .split_whitespace()
                .next()
                .expect("admin address")
                .to_owned();
        }
    }
    assert!(!proxy_addr.is_empty(), "dataplane address not announced");
    assert!(!admin_addr.is_empty(), "admin address not announced");

    // The bodies are the complete section an operator copies out of the
    // file: a document `PUT` replaces the whole table, so a body that leaves
    // a subtable out really does remove it (ADR-0019). The health check has
    // to travel with every write, or the servers stop being probed.
    let health = "[backend.api.health_check]\n\
                  type = \"http\"\n\
                  http_path = \"/healthz\"\n\
                  interval = \"150ms\"\n\
                  timeout = \"1s\"\n\
                  fall = 1\n\
                  rise = 1\n\
                  expect_status = \"200\"\n";
    let pool_body = format!(
        "[backend.api]\n\
         balance = \"roundrobin\"\n\
         all_backups = true\n\
         servers = [{{ addr = \"{a}\" }}, {{ addr = \"{h}\", weight = 2, backup = true }}, {{ addr = \"{l}\", weight = 1, backup = true }}]\n\
         {health}"
    );
    let ladder_body = format!(
        "[backend.api]\n\
         all_backups = true\n\
         servers = [{{ addr = \"{a}\" }}, {{ addr = \"{h}\", backup = true, priority = 10 }}, {{ addr = \"{l}\", backup = true, priority = 5 }}]\n\
         {health}"
    );
    let single_body = format!(
        "[backend.api]\n\
         all_backups = false\n\
         servers = [{{ addr = \"{a}\" }}]\n\
         {health}"
    );

    // Phase 1: the document still describes one primary, so the backup pool
    // that does not exist yet must not be reached.
    for _ in 0..6 {
        assert_eq!(marker_body(&proxy_addr), "a");
    }
    assert_eq!(served_h.load(Ordering::SeqCst), 0, "pool member idle");
    assert_eq!(served_l.load(Ordering::SeqCst), 0, "pool member idle");
    let (status, head) = admin_status(&admin_addr, read_token);
    let revision1 = status["revision"].as_str().expect("revision").to_owned();
    assert!(head.to_ascii_lowercase().contains("etag"), "{head}");
    assert_eq!(
        status["backends"][0]["servers"].as_array().map(Vec::len),
        Some(1),
        "the live document has one server: {status}"
    );

    // Two clients keep hammering the proxy across every flip. Their counts
    // are the proof that a replaced document never breaks a call in flight;
    // they pause only while a weighted cycle is counted, because concurrent
    // requests advance the same round-robin pointer.
    let counts = std::sync::Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let paused = std::sync::Arc::new(AtomicBool::new(false));
    let mut loaders = Vec::new();
    for _ in 0..2 {
        let proxy = proxy_addr.clone();
        let counts = std::sync::Arc::clone(&counts);
        let stop = std::sync::Arc::clone(&stop);
        let paused = std::sync::Arc::clone(&paused);
        loaders.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if paused.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                let mut client = match TcpStream::connect(&proxy) {
                    Ok(client) => client,
                    Err(error) => {
                        counts.1.fetch_add(1, Ordering::Relaxed);
                        eprintln!("live load: connect failed: {error}");
                        continue;
                    }
                };
                let _ = client.set_read_timeout(Some(Duration::from_secs(5)));
                if client
                    .write_all(b"GET /flip-live HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
                    .is_err()
                {
                    counts.1.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let mut raw = Vec::new();
                if client.read_to_end(&mut raw).is_err() {
                    counts.1.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let response = String::from_utf8_lossy(&raw);
                if response.starts_with("HTTP/1.1 200")
                    && matches!(body_of(&response), "a" | "h" | "l")
                {
                    counts.0.fetch_add(1, Ordering::Relaxed);
                } else {
                    counts.1.fetch_add(1, Ordering::Relaxed);
                    eprintln!("live load: unexpected answer {response:?}");
                }
            }
        }));
    }

    // Phase 2: the operator writes the pool into the running document.
    let (code, head, body) = admin_put_toml(
        &admin_addr,
        "/api/v1/backends/api",
        write_token,
        Some(&revision1),
        &pool_body,
    );
    assert_eq!(code, 200, "live pool flip: {head}\n{body}");
    let applied: serde_json::Value = serde_json::from_str(&body).expect("apply json");
    assert_eq!(applied["revision"], "v2", "the flip is one commit: {body}");
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(
        counts.1.load(Ordering::Relaxed),
        0,
        "a client saw a bad answer while the document was replaced"
    );
    assert!(
        counts.0.load(Ordering::Relaxed) > 0,
        "the live load never completed a request"
    );

    // Phase 3: the primary fails and the freshly written pool takes over.
    healthy_a.store(false, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut streak = 0;
    while streak < 3 {
        assert!(
            Instant::now() < deadline,
            "the pool written by PUT never took over after the primary failed"
        );
        if marker_body(&proxy_addr) != "a" {
            streak += 1;
        } else {
            streak = 0;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    paused.store(true, Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(50));
    let (mut high, mut low) = (0, 0);
    for _ in 0..30 {
        match marker_body(&proxy_addr).as_str() {
            "h" => high += 1,
            "l" => low += 1,
            other => panic!("expected a pool member, got {other:?}"),
        }
    }
    assert_eq!(
        (high, low),
        (20, 10),
        "the pool written live balances by weight (2:1)"
    );
    paused.store(false, Ordering::SeqCst);

    // Phase 4: a candidate that contradicts itself is refused and the
    // running revision is untouched — the pool keeps serving.
    let (code, _, body) = admin_put_toml(
        &admin_addr,
        "/api/v1/backends/api",
        write_token,
        Some("v2"),
        &ladder_body,
    );
    assert_eq!(code, 400, "ladder + pool must be refused: {body}");
    assert!(body.contains("invalid_config"), "{body}");
    assert_eq!(
        admin_status(&admin_addr, read_token).0["revision"],
        "v2",
        "a refused candidate must not advance the revision"
    );
    assert!(
        marker_body(&proxy_addr) != "a",
        "the refused candidate left the running pool untouched"
    );

    // Phase 5: the operator retires the pool and the primary owns the tier
    // again; the pool members see no more traffic.
    let (code, _, body) = admin_put_toml(
        &admin_addr,
        "/api/v1/backends/api",
        write_token,
        Some("v2"),
        &single_body,
    );
    assert_eq!(code, 200, "live pool retirement: {body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).expect("apply json")["revision"],
        "v3"
    );
    healthy_a.store(true, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut streak = 0;
    while streak < 3 {
        assert!(
            Instant::now() < deadline,
            "the recovered primary never took the tier back after the flip"
        );
        if marker_body(&proxy_addr) == "a" {
            streak += 1;
        } else {
            streak = 0;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let pool_served = served_h.load(Ordering::SeqCst) + served_l.load(Ordering::SeqCst);
    for _ in 0..10 {
        assert_eq!(
            marker_body(&proxy_addr),
            "a",
            "the retired pool is idle while a primary is eligible"
        );
    }
    assert_eq!(
        served_h.load(Ordering::SeqCst) + served_l.load(Ordering::SeqCst),
        pool_served,
        "the retired pool stops serving"
    );

    stop.store(true, Ordering::Relaxed);
    for loader in loaders {
        loader.join().expect("join live loader");
    }
    assert_eq!(
        counts.1.load(Ordering::Relaxed),
        0,
        "no client request failed across the flips"
    );
    eprintln!(
        "flip-live journey: requests={} primary={} high={} low={} applies=v1..v3 refused=ok",
        counts.0.load(Ordering::Relaxed),
        served_a.load(Ordering::SeqCst),
        served_h.load(Ordering::SeqCst),
        served_l.load(Ordering::SeqCst)
    );

    wait_for_sigint_shutdown(&mut child, &config);
}

/// The web panel (v0.8 / D6, ADR-0029) over the **real** binary: a session is
/// opened with the write token, a whole backend table is applied through the
/// form and one of its servers is drained through the form while traffic
/// flows. The panel is a client of the same applier, so what changes is the
/// running document and what the dataplane does — not a page that only looks
/// changed.
#[cfg_attr(
    miri,
    ignore = "needs processes and the filesystem: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_panel_applies_a_table_and_drains_a_server() {
    use std::sync::atomic::Ordering;
    let served = || std::sync::Arc::new(AtomicUsize::new(0));
    let (served_a, served_b) = (served(), served());
    let (healthy_a, healthy_b) = (
        std::sync::Arc::new(AtomicBool::new(true)),
        std::sync::Arc::new(AtomicBool::new(true)),
    );
    let a = start_balancer_origin(
        "a",
        std::sync::Arc::clone(&healthy_a),
        std::sync::Arc::clone(&served_a),
        None,
    );
    let b = start_balancer_origin(
        "b",
        std::sync::Arc::clone(&healthy_b),
        std::sync::Arc::clone(&served_b),
        None,
    );
    let read_token = "b7e1a4c25d9f30816a2c7e4b1d9f3058";
    let write_token = "1e9c7b3a5d2f80461c9e3b7a4d2f6085";
    let tag = format!("eqproxy-cli-e2e-{}-panel", std::process::id());
    let read_path = std::env::temp_dir().join(format!("{tag}.read"));
    let write_path = std::env::temp_dir().join(format!("{tag}.write"));
    std::fs::write(&read_path, format!("{read_token}\n")).expect("write read token");
    std::fs::write(&write_path, format!("{write_token}\n")).expect("write write token");
    let config = temp_config(
        "panel",
        &format!(
            "schema_version = 1\nshutdown_grace = \"1s\"\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             mode = \"http\"\n\
             backend = \"api\"\n\
             connect_timeout = \"2s\"\n\
             [backend.api]\n\
             balance = \"roundrobin\"\n\
             server = \"{a}\"\n\
             [backend.api.health_check]\n\
             type = \"http\"\n\
             http_path = \"/healthz\"\n\
             interval = \"150ms\"\n\
             timeout = \"1s\"\n\
             fall = 1\n\
             rise = 1\n\
             expect_status = \"200\"\n\
             [admin]\n\
             listen = \"127.0.0.1:0\"\n\
             panel = true\n\
             token_file = \"{}\"\n\
             write_token_file = \"{}\"\n",
            read_path.display(),
            write_path.display()
        ),
    );

    let mut child = ReapOnDrop(
        bin()
            .args(["run", "--config"])
            .arg(&config)
            .args(["--metrics-interval", "1h"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn eqproxy run (panel)"),
    );
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let mut proxy_addr = String::new();
    let mut admin_addr = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline && (proxy_addr.is_empty() || admin_addr.is_empty()) {
        line.clear();
        let read = stderr.read_line(&mut line).expect("read stderr");
        assert!(
            read > 0,
            "eqproxy closed stderr without announcing both binds"
        );
        if proxy_addr.is_empty()
            && let Some(addr) = line.split("listening on ").nth(1)
        {
            proxy_addr = addr.trim().to_owned();
        }
        if let Some(rest) = line.split("admin listening on ").nth(1) {
            admin_addr = rest
                .split_whitespace()
                .next()
                .expect("admin address")
                .to_owned();
        }
        if line.contains("panel /panel") {
            // The plane announces the panel it serves; nothing else proves
            // the route exists until it answers.
            assert!(!admin_addr.is_empty(), "panel announced before the bind");
        }
    }
    assert!(!proxy_addr.is_empty(), "dataplane address not announced");
    assert!(!admin_addr.is_empty(), "admin address not announced");

    // Phase 1: with the panel off there is no page; it is on, so the login
    // form is what an anonymous browser gets.
    let (code, head, body) = admin_get(&admin_addr, "/panel", None);
    assert_eq!(code, 200, "login page: {head}");
    assert!(body.contains("action=\"/panel/login\""), "{body}");
    assert!(
        head.contains("content-security-policy: default-src 'none'"),
        "the page carries a policy: {head}"
    );
    assert!(head.contains("cache-control: no-store"), "{head}");

    // The write token opens a session.
    let form = format!("token={write_token}");
    let login = format!(
        "POST /panel/login HTTP/1.1\r\nhost: admin\r\n\
         content-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\n\r\n{form}",
        form.len()
    );
    let (code, head, _) = admin_exchange(&admin_addr, &login);
    assert_eq!(code, 303, "login: {head}");
    let cookie = head
        .lines()
        .find_map(|line| line.strip_prefix("set-cookie: "))
        .and_then(|value| value.split(';').next())
        .expect("session cookie")
        .to_owned();
    assert!(cookie.starts_with("eqproxy_session="), "{cookie}");
    assert!(
        !head.contains(write_token),
        "the secret never comes back: {head}"
    );

    // The dashboard is rendered from the live topology and carries one CSRF
    // token per form; the panel's own page is what proves the flow.
    let (code, _, page) = admin_get_with(&admin_addr, "/panel", Some(&format!("cookie: {cookie}")));
    assert_eq!(code, 200, "dashboard");
    assert!(page.contains("Backend api"), "{page}");
    assert!(page.contains(&a.to_string()), "{page}");
    assert!(!page.contains(&b.to_string()), "b is not configured yet");
    let csrf = page
        .split_once("name=\"csrf\" value=\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(value, _)| value.to_owned())
        .expect("csrf field");
    let revision = page
        .split_once("name=\"revision\" value=\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(value, _)| value.to_owned())
        .expect("revision field");

    // Phase 2: the whole table goes through the form. It replaces the
    // backend, so the health check travels with it (ADR-0019/ADR-0029).
    let table = format!(
        "[backend.api]\nbalance = \"roundrobin\"\n\
         servers = [{{ addr = \"{a}\" }}, {{ addr = \"{b}\" }}]\n\
         [backend.api.health_check]\n\
         type = \"http\"\n\
         http_path = \"/healthz\"\n\
         interval = \"150ms\"\n\
         timeout = \"1s\"\n\
         fall = 1\n\
         rise = 1\n\
         expect_status = \"200\"\n"
    );
    let form = format!(
        "csrf={csrf}&revision={revision}&name=api&table={}",
        form_encode(&table)
    );
    let request = format!(
        "POST /panel/backends/api HTTP/1.1\r\nhost: admin\r\ncookie: {cookie}\r\n\
         content-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\n\r\n{form}",
        form.len()
    );
    let (code, head, _) = admin_exchange(&admin_addr, &request);
    assert_eq!(code, 303, "panel apply: {head}");
    assert!(
        head.contains("location: /panel?applied=1"),
        "the browser is sent back to the page: {head}"
    );

    // The dataplane serves both servers now: the table really was applied.
    let (code, _, status) = admin_get(
        &admin_addr,
        "/api/v1/status",
        Some(&format!("Bearer {read_token}")),
    );
    assert_eq!(code, 200, "status");
    assert!(status.contains("\"revision\":\"v2\""), "{status}");
    let mut seen_b = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !seen_b && Instant::now() < deadline {
        if marker_body(&proxy_addr) == "b" {
            seen_b = true;
        }
    }
    assert!(seen_b, "the panel-applied table serves the new server");
    assert!(served_a.load(Ordering::SeqCst) > 0, "a still serves");

    // Phase 3: draining `b` from the page takes it out of rotation.
    let form = format!("csrf={csrf}&state=drain");
    let action = format!("/panel/servers/api/{}/state", form_encode(&b.to_string()));
    let request = format!(
        "POST {action} HTTP/1.1\r\nhost: admin\r\ncookie: {cookie}\r\n\
         content-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\n\r\n{form}",
        form.len()
    );
    let (code, head, _) = admin_exchange(&admin_addr, &request);
    assert_eq!(code, 303, "panel drain: {head}");
    assert!(head.contains("location: /panel?applied=drain"), "{head}");
    let (code, _, status) = admin_get(
        &admin_addr,
        "/api/v1/status",
        Some(&format!("Bearer {read_token}")),
    );
    assert_eq!(code, 200, "status after drain");
    assert!(status.contains("\"state\":\"drain\""), "{status}");
    let after_drain = served_b.load(Ordering::SeqCst);
    for _ in 0..10 {
        assert_eq!(
            marker_body(&proxy_addr),
            "a",
            "the drained server takes no new request"
        );
    }
    assert_eq!(
        served_b.load(Ordering::SeqCst),
        after_drain,
        "the drained server is really out of rotation"
    );

    wait_for_sigint_shutdown(&mut child, &config);
}

/// `option allbackups` boundary cases through the **real** binary (Q1): a
/// pool that balances, a pool paired with a `priority` ladder (refused), and
/// the option with no backup slot to balance (refused). Never a silent
/// no-op that looks applied.
#[cfg_attr(
    miri,
    ignore = "needs processes and the filesystem: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn validate_accepts_a_backup_pool_and_refuses_a_contradiction() {
    let ok = temp_config(
        "all-backups-ok",
        "schema_version = 1\n\
         [listener.web]\n\
         listen = \"127.0.0.1:8080\"\n\
         backend = \"api\"\n\
         [backend.api]\n\
         all_backups = true\n\
         servers = [{ addr = \"127.0.0.1:9000\", weight = 2, backup = true }, { addr = \"127.0.0.1:9001\", backup = true }]\n",
    );
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&ok)
        .output()
        .expect("run eqproxy config validate");
    remove_temp(&ok);
    assert!(
        output.status.success(),
        "a weighted backup pool must validate; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let ladder = temp_config(
        "all-backups-ladder",
        "schema_version = 1\n\
         [listener.web]\n\
         listen = \"127.0.0.1:8080\"\n\
         backend = \"api\"\n\
         [backend.api]\n\
         all_backups = true\n\
         servers = [{ addr = \"127.0.0.1:9000\", backup = true, priority = 10 }]\n",
    );
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&ladder)
        .output()
        .expect("run eqproxy config validate");
    remove_temp(&ladder);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a pool with a failover ladder must fail; stderr: {stderr}"
    );
    for expected in [
        "servers[0].priority",
        "all_backups",
        "drop `priority`",
        "example:",
    ] {
        assert!(
            stderr.contains(expected),
            "missing {expected:?} in:\n{stderr}"
        );
    }

    let empty = temp_config(
        "all-backups-empty",
        "schema_version = 1\n\
         [listener.web]\n\
         listen = \"127.0.0.1:8080\"\n\
         backend = \"api\"\n\
         [backend.api]\n\
         all_backups = true\n\
         servers = [{ addr = \"127.0.0.1:9000\" }]\n",
    );
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&empty)
        .output()
        .expect("run eqproxy config validate");
    remove_temp(&empty);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "an option with no pool must fail; stderr: {stderr}"
    );
    for expected in [
        "backend.api.all_backups",
        "no `backup = true` server to balance",
        "example:",
    ] {
        assert!(
            stderr.contains(expected),
            "missing {expected:?} in:\n{stderr}"
        );
    }
}

/// Keep-alive origin on a thread that **never** closes a connection —
/// the interop hazard for a checker that reads its response to EOF.
/// `/healthz` answers `200` + `ok` (Content-Length framed); any other
/// path answers `200` with `marker`. `Connection: close` is ignored.
///
/// Like the balancer origin, a journey that health-checks through this one
/// configures the probe with `timeout = "1s"`, never 150 ms: the probe shares
/// the machine with the whole suite, and `fall = 1` turns one scheduling
/// hiccup on a **healthy** origin into an empty `503`. The hazard this origin
/// exists to catch does not need a short timeout to surface — a checker that
/// waits for EOF fails every cycle, just 1 s later.
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
             timeout = \"1s\"\n\
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

/// How long the map watcher may take to apply a new file on a loaded host.
/// Measured against the real binary in this test's topology: 0.8 s on an
/// idle host, 4.2–7.4 s with 16 CPU burners on 12 cores, and more than the
/// old 10 s budget when the whole instrumented suite (424 tests, 25
/// binaries) competes for the same cores — which is exactly how this test
/// failed under `veyra audit`. The load, not the swap, is what varies, so
/// the wait is event-based and the bound is generous.
const MAP_RELOAD_BUDGET: Duration = Duration::from_secs(60);

/// Kills and reaps a spawned proxy when the test leaves its scope early.
/// A failed run must never leave `eqproxy run` alive: it keeps accepting
/// and dialling, so it burns CPU and makes the next run slower. A failed
/// `llvm-cov` run of this file left one alive for 30 minutes.
struct ReapOnDrop(std::process::Child);

impl std::ops::Deref for ReapOnDrop {
    type Target = std::process::Child;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ReapOnDrop {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for ReapOnDrop {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

/// Waits for one line of a child's stderr, or panics with the whole log
/// after `budget`. Lines that are not the awaited one (metrics, another
/// reload) are skipped; a closed channel or an exhausted budget is a
/// failure that prints what the child did say.
fn await_log_line(
    rx: &std::sync::mpsc::Receiver<String>,
    log: &std::sync::Mutex<String>,
    need: &str,
    budget: Duration,
    what: &str,
) -> String {
    let deadline = Instant::now() + budget;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(line) if line.contains(need) => return line,
            Ok(_) => continue,
            Err(_) => {
                let log = log.lock().map(|l| l.clone()).unwrap_or_default();
                panic!("{what} within {budget:?}: {log}");
            }
        }
    }
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

    let mut child = ReapOnDrop(
        bin()
            .args(["run", "--config"])
            .arg(&config)
            .args(["--metrics-interval", "1h"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn eqproxy run (hot maps)"),
    );
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    // The whole log is kept: the reload line is the event this test waits
    // for, and the tail is what a failure prints.
    let log = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let mut proxy_addr = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        let read = stderr.read_line(&mut line).expect("read stderr");
        assert!(read > 0, "eqproxy closed stderr without announcing bind");
        if let Ok(mut log) = log.lock() {
            log.push_str(&line);
        }
        if let Some(addr) = line.split("listening on ").nth(1) {
            proxy_addr = addr.trim().to_owned();
            break;
        }
    }
    assert!(!proxy_addr.is_empty(), "the address was not announced");

    // Keep draining stderr for the rest of the test, so the reload line can
    // be awaited as an event instead of inferred from response latency.
    let (line_tx, line_rx) = std::sync::mpsc::channel::<String>();
    let reader = {
        let log = std::sync::Arc::clone(&log);
        std::thread::spawn(move || {
            for line in stderr.lines() {
                let Ok(line) = line else { break };
                if let Ok(mut log) = log.lock() {
                    log.push_str(&line);
                    log.push('\n');
                }
                if line_tx.send(line).is_err() {
                    break;
                }
            }
        })
    };

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

    // The watcher is the thing under test: wait for the reload it logs
    // (bounded, but not against a latency budget it cannot control). The
    // dataplane assertion below is what proves the swap is live.
    await_log_line(
        &line_rx,
        &log,
        "map \"tiers\" reloaded: 100001 entries",
        MAP_RELOAD_BUDGET,
        "the map reload did not land",
    );
    // The swap was published before its line was written; traffic must see
    // it without a reconnect or a config reload.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = proxied(proxy_addr.as_str(), as_user("newcomer").as_bytes());
        if body_of(&response) == "vip" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the reloaded map did not reach traffic (last response: {response}; log: {})",
            log.lock().map(|l| l.clone()).unwrap_or_default()
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
    // The process has exited: the reader thread hits EOF and the log is
    // complete (including the final METRICS line) once it is joined.
    reader.join().expect("stderr reader thread");
    let log = log.lock().map(|l| l.clone()).unwrap_or_default();
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

/// A wait for a log line that never comes fails on its own budget and says
/// what the child did log, instead of hanging the suite.
#[test]
#[should_panic(expected = "the line never came within 100ms")]
fn await_log_line_times_out_with_the_log() {
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    tx.send("INFO listener web listening on 127.0.0.1:1".to_owned())
        .expect("send log line");
    drop(tx);
    let log = std::sync::Mutex::new("INFO listener web listening on 127.0.0.1:1\n".to_owned());
    await_log_line(
        &rx,
        &log,
        "reloaded",
        Duration::from_millis(100),
        "the line never came",
    );
}

/// The guard that keeps a failed run from leaving a proxy behind: dropping
/// the handle kills and reaps the child instead of orphaning it.
#[cfg(unix)]
#[test]
fn reap_on_drop_leaves_no_live_child() {
    let child = ReapOnDrop(
        Command::new("sleep")
            .arg("30")
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn sleep"),
    );
    let pid = child.id().to_string();
    drop(child);
    let probe = Command::new("kill")
        .args(["-0", pid.as_str()])
        .stderr(Stdio::null())
        .status()
        .expect("probe the pid");
    assert!(
        !probe.success(),
        "the guard must reap the child, not orphan it"
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
        "AccessLogConfig",
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

// ---------------------------------------------------------------------------
// Response compression (B-N6/H6): gzip negotiated from Accept-Encoding.
// ---------------------------------------------------------------------------

/// Body the compression journeys compress: repetitive text, ~9 KB.
fn compression_text() -> String {
    "the quick brown fox jumps over the lazy dog\n".repeat(200)
}

/// Origin with one route per compression rule under test.
fn start_compression_origin() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind compression origin");
    let addr = listener.local_addr().expect("addr compression origin");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            std::thread::spawn(move || {
                use std::io::Read;
                let mut buf = vec![0u8; 8192];
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
                let head = String::from_utf8_lossy(&buf[..total]).to_ascii_lowercase();
                let path = head
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/");
                match path {
                    "/small" => respond_content_length(&mut stream, "text/plain", b"tiny"),
                    "/json" => {
                        let body = format!(
                            "{{\"items\":[{}]}}",
                            (0..400)
                                .map(|i| i.to_string())
                                .collect::<Vec<_>>()
                                .join(",")
                        );
                        respond_content_length(&mut stream, "application/json", body.as_bytes())
                    }
                    "/png" => {
                        let mut body = vec![0x89u8, b'P', b'N', b'G'];
                        body.extend((0..4092u32).map(|i| (i % 251) as u8));
                        respond_content_length(&mut stream, "image/png", &body)
                    }
                    "/encoded" => {
                        let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: br\r\nContent-Length: 18\r\nConnection: close\r\n\r\nnot-really-brotli!";
                        let _ = stream.write_all(response);
                    }
                    "/notransform" => {
                        let body = compression_text();
                        let head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: no-transform\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(head.as_bytes());
                        let _ = stream.write_all(body.as_bytes());
                    }
                    "/chunked" => {
                        let body = compression_text();
                        let (first, second) = body.split_at(body.len() / 2);
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{first}\r\n{:x}\r\n{second}\r\n0\r\nx-checksum: 42\r\n\r\n",
                            first.len(),
                            second.len()
                        );
                        let _ = stream.write_all(response.as_bytes());
                    }
                    _ => {
                        let body = compression_text();
                        respond_content_length(
                            &mut stream,
                            "text/plain; charset=utf-8",
                            body.as_bytes(),
                        );
                    }
                }
            });
        }
    });
    addr
}

fn respond_content_length(stream: &mut TcpStream, content_type: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
}

/// Raw response bytes through the real binary (compressed bodies are binary:
/// never round-trip them through `String`).
fn proxied_bytes(proxy: &str, request: &[u8]) -> Vec<u8> {
    let mut client = TcpStream::connect(proxy).expect("connect proxy");
    client.write_all(request).expect("write request");
    let mut response = Vec::new();
    client
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("read timeout");
    let _ = client.read_to_end(&mut response);
    assert!(
        !response.is_empty(),
        "the proxy never answered: {:?}",
        String::from_utf8_lossy(&response)
    );
    response
}

/// Splits a raw response into its head, decoded body and chunked trailers.
fn response_body(response: &[u8]) -> (String, Vec<u8>, Vec<String>) {
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response head terminator");
    let head = String::from_utf8_lossy(&response[..split]).into_owned();
    let mut rest = &response[split + 4..];
    if !head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        return (head, rest.to_vec(), Vec::new());
    }
    let mut body = Vec::new();
    let mut trailers = Vec::new();
    loop {
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .expect("chunk size line");
        let line = String::from_utf8_lossy(&rest[..line_end]).into_owned();
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("0").trim(), 16)
            .expect("hex chunk size");
        rest = &rest[line_end + 2..];
        if size == 0 {
            loop {
                let end = rest
                    .windows(2)
                    .position(|w| w == b"\r\n")
                    .expect("trailer line");
                if end == 0 {
                    break;
                }
                trailers.push(String::from_utf8_lossy(&rest[..end]).into_owned());
                rest = &rest[end + 2..];
            }
            break;
        }
        body.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
    (head, body, trailers)
}

fn gunzip(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(body)
        .read_to_end(&mut out)
        .expect("the body must be a valid gzip member");
    out
}

fn get_with_encoding(proxy: &str, path: &str, accept_encoding: Option<&str>) -> Vec<u8> {
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n");
    if let Some(accept) = accept_encoding {
        request.push_str(&format!("Accept-Encoding: {accept}\r\n"));
    }
    request.push_str("\r\n");
    proxied_bytes(proxy, request.as_bytes())
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_compresses_gzip_and_respects_every_refusal_case() {
    let origin = start_compression_origin();
    let config = temp_config(
        "gzip-run",
        &format!(
            "schema_version = 1\nshutdown_grace = \"1s\"\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             mode = \"http\"\n\
             backend = \"api\"\n\
             connect_timeout = \"2s\"\n\
             [listener.web.compression]\n\
             gzip = true\n\
             min_size = 512\n\
             [backend.api]\n\
             server = \"{origin}\"\n"
        ),
    );
    let mut child = bin()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run (gzip)");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let mut proxy = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline && proxy.is_empty() {
        line.clear();
        let read = stderr.read_line(&mut line).expect("read stderr");
        assert!(read > 0, "eqproxy closed stderr without announcing bind");
        if let Some(addr) = line.split("listening on ").nth(1) {
            proxy = addr.trim().to_owned();
        }
    }
    assert!(!proxy.is_empty(), "the listener was not announced");

    // 1) Negotiated: gzip on the wire, decoded body equals the origin's.
    let text = compression_text();
    let compressed = get_with_encoding(&proxy, "/big", Some("gzip, deflate"));
    let (head, body, _) = response_body(&compressed);
    let head_lower = head.to_ascii_lowercase();
    assert!(head_lower.starts_with("http/1.1 200 ok"), "{head}");
    assert!(head_lower.contains("content-encoding: gzip"), "{head}");
    assert!(head_lower.contains("transfer-encoding: chunked"), "{head}");
    assert!(head_lower.contains("vary: accept-encoding"), "{head}");
    assert!(!head_lower.contains("content-length"), "{head}");
    assert_eq!(&body[..2], &[0x1f, 0x8b], "gzip magic missing");
    assert_eq!(gunzip(&body), text.as_bytes(), "decoded body differs");
    assert!(
        body.len() < text.len(),
        "nothing was saved: {} vs {}",
        body.len(),
        text.len()
    );

    // 2) `gzip;q=0` is a refusal: identity, same bytes as the origin sent.
    let identity = get_with_encoding(&proxy, "/big", Some("gzip;q=0"));
    let (head, body, _) = response_body(&identity);
    let head_lower = head.to_ascii_lowercase();
    assert!(!head_lower.contains("content-encoding"), "{head}");
    assert!(
        head_lower.contains(&format!("content-length: {}", text.len())),
        "{head}"
    );
    assert_eq!(body, text.as_bytes());

    // 3) Below min_size: identity even when accepted.
    let (head, body, _) = response_body(&get_with_encoding(&proxy, "/small", Some("gzip")));
    assert!(
        !head.to_ascii_lowercase().contains("content-encoding"),
        "{head}"
    );
    assert_eq!(body, b"tiny");

    // 4) Already encoded: never re-encoded.
    let (head, body, _) = response_body(&get_with_encoding(&proxy, "/encoded", Some("gzip")));
    assert!(
        head.to_ascii_lowercase().contains("content-encoding: br"),
        "{head}"
    );
    assert_eq!(body, b"not-really-brotli!");

    // 5) A type outside the list: identity.
    let (head, body, _) = response_body(&get_with_encoding(&proxy, "/png", Some("gzip")));
    assert!(
        !head.to_ascii_lowercase().contains("content-encoding"),
        "{head}"
    );
    assert_eq!(&body[..4], &[0x89, b'P', b'N', b'G']);

    // 6) Chunked origin body: re-framed compressed, trailers preserved.
    let (head, body, trailers) =
        response_body(&get_with_encoding(&proxy, "/chunked", Some("gzip")));
    assert!(
        head.to_ascii_lowercase().contains("content-encoding: gzip"),
        "{head}"
    );
    assert_eq!(gunzip(&body), text.as_bytes());
    assert_eq!(
        trailers,
        vec!["x-checksum: 42".to_owned()],
        "trailers: {trailers:?}"
    );

    // 7) JSON is in the default list and compresses.
    let (head, body, _) = response_body(&get_with_encoding(&proxy, "/json", Some("*")));
    assert!(
        head.to_ascii_lowercase().contains("content-encoding: gzip"),
        "{head}"
    );
    assert_eq!(gunzip(&body)[0], b'{');

    // 8) `Cache-Control: no-transform` forbids the transformation.
    let (head, body, _) = response_body(&get_with_encoding(&proxy, "/notransform", Some("gzip")));
    assert!(
        !head.to_ascii_lowercase().contains("content-encoding"),
        "{head}"
    );
    assert_eq!(body, text.as_bytes());

    // 9) An HTTP/1.0 client cannot read chunked framing: identity.
    let (head, body, _) = response_body(&proxied_bytes(
        &proxy,
        b"GET /big HTTP/1.0\r\nHost: t\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    ));
    assert!(
        !head.to_ascii_lowercase().contains("content-encoding"),
        "{head}"
    );
    assert_eq!(body, text.as_bytes());

    // Real SIGINT: the final METRICS line carries the compression counters.
    let pid = child.id();
    assert!(
        Command::new("kill")
            .args(["-INT", &pid.to_string()])
            .status()
            .expect("run kill")
            .success()
    );
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
    let mut rest = String::new();
    let _ = stderr.read_to_string(&mut rest);
    remove_temp(&config);
    assert_eq!(status.code(), Some(0), "clean shutdown must exit with 0");
    let final_line = rest
        .lines()
        .find(|line| line.starts_with("METRICS ") && line.contains("(final)"))
        .expect("final METRICS line");
    let group = final_line
        .split("compression[")
        .nth(1)
        .and_then(|rest| rest.split(']').next())
        .expect("compression group");
    let value = |name: &str| -> u64 {
        group
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("missing {name} in {group}"))
    };
    assert_eq!(
        value("gzip"),
        3,
        "big + chunked + json were compressed: {group}"
    );
    assert!(value("bytes_out") < value("bytes_in"), "{group}");
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn validate_and_explain_report_the_compression_settings() {
    let config = temp_config(
        "gzip-validate",
        "schema_version = 1\n\
         [listener.web]\n\
         listen = \"127.0.0.1:0\"\n\
         mode = \"http\"\n\
         backend = \"api\"\n\
         [listener.web.compression]\n\
         gzip = true\n\
         level = 6\n\
         min_size = 512\n\
         types = [\"text/*\", \"application/json\"]\n\
         [backend.api]\n\
         server = \"127.0.0.1:9\"\n",
    );
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&config)
        .output()
        .expect("run validate");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let explain = bin()
        .args(["config", "explain", "--config"])
        .arg(&config)
        .output()
        .expect("run explain");
    assert!(explain.status.success());
    let report = String::from_utf8_lossy(&explain.stdout);
    assert!(
        report.contains("compression: gzip level=6 min_size=512 types=[text/*, application/json]"),
        "report: {report}"
    );

    // A tcp listener cannot serve compressed responses.
    let bad = temp_config(
        "gzip-tcp",
        "schema_version = 1\n\
         [listener.raw]\n\
         listen = \"127.0.0.1:0\"\n\
         mode = \"tcp\"\n\
         backend = \"api\"\n\
         [listener.raw.compression]\n\
         gzip = true\n\
         [backend.api]\n\
         server = \"127.0.0.1:9\"\n",
    );
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&bad)
        .output()
        .expect("run validate (tcp)");
    let text = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {text}");
    assert!(
        text.contains("compression is only meaningful in mode"),
        "{text}"
    );

    // Level and media type are validated with the runtime grammar.
    let bad = temp_config(
        "gzip-bad",
        "schema_version = 1\n\
         [listener.web]\n\
         listen = \"127.0.0.1:0\"\n\
         mode = \"http\"\n\
         backend = \"api\"\n\
         [listener.web.compression]\n\
         gzip = true\n\
         level = 12\n\
         types = [\"text/*\", \"text\"]\n\
         [backend.api]\n\
         server = \"127.0.0.1:9\"\n",
    );
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&bad)
        .output()
        .expect("run validate (bad options)");
    let text = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {text}");
    assert!(text.contains("listener.web.compression.level"), "{text}");
    assert!(text.contains("listener.web.compression.types"), "{text}");
    assert!(text.contains("is not a media type"), "{text}");

    // Brotli alone is a valid configuration and explain names its quality.
    let brotli = temp_config(
        "brotli-validate",
        "schema_version = 1\n\
         [listener.web]\n\
         listen = \"127.0.0.1:0\"\n\
         mode = \"http\"\n\
         backend = \"api\"\n\
         [listener.web.compression]\n\
         brotli = true\n\
         brotli_quality = 7\n\
         min_size = 512\n\
         types = [\"text/*\", \"application/json\"]\n\
         [backend.api]\n\
         server = \"127.0.0.1:9\"\n",
    );
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&brotli)
        .output()
        .expect("run validate (brotli)");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let explain = bin()
        .args(["config", "explain", "--config"])
        .arg(&brotli)
        .output()
        .expect("run explain (brotli)");
    assert!(explain.status.success());
    let report = String::from_utf8_lossy(&explain.stdout);
    assert!(
        report.contains(
            "compression: brotli quality=7 min_size=512 types=[text/*, application/json]"
        ),
        "report: {report}"
    );

    // Brotli quality outside 0-11 is rejected before it reaches the dataplane.
    let bad_brotli = temp_config(
        "brotli-bad",
        "schema_version = 1\n\
         [listener.web]\n\
         listen = \"127.0.0.1:0\"\n\
         mode = \"http\"\n\
         backend = \"api\"\n\
         [listener.web.compression]\n\
         brotli = true\n\
         brotli_quality = 12\n\
         [backend.api]\n\
         server = \"127.0.0.1:9\"\n",
    );
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&bad_brotli)
        .output()
        .expect("run validate (bad brotli quality)");
    let text = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {text}");
    assert!(
        text.contains("listener.web.compression.brotli_quality"),
        "{text}"
    );

    // A tcp listener cannot serve Brotli either.
    let bad = temp_config(
        "brotli-tcp",
        "schema_version = 1\n\
         [listener.raw]\n\
         listen = \"127.0.0.1:0\"\n\
         mode = \"tcp\"\n\
         backend = \"api\"\n\
         [listener.raw.compression]\n\
         brotli = true\n\
         [backend.api]\n\
         server = \"127.0.0.1:9\"\n",
    );
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&bad)
        .output()
        .expect("run validate (brotli tcp)");
    let text = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {text}");
    assert!(
        text.contains("compression is only meaningful in mode"),
        "{text}"
    );

    // Both codings enabled: explain names both, with each tuning knob.
    let both = temp_config(
        "compression-both",
        "schema_version = 1\n\
         [listener.web]\n\
         listen = \"127.0.0.1:0\"\n\
         mode = \"http\"\n\
         backend = \"api\"\n\
         [listener.web.compression]\n\
         gzip = true\n\
         brotli = true\n\
         level = 7\n\
         brotli_quality = 4\n\
         [backend.api]\n\
         server = \"127.0.0.1:9\"\n",
    );
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&both)
        .output()
        .expect("run validate (both codings)");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let explain = bin()
        .args(["config", "explain", "--config"])
        .arg(&both)
        .output()
        .expect("run explain (both codings)");
    assert!(explain.status.success());
    let report = String::from_utf8_lossy(&explain.stdout);
    assert!(
        report.contains("compression: gzip level=7 brotli quality=4 min_size=1024"),
        "report: {report}"
    );
    remove_temp(&both);

    remove_temp(&config);
    remove_temp(&bad);
    remove_temp(&brotli);
    remove_temp(&bad_brotli);
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_serves_gzip_over_h2c_to_a_real_client() {
    let origin = start_compression_origin();
    let config = temp_config(
        "gzip-h2c",
        &format!(
            "schema_version = 1\nshutdown_grace = \"1s\"\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             mode = \"http\"\n\
             backend = \"api\"\n\
             connect_timeout = \"2s\"\n\
             [listener.web.compression]\n\
             gzip = true\n\
             [backend.api]\n\
             server = \"{origin}\"\n"
        ),
    );
    let mut child = bin()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run (h2c gzip)");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let mut proxy = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline && proxy.is_empty() {
        line.clear();
        let read = stderr.read_line(&mut line).expect("read stderr");
        assert!(read > 0, "eqproxy closed stderr without announcing bind");
        if let Some(addr) = line.split("listening on ").nth(1) {
            proxy = addr.trim().to_owned();
        }
    }
    assert!(!proxy.is_empty());

    // curl with h2 prior knowledge and `--compressed`: it negotiates gzip,
    // decodes it and prints the decoded body, while `-D -` shows the headers
    // that crossed the wire.
    let dump = curl_stdout(&[
        "--http2-prior-knowledge",
        "--compressed",
        &format!("http://{proxy}/big"),
    ]);
    assert!(
        dump.starts_with("HTTP/2 200"),
        "h2c must negotiate HTTP/2: {dump}"
    );
    let lower = dump.to_ascii_lowercase();
    assert!(lower.contains("content-encoding: gzip"), "{dump}");
    assert!(
        !lower.contains("transfer-encoding:"),
        "h2 has no chunked framing: {dump}"
    );
    let (_, body) = dump.split_once("\r\n\r\n").expect("curl headers and body");
    assert_eq!(body, compression_text(), "the decoded h2 body differs");

    let pid = child.id();
    assert!(
        Command::new("kill")
            .args(["-INT", &pid.to_string()])
            .status()
            .expect("run kill")
            .success()
    );
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
    assert_eq!(status.code(), Some(0));
}

fn unbrotli(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    brotli::Decompressor::new(body, 4096)
        .read_to_end(&mut out)
        .expect("the body must be a valid brotli stream");
    out
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_compresses_brotli_and_prefers_it_over_gzip() {
    let origin = start_compression_origin();
    let config = temp_config(
        "brotli-run",
        &format!(
            "schema_version = 1\nshutdown_grace = \"1s\"\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             mode = \"http\"\n\
             backend = \"api\"\n\
             connect_timeout = \"2s\"\n\
             [listener.web.compression]\n\
             gzip = true\n\
             brotli = true\n\
             brotli_quality = 5\n\
             min_size = 512\n\
             [backend.api]\n\
             server = \"{origin}\"\n"
        ),
    );
    let mut child = bin()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run (brotli)");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let mut proxy = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline && proxy.is_empty() {
        line.clear();
        let read = stderr.read_line(&mut line).expect("read stderr");
        assert!(read > 0, "eqproxy closed stderr without announcing bind");
        if let Some(addr) = line.split("listening on ").nth(1) {
            proxy = addr.trim().to_owned();
        }
    }
    assert!(!proxy.is_empty(), "the listener was not announced");

    let text = compression_text();

    // 1) Both accepted: Brotli wins the tie and the body decodes.
    let (head, body, _) = response_body(&get_with_encoding(&proxy, "/big", Some("gzip, br")));
    let head_lower = head.to_ascii_lowercase();
    assert!(head_lower.starts_with("http/1.1 200 ok"), "{head}");
    assert!(
        head_lower.contains("content-encoding: br"),
        "brotli must win the tie: {head}"
    );
    assert!(head_lower.contains("transfer-encoding: chunked"), "{head}");
    assert!(!head_lower.contains("content-length"), "{head}");
    assert_eq!(unbrotli(&body), text.as_bytes(), "decoded body differs");
    assert!(
        body.len() < text.len(),
        "nothing was saved: {} vs {}",
        body.len(),
        text.len()
    );

    // 2) Only gzip accepted: gzip is still served when Brotli is not offered.
    let (head, body, _) = response_body(&get_with_encoding(&proxy, "/big", Some("gzip")));
    assert!(
        head.to_ascii_lowercase().contains("content-encoding: gzip"),
        "{head}"
    );
    assert_eq!(gunzip(&body), text.as_bytes());

    // 3) Explicit q-values order the choice: gzip can beat a low-q Brotli.
    let (head, body, _) = response_body(&get_with_encoding(
        &proxy,
        "/big",
        Some("gzip;q=0.9, br;q=0.2"),
    ));
    assert!(
        head.to_ascii_lowercase().contains("content-encoding: gzip"),
        "{head}"
    );
    assert_eq!(gunzip(&body), text.as_bytes());

    // 4) `br;q=0` refuses Brotli; gzip was not offered, so identity.
    let (head, body, _) = response_body(&get_with_encoding(&proxy, "/big", Some("br;q=0")));
    assert!(
        !head.to_ascii_lowercase().contains("content-encoding"),
        "{head}"
    );
    assert_eq!(body, text.as_bytes());

    // 5) Below min_size: identity even when Brotli is accepted.
    let (head, body, _) = response_body(&get_with_encoding(&proxy, "/small", Some("br")));
    assert!(
        !head.to_ascii_lowercase().contains("content-encoding"),
        "{head}"
    );
    assert_eq!(body, b"tiny");

    // 6) Chunked origin body: re-framed as Brotli, trailers preserved.
    let (head, body, trailers) = response_body(&get_with_encoding(&proxy, "/chunked", Some("br")));
    assert!(
        head.to_ascii_lowercase().contains("content-encoding: br"),
        "{head}"
    );
    assert_eq!(unbrotli(&body), text.as_bytes());
    assert_eq!(trailers, vec!["x-checksum: 42".to_owned()]);

    // Real SIGINT: the final METRICS line distinguishes the two codings.
    let pid = child.id();
    assert!(
        Command::new("kill")
            .args(["-INT", &pid.to_string()])
            .status()
            .expect("run kill")
            .success()
    );
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
    let mut rest = String::new();
    let _ = stderr.read_to_string(&mut rest);
    remove_temp(&config);
    assert_eq!(status.code(), Some(0), "clean shutdown must exit with 0");
    let final_line = rest
        .lines()
        .find(|line| line.starts_with("METRICS ") && line.contains("(final)"))
        .expect("final METRICS line");
    let group = final_line
        .split("compression[")
        .nth(1)
        .and_then(|rest| rest.split(']').next())
        .expect("compression group");
    let value = |name: &str| -> u64 {
        group
            .split_whitespace()
            .find_map(|field| field.strip_prefix(&format!("{name}=")))
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("missing {name} in {group}"))
    };
    assert_eq!(
        value("brotli"),
        2,
        "big + chunked were compressed with Brotli: {group}"
    );
    assert_eq!(value("gzip"), 2, "big gzip + q-value gzip: {group}");
    assert!(value("bytes_out") < value("bytes_in"), "{group}");
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_serves_brotli_over_h2c_to_a_real_client() {
    let origin = start_compression_origin();
    let config = temp_config(
        "brotli-h2c",
        &format!(
            "schema_version = 1\nshutdown_grace = \"1s\"\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             mode = \"http\"\n\
             backend = \"api\"\n\
             connect_timeout = \"2s\"\n\
             [listener.web.compression]\n\
             brotli = true\n\
             [backend.api]\n\
             server = \"{origin}\"\n"
        ),
    );
    let mut child = bin()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run (h2c brotli)");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let mut proxy = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline && proxy.is_empty() {
        line.clear();
        let read = stderr.read_line(&mut line).expect("read stderr");
        assert!(read > 0, "eqproxy closed stderr without announcing bind");
        if let Some(addr) = line.split("listening on ").nth(1) {
            proxy = addr.trim().to_owned();
        }
    }
    assert!(!proxy.is_empty(), "the listener was not announced");

    let tag = format!("eqproxy-cli-e2e-{}-h2c-br", std::process::id());
    let body_path = std::env::temp_dir().join(format!("{tag}.body"));
    let head_path = std::env::temp_dir().join(format!("{tag}.head"));
    // This curl has no Brotli support, so it forwards the raw body: the test
    // decodes it itself instead of trusting `--compressed`.
    let output = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "15",
            "--http2-prior-knowledge",
            "-H",
            "Accept-Encoding: br",
            "-D",
        ])
        .arg(&head_path)
        .arg("-o")
        .arg(&body_path)
        .arg(format!("http://{proxy}/big"))
        .output()
        .expect("run curl (needed for the HTTP/2 e2e)");
    assert!(
        output.status.success(),
        "curl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let head = std::fs::read_to_string(&head_path).expect("read h2 headers");
    assert!(head.starts_with("HTTP/2 200"), "{head}");
    let lower = head.to_ascii_lowercase();
    assert!(lower.contains("content-encoding: br"), "{head}");
    assert!(
        !lower.contains("transfer-encoding:"),
        "h2 has no chunked framing: {head}"
    );
    let body = std::fs::read(&body_path).expect("read h2 body");
    assert_eq!(unbrotli(&body), compression_text().as_bytes());

    let pid = child.id();
    assert!(
        Command::new("kill")
            .args(["-INT", &pid.to_string()])
            .status()
            .expect("run kill")
            .success()
    );
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
    let _ = std::fs::remove_file(&body_path);
    let _ = std::fs::remove_file(&head_path);
    assert_eq!(status.code(), Some(0));
}

/// One request to the admin plane over a raw socket; returns
/// `(status, head, body)` of the answer (the plane closes the connection).
fn admin_exchange(addr: &str, request: &str) -> (u16, String, String) {
    let mut client = TcpStream::connect(addr).expect("connect admin");
    client
        .write_all(request.as_bytes())
        .expect("write admin request");
    client
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("read timeout");
    let mut raw = Vec::new();
    let _ = client.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("the admin plane never completed a head: {text:?}"));
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("no status line in the admin answer: {head}"));
    (status, head.to_owned(), body.to_owned())
}

/// `application/x-www-form-urlencoded` value: everything outside the
/// unreserved set becomes `%XX`, so a TOML table survives the body intact.
fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*byte as char);
            }
            byte => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// One `GET` with an explicit header line (`authorization: …` or `cookie: …`).
fn admin_get_with(addr: &str, path: &str, header_line: Option<&str>) -> (u16, String, String) {
    let mut head = format!("GET {path} HTTP/1.1\r\nhost: admin\r\n");
    if let Some(line) = header_line {
        head.push_str(&format!("{line}\r\n"));
    }
    head.push_str("\r\n");
    admin_exchange(addr, &head)
}

fn admin_get(addr: &str, path: &str, authorization: Option<&str>) -> (u16, String, String) {
    let mut head = format!("GET {path} HTTP/1.1\r\nhost: admin\r\n");
    if let Some(value) = authorization {
        head.push_str(&format!("authorization: {value}\r\n"));
    }
    head.push_str("\r\n");
    admin_exchange(addr, &head)
}

/// Reads one Prometheus counter from the exported text.
fn prometheus_value(text: &str, name: &str) -> u64 {
    text.lines()
        .find_map(|line| {
            let rest = line.strip_prefix(name)?.strip_prefix(' ')?;
            rest.trim().parse::<u64>().ok()
        })
        .unwrap_or_else(|| panic!("{name} is missing from the export: {text}"))
}

/// The read-only admin plane through the **real** binary (v0.8, D6): the
/// bearer token from `token_file` (trailing newline trimmed) gates both
/// routes, the status JSON names the validated config, the Prometheus export
/// moves with **real proxied traffic** on a separate listener, and SIGINT
/// stops both planes cleanly. The dataplane assertion in the same run is what
/// proves the plane is additive, not a substitute for proxying.
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_admin_plane_serves_status_and_metrics_with_a_bearer_token() {
    let backend = start_static_backend("hello-admin");
    let token = "3f9a1c0d7b2e4f6a8c5d1e0b9a7c3f2d";
    let token_path = std::env::temp_dir().join(format!(
        "eqproxy-cli-e2e-{}-admin.token",
        std::process::id()
    ));
    // A token file as an operator writes it: one secret plus a newline, which
    // the CLI trims (a stray `\n` must not make the token unusable).
    std::fs::write(&token_path, format!("{token}\n")).expect("write token file");
    let config = temp_config(
        "admin",
        &format!(
            "schema_version = 1\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             mode = \"http\"\n\
             backend = \"api\"\n\
             \n\
             [backend.api]\n\
             server = \"{backend}\"\n\
             \n\
             [admin]\n\
             listen = \"127.0.0.1:0\"\n\
             token_file = \"{}\"\n",
            token_path.display()
        ),
    );

    let mut child = ReapOnDrop(
        bin()
            .args(["run", "--config"])
            .arg(&config)
            .args(["--metrics-interval", "1h"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn eqproxy run (admin)"),
    );
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let log = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let mut proxy_addr = String::new();
    let mut admin_addr = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline && (proxy_addr.is_empty() || admin_addr.is_empty()) {
        line.clear();
        let read = stderr.read_line(&mut line).expect("read stderr");
        assert!(
            read > 0,
            "eqproxy closed stderr without announcing both binds"
        );
        if let Ok(mut log) = log.lock() {
            log.push_str(&line);
        }
        if proxy_addr.is_empty()
            && let Some(addr) = line.split("listening on ").nth(1)
        {
            proxy_addr = addr.trim().to_owned();
        }
        if let Some(rest) = line.split("admin listening on ").nth(1) {
            admin_addr = rest
                .split_whitespace()
                .next()
                .expect("admin address")
                .to_owned();
        }
    }
    assert!(
        !proxy_addr.is_empty(),
        "the dataplane address was not announced"
    );
    assert!(
        !admin_addr.is_empty(),
        "the admin address was not announced"
    );
    assert_ne!(proxy_addr, admin_addr, "the plane has its own listener");

    // Keep draining stderr so the child never blocks on a full pipe.
    let (line_tx, line_rx) = std::sync::mpsc::channel::<String>();
    let reader = {
        let log = std::sync::Arc::clone(&log);
        std::thread::spawn(move || {
            for line in stderr.lines() {
                let Ok(line) = line else { break };
                if let Ok(mut log) = log.lock() {
                    log.push_str(&line);
                    log.push('\n');
                }
                if line_tx.send(line).is_err() {
                    break;
                }
            }
        })
    };

    // Authentication first: without the token, nothing about the plane leaks.
    let (status, head, body) = admin_get(&admin_addr, "/api/v1/status", None);
    assert_eq!(status, 401, "anonymous status: {head}\n{body}");
    assert!(
        head.to_ascii_lowercase()
            .contains("www-authenticate: bearer"),
        "the plane advertises its scheme: {head}"
    );
    assert!(
        !body.contains("listeners") && !body.contains(token),
        "an unauthorized caller learns nothing: {body}"
    );
    for wrong in [
        "Bearer wrong-token",
        "Basic M2Y5",
        &format!("Bearer {token}x"),
    ] {
        let (status, _, body) = admin_get(&admin_addr, "/api/v1/status", Some(wrong));
        assert_eq!(status, 401, "{wrong:?} must be refused (body: {body})");
    }

    // The real token (from the file, newline trimmed) opens both routes.
    let bearer = format!("Bearer {token}");
    let (status, head, body) = admin_get(&admin_addr, "/api/v1/status", Some(&bearer));
    assert_eq!(status, 200, "status: {head}\n{body}");
    assert!(
        head.to_ascii_lowercase()
            .contains("content-type: application/json"),
        "{head}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("status is valid JSON");
    assert_eq!(parsed["listeners"][0]["name"], "web");
    assert_eq!(parsed["listeners"][0]["mode"], "http");
    // The status reports the port the dataplane really opened, not the
    // configured `:0`: a dashboard must not show an unresolvable address.
    assert_eq!(
        parsed["listeners"][0]["listen"], proxy_addr,
        "the reported address is the bound one: {body}"
    );
    assert_eq!(parsed["backends"][0]["name"], "api");
    assert_eq!(
        parsed["backends"][0]["servers"][0]["addr"],
        backend.to_string()
    );
    assert!(parsed["uptime_seconds"].is_u64(), "{body}");
    assert!(!body.contains(token), "the status never echoes the token");

    // Baseline of the exported counters, then real traffic through the
    // dataplane, then the same export: the plane reports the real counters.
    let (status, head, metrics_before) = admin_get(&admin_addr, "/metrics", Some(&bearer));
    assert_eq!(status, 200, "{head}");
    assert!(
        head.to_ascii_lowercase()
            .contains("content-type: text/plain; version=0.0.4"),
        "{head}"
    );
    let proxied_before = prometheus_value(&metrics_before, "eqproxy_http_requests_proxied_total");

    let response = proxied(
        &proxy_addr,
        b"GET /admin-e2e HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    );
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert_eq!(body_of(&response), "hello-admin", "{response}");

    let (status, _, metrics_after) = admin_get(&admin_addr, "/metrics", Some(&bearer));
    assert_eq!(status, 200);
    assert_eq!(
        prometheus_value(&metrics_after, "eqproxy_http_requests_proxied_total"),
        proxied_before + 1,
        "the export follows the dataplane\nbefore:\n{metrics_before}\nafter:\n{metrics_after}"
    );
    assert!(metrics_after.contains(&format!(
        "eqproxy_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    )));

    // Routing errors once authenticated.
    let (status, _, body) = admin_get(&admin_addr, "/nope", Some(&bearer));
    assert_eq!(status, 404, "{body}");
    let (status, head, _) = admin_exchange(
        &admin_addr,
        &format!("POST /metrics HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {token}\r\n\r\n"),
    );
    assert_eq!(status, 405, "{head}");
    assert!(head.to_ascii_lowercase().contains("allow: get"), "{head}");

    // The plane still answers, and the dataplane never stopped serving.
    let (status, _, _) = admin_get(&admin_addr, "/metrics", Some(&bearer));
    assert_eq!(status, 200, "the plane survives the refusals");
    let response = proxied(
        &proxy_addr,
        b"GET /after-admin-refusals HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body_of(&response), "hello-admin", "{response}");

    let pid = child.id();
    assert!(
        Command::new("kill")
            .args(["-INT", &pid.to_string()])
            .status()
            .expect("run kill")
            .success()
    );
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
    drop(line_rx);
    let _ = reader.join();
    remove_temp(&config);
    let _ = std::fs::remove_file(&token_path);
    assert_eq!(
        status.code(),
        Some(0),
        "clean shutdown with the admin plane up; log:\n{}",
        log.lock().map(|l| l.clone()).unwrap_or_default()
    );
}

/// One authenticated `PUT` against the admin plane.
fn admin_put(addr: &str, path: &str, token: &str, body: &str) -> (u16, String, String) {
    let request = format!(
        "PUT {path} HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {token}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    );
    admin_exchange(addr, &request)
}

/// The first write path through the **real** binary (v0.8, ADR-0018): the
/// read token cannot drain, the write token can, the drained slot stops
/// taking new requests (explicit 503 on a single-server backend), `ready`
/// returns it, and every write leaves an `AUDIT` line without the secret.
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_admin_plane_drains_a_server_with_the_write_token() {
    let backend = start_static_backend("hello-write");
    let read_token = "3f9a1c0d7b2e4f6a8c5d1e0b9a7c3f2d";
    let write_token = "9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e";
    let tag = format!("eqproxy-cli-e2e-{}-admin-write", std::process::id());
    let read_path = std::env::temp_dir().join(format!("{tag}.read"));
    let write_path = std::env::temp_dir().join(format!("{tag}.write"));
    std::fs::write(&read_path, format!("{read_token}\n")).expect("write read token");
    std::fs::write(&write_path, format!("{write_token}\n")).expect("write write token");
    let config = temp_config(
        "admin-write",
        &format!(
            "schema_version = 1\nshutdown_grace = \"1s\"\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             mode = \"http\"\n\
             backend = \"api\"\n\
             connect_timeout = \"2s\"\n\
             [backend.api]\n\
             server = \"{backend}\"\n\
             [admin]\n\
             listen = \"127.0.0.1:0\"\n\
             token_file = \"{}\"\n\
             write_token_file = \"{}\"\n",
            read_path.display(),
            write_path.display()
        ),
    );

    let mut child = ReapOnDrop(
        bin()
            .args(["run", "--config"])
            .arg(&config)
            .args(["--metrics-interval", "1h"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn eqproxy run (admin write)"),
    );
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let log = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let mut proxy_addr = String::new();
    let mut admin_addr = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline && (proxy_addr.is_empty() || admin_addr.is_empty()) {
        line.clear();
        let read = stderr.read_line(&mut line).expect("read stderr");
        assert!(
            read > 0,
            "eqproxy closed stderr without announcing both binds"
        );
        if let Ok(mut log) = log.lock() {
            log.push_str(&line);
        }
        if proxy_addr.is_empty()
            && let Some(addr) = line.split("listening on ").nth(1)
        {
            proxy_addr = addr.trim().to_owned();
        }
        if let Some(rest) = line.split("admin listening on ").nth(1) {
            admin_addr = rest
                .split_whitespace()
                .next()
                .expect("admin address")
                .to_owned();
        }
    }
    assert!(!proxy_addr.is_empty(), "dataplane address not announced");
    assert!(!admin_addr.is_empty(), "admin address not announced");

    // Keep draining stderr into the shared log.
    let reader = {
        let log = std::sync::Arc::clone(&log);
        std::thread::spawn(move || {
            for line in stderr.lines() {
                let Ok(line) = line else { break };
                if let Ok(mut log) = log.lock() {
                    log.push_str(&line);
                    log.push('\n');
                }
            }
        })
    };

    // The slot is addressed by its configured target, exactly as reported.
    let (status, _, body) = admin_get(
        &admin_addr,
        "/api/v1/status",
        Some(&format!("Bearer {read_token}")),
    );
    assert_eq!(status, 200, "{body}");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("status json");
    let target = parsed["backends"][0]["servers"][0]["addr"]
        .as_str()
        .expect("server target")
        .to_owned();
    assert_eq!(target, backend.to_string());
    assert_eq!(parsed["backends"][0]["servers"][0]["state"], "ready");
    let path = format!("/api/v1/backends/api/servers/{target}/state");

    // The read role cannot drain; the write role can.
    let (status, _, body) = admin_put(&admin_addr, &path, read_token, "{\"state\":\"drain\"}");
    assert_eq!(status, 403, "read token must not write: {body}");
    assert!(body.contains("forbidden"), "{body}");
    let (status, _, body) = admin_put(&admin_addr, &path, write_token, "{\"state\":\"drain\"}");
    assert_eq!(status, 200, "write token must drain: {body}");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("write json");
    assert_eq!(parsed["state"], "drain");
    assert_eq!(parsed["previous"], "ready");

    // The live status reflects the drain without a restart.
    let (status, _, body) = admin_get(
        &admin_addr,
        "/api/v1/status",
        Some(&format!("Bearer {read_token}")),
    );
    assert_eq!(status, 200);
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("status json");
    assert_eq!(parsed["backends"][0]["servers"][0]["state"], "drain");

    // New requests find no server: explicit 503, and the origin is untouched.
    let response = proxied(
        &proxy_addr,
        b"GET /while-drained HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    );
    assert!(
        response.starts_with("HTTP/1.1 503"),
        "a drained backend must answer 503: {response}"
    );

    // A SIGHUP reload rebuilds the balancers; the drain must survive it
    // instead of silently returning the server to rotation.
    let pid = child.id();
    assert!(
        Command::new("kill")
            .args(["-HUP", &pid.to_string()])
            .status()
            .expect("run kill -HUP")
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline
        && !log
            .lock()
            .is_ok_and(|log| log.contains("config reload applied"))
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        log.lock()
            .is_ok_and(|log| log.contains("config reload applied")),
        "the SIGHUP reload must land: {:?}",
        log.lock().map(|l| l.clone()).unwrap_or_default()
    );
    let (status, _, body) = admin_get(
        &admin_addr,
        "/api/v1/status",
        Some(&format!("Bearer {read_token}")),
    );
    assert_eq!(status, 200);
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("status json");
    assert_eq!(
        parsed["backends"][0]["servers"][0]["state"], "drain",
        "the drain must survive SIGHUP: {body}"
    );
    let response = proxied(
        &proxy_addr,
        b"GET /after-reload-while-drained HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    );
    assert!(
        response.starts_with("HTTP/1.1 503"),
        "a reload must not return a drained server to rotation: {response}"
    );

    // Back to rotation: the same server serves again.
    let (status, _, body) = admin_put(&admin_addr, &path, write_token, "{\"state\":\"ready\"}");
    assert_eq!(status, 200, "{body}");
    let response = proxied(
        &proxy_addr,
        b"GET /after-ready HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    );
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "ready must return the server: {response}"
    );
    assert_eq!(body_of(&response), "hello-write");

    // The audit trail names both outcomes and never the secrets.
    let pid = child.id();
    assert!(
        Command::new("kill")
            .args(["-INT", &pid.to_string()])
            .status()
            .expect("run kill")
            .success()
    );
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
    let _ = reader.join();
    remove_temp(&config);
    let _ = std::fs::remove_file(&read_path);
    let _ = std::fs::remove_file(&write_path);
    let log = log.lock().map(|l| l.clone()).unwrap_or_default();
    assert_eq!(status.code(), Some(0), "clean shutdown; log:\n{log}");
    assert!(
        log.contains("AUDIT ") && log.contains("\"to\":\"drain\""),
        "the accepted write must be audited: {log}"
    );
    assert!(
        log.contains("\"status\":403"),
        "the refused write must be audited: {log}"
    );
    assert!(
        !log.contains(read_token) && !log.contains(write_token),
        "an audit line never carries a secret"
    );
}

/// Drain observability through the **real** binary (v0.8, H3): a gated origin
/// keeps one exchange in flight on purpose, so the status reports how many
/// exchanges are left on the draining slot and whether the drain has
/// finished, `/metrics` carries the two label-free drain series, and the
/// process writes the event at the exact moment the last exchange ends.
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_admin_plane_reports_drain_progress_and_completion() {
    let (backend, gate) = start_gated_backend("held-exchange");
    let read_token = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d";
    let write_token = "6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a";
    let tag = format!("eqproxy-cli-e2e-{}-drain-observe", std::process::id());
    let read_path = std::env::temp_dir().join(format!("{tag}.read"));
    let write_path = std::env::temp_dir().join(format!("{tag}.write"));
    std::fs::write(&read_path, format!("{read_token}\n")).expect("write read token");
    std::fs::write(&write_path, format!("{write_token}\n")).expect("write write token");
    let config = temp_config(
        "drain-observe",
        &format!(
            "schema_version = 1\nshutdown_grace = \"1s\"\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             mode = \"http\"\n\
             backend = \"api\"\n\
             connect_timeout = \"5s\"\n\
             [backend.api]\n\
             server = \"{backend}\"\n\
             [admin]\n\
             listen = \"127.0.0.1:0\"\n\
             token_file = \"{}\"\n\
             write_token_file = \"{}\"\n",
            read_path.display(),
            write_path.display()
        ),
    );

    let mut child = ReapOnDrop(
        bin()
            .args(["run", "--config"])
            .arg(&config)
            .args(["--metrics-interval", "1h"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn eqproxy run (drain observe)"),
    );
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let log = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let mut proxy_addr = String::new();
    let mut admin_addr = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline && (proxy_addr.is_empty() || admin_addr.is_empty()) {
        line.clear();
        let read = stderr.read_line(&mut line).expect("read stderr");
        assert!(
            read > 0,
            "eqproxy closed stderr without announcing both binds"
        );
        if let Ok(mut log) = log.lock() {
            log.push_str(&line);
        }
        if proxy_addr.is_empty()
            && let Some(addr) = line.split("listening on ").nth(1)
        {
            proxy_addr = addr.trim().to_owned();
        }
        if let Some(rest) = line.split("admin listening on ").nth(1) {
            admin_addr = rest
                .split_whitespace()
                .next()
                .expect("admin address")
                .to_owned();
        }
    }
    assert!(!proxy_addr.is_empty(), "dataplane address not announced");
    assert!(!admin_addr.is_empty(), "admin address not announced");
    let reader = {
        let log = std::sync::Arc::clone(&log);
        std::thread::spawn(move || {
            for line in stderr.lines() {
                let Ok(line) = line else { break };
                if let Ok(mut log) = log.lock() {
                    log.push_str(&line);
                    log.push('\n');
                }
            }
        })
    };

    let auth = format!("Bearer {read_token}");
    let target = backend.to_string();
    let path = format!("/api/v1/backends/api/servers/{target}/state");

    // Hold one real exchange through the proxy.
    let exchange = {
        let proxy_addr = proxy_addr.clone();
        std::thread::spawn(move || {
            proxied(
                &proxy_addr,
                b"GET /held HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
            )
        })
    };
    assert!(
        gate.wait_until_reached(Duration::from_secs(10)),
        "the origin never saw the proxied request"
    );

    // Declared while the exchange is in flight: one left, not finished.
    let (status, _, body) = admin_put(&admin_addr, &path, write_token, "{\"state\":\"drain\"}");
    assert_eq!(status, 200, "{body}");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("drain json");
    assert_eq!(parsed["state"], "drain");
    assert_eq!(
        parsed["active"], 1,
        "the in-flight exchange is reported: {body}"
    );
    assert_eq!(
        parsed["drained"], false,
        "a drain with work left has not finished: {body}"
    );

    let (status, _, body) = admin_get(&admin_addr, "/api/v1/status", Some(&auth));
    assert_eq!(status, 200);
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("status json");
    assert_eq!(parsed["backends"][0]["servers"][0]["state"], "drain");
    assert_eq!(
        parsed["backends"][0]["servers"][0]["active"], 1,
        "the status reports how many exchanges are left: {body}"
    );
    assert_eq!(
        parsed["backends"][0]["servers"][0]["drained"], false,
        "the drain is not finished while the exchange runs: {body}"
    );

    let (status, _, metrics) = admin_get(&admin_addr, "/metrics", Some(&auth));
    assert_eq!(status, 200);
    assert_eq!(
        prometheus_value(&metrics, "eqproxy_backend_servers_draining"),
        1,
        "one slot is draining: {metrics}"
    );
    assert_eq!(
        prometheus_value(&metrics, "eqproxy_backend_drains_completed_total"),
        0,
        "nothing finished yet: {metrics}"
    );

    // Release the exchange: it finishes on the draining slot.
    gate.open();
    let response = exchange.join().expect("exchange thread");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "the held exchange must complete: {response}"
    );
    assert_eq!(body_of(&response), "held-exchange");

    // The status turns to finished exactly when the last exchange ends.
    let deadline = Instant::now() + Duration::from_secs(10);
    let (mut active, mut drained) = (u64::MAX, false);
    while Instant::now() < deadline {
        let (status, _, body) = admin_get(&admin_addr, "/api/v1/status", Some(&auth));
        assert_eq!(status, 200);
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("status json");
        active = parsed["backends"][0]["servers"][0]["active"]
            .as_u64()
            .expect("active");
        drained = parsed["backends"][0]["servers"][0]["drained"] == true;
        if active == 0 && drained {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(active, 0, "the released exchange no longer counts");
    assert!(drained, "the status must report the finished drain");

    let (_, _, metrics) = admin_get(&admin_addr, "/metrics", Some(&auth));
    assert_eq!(
        prometheus_value(&metrics, "eqproxy_backend_servers_draining"),
        1,
        "the slot is still administratively drained: {metrics}"
    );
    assert_eq!(
        prometheus_value(&metrics, "eqproxy_backend_drains_completed_total"),
        1,
        "exactly one drain finished on that exchange: {metrics}"
    );

    // New exchanges find the slot out of rotation.
    let response = proxied(
        &proxy_addr,
        b"GET /after-drain HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    );
    assert!(
        response.starts_with("HTTP/1.1 503"),
        "a finished drain still keeps the slot out of rotation: {response}"
    );

    // One event line, naming the slot, written when it happened.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline
        && !log
            .lock()
            .is_ok_and(|log| log.contains("INFO server drained:"))
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    let pid = child.id();
    assert!(
        Command::new("kill")
            .args(["-INT", &pid.to_string()])
            .status()
            .expect("run kill")
            .success()
    );
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
    let _ = reader.join();
    remove_temp(&config);
    let _ = std::fs::remove_file(&read_path);
    let _ = std::fs::remove_file(&write_path);
    let log = log.lock().map(|l| l.clone()).unwrap_or_default();
    assert_eq!(status.code(), Some(0), "clean shutdown; log:\n{log}");
    assert_eq!(
        log.matches("INFO server drained:").count(),
        1,
        "one event per finished drain: {log}"
    );
    assert!(
        log.contains(&format!("backend=api target={target} active=0")),
        "the event names the slot and the count: {log}"
    );
    assert!(
        !log.contains(read_token) && !log.contains(write_token),
        "the event never carries a secret"
    );
}

/// One authenticated `PUT` of a TOML table body (ADR-0019).
fn admin_put_toml(
    addr: &str,
    path: &str,
    token: &str,
    if_match: Option<&str>,
    body: &str,
) -> (u16, String, String) {
    let mut request = format!(
        "PUT {path} HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {token}\r\ncontent-type: application/toml\r\ncontent-length: {}\r\n",
        body.len()
    );
    if let Some(revision) = if_match {
        request.push_str(&format!("if-match: \"{revision}\"\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);
    admin_exchange(addr, &request)
}

/// Reads exactly one `Content-Length`-framed response from a connection that
/// stays open (the body of a keep-alive exchange), returning the body.
fn read_keepalive_response(stream: &mut TcpStream) -> String {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        if let Some(at) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break at + 4;
        }
        let read = stream.read(&mut chunk).expect("read response head");
        assert!(read > 0, "the proxy closed an established connection");
        raw.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).to_ascii_lowercase();
    let length = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .expect("framed response with content-length");
    while raw.len() < head_end + length {
        let read = stream.read(&mut chunk).expect("read response body");
        assert!(read > 0, "truncated response body");
        raw.extend_from_slice(&chunk[..read]);
    }
    String::from_utf8_lossy(&raw[head_end..head_end + length]).into_owned()
}

/// Authenticated status: parsed JSON plus the raw head (for `ETag`).
fn admin_status(addr: &str, token: &str) -> (serde_json::Value, String) {
    let (status, head, body) = admin_get(addr, "/api/v1/status", Some(&format!("Bearer {token}")));
    assert_eq!(status, 200, "status: {head}\n{body}");
    let parsed = serde_json::from_str(&body).expect("status is JSON");
    (parsed, head)
}

/// Hot configuration through the **real** binary (v0.8, ADR-0019), under
/// load: a backend is modified while four clients are proxying, a new backend
/// is created and a listener is repointed to it; no request may fail. The
/// same run proves the optimistic revision (`If-Match`: stale is 412, missing
/// is 428), that an invalid table never reaches the dataplane, that a bind
/// conflict is refused with the old generation still serving, and that the
/// file remains the baseline on SIGHUP.
#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_admin_plane_applies_backend_config_under_traffic() {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    #[derive(Default)]
    struct Counts {
        a: AtomicU64,
        b: AtomicU64,
        c: AtomicU64,
        failed: AtomicU64,
    }

    // Origin A never closes its connections, so an established client
    // connection can outlive the swap and must keep its accepted generation.
    let origin_a = start_keepalive_origin("origin-a");
    let origin_b = start_static_backend("origin-b");
    let origin_c = start_static_backend("origin-c");
    let read_token = "3f9a1c0d7b2e4f6a8c5d1e0b9a7c3f2d";
    let write_token = "9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e";
    let tag = format!("eqproxy-cli-e2e-{}-admin-config", std::process::id());
    let read_path = std::env::temp_dir().join(format!("{tag}.read"));
    let write_path = std::env::temp_dir().join(format!("{tag}.write"));
    std::fs::write(&read_path, format!("{read_token}\n")).expect("write read token");
    std::fs::write(&write_path, format!("{write_token}\n")).expect("write write token");
    let config = temp_config(
        "admin-config",
        &format!(
            "schema_version = 1\nshutdown_grace = \"1s\"\n\
             [listener.web]\n\
             listen = \"127.0.0.1:0\"\n\
             mode = \"http\"\n\
             backend = \"api\"\n\
             connect_timeout = \"2s\"\n\
             [backend.api]\n\
             server = \"{origin_a}\"\n\
             [admin]\n\
             listen = \"127.0.0.1:0\"\n\
             token_file = \"{}\"\n\
             write_token_file = \"{}\"\n",
            read_path.display(),
            write_path.display()
        ),
    );

    let mut child = ReapOnDrop(
        bin()
            .args(["run", "--config"])
            .arg(&config)
            .args(["--metrics-interval", "1h"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn eqproxy run (admin config)"),
    );
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let log = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let mut proxy_addr = String::new();
    let mut admin_addr = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline && (proxy_addr.is_empty() || admin_addr.is_empty()) {
        line.clear();
        let read = stderr.read_line(&mut line).expect("read stderr");
        assert!(
            read > 0,
            "eqproxy closed stderr without announcing both binds"
        );
        if let Ok(mut log) = log.lock() {
            log.push_str(&line);
        }
        if proxy_addr.is_empty()
            && let Some(addr) = line.split("listening on ").nth(1)
        {
            proxy_addr = addr.trim().to_owned();
        }
        if let Some(rest) = line.split("admin listening on ").nth(1) {
            admin_addr = rest
                .split_whitespace()
                .next()
                .expect("admin address")
                .to_owned();
        }
    }
    assert!(!proxy_addr.is_empty(), "dataplane address not announced");
    assert!(!admin_addr.is_empty(), "admin address not announced");

    // Keep draining stderr into the shared log.
    let reader = {
        let log = std::sync::Arc::clone(&log);
        std::thread::spawn(move || {
            for line in stderr.lines() {
                let Ok(line) = line else { break };
                if let Ok(mut log) = log.lock() {
                    log.push_str(&line);
                    log.push('\n');
                }
            }
        })
    };

    // Four concurrent clients hammer the proxy for the whole run: every
    // configuration swap must be invisible to them.
    let counts = std::sync::Arc::new(Counts::default());
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let mut loaders = Vec::new();
    for _ in 0..4 {
        let proxy = proxy_addr.clone();
        let counts = std::sync::Arc::clone(&counts);
        let stop = std::sync::Arc::clone(&stop);
        loaders.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let mut client = match TcpStream::connect(&proxy) {
                    Ok(client) => client,
                    Err(error) => {
                        counts.failed.fetch_add(1, Ordering::Relaxed);
                        eprintln!("load: connect failed: {error}");
                        continue;
                    }
                };
                let _ = client.set_read_timeout(Some(Duration::from_secs(5)));
                if client
                    .write_all(b"GET /under-load HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
                    .is_err()
                {
                    counts.failed.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let mut raw = Vec::new();
                if client.read_to_end(&mut raw).is_err() {
                    counts.failed.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let response = String::from_utf8_lossy(&raw);
                if !response.starts_with("HTTP/1.1 200") {
                    counts.failed.fetch_add(1, Ordering::Relaxed);
                    eprintln!("load: non-200: {response}");
                    continue;
                }
                match body_of(&response) {
                    "origin-a" => counts.a.fetch_add(1, Ordering::Relaxed),
                    "origin-b" => counts.b.fetch_add(1, Ordering::Relaxed),
                    "origin-c" => counts.c.fetch_add(1, Ordering::Relaxed),
                    other => {
                        counts.failed.fetch_add(1, Ordering::Relaxed);
                        eprintln!("load: unexpected body {other:?}");
                        0
                    }
                };
            }
        }));
    }
    let wait_for = |what: &str, condition: &dyn Fn() -> bool| {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if condition() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!(
            "{what} never happened; counts a={} b={} c={} failed={}",
            counts.a.load(Ordering::Relaxed),
            counts.b.load(Ordering::Relaxed),
            counts.c.load(Ordering::Relaxed),
            counts.failed.load(Ordering::Relaxed)
        );
    };
    wait_for("initial traffic", &|| {
        counts.a.load(Ordering::Relaxed) >= 20
    });

    // A connection established **before** the swap, kept open across it.
    let mut pinned = TcpStream::connect(&proxy_addr).expect("connect pinned client");
    pinned
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("pinned timeout");
    pinned
        .write_all(b"GET /pinned-before HTTP/1.1\r\nHost: t\r\n\r\n")
        .expect("write pinned request");
    assert_eq!(read_keepalive_response(&mut pinned), "origin-a");

    let (status, head) = admin_status(&admin_addr, read_token);
    let revision1 = status["revision"].as_str().expect("revision").to_owned();
    assert_eq!(revision1, "v1");
    assert!(head.to_ascii_lowercase().contains("etag: \"v1\""), "{head}");
    assert_eq!(status["listeners"][0]["listen"], proxy_addr);
    assert_eq!(
        status["backends"][0]["servers"][0]["addr"],
        origin_a.to_string()
    );

    // The read role and an unconditional write are both refused.
    let body_a = format!("server = \"{origin_b}\"\n");
    let (code, _, body) = admin_put_toml(
        &admin_addr,
        "/api/v1/backends/api",
        read_token,
        Some(&revision1),
        &body_a,
    );
    assert_eq!(code, 403, "the read token must not configure: {body}");
    let (code, _, body) = admin_put_toml(
        &admin_addr,
        "/api/v1/backends/api",
        write_token,
        None,
        &body_a,
    );
    assert_eq!(code, 428, "a config write is conditional: {body}");
    assert!(body.contains("precondition_required"), "{body}");

    // 1. Modify the live backend: origin A -> B, with the current revision.
    let (code, head, body) = admin_put_toml(
        &admin_addr,
        "/api/v1/backends/api",
        write_token,
        Some(&revision1),
        &body_a,
    );
    assert_eq!(code, 200, "backend update: {head}\n{body}");
    let applied: serde_json::Value = serde_json::from_str(&body).expect("apply json");
    assert_eq!(applied["revision"], "v2");
    assert_eq!(applied["summary"], "listeners kept=1 added=0 removed=0");
    assert!(
        applied["elapsed_ms"].as_u64().expect("measured commit") < 1000,
        "the roadmap gate is a swap under one second: {applied}"
    );
    assert!(
        head.to_ascii_lowercase().contains("etag: \"v2\""),
        "the answer carries the new revision: {head}"
    );
    wait_for("traffic on the new origin", &|| {
        counts.b.load(Ordering::Relaxed) >= 10
    });

    // The established connection was accepted with the old generation: it
    // keeps serving origin A while new connections already see B.
    pinned
        .write_all(b"GET /pinned-after HTTP/1.1\r\nHost: t\r\n\r\n")
        .expect("write pinned request after the swap");
    assert_eq!(
        read_keepalive_response(&mut pinned),
        "origin-a",
        "an established connection must finish on the generation it accepted"
    );
    let response = proxied(
        &proxy_addr,
        b"GET /fresh-after HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body_of(&response), "origin-b", "{response}");
    drop(pinned);

    // A stale revision is refused and changes nothing.
    let (code, _, body) = admin_put_toml(
        &admin_addr,
        "/api/v1/backends/api",
        write_token,
        Some(&revision1),
        &format!("server = \"{origin_c}\"\n"),
    );
    assert_eq!(code, 412, "a stale If-Match must fail: {body}");
    let stale: serde_json::Value = serde_json::from_str(&body).expect("stale json");
    assert_eq!(stale["error"], "precondition_failed");
    assert_eq!(stale["revision"], "v2");

    // 2. Create a brand-new backend while traffic keeps flowing.
    let (code, _, body) = admin_put_toml(
        &admin_addr,
        "/api/v1/backends/green",
        write_token,
        Some("v2"),
        &format!("server = \"{origin_c}\"\n"),
    );
    assert_eq!(code, 200, "new backend: {body}");
    let applied: serde_json::Value = serde_json::from_str(&body).expect("apply json");
    assert_eq!(applied["revision"], "v3");
    assert!(
        applied["elapsed_ms"].as_u64().expect("measured commit") < 1000,
        "creating a backend is a sub-second swap: {applied}"
    );
    let (status, _) = admin_status(&admin_addr, read_token);
    assert_eq!(status["revision"], "v3");
    assert!(
        status["backends"]
            .as_array()
            .expect("backends")
            .iter()
            .any(|backend| backend["name"] == "green"
                && backend["servers"][0]["addr"] == origin_c.to_string()),
        "the created backend must be reported: {status}"
    );

    // 3. Repoint the live listener at the new backend (same socket: kept).
    let listener_body = "listen = \"127.0.0.1:0\"\nmode = \"http\"\nbackend = \"green\"\n";
    let (code, _, body) = admin_put_toml(
        &admin_addr,
        "/api/v1/listeners/web",
        write_token,
        Some("v3"),
        listener_body,
    );
    assert_eq!(code, 200, "listener update: {body}");
    let applied: serde_json::Value = serde_json::from_str(&body).expect("apply json");
    assert_eq!(applied["revision"], "v4");
    assert_eq!(applied["summary"], "listeners kept=1 added=0 removed=0");
    assert!(
        applied["elapsed_ms"].as_u64().expect("measured commit") < 1000,
        "repointing a listener is a sub-second swap: {applied}"
    );
    wait_for("traffic on the created backend", &|| {
        counts.c.load(Ordering::Relaxed) >= 10
    });
    let (status, _) = admin_status(&admin_addr, read_token);
    assert_eq!(status["listeners"][0]["backend"], "green");
    assert_eq!(status["listeners"][0]["listen"], proxy_addr);

    // 4. An invalid table is refused before the dataplane sees it.
    let (code, _, body) = admin_put_toml(
        &admin_addr,
        "/api/v1/backends/api",
        write_token,
        Some("v4"),
        "balance = \"random\"\n",
    );
    assert_eq!(code, 400, "invalid config: {body}");
    let invalid: serde_json::Value = serde_json::from_str(&body).expect("invalid json");
    assert_eq!(invalid["error"], "invalid_config");
    assert_eq!(
        admin_status(&admin_addr, read_token).0["revision"],
        "v4",
        "a refused candidate must not advance the revision"
    );

    // 5. A bind conflict is refused atomically: the old generation serves.
    let held = TcpListener::bind("127.0.0.1:0").expect("hold a port");
    let held_addr = held.local_addr().expect("held addr");
    let conflict = format!("listen = \"{held_addr}\"\nmode = \"http\"\nbackend = \"green\"\n");
    let (code, _, body) = admin_put_toml(
        &admin_addr,
        "/api/v1/listeners/web",
        write_token,
        Some("v4"),
        &conflict,
    );
    assert_eq!(code, 409, "a bind conflict is refused: {body}");
    let rejected: serde_json::Value = serde_json::from_str(&body).expect("rejected json");
    assert_eq!(rejected["error"], "swap_rejected");
    drop(held);
    let (status, _) = admin_status(&admin_addr, read_token);
    assert_eq!(status["revision"], "v4");
    assert_eq!(status["listeners"][0]["listen"], proxy_addr);
    let response = proxied(
        &proxy_addr,
        b"GET /after-rejected-swap HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body_of(&response), "origin-c", "{response}");

    // 6. SIGHUP re-reads the file, which is still the baseline: the runtime
    //    changes are replaced by the file's generation, atomically.
    send_signal(&child, "-HUP");
    // The revision is the observable commit point: API applies log the same
    // "config reload applied" line, so the log alone cannot tell this reload
    // apart from the earlier writes.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut status = admin_status(&admin_addr, read_token).0;
    while Instant::now() < deadline && status["revision"] != "v5" {
        std::thread::sleep(Duration::from_millis(20));
        status = admin_status(&admin_addr, read_token).0;
    }
    assert_eq!(
        status["revision"],
        "v5",
        "the SIGHUP reload must commit a new revision: {status}\nlog:\n{}",
        log.lock().map(|l| l.clone()).unwrap_or_default()
    );
    assert_eq!(status["listeners"][0]["backend"], "api");
    assert_eq!(
        status["backends"][0]["servers"][0]["addr"],
        origin_a.to_string()
    );
    wait_for("traffic back on the file generation", &|| {
        let before = counts.a.load(Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(30));
        counts.a.load(Ordering::Relaxed) > before
    });

    // Two writers that read the same revision: exactly one may commit; the
    // other is told to re-read. This is what serializing the revision check
    // and the swap in one task buys.
    let mut racers = Vec::new();
    for body in [
        format!("server = \"{origin_a}\"\n"),
        format!("server = \"{origin_b}\"\n"),
    ] {
        let admin = admin_addr.clone();
        racers.push(std::thread::spawn(move || {
            admin_put_toml(
                &admin,
                "/api/v1/backends/api",
                write_token,
                Some("v5"),
                &body,
            )
            .0
        }));
    }
    let mut codes: Vec<u16> = racers
        .into_iter()
        .map(|racer| racer.join().expect("racer thread"))
        .collect();
    codes.sort_unstable();
    assert_eq!(codes, vec![200, 412], "one writer commits, one re-reads");
    let (status, _) = admin_status(&admin_addr, read_token);
    assert_eq!(status["revision"], "v6");

    stop.store(true, Ordering::Relaxed);
    for loader in loaders {
        loader.join().expect("loader thread");
    }
    let failed = counts.failed.load(Ordering::Relaxed);
    let total = counts.a.load(Ordering::Relaxed)
        + counts.b.load(Ordering::Relaxed)
        + counts.c.load(Ordering::Relaxed);
    assert_eq!(
        failed,
        0,
        "no request may fail across the swaps (a={} b={} c={} total={total})",
        counts.a.load(Ordering::Relaxed),
        counts.b.load(Ordering::Relaxed),
        counts.c.load(Ordering::Relaxed)
    );
    assert!(total >= 100, "the load must be real: {total} requests");
    assert!(
        counts.a.load(Ordering::Relaxed) > 0
            && counts.b.load(Ordering::Relaxed) > 0
            && counts.c.load(Ordering::Relaxed) > 0,
        "each generation must have served: a={} b={} c={}",
        counts.a.load(Ordering::Relaxed),
        counts.b.load(Ordering::Relaxed),
        counts.c.load(Ordering::Relaxed)
    );

    send_signal(&child, "-INT");
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
    let _ = reader.join();
    remove_temp(&config);
    let _ = std::fs::remove_file(&read_path);
    let _ = std::fs::remove_file(&write_path);
    let log = log.lock().map(|l| l.clone()).unwrap_or_default();
    assert_eq!(status.code(), Some(0), "clean shutdown; log:\n{log}");
    assert!(
        log.contains("\"status\":200"),
        "successful config writes are audited: {log}"
    );
    assert!(
        !log.contains(read_token) && !log.contains(write_token),
        "{log}"
    );
}

// --- Admin plane on a Unix socket (v0.8, ADR-0021) ---

/// The test process's effective uid/gid, read from a file it just created.
#[cfg(unix)]
fn current_ids() -> (u32, u32) {
    use std::os::unix::fs::MetadataExt;

    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "eqproxy-cli-ids-{}-{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::write(&path, b"x").expect("write id probe");
    let metadata = std::fs::metadata(&path).expect("id probe metadata");
    let ids = (metadata.uid(), metadata.gid());
    std::fs::remove_file(&path).expect("remove id probe");
    ids
}

/// Exchanges one raw head over a Unix socket and reads the whole answer.
#[cfg(unix)]
fn unix_admin_exchange(path: &Path, head: &str) -> String {
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(path).expect("connect admin Unix socket");
    stream.write_all(head.as_bytes()).expect("write admin head");
    let mut answer = String::new();
    stream
        .read_to_string(&mut answer)
        .expect("read admin answer");
    answer
}

/// The **real binary** on a Unix socket (v0.8, B-H14): the relative path in
/// the TOML resolves against the config file, the socket is owner-only, the
/// bearer token still gates every route, proxied traffic is untouched, and
/// SIGINT removes the socket file. The TCP admin plane is not opened at all.
#[cfg(unix)]
#[cfg_attr(
    miri,
    ignore = "needs processes and Unix sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_admin_plane_listens_on_a_unix_socket_and_removes_it_on_shutdown() {
    use std::os::unix::fs::PermissionsExt;

    let origin = start_static_backend("hello-unix-admin");
    let token = "7c4e2b9d1a6f8e3c5b0d9a7f2e4c6b8d";
    let socket_name = format!("eqproxy-cli-e2e-{}-admin.sock", std::process::id());
    let socket_path = std::env::temp_dir().join(&socket_name);
    let _ = std::fs::remove_file(&socket_path);
    let config = temp_config(
        "admin-unix",
        &format!(
            "schema_version = 1\nshutdown_grace = \"1s\"\n\
             [listener.web]\nlisten = \"127.0.0.1:0\"\nmode = \"http\"\nbackend = \"api\"\n\
             [backend.api]\nserver = \"{origin}\"\n\
             [admin]\nunix_socket = \"{socket_name}\"\ntoken = \"{token}\"\n"
        ),
    );
    let (mut child, proxy_addr, mut stderr) = spawn_run_and_wait(&config, "web");

    // The announcement names the real endpoint, not the configured one.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut announcement = String::new();
    while Instant::now() < deadline && !announcement.contains("admin listening on ") {
        let mut line = String::new();
        let read = stderr.read_line(&mut line).expect("read stderr");
        assert!(
            read > 0,
            "eqproxy closed stderr before opening the admin socket; log:\n{announcement}"
        );
        announcement.push_str(&line);
    }
    assert!(
        socket_path.exists(),
        "the announced socket exists; log:\n{announcement}"
    );
    assert!(
        announcement.contains(&format!(
            "admin listening on unix:{}",
            socket_path.display()
        )),
        "the admin endpoint is announced with its real path: {announcement}"
    );

    let mode = std::fs::metadata(&socket_path)
        .expect("socket metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "the socket is owner-only");

    // Anonymous and authenticated reads over the socket.
    let anonymous = unix_admin_exchange(
        &socket_path,
        "GET /api/v1/status HTTP/1.1\r\nhost: admin\r\n\r\n",
    );
    assert!(anonymous.starts_with("HTTP/1.1 401"), "{anonymous}");
    let status = unix_admin_exchange(
        &socket_path,
        &format!(
            "GET /api/v1/status HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {token}\r\n\r\n"
        ),
    );
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    let parsed: serde_json::Value =
        serde_json::from_str(status.split("\r\n\r\n").nth(1).expect("status body"))
            .expect("status is JSON");
    assert_eq!(parsed["listeners"][0]["name"], "web");
    assert_eq!(
        parsed["listeners"][0]["listen"], proxy_addr,
        "the status reports the bound dataplane address: {status}"
    );
    let metrics = unix_admin_exchange(
        &socket_path,
        &format!("GET /metrics HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {token}\r\n\r\n"),
    );
    assert!(metrics.starts_with("HTTP/1.1 200"), "{metrics}");
    assert!(metrics.contains("eqproxy_build_info"), "{metrics}");

    // The dataplane never depended on the admin transport.
    let response = proxied(
        &proxy_addr,
        b"GET /unix-admin HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body_of(&response), "hello-unix-admin", "{response}");

    // Keep draining stderr so the child never blocks on a full pipe.
    let reader = std::thread::spawn(move || {
        let mut rest = String::new();
        let _ = stderr.read_to_string(&mut rest);
        rest
    });
    wait_for_sigint_shutdown(&mut child, &config);
    let _ = reader.join();
    assert!(
        !socket_path.exists(),
        "a clean SIGINT removes the socket file this process created"
    );
    let _ = std::fs::remove_file(&socket_path);
}

/// Reads stderr until the Unix admin socket exists, returning what was read.
#[cfg(unix)]
fn wait_for_unix_admin(stderr: &mut BufReader<std::process::ChildStderr>, socket: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut log = String::new();
    // Wait for the announcement, not merely for the file: the socket exists a
    // few instructions before the line is written, and reading the file as
    // the condition made this helper race the logger.
    while Instant::now() < deadline && !log.contains("admin listening on unix:") {
        let mut line = String::new();
        let read = stderr.read_line(&mut line).expect("read stderr");
        assert!(
            read > 0,
            "eqproxy closed stderr before announcing the admin socket; log:\n{log}"
        );
        log.push_str(&line);
    }
    assert!(
        log.contains("admin listening on unix:"),
        "the admin endpoint was not announced; log:\n{log}"
    );
    assert!(
        socket.exists(),
        "the announced admin socket does not exist; log:\n{log}"
    );
    log
}

/// Group-shared socket plus a `SO_PEERCRED` uid allowlist, through the real
/// binary (v0.8, B-H14/ADR-0022): the owner's uid passes, the group owns the
/// file, and a uid outside the list is closed before any HTTP answer.
#[cfg(unix)]
#[cfg_attr(
    miri,
    ignore = "needs processes and Unix sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_admin_plane_enforces_group_mode_and_uid_allowlist() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixStream;

    let origin = start_static_backend("hello-group-admin");
    let (uid, gid) = current_ids();
    let token = "1d9f3a7c5e2b8f4a6c0d3e7b9a1f5c2e";

    // Allowed uid: the socket is 0660, owned by the process group, and the
    // routes answer over it.
    let allowed_name = format!("eqproxy-cli-e2e-{}-admin-group.sock", std::process::id());
    let allowed_path = std::env::temp_dir().join(&allowed_name);
    let _ = std::fs::remove_file(&allowed_path);
    let allowed_config = temp_config(
        "admin-unix-group",
        &format!(
            "schema_version = 1\nshutdown_grace = \"1s\"\n\
             [listener.web]\nlisten = \"127.0.0.1:0\"\nmode = \"http\"\nbackend = \"api\"\n\
             [backend.api]\nserver = \"{origin}\"\n\
             [admin]\nunix_socket = \"{allowed_name}\"\ntoken = \"{token}\"\n\
             unix_socket_mode = \"0660\"\nunix_socket_gid = {gid}\n\
             unix_socket_allow_uids = [{uid}]\n"
        ),
    );
    let (mut child, _proxy_addr, mut stderr) = spawn_run_and_wait(&allowed_config, "web");
    let _log = wait_for_unix_admin(&mut stderr, &allowed_path);
    let metadata = std::fs::metadata(&allowed_path).expect("socket metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o660);
    assert_eq!(metadata.uid(), uid);
    assert_eq!(metadata.gid(), gid);
    let status = unix_admin_exchange(
        &allowed_path,
        &format!(
            "GET /api/v1/status HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {token}\r\n\r\n"
        ),
    );
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    let reader = std::thread::spawn(move || {
        let mut rest = String::new();
        let _ = stderr.read_to_string(&mut rest);
        rest
    });
    wait_for_sigint_shutdown(&mut child, &allowed_config);
    let _ = reader.join();
    assert!(!allowed_path.exists(), "clean shutdown removed the socket");

    // Denied uid: the filesystem still lets the owner connect, but the plane
    // closes the connection before parsing an HTTP head.
    let denied_name = format!("eqproxy-cli-e2e-{}-admin-denied.sock", std::process::id());
    let denied_path = std::env::temp_dir().join(&denied_name);
    let _ = std::fs::remove_file(&denied_path);
    let denied_config = temp_config(
        "admin-unix-denied",
        &format!(
            "schema_version = 1\nshutdown_grace = \"1s\"\n\
             [listener.web]\nlisten = \"127.0.0.1:0\"\nmode = \"http\"\nbackend = \"api\"\n\
             [backend.api]\nserver = \"{origin}\"\n\
             [admin]\nunix_socket = \"{denied_name}\"\ntoken = \"{token}\"\n\
             unix_socket_mode = \"0660\"\nunix_socket_gid = {gid}\n\
             unix_socket_allow_uids = [{}]\n",
            uid.wrapping_add(1)
        ),
    );
    let (mut child, proxy_addr_denied, mut stderr) = spawn_run_and_wait(&denied_config, "web");
    let _log = wait_for_unix_admin(&mut stderr, &denied_path);
    let mut stream =
        UnixStream::connect(&denied_path).expect("the owner can still open the socket file");
    let _ = stream.write_all(b"GET /api/v1/status HTTP/1.1\r\nhost: admin\r\n\r\n");
    let mut answer = String::new();
    match stream.read_to_string(&mut answer) {
        Ok(read) => assert_eq!(read, 0, "no HTTP bytes for a denied uid: {answer}"),
        Err(error) => assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
            ),
            "unexpected error after the uid check: {error}"
        ),
    }
    assert!(
        answer.is_empty(),
        "the refused peer learns nothing about the plane: {answer}"
    );

    // The dataplane is independent of the admin decision.
    let response = proxied(
        &proxy_addr_denied,
        b"GET /denied-admin HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body_of(&response), "hello-group-admin", "{response}");

    let reader = std::thread::spawn(move || {
        let mut rest = String::new();
        let _ = stderr.read_to_string(&mut rest);
        rest
    });
    wait_for_sigint_shutdown(&mut child, &denied_config);
    let log = reader.join().unwrap_or_default();
    assert!(
        log.contains("is not in unix_socket_allow_uids"),
        "the refusal is logged: {log}"
    );
    assert!(
        !denied_path.exists(),
        "clean shutdown removed the denied socket"
    );
}

/// Hot reload of the admin socket policy (v0.8, ADR-0022): a SIGHUP applies a
/// new mode, group and `SO_PEERCRED` allowlist to the socket the **real
/// binary** already bound, a policy the process cannot write is rejected with
/// the previous one still in force, and no restart or rebind happens.
#[cfg(unix)]
#[cfg_attr(
    miri,
    ignore = "needs processes and Unix sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_admin_plane_reloads_unix_socket_policy_on_sighup() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixStream;

    let origin = start_static_backend("hello-reloaded-admin");
    let (uid, gid) = current_ids();
    let token = "5b8e2f6a9c1d4e7f0a3b6c8d1e4f7a2b";
    let socket_name = format!("eqproxy-cli-e2e-{}-admin-reload.sock", std::process::id());
    let socket_path = std::env::temp_dir().join(&socket_name);
    let _ = std::fs::remove_file(&socket_path);

    let body = |mode: &str, gid_line: &str, allow: &str| {
        format!(
            "schema_version = 1\nshutdown_grace = \"1s\"\n\
             [listener.web]\nlisten = \"127.0.0.1:0\"\nmode = \"http\"\nbackend = \"api\"\n\
             [backend.api]\nserver = \"{origin}\"\n\
             [admin]\nunix_socket = \"{socket_name}\"\ntoken = \"{token}\"\n\
             unix_socket_mode = \"{mode}\"\n{gid_line}unix_socket_allow_uids = [{allow}]\n"
        )
    };
    let authorized = format!(
        "GET /api/v1/status HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {token}\r\n\r\n"
    );

    let config = temp_config("admin-unix-reload", &body("0600", "", &uid.to_string()));
    let (mut child, proxy_addr, mut stderr) = spawn_run_and_wait(&config, "web");
    wait_for_unix_admin(&mut stderr, &socket_path);
    let metadata = std::fs::metadata(&socket_path).expect("socket metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let answer = unix_admin_exchange(&socket_path, &authorized);
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");

    // 1. Widen the file to the group **and** drop the owner from the list in
    //    one generation: both halves must move on SIGHUP, without a rebind.
    std::fs::write(
        &config,
        body(
            "0660",
            &format!("unix_socket_gid = {gid}\n"),
            &uid.wrapping_add(1).to_string(),
        ),
    )
    .expect("write the widened policy");
    send_signal(&child, "-HUP");
    let applied = wait_for_stderr(&mut stderr, "INFO admin socket policy applied");
    assert!(applied.contains("mode 0660"), "{applied}");
    assert!(applied.contains("allowed uid(s)"), "{applied}");
    let metadata = std::fs::metadata(&socket_path).expect("socket metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o660);
    assert_eq!(metadata.gid(), gid);
    // The owner can still `connect(2)` (the file is the owner's) but the
    // running accept loop now refuses its credential before parsing HTTP.
    let mut stream = UnixStream::connect(&socket_path).expect("connect after reload");
    let _ = stream.write_all(authorized.as_bytes());
    let mut denied = String::new();
    match stream.read_to_string(&mut denied) {
        Ok(read) => assert_eq!(read, 0, "no HTTP bytes after the reload: {denied}"),
        Err(error) => assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
            ),
            "unexpected error after the reloaded check: {error}"
        ),
    }
    assert!(denied.is_empty(), "{denied}");
    // The dataplane was never part of this: no restart, no rebind, no drop.
    let response = proxied(
        &proxy_addr,
        b"GET /after-admin-reload HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body_of(&response), "hello-reloaded-admin", "{response}");

    // 2. A policy the process cannot write is refused as a whole: the socket
    //    keeps 0660, the group and the deny list, and nothing is swapped.
    //
    //    An **unprivileged** process is the premise of this step: root is
    //    allowed to `chown(2)` the socket to group 54321, so for it the reload
    //    is **applied**, not rejected, and the log line this step waits for
    //    never arrives (the run would block, not fail). A root run therefore
    //    declares the step skipped, with the reason printed, and carries on
    //    with step 3; CI's runners and normal developer runs are unprivileged,
    //    where the refusal is meaningful. What root does verify about a live
    //    reload is step 1: mode, group and allowlist applied as a whole.
    if current_ids().0 == 0 {
        eprintln!(
            "SKIP (running as root): the reload can only be refused for an \
             unprivileged process, and root is allowed to chown the socket to \
             group 54321, so this step is not run. CI and normal developer \
             runs are unprivileged; the reason is intentional, not a missing \
             assertion."
        );
    } else {
        std::fs::write(&config, body("0660", "unix_socket_gid = 54321\n", ""))
            .expect("write the impossible policy");
        send_signal(&child, "-HUP");
        let rejected = wait_for_stderr(
            &mut stderr,
            "ERROR admin unix socket policy cannot be applied",
        );
        assert!(
            rejected.contains("unix_socket_gid") || rejected.contains("Operation not permitted"),
            "the rejection names the failing operation: {rejected}"
        );
        let metadata = std::fs::metadata(&socket_path).expect("socket metadata");
        assert_eq!(
            metadata.permissions().mode() & 0o777,
            0o660,
            "a refused reload must not roll the mode back or forward"
        );
        assert_eq!(metadata.gid(), gid);
        let mut stream = UnixStream::connect(&socket_path).expect("connect after the rejection");
        let _ = stream.write_all(authorized.as_bytes());
        let mut still_denied = String::new();
        let _ = stream.read_to_string(&mut still_denied);
        assert!(
            still_denied.is_empty(),
            "the denied list must survive the rejected reload: {still_denied}"
        );
    }

    // 3. Back to owner-only and admitting the owner: the same socket answers
    //    again, so the reload works in both directions.
    std::fs::write(&config, body("0600", "", &uid.to_string())).expect("write step 3");
    send_signal(&child, "-HUP");
    let restored = wait_for_stderr(&mut stderr, "INFO admin socket policy applied");
    assert!(restored.contains("mode 0600"), "{restored}");
    let metadata = std::fs::metadata(&socket_path).expect("socket metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.uid(), uid);
    let answer = unix_admin_exchange(&socket_path, &authorized);
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");

    // Keep draining stderr so the child never blocks on a full pipe.
    let reader = std::thread::spawn(move || {
        let mut rest = String::new();
        let _ = stderr.read_to_string(&mut rest);
        rest
    });
    wait_for_sigint_shutdown(&mut child, &config);
    let _ = reader.join();
    assert!(
        !socket_path.exists(),
        "a clean shutdown still removes the socket after reloads"
    );
}

// --- Structured access log (v0.8, ADR-0020) ---

/// Spawns `run`, reads stderr until the named listener is announced.
fn spawn_run_and_wait(
    config: &Path,
    listener: &str,
) -> (
    std::process::Child,
    String,
    BufReader<std::process::ChildStderr>,
) {
    let mut child = bin()
        .args(["run", "--config"])
        .arg(config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));
    let needle = format!("listener {listener} listening on ");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    let mut addr = String::new();
    while Instant::now() < deadline && addr.is_empty() {
        line.clear();
        let read = stderr.read_line(&mut line).expect("read stderr");
        assert!(
            read > 0,
            "eqproxy closed stderr without announcing the listener"
        );
        if let Some(found) = line.split(&needle).nth(1) {
            addr = found.trim().to_owned();
        }
    }
    assert!(!addr.is_empty(), "listener {listener} was not announced");
    // Keep the reader alive: closing it would give the child EPIPE on its next
    // stderr line (the final METRICS), which is not what this test measures.
    (child, addr, stderr)
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_writes_one_json_access_line_per_request_under_traffic() {
    let origin = start_body_echo_origin();
    let log_path = std::env::temp_dir().join(format!(
        "eqproxy-cli-e2e-{}-access.jsonl",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&log_path);
    let config = temp_config(
        "access-json",
        &format!(
            "schema_version = 1\nshutdown_grace = \"1s\"\n\
             [access_log]\nformat = \"json\"\npath = \"{}\"\n\
             [listener.web]\nlisten = \"127.0.0.1:0\"\nmode = \"http\"\nbackend = \"api\"\n\
             [backend.api]\nserver = \"{origin}\"\n",
            log_path.display()
        ),
    );
    let (mut child, addr, _stderr) = spawn_run_and_wait(&config, "web");

    let mut workers = Vec::new();
    for worker in 0..4 {
        let addr = addr.clone();
        workers.push(std::thread::spawn(move || {
            for request in 0..10 {
                let mut client = TcpStream::connect(&addr).expect("connect proxy");
                let head = format!(
                    "GET /w{worker}/r{request}?token=secret HTTP/1.1\r\nHost: log.test\r\nUser-Agent: e2e/1\r\nConnection: close\r\n\r\n"
                );
                client.write_all(head.as_bytes()).expect("write request");
                let mut response = String::new();
                client.read_to_string(&mut response).expect("read response");
                assert!(
                    response.starts_with("HTTP/1.1 200"),
                    "request {worker}/{request}: {response}"
                );
            }
        }));
    }
    for worker in workers {
        worker.join().expect("worker must finish");
    }
    wait_for_sigint_shutdown(&mut child, &config);

    let text = std::fs::read_to_string(&log_path).expect("the access log must exist");
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), 40, "one line per request; got:\n{text}");
    for line in lines {
        let value: serde_json::Value =
            serde_json::from_str(line).expect("one JSON object per line");
        assert_eq!(value["listener"], "web");
        assert_eq!(value["protocol"], "http/1.1");
        assert_eq!(value["method"], "GET");
        assert_eq!(value["status"], 200);
        assert_eq!(value["backend"], "api");
        assert_eq!(value["bytes"], 0);
        let path = value["path"].as_str().expect("path");
        assert!(path.starts_with("/w"), "{path}");
        assert!(
            !path.contains("secret"),
            "the query is never logged: {path}"
        );
        assert!(
            value["client"]
                .as_str()
                .expect("client")
                .starts_with("127.0.0.1:"),
            "{}",
            value["client"]
        );
        assert!(value["time"].as_str().expect("time").ends_with('Z'));
        assert!(value["duration_ms"].is_u64());
    }
    let _ = std::fs::remove_file(&log_path);
}

#[cfg_attr(
    miri,
    ignore = "needs processes and TCP sockets: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_writes_combined_lines_when_configured() {
    let origin = start_body_echo_origin();
    let log_path =
        std::env::temp_dir().join(format!("eqproxy-cli-e2e-{}-access.log", std::process::id()));
    let _ = std::fs::remove_file(&log_path);
    let config = temp_config(
        "access-combined",
        &format!(
            "schema_version = 1\nshutdown_grace = \"1s\"\n\
             [access_log]\nformat = \"combined\"\npath = \"{}\"\n\
             [listener.web]\nlisten = \"127.0.0.1:0\"\nmode = \"http\"\nbackend = \"api\"\n\
             [backend.api]\nserver = \"{origin}\"\n",
            log_path.display()
        ),
    );
    let (mut child, addr, _stderr) = spawn_run_and_wait(&config, "web");

    let mut client = TcpStream::connect(&addr).expect("connect proxy");
    client
        .write_all(
            b"GET /first?token=secret HTTP/1.1\r\nHost: log.test\r\nUser-Agent: e2e/1\r\nConnection: close\r\n\r\n",
        )
        .expect("write request");
    let mut response = String::new();
    client.read_to_string(&mut response).expect("read response");
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    wait_for_sigint_shutdown(&mut child, &config);

    let text = std::fs::read_to_string(&log_path).expect("the access log must exist");
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), 1, "one line per request; got:\n{text}");
    let line = lines[0];
    assert!(
        line.contains("\"GET /first HTTP/1.1\" 200 0 \"-\" \"e2e/1\""),
        "combined shape: {line}"
    );
    assert!(line.starts_with("127.0.0.1 - - "), "{line}");
    // The stamp must be the real clock in UTC, so the test checks its shape
    // (`DD/Mon/YYYY:HH:MM:SS +0000`) and not a calendar day it cannot own.
    let stamp_start = line.find(" [").expect("bracketed timestamp") + 2;
    let stamp_end = stamp_start + line[stamp_start..].find(']').expect("closed stamp");
    let stamp = &line[stamp_start..stamp_end];
    let parts: Vec<&str> = stamp.split(['/', ':', ' ']).collect();
    assert_eq!(parts.len(), 7, "stamp shape: {stamp}");
    let is_two_digits = |part: &str| part.len() == 2 && part.chars().all(|c| c.is_ascii_digit());
    assert!(is_two_digits(parts[0]), "day: {stamp}");
    assert!(
        [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ]
        .contains(&parts[1]),
        "month: {stamp}"
    );
    assert!(
        parts[2].len() == 4 && parts[2].chars().all(|c| c.is_ascii_digit()),
        "year: {stamp}"
    );
    assert!(
        parts[3..6].iter().all(|part| is_two_digits(part)),
        "clock: {stamp}"
    );
    assert_eq!(parts[6], "+0000", "UTC offset: {stamp}");
    assert!(
        !line.contains("secret"),
        "the query is never logged: {line}"
    );
    let _ = std::fs::remove_file(&log_path);
}

#[cfg_attr(
    miri,
    ignore = "needs processes: miri does not support them (rust-lang/miri#3449)"
)]
#[test]
fn run_refuses_to_start_when_the_access_log_cannot_be_opened() {
    let origin = start_body_echo_origin();
    // A directory cannot be opened for append: startup must fail, not serve
    // without the sink the operator configured.
    let directory = std::env::temp_dir();
    let config = temp_config(
        "access-unopenable",
        &format!(
            "schema_version = 1\n\
             [access_log]\npath = \"{}\"\n\
             [listener.web]\nlisten = \"127.0.0.1:0\"\nmode = \"http\"\nbackend = \"api\"\n\
             [backend.api]\nserver = \"{origin}\"\n",
            directory.display()
        ),
    );
    let output = bin()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--metrics-interval", "1h"])
        .output()
        .expect("run eqproxy");
    remove_temp(&config);
    assert_eq!(output.status.code(), Some(1), "must fail closed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("access log cannot be opened"),
        "stderr: {stderr}"
    );
}
