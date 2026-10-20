//! Migration gate (v0.6): the four real source configs of `docs/migration/`
//! and their EQProxy translation route the matrix of `docs/migration/README.md`
//! exactly the same.
//!
//! Runs HAProxy, operator nginx, the ingress-nginx data plane (controller-shaped
//! generated config) and Envoy as containers, and the freshly built EQProxy
//! binary natively, all in front of the same five echo backends; every case is
//! sent to all five implementations and the declared outcome is asserted on
//! each. The report is written to `$CARGO_TARGET_TMPDIR/migration-report.md`.
//!
//! Ignored by default (needs Docker + the reference images):
//! `cargo test -p eqproxy-cli --test migration -- --ignored --nocapture`

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const HAPROXY_IMAGE: &str = "haproxy:3.4.6";
const NGINX_IMAGE: &str = "nginx:alpine";
const INGRESS_NGINX_IMAGE: &str = "registry.k8s.io/ingress-nginx/controller:v1.13.0";
const ENVOY_IMAGE: &str = "envoyproxy/envoy:v1.34.2";
const BACKEND_IMAGE: &str = "nginx:alpine";

/// The demo pools of the matrix: id and fixed container address. The
/// source configs address them exactly like this; the native EQProxy
/// reaches them through the published host ports instead (declared
/// substitution, see the README).
const POOLS: [(&str, &str); 5] = [
    ("web", "172.24.0.11"),
    ("api", "172.24.0.12"),
    ("admin", "172.24.0.13"),
    ("canary", "172.24.0.14"),
    ("fallback", "172.24.0.15"),
];

/// Declared outcome of one matrix case.
struct Expect {
    status: u16,
    /// Expected `Location`, reduced to path + query when absolute.
    location: Option<&'static str>,
    /// Expected body; `None` = not compared (a redirect body is not
    /// shared semantics).
    body: Option<&'static str>,
}

struct Case {
    id: &'static str,
    why: &'static str,
    request_line: &'static str,
    host: &'static str,
    headers: &'static [(&'static str, &'static str)],
    expect: Expect,
}

/// The matrix: same deployment, same requests, same answers on every
/// implementation — no exclusions.
const CASES: &[Case] = &[
    Case {
        id: "m1-root",
        why: "storefront vhost reaches the web pool",
        request_line: "GET / HTTP/1.1",
        host: "shop.example.com",
        headers: &[],
        expect: Expect {
            status: 200,
            location: None,
            body: Some("web /"),
        },
    },
    Case {
        id: "m2-canary-cookie",
        why: "canary-by-cookie marks the storefront canary",
        request_line: "GET /api/x HTTP/1.1",
        host: "shop.example.com",
        headers: &[("Cookie", "canary=on")],
        expect: Expect {
            status: 200,
            location: None,
            body: Some("canary /api/x"),
        },
    },
    Case {
        id: "m3-canary-header",
        why: "canary-by-header marks the storefront canary",
        request_line: "GET / HTTP/1.1",
        host: "shop.example.com",
        headers: &[("X-Canary", "on")],
        expect: Expect {
            status: 200,
            location: None,
            body: Some("canary /"),
        },
    },
    Case {
        id: "m4-api-post",
        why: "API vhost reaches the api pool",
        request_line: "POST /api/x HTTP/1.1",
        host: "api.example.com",
        headers: &[],
        expect: Expect {
            status: 200,
            location: None,
            body: Some("api /api/x"),
        },
    },
    Case {
        id: "m5-admin-post",
        why: "method-scoped routing sends POST /admin to the admin pool",
        request_line: "POST /admin/x HTTP/1.1",
        host: "shop.example.com",
        headers: &[],
        expect: Expect {
            status: 200,
            location: None,
            body: Some("admin /admin/x"),
        },
    },
    Case {
        id: "m6-admin-get",
        why: "a non-POST /admin request stays on the storefront pool",
        request_line: "GET /admin/x HTTP/1.1",
        host: "shop.example.com",
        headers: &[],
        expect: Expect {
            status: 200,
            location: None,
            body: Some("web /admin/x"),
        },
    },
    Case {
        id: "m7-reports",
        why: "the /reports prefix reaches the api pool on the shop vhost",
        request_line: "GET /reports/x HTTP/1.1",
        host: "shop.example.com",
        headers: &[],
        expect: Expect {
            status: 200,
            location: None,
            body: Some("api /reports/x"),
        },
    },
    Case {
        id: "m8-rewrite",
        why: "rewrite-target /api/v1/<rest> -> /api/<rest>",
        request_line: "GET /api/v1/users HTTP/1.1",
        host: "api.example.com",
        headers: &[],
        expect: Expect {
            status: 200,
            location: None,
            body: Some("api /api/users"),
        },
    },
    Case {
        id: "m9-json",
        why: "regex routing of *.json under /api/",
        request_line: "GET /api/a.json HTTP/1.1",
        host: "api.example.com",
        headers: &[],
        expect: Expect {
            status: 200,
            location: None,
            body: Some("api /api/a.json"),
        },
    },
    Case {
        id: "m10-redirect",
        why: "the legacy path redirects to /blog",
        request_line: "GET /old/blog HTTP/1.1",
        host: "shop.example.com",
        headers: &[],
        expect: Expect {
            status: 301,
            location: Some("/blog"),
            body: None,
        },
    },
    Case {
        id: "m11-healthz",
        why: "the health answer is local (no backend contacted)",
        request_line: "GET /healthz HTTP/1.1",
        host: "shop.example.com",
        headers: &[],
        expect: Expect {
            status: 200,
            location: None,
            body: Some("ok"),
        },
    },
    Case {
        id: "m12-default-host",
        why: "an unknown host reaches the default backend",
        request_line: "GET /x HTTP/1.1",
        host: "other.example.com",
        headers: &[],
        expect: Expect {
            status: 200,
            location: None,
            body: Some("fallback /x"),
        },
    },
    Case {
        id: "m13-api-fallback",
        why: "the api vhost falls back for unmatched paths",
        request_line: "GET /x HTTP/1.1",
        host: "api.example.com",
        headers: &[],
        expect: Expect {
            status: 200,
            location: None,
            body: Some("fallback /x"),
        },
    },
];

// --- docker orchestration -------------------------------------------------

fn docker(args: &[&str]) -> String {
    let out = Command::new("docker")
        .args(args)
        .output()
        .expect("run docker (is Docker running?)");
    assert!(
        out.status.success(),
        "docker {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Cleanup helper: never panics.
fn docker_quiet(args: &[&str]) {
    let _ = Command::new("docker").args(args).output();
}

/// Owns the docker network and containers; Drop removes them even when
/// the test panics mid-assertion.
struct Scope {
    network: String,
    containers: Vec<String>,
}

impl Scope {
    fn new() -> Self {
        let network = format!("eqmig-{}", std::process::id());
        docker(&["network", "create", "--subnet", "172.24.0.0/24", &network]);
        Scope {
            network,
            containers: Vec::new(),
        }
    }

    /// `before` are docker run flags (network, mounts, entrypoint
    /// override); `after` are command arguments placed after the image.
    fn run(&mut self, name: &str, image: &str, before: &[&str], after: &[&str]) {
        let mut args = vec![
            "run".to_owned(),
            "-d".to_owned(),
            "--name".to_owned(),
            name.to_owned(),
            "--network".to_owned(),
            self.network.clone(),
        ];
        args.extend(before.iter().map(|a| (*a).to_owned()));
        args.push(image.to_owned());
        args.extend(after.iter().map(|a| (*a).to_owned()));
        let out = Command::new("docker")
            .args(&args)
            .output()
            .expect("run docker");
        assert!(
            out.status.success(),
            "docker {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        self.containers.push(name.to_owned());
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        for name in &self.containers {
            docker_quiet(&["rm", "-f", name]);
        }
        docker_quiet(&["network", "rm", &self.network]);
    }
}

fn published_port(name: &str, inner: u16) -> u16 {
    for _ in 0..50 {
        let out = docker(&["port", name, &format!("{inner}/tcp")]);
        if let Some(port) = out.lines().next().and_then(|l| l.rsplit(':').next())
            && let Ok(p) = port.trim().parse()
        {
            return p;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("no published host port for {name}:{inner}");
}

fn wait_tcp(addr: &str, label: &str, logs: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("{label} never accepted TCP on {addr}\n--- diagnostics ---\n{logs}");
}

fn container_logs(name: &str) -> String {
    docker(&["logs", "--tail", "30", name])
}

/// Keeps the EQProxy child from leaking when the test panics.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let pid = self.0.id();
        let _ = Command::new("kill")
            .args(["-INT", &pid.to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if matches!(self.0.try_wait(), Ok(Some(_))) {
                return;
            }
            if Instant::now() >= deadline {
                let _ = self.0.kill();
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

// --- requests and normalization ------------------------------------------

fn raw_request(case: &Case) -> String {
    let mut out = format!("{}\r\nHost: {}\r\n", case.request_line, case.host);
    for (name, value) in case.headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("Connection: close\r\n\r\n");
    out
}

fn http_request(addr: &str, raw: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect to implementation");
    stream.write_all(raw.as_bytes()).expect("write request");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).into_owned()
}

struct Normalized {
    status: u16,
    location: Option<String>,
    body: String,
}

fn normalize(response: &str) -> Normalized {
    let status = response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let (head, body) = response.split_once("\r\n\r\n").unwrap_or((response, ""));
    let location = head
        .lines()
        .skip(1)
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name.trim().eq_ignore_ascii_case("location")).then(|| reduce_location(value.trim()))
        })
        .next();
    Normalized {
        status,
        location,
        body: body.to_owned(),
    }
}

/// Absolute `Location`s are reduced to path + query: the scheme and
/// authority legitimately differ per deployment, the redirect target is
/// the shared semantics.
fn reduce_location(value: &str) -> String {
    let rest = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"));
    match rest {
        Some(rest) => match rest.find('/') {
            Some(i) => rest[i..].to_owned(),
            None => "/".to_owned(),
        },
        None => value.to_owned(),
    }
}

fn summary(got: &Normalized) -> String {
    let mut out = got.status.to_string();
    if let Some(location) = &got.location {
        out.push_str(&format!(" -> {location}"));
    }
    out.push_str(&format!(" {:?}", got.body));
    out
}

fn check(case: &Case, got: &Normalized) -> Result<(), String> {
    if got.status != case.expect.status {
        return Err(format!(
            "status {} != declared {}",
            got.status, case.expect.status
        ));
    }
    if let Some(want) = case.expect.location
        && got.location.as_deref() != Some(want)
    {
        return Err(format!("location {:?} != declared {want:?}", got.location));
    }
    if let Some(want) = case.expect.body
        && got.body != want
    {
        return Err(format!("body {:?} != declared {want:?}", got.body));
    }
    Ok(())
}

// --- evidence helpers -----------------------------------------------------

fn sha256(path: &str) -> String {
    if let Ok(out) = Command::new("shasum").args(["-a", "256", path]).output()
        && out.status.success()
    {
        return String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .next()
            .unwrap_or("unavailable")
            .to_owned();
    }
    if let Ok(out) = Command::new("sha256sum").arg(path).output()
        && out.status.success()
    {
        return String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .next()
            .unwrap_or("unavailable")
            .to_owned();
    }
    "unavailable".to_owned()
}

fn image_id(tag: &str) -> String {
    docker(&["image", "inspect", "--format", "{{.Id}}", tag])
        .trim()
        .to_owned()
}

/// The matrix backend: echoes `<pool> <request_uri>`, so the serving pool and
/// any path rewrite are both observable in the body.
fn backend_conf(id: &str) -> String {
    format!(
        "server {{\n    listen 80;\n    server_name _;\n    location / {{\n        return 200 \"{id} $request_uri\";\n    }}\n}}\n"
    )
}

// --- the gate -------------------------------------------------------------

#[cfg_attr(
    miri,
    ignore = "needs processes, TCP sockets and Docker: miri does not support them (rust-lang/miri#3449)"
)]
#[ignore = "migration matrix: needs Docker + reference images; run: cargo test -p eqproxy-cli --test migration -- --ignored --nocapture"]
#[test]
fn migration_matrix_same_routing_as_the_originals() {
    let docs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../docs/migration");
    let work = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("migration-{}", std::process::id()));
    std::fs::create_dir_all(&work).expect("create work dir");

    // The artifacts under test are the checked-in ones: fail loudly if a
    // source config or the translation is missing.
    let mut sources = Vec::new();
    for name in [
        "haproxy.cfg",
        "nginx.conf",
        "envoy.yaml",
        "ingress.yaml",
        "ingress-nginx-generated.conf",
        "eqproxy.toml",
    ] {
        let path = docs.join(name);
        let contents = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert!(!contents.trim().is_empty(), "{} is empty", path.display());
        sources.push(path);
    }

    let mut scope = Scope::new();

    // Backends on fixed container IPs + published host ports (the native
    // EQProxy reaches them through 127.0.0.1).
    let mut host_ports: Vec<(&str, u16)> = Vec::new();
    for (id, ip) in POOLS {
        let conf = work.join(format!("backend-{id}.conf"));
        std::fs::write(&conf, backend_conf(id)).expect("write backend conf");
        let name = format!("eqmig-be-{id}-{}", std::process::id());
        scope.run(
            &name,
            BACKEND_IMAGE,
            &[
                "--ip",
                ip,
                "-p",
                "127.0.0.1::80",
                "-v",
                &format!("{}:/etc/nginx/conf.d/default.conf:ro", conf.display()),
            ],
            &[],
        );
        let port = published_port(&name, 80);
        wait_tcp(
            &format!("127.0.0.1:{port}"),
            &format!("backend {id}"),
            &container_logs(&name),
        );
        host_ports.push((id, port));
    }
    let port_of = |pool: &str| {
        host_ports
            .iter()
            .find(|(id, _)| *id == pool)
            .map(|(_, port)| *port)
            .unwrap_or_else(|| panic!("no published port for {pool}"))
    };

    // The four originals, each with its own checked-in source config.
    let hap_name = format!("eqmig-hap-{}", std::process::id());
    scope.run(
        &hap_name,
        HAPROXY_IMAGE,
        &[
            "--ip",
            "172.24.0.21",
            "-p",
            "127.0.0.1::8080",
            "-v",
            &format!(
                "{}:/usr/local/etc/haproxy/haproxy.cfg:ro",
                docs.join("haproxy.cfg").display()
            ),
        ],
        &[],
    );
    let nginx_name = format!("eqmig-nginx-{}", std::process::id());
    scope.run(
        &nginx_name,
        NGINX_IMAGE,
        &[
            "--ip",
            "172.24.0.22",
            "-p",
            "127.0.0.1::8080",
            "-v",
            &format!(
                "{}:/etc/nginx/nginx.conf:ro",
                docs.join("nginx.conf").display()
            ),
        ],
        &[],
    );
    let ing_name = format!("eqmig-ing-{}", std::process::id());
    let ing_mount = format!(
        "{}:/tmp/migration.conf:ro",
        docs.join("ingress-nginx-generated.conf").display()
    );
    scope.run(
        &ing_name,
        INGRESS_NGINX_IMAGE,
        &[
            "--ip",
            "172.24.0.23",
            "-p",
            "127.0.0.1::8080",
            "-v",
            &ing_mount,
            "--entrypoint",
            "nginx",
        ],
        &["-c", "/tmp/migration.conf", "-g", "daemon off;"],
    );
    let env_name = format!("eqmig-env-{}", std::process::id());
    scope.run(
        &env_name,
        ENVOY_IMAGE,
        &[
            "--ip",
            "172.24.0.24",
            "-p",
            "127.0.0.1::8080",
            "-v",
            &format!(
                "{}:/etc/envoy/envoy.yaml:ro",
                docs.join("envoy.yaml").display()
            ),
        ],
        &[],
    );

    let hap_port = published_port(&hap_name, 8080);
    let nginx_port = published_port(&nginx_name, 8080);
    let ing_port = published_port(&ing_name, 8080);
    let env_port = published_port(&env_name, 8080);
    wait_tcp(
        &format!("127.0.0.1:{hap_port}"),
        "haproxy",
        &container_logs(&hap_name),
    );
    wait_tcp(
        &format!("127.0.0.1:{nginx_port}"),
        "nginx",
        &container_logs(&nginx_name),
    );
    wait_tcp(
        &format!("127.0.0.1:{ing_port}"),
        "ingress-nginx",
        &container_logs(&ing_name),
    );
    wait_tcp(
        &format!("127.0.0.1:{env_port}"),
        "envoy",
        &container_logs(&env_name),
    );

    // EQProxy: the translation under test, with the two declared
    // substitutions (free local listen, pools through published ports).
    let translation = docs.join("eqproxy.toml");
    let source = std::fs::read_to_string(&translation).expect("read translation");
    let mut rendered = source.replace("listen = \"0.0.0.0:8080\"", "listen = \"127.0.0.1:0\"");
    for (pool, _ip) in POOLS {
        let from = format!("server = \"{}:80\"", pool_addr(pool));
        let to = format!("server = \"127.0.0.1:{}\"", port_of(pool));
        assert!(rendered.contains(&from), "translation lost {from}");
        rendered = rendered.replace(&from, &to);
    }
    assert!(
        !rendered.contains("172.24."),
        "rendered translation still points at container addresses"
    );
    let eq_config = work.join("eqproxy.toml");
    std::fs::write(&eq_config, &rendered).expect("write rendered translation");

    // The config gate first: the translation must be valid on its own.
    let eq_bin = env!("CARGO_BIN_EXE_eqproxy");
    let validate = Command::new(eq_bin)
        .args(["config", "validate", "--config"])
        .arg(&eq_config)
        .output()
        .expect("run config validate");
    assert!(
        validate.status.success(),
        "config validate rejected the translation:\n{}{}",
        String::from_utf8_lossy(&validate.stdout),
        String::from_utf8_lossy(&validate.stderr)
    );

    let child = Command::new(eq_bin)
        .args(["run", "--config"])
        .arg(&eq_config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run");
    let mut guard = ChildGuard(child);
    let mut stderr = BufReader::new(guard.0.stderr.take().expect("eqproxy stderr piped"));
    let mut eq_addr = String::new();
    let mut seen = String::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        let read = stderr.read_line(&mut line).expect("read eqproxy stderr");
        assert!(
            read > 0,
            "eqproxy closed stderr without announcing its listener\n--- eqproxy stderr ---\n{seen}"
        );
        seen.push_str(&line);
        if let Some(addr) = line.split("listening on ").nth(1)
            && line.contains("listener web listening on")
        {
            eq_addr = addr.trim().to_owned();
            break;
        }
    }
    assert!(
        !eq_addr.is_empty(),
        "eqproxy did not announce listener web\n--- eqproxy stderr ---\n{seen}"
    );

    // --- run the matrix against every implementation --------------------
    let implementations: [(&str, String); 5] = [
        ("eqproxy", eq_addr.clone()),
        ("haproxy", format!("127.0.0.1:{hap_port}")),
        ("nginx", format!("127.0.0.1:{nginx_port}")),
        ("ingress-nginx", format!("127.0.0.1:{ing_port}")),
        ("envoy", format!("127.0.0.1:{env_port}")),
    ];

    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    let mut agreed = 0usize;
    for case in CASES {
        let raw = raw_request(case);
        let mut row = vec![case.id.to_owned(), case.why.to_owned()];
        let mut case_ok = true;
        for (impl_name, addr) in &implementations {
            let got = normalize(&http_request(addr, &raw));
            match check(case, &got) {
                Ok(()) => row.push(format!("OK {}", summary(&got))),
                Err(why) => {
                    row.push(format!("DIVERGED {}", summary(&got)));
                    case_ok = false;
                    failures.push(format!(
                        "{} @ {impl_name}: {why} (got {})",
                        case.id,
                        summary(&got)
                    ));
                }
            }
        }
        if case_ok {
            agreed += 1;
        }
        rows.push(row);
    }

    // --- report ---------------------------------------------------------
    let mut report = String::new();
    report.push_str("# Migration report — real source configs vs the EQProxy translation\n\n");
    report.push_str(&format!(
        "- date (UTC epoch): {}\n",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs()
    ));
    report.push_str(&format!(
        "- eqproxy binary: {eq_bin} (sha256 {})\n",
        sha256(eq_bin)
    ));
    for path in &sources {
        report.push_str(&format!(
            "- {} (sha256 {})\n",
            path.display(),
            sha256(&path.display().to_string())
        ));
    }
    report.push_str(&format!(
        "- haproxy: {HAPROXY_IMAGE} ({})\n",
        image_id(HAPROXY_IMAGE)
    ));
    report.push_str(&format!(
        "- nginx: {NGINX_IMAGE} ({})\n",
        image_id(NGINX_IMAGE)
    ));
    report.push_str(&format!(
        "- ingress-nginx data plane: {INGRESS_NGINX_IMAGE} ({})\n",
        image_id(INGRESS_NGINX_IMAGE)
    ));
    report.push_str(&format!(
        "- envoy: {ENVOY_IMAGE} ({})\n",
        image_id(ENVOY_IMAGE)
    ));
    report.push_str(&format!(
        "- backends: {BACKEND_IMAGE} ({})\n",
        image_id(BACKEND_IMAGE)
    ));
    report.push_str(
        "- substitutions on the EQProxy translation (declared): free local listen\n  address, and the five pools reached through their published host ports\n  instead of the fixed container addresses.\n\n",
    );
    report.push_str("| case | semantics | eqproxy | haproxy | nginx | ingress-nginx | envoy |\n");
    report.push_str("|---|---|---|---|---|---|---|\n");
    for row in &rows {
        report.push_str(&format!("| {} |\n", row.join(" | ")));
    }
    report.push_str(&format!(
        "\nverdict: {agreed}/{} cases route identically across the five implementations ({} checks).\n",
        CASES.len(),
        CASES.len() * implementations.len()
    ));

    let report_path = work.join("migration-report.md");
    std::fs::write(&report_path, &report).expect("write report");
    println!("{report}");
    println!("report written to {}", report_path.display());

    assert!(
        failures.is_empty(),
        "{} of {} matrix checks diverged:\n{}\nreport: {}",
        failures.len(),
        CASES.len() * implementations.len(),
        failures.join("\n"),
        report_path.display()
    );
}

/// The container address the checked-in translation uses for a pool.
fn pool_addr(pool: &str) -> &'static str {
    POOLS
        .iter()
        .find(|(id, _)| *id == pool)
        .map(|(_, ip)| *ip)
        .unwrap_or_else(|| panic!("unknown pool {pool}"))
}
