//! Differential harness (v0.6 acceptance gate): one **declared corpus**
//! of shared-semantics cases ([docs/differential-corpus.md](../../../docs/differential-corpus.md))
//! runs unchanged against EQProxy (the built binary) and the reference
//! implementations — HAProxy 3.4.6, the ingress-nginx data plane (the
//! `nginx` binary shipped inside the official controller image, driven
//! by a static config, like «Envoy estático») and Envoy v1.34.2 with a
//! static bootstrap. Every normalized observable result (status,
//! `Location`, body) must match the case's declared outcome, so the
//! four implementations must agree on the shared semantics.
//!
//! Normalization (declared in the corpus doc): the reason phrase is
//! ignored; `Location` is reduced to path + query when absolute; the
//! body is compared only when the case declares one (3xx bodies differ
//! legitimately per implementation).
//!
//! Run (needs Docker; images are pulled on first use):
//!     cargo test -p eqproxy-cli --test differential -- --ignored --nocapture
//!
//! The report is written to `$CARGO_TARGET_TMPDIR/differential-report.md`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const HAPROXY_IMAGE: &str = "haproxy:3.4.6";
const INGRESS_NGINX_IMAGE: &str = "registry.k8s.io/ingress-nginx/controller:v1.13.0";
const ENVOY_IMAGE: &str = "envoyproxy/envoy:v1.34.2";
const BACKEND_IMAGE: &str = "nginx:alpine";

/// Declared outcome of one case (the shared semantics).
struct Outcome {
    status: u16,
    /// Expected `Location`, reduced to path + query.
    location: Option<&'static str>,
    /// Expected body; `None` = not compared (documented per case).
    body: Option<&'static str>,
}

struct Case {
    id: &'static str,
    why: &'static str,
    /// Raw request head (sent verbatim).
    request: &'static str,
    expect: Outcome,
    /// (implementation, reason) for cases whose semantics are NOT shared
    /// with that reference; recorded in the report, never asserted there.
    skip: &'static [(&'static str, &'static str)],
}

/// The corpus: path namespaces are disjoint, so one config per
/// implementation covers every case and first-match ordering is real.
const CASES: &[Case] = &[
    Case {
        id: "c1-prefix",
        why: "path_prefix routes the request to its backend",
        request: "GET /c1/users HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        expect: Outcome {
            status: 200,
            location: None,
            body: Some("api /c1/users"),
        },
        skip: &[],
    },
    Case {
        id: "c1-boundary",
        why: "a literal prefix boundary: /c1/ must not swallow /c10",
        request: "GET /c10/users HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        expect: Outcome {
            status: 200,
            location: None,
            body: Some("fallback /c10/users"),
        },
        skip: &[],
    },
    Case {
        id: "c2-host",
        why: "host match is case-insensitive",
        request: "GET /c2/x HTTP/1.1\r\nHost: Special.Example.com\r\nConnection: close\r\n\r\n",
        expect: Outcome {
            status: 200,
            location: None,
            body: Some("mgmt /c2/x"),
        },
        skip: &[],
    },
    Case {
        id: "c2-port",
        why: "host match compares without the :port suffix",
        request: "GET /c2/x HTTP/1.1\r\nHost: special.example.com:8443\r\nConnection: close\r\n\r\n",
        expect: Outcome {
            status: 200,
            location: None,
            body: Some("mgmt /c2/x"),
        },
        skip: &[],
    },
    Case {
        id: "c2-near",
        why: "a host near miss must not route",
        request: "GET /c2/x HTTP/1.1\r\nHost: other.example.com\r\nConnection: close\r\n\r\n",
        expect: Outcome {
            status: 200,
            location: None,
            body: Some("fallback /c2/x"),
        },
        skip: &[],
    },
    Case {
        id: "c3-method",
        why: "method condition matches",
        request: "POST /c3/x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        expect: Outcome {
            status: 200,
            location: None,
            body: Some("mgmt /c3/x"),
        },
        skip: &[],
    },
    Case {
        id: "c3-near",
        why: "method near miss must not route",
        request: "GET /c3/x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        expect: Outcome {
            status: 200,
            location: None,
            body: Some("fallback /c3/x"),
        },
        skip: &[],
    },
    Case {
        id: "c4-header",
        why: "header exact match routes",
        request: "GET /c4/x HTTP/1.1\r\nHost: x\r\nx-beta: on\r\nConnection: close\r\n\r\n",
        expect: Outcome {
            status: 200,
            location: None,
            body: Some("mgmt /c4/x"),
        },
        skip: &[],
    },
    Case {
        id: "c4-near",
        why: "missing header must not route",
        request: "GET /c4/x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        expect: Outcome {
            status: 200,
            location: None,
            body: Some("fallback /c4/x"),
        },
        skip: &[],
    },
    Case {
        id: "c5-first",
        why: "ordered rules: the first matching rule wins over a later one",
        request: "GET /c5/x HTTP/1.1\r\nHost: x\r\nx-beta: on\r\nConnection: close\r\n\r\n",
        expect: Outcome {
            status: 200,
            location: None,
            body: Some("mgmt /c5/x"),
        },
        skip: &[],
    },
    Case {
        id: "c5-second",
        why: "ordered rules: the later rule catches what the first misses",
        request: "GET /c5/x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        expect: Outcome {
            status: 200,
            location: None,
            body: Some("api /c5/x"),
        },
        skip: &[],
    },
    Case {
        id: "c6-redirect",
        why: "local 3xx with Location (body not compared: per-implementation)",
        request: "GET /c6/old HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        expect: Outcome {
            status: 301,
            location: Some("/c6/new"),
            body: None,
        },
        skip: &[],
    },
    Case {
        id: "c7-direct",
        why: "local direct response (no backend contacted)",
        request: "GET /c7/ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        expect: Outcome {
            status: 200,
            location: None,
            body: Some("pong"),
        },
        skip: &[],
    },
    Case {
        id: "c8-rewrite",
        why: "prefix rewrite: the backend sees the rewritten target",
        request: "GET /c8/v1/users HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        expect: Outcome {
            status: 200,
            location: None,
            body: Some("api /c8/api/users"),
        },
        skip: &[],
    },
    Case {
        id: "c11-regex",
        why: "path regex routes .json paths (spelling per implementation, see corpus doc)",
        request: "GET /c11/data.json HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        expect: Outcome {
            status: 200,
            location: None,
            body: Some("mgmt /c11/data.json"),
        },
        skip: &[],
    },
    Case {
        id: "c11-boundary",
        why: "regex near miss (.jsonx) must not route",
        request: "GET /c11/data.jsonx HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        expect: Outcome {
            status: 200,
            location: None,
            body: Some("fallback /c11/data.jsonx"),
        },
        skip: &[],
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
        let network = format!("eqdiff-{}", std::process::id());
        docker(&["network", "create", "--subnet", "172.23.0.0/24", &network]);
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
    let deadline = Instant::now() + Duration::from_secs(20);
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

// --- requests and normalization ------------------------------------------

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
    let location = head.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("location")
            .then(|| reduce_location(value.trim()))
    });
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

// --- generated configs (one per implementation) ---------------------------

/// Backends answer `<id> <request_uri>` so the received target — and
/// therefore any rewrite — is observable in the body.
fn backend_conf(id: &str) -> String {
    format!(
        "server {{\n    listen 80;\n    server_name _;\n    location / {{\n        return 200 \"{id} $request_uri\";\n    }}\n}}\n"
    )
}

/// HAProxy 3.4.6. `http-request` rules always run before `use_backend`
/// rules, so the c8 rewrite lands before the c8 routing decision.
fn haproxy_cfg() -> String {
    r#"global
    maxconn 256
defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s
frontend fe
    bind :8080
    http-request redirect code 301 location /c6/new if { path /c6/old }
    http-request return status 200 content-type "text/plain" string "pong" if { path /c7/ping }
    http-request set-path %[path,regsub(^/c8/v1/,/c8/api/)] if { path_beg /c8/v1/ }
    use_backend api if { path_beg /c1/ }
    use_backend mgmt if { path_beg /c2/ } { req.hdr(host),lower,field(1,:) -m str special.example.com }
    use_backend mgmt if { path_beg /c3/ } { method POST }
    use_backend mgmt if { path_beg /c4/ } { req.hdr(x-beta) -m str on }
    use_backend mgmt if { path_beg /c5/ } { req.hdr(x-beta) -m str on }
    use_backend api if { path_beg /c5/ }
    use_backend api if { path_beg /c8/api/ }
    use_backend mgmt if { path_beg /c11/ } { path -m reg \.json$ }
    default_backend fallback
backend api
    server s1 172.23.0.11:80
backend mgmt
    server s1 172.23.0.12:80
backend fallback
    server s1 172.23.0.13:80
"#
    .to_owned()
}

/// Envoy v1.34 static bootstrap. `strip_any_host_port` declares the
/// port-free host comparison shared with the other implementations.
fn envoy_yaml() -> String {
    r#"admin:
  access_log_path: /dev/null
  address:
    socket_address: { address: 127.0.0.1, port_value: 9901 }
static_resources:
  listeners:
    - name: main
      address:
        socket_address: { address: 0.0.0.0, port_value: 8080 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: differential
                strip_any_host_port: true
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: differential
                  virtual_hosts:
                    - name: special
                      domains: ["special.example.com"]
                      routes:
                        - match: { prefix: "/c2/" }
                          route: { cluster: mgmt }
                        - match: { prefix: "/" }
                          route: { cluster: fallback }
                    - name: default
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/c1/" }
                          route: { cluster: api }
                        - match: { prefix: "/c3/", headers: [{ name: ":method", exact_match: "POST" }] }
                          route: { cluster: mgmt }
                        - match: { prefix: "/c4/", headers: [{ name: "x-beta", exact_match: "on" }] }
                          route: { cluster: mgmt }
                        - match: { prefix: "/c5/", headers: [{ name: "x-beta", exact_match: "on" }] }
                          route: { cluster: mgmt }
                        - match: { prefix: "/c5/" }
                          route: { cluster: api }
                        - match: { path: "/c6/old" }
                          redirect: { path_redirect: "/c6/new" }
                        - match: { path: "/c7/ping" }
                          direct_response: { status: 200, body: { inline_string: "pong" } }
                        - match: { prefix: "/c8/v1/" }
                          route: { cluster: api, prefix_rewrite: "/c8/api/" }
                        - match: { safe_regex: { google_re2: {}, regex: "/c11/.*\\.json$" } }
                          route: { cluster: mgmt }
                        - match: { prefix: "/" }
                          route: { cluster: fallback }
  clusters:
    - name: api
      connect_timeout: 5s
      type: STATIC
      load_assignment:
        cluster_name: api
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: 172.23.0.11, port_value: 80 }
    - name: mgmt
      connect_timeout: 5s
      type: STATIC
      load_assignment:
        cluster_name: mgmt
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: 172.23.0.12, port_value: 80 }
    - name: fallback
      connect_timeout: 5s
      type: STATIC
      load_assignment:
        cluster_name: fallback
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: 172.23.0.13, port_value: 80 }
"#
    .to_owned()
}

/// ingress-nginx data plane: the `nginx` binary from the official
/// controller image (nginx/1.27.x), driven by a static config in the
/// shapes the controller generates for these features. The controller
/// (k8s object → config translation) is NOT exercised; see the corpus doc.
fn ingress_nginx_conf() -> String {
    r#"worker_processes 1;
error_log /dev/stderr warn;
pid /tmp/diff-nginx.pid;
events { worker_connections 128; }
http {
    client_body_temp_path /tmp/diff-client-body;
    proxy_temp_path /tmp/diff-proxy-temp;
    access_log off;
    map $request_method $c3_backend {
        "POST"  172.23.0.12:80;
        default 172.23.0.13:80;
    }
    map $http_x_beta $c4_backend {
        "on"    172.23.0.12:80;
        default 172.23.0.13:80;
    }
    map $http_x_beta $c5_backend {
        "on"    172.23.0.12:80;
        default 172.23.0.11:80;
    }
    server {
        listen 8080;
        server_name special.example.com;
        location /c2/ { proxy_pass http://172.23.0.12:80; }
        location / { proxy_pass http://172.23.0.13:80; }
    }
    server {
        listen 8080 default_server;
        server_name _;
        location /c1/ { proxy_pass http://172.23.0.11:80; }
        location /c3/ { proxy_pass http://$c3_backend; }
        location /c4/ { proxy_pass http://$c4_backend; }
        location /c5/ { proxy_pass http://$c5_backend; }
        location = /c6/old { return 301 /c6/new; }
        location = /c7/ping { return 200 "pong"; }
        location /c8/v1/ { rewrite ^/c8/v1/(.*)$ /c8/api/$1 break; proxy_pass http://172.23.0.11:80; }
        location ~* ^/c11/.*\.json$ { proxy_pass http://172.23.0.12:80; }
        location / { proxy_pass http://172.23.0.13:80; }
    }
}
"#
    .to_owned()
}

/// EQProxy: the same corpus as typed routing rules (the format under
/// test), backends on the published host ports of the backend containers.
fn eqproxy_toml(api: u16, mgmt: u16, fallback: u16) -> String {
    format!(
        r#"schema_version = 1
[listener.web]
listen = "127.0.0.1:0"
mode = "http"
backend = "fallback"

[[listener.web.rules]]
name = "c1"
path_prefix = "/c1/"
use_backend = "api"

[[listener.web.rules]]
name = "c2"
path_prefix = "/c2/"
host = "special.example.com"
use_backend = "mgmt"

[[listener.web.rules]]
name = "c3"
path_prefix = "/c3/"
methods = ["POST"]
use_backend = "mgmt"

[[listener.web.rules]]
name = "c4"
path_prefix = "/c4/"
headers = [{{ name = "x-beta", exact = "on" }}]
use_backend = "mgmt"

[[listener.web.rules]]
name = "c5a"
path_prefix = "/c5/"
headers = [{{ name = "x-beta", exact = "on" }}]
use_backend = "mgmt"

[[listener.web.rules]]
name = "c5b"
path_prefix = "/c5/"
use_backend = "api"

[[listener.web.rules]]
name = "c6"
path = "/c6/old"
[listener.web.rules.redirect]
status = 301
location = "/c6/new"

[[listener.web.rules]]
name = "c7"
path = "/c7/ping"
[listener.web.rules.direct_response]
status = 200
body = "pong"

[[listener.web.rules]]
name = "c8"
path_prefix = "/c8/v1/"
use_backend = "api"
[listener.web.rules.rewrite]
path_prefix_rewrite = "/c8/api/"

[[listener.web.rules]]
name = "c11"
path_regex = "^/c11/.*\\.json$"
use_backend = "mgmt"

[backend.api]
server = "127.0.0.1:{api}"
[backend.mgmt]
server = "127.0.0.1:{mgmt}"
[backend.fallback]
server = "127.0.0.1:{fallback}"
"#
    )
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

// --- the harness ----------------------------------------------------------

#[cfg_attr(
    miri,
    ignore = "needs processes, TCP sockets and Docker: miri does not support them (rust-lang/miri#3449)"
)]
#[ignore = "differential harness: needs Docker + reference images; run: cargo test -p eqproxy-cli --test differential -- --ignored --nocapture"]
#[test]
fn differential_shared_semantics_corpus() {
    let work = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("differential-{}", std::process::id()));
    std::fs::create_dir_all(&work).expect("create work dir");
    let write = |name: &str, contents: &str| {
        let path = work.join(name);
        std::fs::write(&path, contents).expect("write config");
        path
    };

    // Configs, written once (the corpus doc references these shapes).
    let backend_confs: Vec<_> = ["api", "mgmt", "fallback"]
        .iter()
        .map(|id| write(&format!("{id}.conf"), &backend_conf(id)))
        .collect();
    let haproxy_cfg = write("haproxy.cfg", &haproxy_cfg());
    let envoy_yaml = write("envoy.yaml", &envoy_yaml());
    let nginx_conf = write("ingress-nginx.conf", &ingress_nginx_conf());

    let mut scope = Scope::new();

    // Backends on fixed container IPs (references) + published host
    // ports (native EQProxy reaches them through 127.0.0.1).
    let mut backend_host_ports = Vec::new();
    for (id, ip, conf) in [
        ("api", "172.23.0.11", &backend_confs[0]),
        ("mgmt", "172.23.0.12", &backend_confs[1]),
        ("fallback", "172.23.0.13", &backend_confs[2]),
    ] {
        let name = format!("eqdiff-{id}-{}", std::process::id());
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
        backend_host_ports.push(port);
    }

    // Reference implementations. The ingress-nginx container overrides
    // the entrypoint (static config, like «Envoy estático»), so its nginx
    // arguments come after the image name.
    let hap_name = format!("eqdiff-hap-{}", std::process::id());
    scope.run(
        &hap_name,
        HAPROXY_IMAGE,
        &[
            "--ip",
            "172.23.0.21",
            "-p",
            "127.0.0.1::8080",
            "-v",
            &format!(
                "{}:/usr/local/etc/haproxy/haproxy.cfg:ro",
                haproxy_cfg.display()
            ),
        ],
        &[],
    );
    let env_name = format!("eqdiff-env-{}", std::process::id());
    scope.run(
        &env_name,
        ENVOY_IMAGE,
        &[
            "--ip",
            "172.23.0.22",
            "-p",
            "127.0.0.1::8080",
            "-v",
            &format!("{}:/etc/envoy/envoy.yaml:ro", envoy_yaml.display()),
        ],
        &[],
    );
    let ing_name = format!("eqdiff-ing-{}", std::process::id());
    let ing_mount = format!("{}:/tmp/diff.conf:ro", nginx_conf.display());
    scope.run(
        &ing_name,
        INGRESS_NGINX_IMAGE,
        &[
            "--ip",
            "172.23.0.23",
            "-p",
            "127.0.0.1::8080",
            "-v",
            &ing_mount,
            "--entrypoint",
            "nginx",
        ],
        &["-c", "/tmp/diff.conf", "-g", "daemon off;"],
    );

    let hap_port = published_port(&hap_name, 8080);
    let env_port = published_port(&env_name, 8080);
    let ing_port = published_port(&ing_name, 8080);
    wait_tcp(
        &format!("127.0.0.1:{hap_port}"),
        "haproxy",
        &container_logs(&hap_name),
    );
    wait_tcp(
        &format!("127.0.0.1:{env_port}"),
        "envoy",
        &container_logs(&env_name),
    );
    wait_tcp(
        &format!("127.0.0.1:{ing_port}"),
        "ingress-nginx",
        &container_logs(&ing_name),
    );

    // EQProxy: the freshly built binary, natively.
    let eq_config = write(
        "eqproxy.toml",
        &eqproxy_toml(
            backend_host_ports[0],
            backend_host_ports[1],
            backend_host_ports[2],
        ),
    );
    let eq_bin = env!("CARGO_BIN_EXE_eqproxy");
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
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        let read = stderr.read_line(&mut line).expect("read eqproxy stderr");
        assert!(
            read > 0,
            "eqproxy closed stderr without announcing bind\n--- eqproxy stderr ---\n{seen}"
        );
        seen.push_str(&line);
        if let Some(addr) = line.split("listening on ").nth(1) {
            eq_addr = addr.trim().to_owned();
            break;
        }
    }
    assert!(
        !eq_addr.is_empty(),
        "eqproxy did not announce its address\n--- eqproxy stderr ---\n{seen}"
    );

    // --- run the corpus against every implementation --------------------
    let hap_addr = format!("127.0.0.1:{hap_port}");
    let ing_addr = format!("127.0.0.1:{ing_port}");
    let env_addr = format!("127.0.0.1:{env_port}");
    let addrs: [(&str, &str); 4] = [
        ("eqproxy", eq_addr.as_str()),
        ("haproxy", hap_addr.as_str()),
        ("ingress-nginx", ing_addr.as_str()),
        ("envoy", env_addr.as_str()),
    ];

    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    let mut agreed = 0usize;
    for case in CASES {
        let mut row = vec![case.id.to_owned(), case.why.to_owned()];
        let mut case_ok = true;
        for (impl_name, addr) in addrs {
            if let Some((_, reason)) = case.skip.iter().find(|(i, _)| *i == impl_name) {
                row.push(format!("SKIP: {reason}"));
                continue;
            }
            let got = normalize(&http_request(addr, case.request));
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
    report.push_str("# Differential report — shared-semantics corpus (v0.6 gate)\n\n");
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
    report.push_str(&format!(
        "- haproxy: {HAPROXY_IMAGE} ({})\n",
        image_id(HAPROXY_IMAGE)
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
        "- normalization: status code only (reason phrase ignored); `Location` reduced to\n  path + query when absolute; body compared only when the case declares one.\n\n",
    );
    report.push_str("| case | shared semantics | eqproxy | haproxy | ingress-nginx | envoy |\n");
    report.push_str("|---|---|---|---|---|---|\n");
    for row in &rows {
        report.push_str(&format!("| {} |\n", row.join(" | ")));
    }
    report.push_str(&format!(
        "\nverdict: {agreed}/{} cases agree across their applicable implementations.\n",
        CASES.len()
    ));
    if !failures.is_empty() {
        report.push_str("\n## Divergences\n\n");
        for failure in &failures {
            report.push_str(&format!("- {failure}\n"));
        }
    }

    let report_path = work.join("differential-report.md");
    std::fs::write(&report_path, &report).expect("write report");
    println!("{report}");
    println!("report written to {}", report_path.display());

    assert!(
        failures.is_empty(),
        "{} of {} cases diverged from the declared corpus:\n{}\nreport: {}",
        failures.len(),
        CASES.len(),
        failures.join("\n"),
        report_path.display()
    );
}
