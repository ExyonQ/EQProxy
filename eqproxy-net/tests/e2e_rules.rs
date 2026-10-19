//! E2E tests of the routing rule engine (v0.6, B-H3/B-H4) with **real
//! sockets**: host/path/method/header/IP matching, first-match order,
//! default-backend fallback and per-exchange selection on keep-alive
//! connections. No network mocks.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use eqproxy_core::rules::{HeaderSpec, Rule, RuleSpec};
use eqproxy_core::{Metrics, shutdown};
use eqproxy_net::{
    BoundProxy, ProxyMode, ResolvedBackend, ResolvedListener, ResolvedRewrite, ResolvedRoute,
    RouteAction, bind,
};

const WAIT: Duration = Duration::from_secs(5);

/// Real HTTP backend that identifies itself with a fixed body.
async fn start_identity_backend(id: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind identity backend");
    let addr = listener.local_addr().expect("addr identity backend");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    // Reads the full head (the tests never send bodies).
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
                    let close = buf[..head_end].windows(7).any(|w| w == b"close\r\n");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                        id.len(),
                        id
                    );
                    if socket.write_all(response.as_bytes()).await.is_err() {
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

fn rule(spec: RuleSpec, name: &str, server: SocketAddr) -> ResolvedRoute {
    ResolvedRoute {
        rule: Rule::compile(&spec).expect("rule compiles"),
        action: RouteAction::Backend {
            backend: Arc::new(ResolvedBackend::single(name, server)),
            rewrite: None,
        },
    }
}

/// Rule with an arbitrary action (v0.6 slice 2: rewrite / redirect /
/// direct_response).
fn rule_action(spec: RuleSpec, action: RouteAction) -> ResolvedRoute {
    ResolvedRoute {
        rule: Rule::compile(&spec).expect("rule compiles"),
        action,
    }
}

fn rewrite_with(
    matched_prefix: &str,
    path_prefix_rewrite: &str,
    host_rewrite: Option<&str>,
) -> Option<ResolvedRewrite> {
    Some(ResolvedRewrite {
        matched_prefix: matched_prefix.to_owned(),
        path_prefix_rewrite: Some(path_prefix_rewrite.to_owned()),
        host_rewrite: host_rewrite.map(str::to_owned),
    })
}

/// Listener with `default` as fallback backend and the given rules.
fn routing_listener(
    listen: SocketAddr,
    default_server: SocketAddr,
    routes: Vec<ResolvedRoute>,
) -> ResolvedListener {
    ResolvedListener::new(
        "web",
        listen,
        "default",
        default_server,
        ProxyMode::Http,
        64,
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .with_routes(routes)
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
        bound
            .serve(signal, Duration::from_secs(2))
            .await
            .expect("serve");
    });
    (addr, handle, serve)
}

fn get(host: &str, path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
}

/// Sends one raw request (head only) and returns the response body.
async fn request_body(proxy: SocketAddr, head: &str) -> String {
    let mut stream = tokio::time::timeout(WAIT, TcpStream::connect(proxy))
        .await
        .expect("connect timeout")
        .expect("connect proxy");
    stream.write_all(head.as_bytes()).await.expect("write head");
    let mut response = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut response))
        .await
        .expect("response timeout")
        .expect("read response");
    String::from_utf8_lossy(&response)
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default()
}

/// Dimension-by-dimension routing: path prefix, host, method, header and
/// source IP each land on their backend; everything else falls back to
/// the default backend.
#[tokio::test]
async fn rules_route_by_path_host_method_header_and_ip() {
    let api = start_identity_backend("api").await;
    let web = start_identity_backend("web").await;
    let ops = start_identity_backend("ops").await;
    let trusted = start_identity_backend("trusted").await;
    let fallback = start_identity_backend("fallback").await;

    let routes = vec![
        rule(
            RuleSpec {
                name: "api-v1".to_owned(),
                path_prefix: Some("/v1/".to_owned()),
                ..RuleSpec::default()
            },
            "api",
            api,
        ),
        rule(
            RuleSpec {
                name: "web-host".to_owned(),
                host: Some("www.example.com".to_owned()),
                ..RuleSpec::default()
            },
            "web",
            web,
        ),
        rule(
            RuleSpec {
                name: "ops-method".to_owned(),
                methods: vec!["DELETE".to_owned()],
                ..RuleSpec::default()
            },
            "ops",
            ops,
        ),
        rule(
            RuleSpec {
                name: "trusted-ip".to_owned(),
                ip: vec!["127.0.0.0/8".to_owned()],
                headers: vec![HeaderSpec {
                    name: "x-trace".to_owned(),
                    exact: None,
                    regex: None,
                    present: true,
                }],
                ..RuleSpec::default()
            },
            "trusted",
            trusted,
        ),
    ];
    let cfg = routing_listener("127.0.0.1:0".parse().expect("addr"), fallback, routes);
    let metrics = Arc::new(Metrics::default());
    let (proxy, _handle, serve) = start_proxy(cfg, metrics).await;

    // path_prefix -> api
    assert_eq!(
        request_body(proxy, &get("other.example.com", "/v1/users")).await,
        "api"
    );
    // host exact -> web
    assert_eq!(
        request_body(proxy, &get("www.example.com:8080", "/page")).await,
        "web"
    );
    // methods -> ops
    let delete = "DELETE /item/1 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    assert_eq!(request_body(proxy, delete).await, "ops");
    // header present + ip allowlist -> trusted
    let traced = "GET / HTTP/1.1\r\nHost: x\r\nx-trace: 1\r\nConnection: close\r\n\r\n";
    assert_eq!(request_body(proxy, traced).await, "trusted");
    // No rule matches -> default backend.
    assert_eq!(request_body(proxy, &get("x", "/plain")).await, "fallback");

    _handle.trigger();
    serve.await.expect("serve ends");
}

/// Ordered rules, first match wins: an early catch-all shadows a later
/// more specific rule.
#[tokio::test]
async fn first_matching_rule_wins_over_later_ones() {
    let first = start_identity_backend("first").await;
    let second = start_identity_backend("second").await;
    let fallback = start_identity_backend("fallback").await;

    let routes = vec![
        rule(
            RuleSpec {
                name: "catch-all".to_owned(),
                path_prefix: Some("/".to_owned()),
                ..RuleSpec::default()
            },
            "first",
            first,
        ),
        rule(
            RuleSpec {
                name: "specific".to_owned(),
                path: Some("/specific".to_owned()),
                ..RuleSpec::default()
            },
            "second",
            second,
        ),
    ];
    let cfg = routing_listener("127.0.0.1:0".parse().expect("addr"), fallback, routes);
    let metrics = Arc::new(Metrics::default());
    let (proxy, _handle, serve) = start_proxy(cfg, metrics).await;

    assert_eq!(request_body(proxy, &get("x", "/specific")).await, "first");
    assert_eq!(request_body(proxy, &get("x", "/other")).await, "first");

    _handle.trigger();
    serve.await.expect("serve ends");
}

/// Keep-alive connections route per exchange: two requests on the same
/// socket can land on different backends.
#[tokio::test]
async fn keep_alive_routes_each_exchange_independently() {
    let api = start_identity_backend("api").await;
    let fallback = start_identity_backend("fallback").await;

    let routes = vec![rule(
        RuleSpec {
            name: "api-v1".to_owned(),
            path_prefix: Some("/v1/".to_owned()),
            ..RuleSpec::default()
        },
        "api",
        api,
    )];
    let cfg = routing_listener("127.0.0.1:0".parse().expect("addr"), fallback, routes);
    let metrics = Arc::new(Metrics::default());
    let (proxy, _handle, serve) = start_proxy(cfg, metrics).await;

    let mut stream = TcpStream::connect(proxy).await.expect("connect proxy");
    let first = "GET /v1/a HTTP/1.1\r\nHost: x\r\n\r\n";
    let second = "GET /plain HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    // Both requests in a single write: pipelined in one segment, so the
    // second is provably in the proxy's read buffer while the first is
    // parsed (regression: the leftover carry must survive the exchange).
    stream
        .write_all(format!("{first}{second}").as_bytes())
        .await
        .expect("write both");
    let mut response = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut response))
        .await
        .expect("response timeout")
        .expect("read response");
    let text = String::from_utf8_lossy(&response);
    // Both exchanges answered, each by its own backend, on one socket.
    assert!(text.starts_with("HTTP/1.1 200 OK"), "head 1: {text}");
    let bodies: Vec<&str> = text.split("\r\n\r\n").skip(1).collect();
    let joined = bodies.join("|");
    assert!(joined.contains("api"), "api exchange missing: {text}");
    assert!(
        joined.contains("fallback"),
        "fallback exchange missing: {text}"
    );

    _handle.trigger();
    serve.await.expect("serve ends");
}

/// Negative: a rule whose conditions do not hold never routes, even one
/// field away (regex anchored semantics, case sensitivity, literal
/// prefixes).
#[tokio::test]
async fn near_misses_never_route() {
    let api = start_identity_backend("api").await;
    let fallback = start_identity_backend("fallback").await;

    let routes = vec![rule(
        RuleSpec {
            name: "strict".to_owned(),
            host_regex: Some("^api-[0-9]+\\.".to_owned()),
            path: Some("/Exact".to_owned()),
            methods: vec!["GET".to_owned()],
            ..RuleSpec::default()
        },
        "api",
        api,
    )];
    let cfg = routing_listener("127.0.0.1:0".parse().expect("addr"), fallback, routes);
    let metrics = Arc::new(Metrics::default());
    let (proxy, _handle, serve) = start_proxy(cfg, metrics).await;

    // Exact hit routes.
    assert_eq!(
        request_body(proxy, &get("api-7.example.com", "/Exact")).await,
        "api"
    );
    // Each near miss falls back: bad host regex, wrong path case, wrong
    // method.
    assert_eq!(
        request_body(proxy, &get("api.example.com", "/Exact")).await,
        "fallback"
    );
    assert_eq!(
        request_body(proxy, &get("api-7.example.com", "/exact")).await,
        "fallback"
    );
    let post = "POST /Exact HTTP/1.1\r\nHost: api-7.example.com\r\nConnection: close\r\n\r\n";
    assert_eq!(request_body(proxy, post).await, "fallback");

    _handle.trigger();
    serve.await.expect("serve ends");
}

// --- v0.6 slice 2: rule actions (rewrite / redirect / direct_response) ---

/// Real HTTP backend that answers with the request target and Host it
/// received, so rewrites on the forwarded copy are observable.
async fn start_echo_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo backend");
    let addr = listener.local_addr().expect("addr echo backend");
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
                            break pos;
                        }
                        if total == buf.len() {
                            return;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                    let target = head.split(' ').nth(1).unwrap_or("").to_owned();
                    let host = head
                        .lines()
                        .find_map(|line| {
                            line.split_once(": ")
                                .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
                                .map(|(_, value)| value.to_owned())
                        })
                        .unwrap_or_default();
                    let close = buf[..head_end].windows(7).any(|w| w == b"close\r\n");
                    let body = format!("{target}|{host}");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    if socket.write_all(response.as_bytes()).await.is_err() {
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

/// Sends one raw request and returns the full response text.
async fn request_full(proxy: SocketAddr, head: &str) -> String {
    let mut stream = tokio::time::timeout(WAIT, TcpStream::connect(proxy))
        .await
        .expect("connect timeout")
        .expect("connect proxy");
    stream.write_all(head.as_bytes()).await.expect("write head");
    let mut response = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut response))
        .await
        .expect("response timeout")
        .expect("read response");
    String::from_utf8_lossy(&response).into_owned()
}

/// Rewrite (v0.6 slice 2): the matched prefix is replaced on the
/// forwarded copy — query preserved — and/or `Host` set to the
/// configured upstream value. The client's bytes are never mutated.
#[tokio::test]
async fn rewrite_action_rewrites_target_and_host_for_the_backend() {
    let echo = start_echo_backend().await;
    let routes = vec![
        rule_action(
            RuleSpec {
                name: "api-rewrite".to_owned(),
                path_prefix: Some("/api".to_owned()),
                ..RuleSpec::default()
            },
            RouteAction::Backend {
                backend: Arc::new(ResolvedBackend::single("echo", echo)),
                rewrite: rewrite_with("/api", "/v2", Some("internal.svc")),
            },
        ),
        rule_action(
            RuleSpec {
                name: "strip".to_owned(),
                path_prefix: Some("/strip".to_owned()),
                ..RuleSpec::default()
            },
            RouteAction::Backend {
                backend: Arc::new(ResolvedBackend::single("echo", echo)),
                rewrite: rewrite_with("/strip", "", None),
            },
        ),
    ];
    let cfg = routing_listener("127.0.0.1:0".parse().expect("addr"), echo, routes);
    let metrics = Arc::new(Metrics::default());
    let (proxy, _handle, serve) = start_proxy(cfg, metrics).await;

    // Prefix replaced, query preserved, upstream Host rewritten.
    assert_eq!(
        request_body(proxy, &get("www.example.com", "/api/users?x=1")).await,
        "/v2/users?x=1|internal.svc"
    );
    // Empty replacement strips the prefix; Host untouched.
    assert_eq!(
        request_body(proxy, &get("www.example.com", "/strip/a")).await,
        "/a|www.example.com"
    );

    _handle.trigger();
    serve.await.expect("serve ends");
}

/// Redirect (v0.6 slice 2): answered locally with the Location rendered
/// per request ($host/$request_uri); no backend is ever contacted.
#[tokio::test]
async fn redirect_action_answers_locally_with_rendered_location() {
    let fallback = start_identity_backend("fallback").await;
    let routes = vec![rule_action(
        RuleSpec {
            name: "canonical".to_owned(),
            path_prefix: Some("/old".to_owned()),
            ..RuleSpec::default()
        },
        RouteAction::Redirect {
            status: 308,
            location: "https://$host$request_uri".to_owned(),
        },
    )];
    let cfg = routing_listener("127.0.0.1:0".parse().expect("addr"), fallback, routes);
    let metrics = Arc::new(Metrics::default());
    let (proxy, _handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let response = request_full(proxy, &get("www.example.com", "/old/x?a=1")).await;
    assert!(response.starts_with("HTTP/1.1 308 "), "{response}");
    assert!(
        response.contains("location: https://www.example.com/old/x?a=1"),
        "{response}"
    );
    // No backend involved: empty body and the counters tell the truth.
    assert!(response.ends_with("\r\n\r\n"), "{response}");
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.redirects_served, 1);
    assert_eq!(snapshot.http_requests_proxied, 0);

    _handle.trigger();
    serve.await.expect("serve ends");
}

/// direct_response (v0.6 slice 2): the configured status/body is served
/// locally; request bodies are drained so keep-alive stays aligned.
#[tokio::test]
async fn direct_response_answers_locally_and_keeps_keep_alive() {
    let fallback = start_identity_backend("fallback").await;
    let routes = vec![rule_action(
        RuleSpec {
            name: "shed".to_owned(),
            path_prefix: Some("/shed".to_owned()),
            ..RuleSpec::default()
        },
        RouteAction::Direct {
            status: 200,
            content_type: "application/json".to_owned(),
            body: "{\"shed\":true}".to_owned(),
        },
    )];
    let cfg = routing_listener("127.0.0.1:0".parse().expect("addr"), fallback, routes);
    let metrics = Arc::new(Metrics::default());
    let (proxy, _handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    // One keep-alive connection: a POST with a body followed by a second
    // request. The body is drained (never desyncs the next exchange) and
    // neither request reaches the backend.
    let mut stream = tokio::time::timeout(WAIT, TcpStream::connect(proxy))
        .await
        .expect("connect timeout")
        .expect("connect proxy");
    let post = "POST /shed HTTP/1.1\r\nHost: www.example.com\r\nContent-Length: 5\r\n\r\nhello";
    stream.write_all(post.as_bytes()).await.expect("write post");
    let second = "GET /shed HTTP/1.1\r\nHost: www.example.com\r\n\r\n";
    stream
        .write_all(second.as_bytes())
        .await
        .expect("write get");
    let mut response = Vec::new();
    let mut buf = [0u8; 2048];
    while response
        .windows(13)
        .filter(|w| *w == b"{\"shed\":true}")
        .count()
        < 2
    {
        let got = tokio::time::timeout(WAIT, stream.read(&mut buf))
            .await
            .expect("response timeout")
            .expect("read response");
        if got == 0 {
            break;
        }
        response.extend_from_slice(&buf[..got]);
    }
    let text = String::from_utf8_lossy(&response);
    assert_eq!(text.matches("HTTP/1.1 200").count(), 2, "{text}");
    assert_eq!(text.matches("{\"shed\":true}").count(), 2, "{text}");
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.direct_responses_served, 2);
    assert_eq!(snapshot.http_requests_proxied, 0);

    _handle.trigger();
    serve.await.expect("serve ends");
}

/// First match wins across action kinds and the default backend stays
/// the fallback (v0.6 slice 2 changes nothing about ordering).
#[tokio::test]
async fn action_order_and_fallback_are_unchanged() {
    let fallback = start_identity_backend("fallback").await;
    let routes = vec![
        rule_action(
            RuleSpec {
                name: "first".to_owned(),
                path_prefix: Some("/mix".to_owned()),
                ..RuleSpec::default()
            },
            RouteAction::Redirect {
                status: 301,
                location: "/moved$request_uri".to_owned(),
            },
        ),
        rule_action(
            RuleSpec {
                name: "second".to_owned(),
                path_prefix: Some("/mix".to_owned()),
                ..RuleSpec::default()
            },
            RouteAction::Direct {
                status: 500,
                content_type: "text/plain".to_owned(),
                body: "never".to_owned(),
            },
        ),
    ];
    let cfg = routing_listener("127.0.0.1:0".parse().expect("addr"), fallback, routes);
    let metrics = Arc::new(Metrics::default());
    let (proxy, _handle, serve) = start_proxy(cfg, metrics).await;

    // First rule wins: the redirect, never the direct_response below it.
    let response = request_full(proxy, &get("h", "/mix/x")).await;
    assert!(response.starts_with("HTTP/1.1 301 "), "{response}");
    assert!(response.contains("location: /moved/mix/x"), "{response}");
    // No rule matches -> default backend.
    assert_eq!(request_body(proxy, &get("h", "/other")).await, "fallback");

    _handle.trigger();
    serve.await.expect("serve ends");
}
