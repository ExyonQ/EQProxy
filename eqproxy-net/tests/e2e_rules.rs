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

use eqproxy_core::auth::AuthUrl;
use eqproxy_core::rules::{HeaderSpec, Rule, RuleSpec};
use eqproxy_core::{Metrics, shutdown};
use eqproxy_net::{
    AffinityMode, BoundProxy, ProxyMode, ResolvedAffinity, ResolvedAuth, ResolvedBackend,
    ResolvedCors, ResolvedHeaders, ResolvedListener, ResolvedRewrite, ResolvedRoute,
    ResolvedServer, RouteAction, bind,
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

/// Real HTTP backend that echoes the forwarding headers it received
/// (B-N4/B-I4 corpus shape: `xff=[…] real=[…] …`).
async fn start_header_echo_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo backend");
    let addr = listener.local_addr().expect("addr echo backend");
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
                    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                    let value_of = |name: &str| {
                        head.lines()
                            .filter_map(|line| line.split_once(':'))
                            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
                            .map(|(_, v)| v.trim())
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    let body = format!(
                        "xff=[{}] real=[{}] proto=[{}] beta=[{}] gone=[{}] added=[{}]",
                        value_of("x-forwarded-for"),
                        value_of("x-real-ip"),
                        value_of("x-forwarded-proto"),
                        value_of("x-beta"),
                        value_of("x-gone"),
                        value_of("x-added"),
                    );
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
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
        headers: None,
    }
}

/// Rule with an arbitrary action (v0.6 slice 2: rewrite / redirect /
/// direct_response).
fn rule_action(spec: RuleSpec, action: RouteAction) -> ResolvedRoute {
    ResolvedRoute {
        rule: Rule::compile(&spec).expect("rule compiles"),
        action,
        headers: None,
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

/// Sends one raw request (head only) and returns the whole response.
async fn request_response(proxy: SocketAddr, head: &str) -> String {
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

/// Sends one raw request (head only) and returns the response body.
async fn request_body(proxy: SocketAddr, head: &str) -> String {
    request_response(proxy, head)
        .await
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default()
}

/// Header actions end to end (B-N4/B-I4/B-E17): the backend sees the
/// set/add/del results and the client the response marker, with
/// `$remote_addr`/`$host`/`$scheme` rendered per request. A rule can
/// never override the forwarded-headers policy (the client's spoofed
/// `x-forwarded-proto` is replaced by the real scheme).
#[tokio::test]
async fn header_actions_apply_to_request_and_response() {
    let echo = start_header_echo_backend().await;
    let routes = vec![
        ResolvedRoute {
            rule: Rule::compile(&RuleSpec {
                name: "h".to_owned(),
                path_prefix: Some("/h/".to_owned()),
                ..RuleSpec::default()
            })
            .expect("rule compiles"),
            action: RouteAction::Backend {
                backend: Arc::new(ResolvedBackend::single("api", echo)),
                rewrite: None,
            },
            headers: Some(ResolvedHeaders {
                set: vec![("x-beta".to_owned(), "on-$scheme".to_owned())],
                add: vec![("x-added".to_owned(), "extra@$remote_addr".to_owned())],
                del: vec!["x-gone".to_owned()],
                response: vec![("x-marker".to_owned(), "$host@$scheme".to_owned())],
                cors: None,
                rate_limit: None,
                auth: None,
            }),
        },
        ResolvedRoute {
            rule: Rule::compile(&RuleSpec {
                name: "r".to_owned(),
                path: Some("/r".to_owned()),
                ..RuleSpec::default()
            })
            .expect("rule compiles"),
            action: RouteAction::Redirect {
                status: 302,
                location: "/new".to_owned(),
            },
            headers: Some(ResolvedHeaders {
                set: Vec::new(),
                add: Vec::new(),
                del: Vec::new(),
                response: vec![("x-marker".to_owned(), "local".to_owned())],
                cors: None,
                rate_limit: None,
                auth: None,
            }),
        },
    ];
    let cfg = routing_listener("127.0.0.1:0".parse().expect("addr"), echo, routes)
        .with_forwarded_headers(eqproxy_net::proxy::ForwardedMode::Append);
    let metrics = Arc::new(Metrics::default());
    let (proxy, _handle, serve) = start_proxy(cfg, metrics).await;

    let response = request_response(
        proxy,
        "GET /h/x HTTP/1.1\r\nHost: svc.example\r\nx-beta: off\r\nx-gone: please\r\nx-added: base\r\nx-forwarded-proto: https\r\nConnection: close\r\n\r\n",
    )
    .await;
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or_default();
    assert_eq!(
        body,
        "xff=[127.0.0.1] real=[] proto=[http] beta=[on-http] gone=[] added=[base, extra@127.0.0.1]"
    );
    assert!(
        response.contains("x-marker: svc.example@http"),
        "{response}"
    );

    // Local answers carry the rule's response headers too.
    let response = request_response(proxy, &get("svc.example", "/r")).await;
    assert!(response.starts_with("HTTP/1.1 302"), "{response}");
    assert!(response.contains("location: /new"), "{response}");
    assert!(response.contains("x-marker: local"), "{response}");

    _handle.trigger();
    serve.await.expect("serve ends");
}

/// CORS (B-I10): a rule with a `cors` policy answers the preflight
/// locally (the backend never sees it) and stamps the CORS headers on
/// every response of the rule.
#[tokio::test]
async fn cors_preflight_is_local_and_responses_carry_headers() {
    let echo = start_identity_backend("api").await;
    let routes = vec![ResolvedRoute {
        rule: Rule::compile(&RuleSpec {
            name: "c".to_owned(),
            path_prefix: Some("/c/".to_owned()),
            ..RuleSpec::default()
        })
        .expect("rule compiles"),
        action: RouteAction::Backend {
            backend: Arc::new(ResolvedBackend::single("api", echo)),
            rewrite: None,
        },
        headers: Some(ResolvedHeaders {
            set: Vec::new(),
            add: Vec::new(),
            del: Vec::new(),
            response: vec![("x-marker".to_owned(), "cors".to_owned())],
            cors: Some(ResolvedCors {
                allow_origin: "https://app.example".to_owned(),
                allow_methods: "GET, POST, OPTIONS".to_owned(),
                allow_headers: Some("content-type".to_owned()),
                expose_headers: Some("x-marker".to_owned()),
                max_age: Duration::from_secs(600),
                allow_credentials: true,
            }),
            rate_limit: None,
            auth: None,
        }),
    }];
    let cfg = routing_listener("127.0.0.1:0".parse().expect("addr"), echo, routes);
    let metrics = Arc::new(Metrics::default());
    let (proxy, _handle, serve) = start_proxy(cfg, metrics).await;

    // Preflight: local 204 with the CORS trio — the identity body never
    // appears, so the backend was not contacted.
    let response = request_response(
        proxy,
        "OPTIONS /c/x HTTP/1.1\r\nHost: svc.example\r\nOrigin: https://app.example\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: content-type\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 204"), "{response}");
    assert!(
        response.contains("access-control-allow-origin: https://app.example"),
        "{response}"
    );
    assert!(
        response.contains("access-control-allow-credentials: true"),
        "{response}"
    );
    assert!(
        response.contains("access-control-allow-methods: GET, POST, OPTIONS"),
        "{response}"
    );
    assert!(
        response.contains("access-control-allow-headers: content-type"),
        "{response}"
    );
    assert!(
        response.contains("access-control-max-age: 600"),
        "{response}"
    );
    assert!(response.contains("vary: origin"), "{response}");
    assert!(response.contains("x-marker: cors"), "{response}");
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or_default();
    assert!(body.is_empty(), "preflight answered locally: {body}");

    // A normal request gets the CORS response headers + the backend body.
    let response = request_response(
        proxy,
        "GET /c/x HTTP/1.1\r\nHost: svc.example\r\nOrigin: https://app.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or_default();
    assert_eq!(body, "api");
    assert!(
        response.contains("access-control-allow-origin: https://app.example"),
        "{response}"
    );
    assert!(
        response.contains("access-control-expose-headers: x-marker"),
        "{response}"
    );
    assert!(response.contains("vary: origin"), "{response}");

    _handle.trigger();
    serve.await.expect("serve ends");
}

/// Rate limiting (B-N8/B-I7/B-E16): the rule's token bucket is per
/// client IP; over the limit the request is rejected explicitly (429 +
/// counter, Q6: never a silent drop). Real time: `burst = 2` lets two
/// requests through, the third is rejected; one window later a token
/// has refilled and the next request passes again.
#[tokio::test]
async fn rate_limit_rejects_over_the_limit_explicitly() {
    let echo = start_identity_backend("api").await;
    let routes = vec![ResolvedRoute {
        rule: Rule::compile(&RuleSpec {
            name: "rl".to_owned(),
            path_prefix: Some("/rl/".to_owned()),
            ..RuleSpec::default()
        })
        .expect("rule compiles"),
        action: RouteAction::Backend {
            backend: Arc::new(ResolvedBackend::single("api", echo)),
            rewrite: None,
        },
        headers: Some(ResolvedHeaders {
            set: Vec::new(),
            add: Vec::new(),
            del: Vec::new(),
            response: Vec::new(),
            cors: None,
            rate_limit: Some(Arc::new(eqproxy_net::RateLimiter::new(
                1,
                Duration::from_secs(1),
                2,
            ))),
            auth: None,
        }),
    }];
    let cfg = routing_listener("127.0.0.1:0".parse().expect("addr"), echo, routes);
    let metrics = Arc::new(Metrics::default());
    let (proxy, _handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    for _ in 0..2 {
        let response = request_response(proxy, &get("svc.example", "/rl/x")).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }
    let response = request_response(proxy, &get("svc.example", "/rl/x")).await;
    assert!(response.starts_with("HTTP/1.1 429"), "{response}");
    assert_eq!(
        metrics.snapshot().rate_limited,
        1,
        "the rejection is counted (explicit, never silent)"
    );

    // One window later a token refilled: the next request passes.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let response = request_response(proxy, &get("svc.example", "/rl/x")).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    _handle.trigger();
    serve.await.expect("serve ends");
}

/// Session affinity (B-H8/B-N13/B-I8): cookie mode sticks a client to
/// the server that first served it (sticky cookie re-issued only when
/// missing or stale) and source mode pins by client IP hash. Two
/// equal-weight servers alternate under plain RR, so "the same server
/// again" is the pin.
#[tokio::test]
async fn affinity_cookie_and_source_pin_clients_to_a_server() {
    let a = start_identity_backend("a").await;
    let b = start_identity_backend("b").await;
    let affinity_backend = |name: &'static str, mode: AffinityMode| {
        ResolvedBackend::new(
            name,
            vec![
                ResolvedServer {
                    addr: a.into(),
                    weight: 1,
                },
                ResolvedServer {
                    addr: b.into(),
                    weight: 1,
                },
            ],
            3,
            2,
        )
        .with_affinity(ResolvedAffinity {
            mode,
            cookie: "eq_aff".to_owned(),
        })
    };
    let routes = vec![
        ResolvedRoute {
            rule: Rule::compile(&RuleSpec {
                name: "c".to_owned(),
                path_prefix: Some("/c/".to_owned()),
                ..RuleSpec::default()
            })
            .expect("rule compiles"),
            action: RouteAction::Backend {
                backend: Arc::new(affinity_backend("cookie-api", AffinityMode::Cookie)),
                rewrite: None,
            },
            headers: None,
        },
        ResolvedRoute {
            rule: Rule::compile(&RuleSpec {
                name: "s".to_owned(),
                path_prefix: Some("/s/".to_owned()),
                ..RuleSpec::default()
            })
            .expect("rule compiles"),
            action: RouteAction::Backend {
                backend: Arc::new(affinity_backend("source-api", AffinityMode::Source)),
                rewrite: None,
            },
            headers: None,
        },
    ];
    let cfg = routing_listener("127.0.0.1:0".parse().expect("addr"), a, routes);
    let metrics = Arc::new(Metrics::default());
    let (proxy, _handle, serve) = start_proxy(cfg, metrics).await;

    // Cookie mode: the first response sets the sticky cookie.
    let cookie_token = |response: &str| -> Option<String> {
        response
            .lines()
            .filter(|line| line.to_lowercase().starts_with("set-cookie: eq_aff="))
            .filter_map(|line| line.split_once('=').map(|(_, rest)| rest.trim()))
            .filter_map(|rest| rest.split(';').next())
            .map(|token| token.trim().to_owned())
            .next()
    };
    let first = request_response(proxy, &get("svc.example", "/c/x")).await;
    let body = first
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or_default()
        .to_owned();
    let token = cookie_token(&first).expect("the first response sets the sticky cookie");
    assert!(
        first.to_lowercase().contains("set-cookie: eq_aff="),
        "{first}"
    );

    // The cookie pins: repeated requests all land on the same server
    // (plain RR would alternate) and no new cookie is issued.
    for _ in 0..4 {
        let response = request_response(
            proxy,
            &format!(
                "GET /c/x HTTP/1.1\r\nHost: svc.example\r\nCookie: eq_aff={token}\r\nConnection: close\r\n\r\n"
            ),
        )
        .await;
        let pinned = response
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .unwrap_or_default();
        assert_eq!(pinned, body, "the cookie pins: {response}");
        assert!(
            !response.to_lowercase().contains("set-cookie: eq_aff="),
            "a valid pin is not re-issued: {response}"
        );
    }

    // A stale cookie is replaced with a valid pin.
    let stale = request_response(
        proxy,
        "GET /c/x HTTP/1.1\r\nHost: svc.example\r\nCookie: eq_aff=9999\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        stale.to_lowercase().contains("set-cookie: eq_aff="),
        "a stale pin is re-issued: {stale}"
    );

    // Source mode: the same client IP always lands on the same server.
    let s1 = request_body(proxy, &get("svc.example", "/s/x")).await;
    let s2 = request_body(proxy, &get("svc.example", "/s/x")).await;
    assert_eq!(s1, s2, "same client IP → same server");

    _handle.trigger();
    serve.await.expect("serve ends");
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

/// One fixed-response auth service for the subrequest gate (B-N9/B-I9);
/// records the request head it received.
async fn start_auth_backend(
    status: u16,
    reason: &str,
    headers: &str,
    body: &str,
) -> (SocketAddr, Arc<std::sync::Mutex<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind auth backend");
    let addr = listener.local_addr().expect("addr auth backend");
    let seen = Arc::new(std::sync::Mutex::new(String::new()));
    let recorded = Arc::clone(&seen);
    let (reason, headers, body) = (reason.to_owned(), headers.to_owned(), body.to_owned());
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = vec![0u8; 8192];
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
            *recorded.lock().expect("auth seen lock") =
                String::from_utf8_lossy(&buf[..head_end]).into_owned();
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\n{headers}content-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });
    (addr, seen)
}

/// Auth rule helper: one path prefix gated by the given mechanisms.
fn auth_rule(
    name: &str,
    path_prefix: &str,
    server: SocketAddr,
    auth: eqproxy_net::ResolvedAuth,
) -> ResolvedRoute {
    ResolvedRoute {
        rule: Rule::compile(&RuleSpec {
            name: name.to_owned(),
            path_prefix: Some(path_prefix.to_owned()),
            ..RuleSpec::default()
        })
        .expect("rule compiles"),
        action: RouteAction::Backend {
            backend: Arc::new(ResolvedBackend::single("api", server)),
            rewrite: None,
        },
        headers: Some(ResolvedHeaders {
            set: Vec::new(),
            add: Vec::new(),
            del: Vec::new(),
            response: Vec::new(),
            cors: None,
            rate_limit: None,
            auth: Some(auth),
        }),
    }
}

/// Basic auth (B-N9/B-I9, `type = "basic"`): missing or wrong
/// credentials get an explicit 401 with `WWW-Authenticate`; good
/// htpasswd credentials reach the backend.
#[tokio::test]
async fn auth_basic_rejects_missing_or_wrong_credentials_explicitly() {
    let echo = start_identity_backend("api").await;
    // `openssl passwd -apr1 -salt eqpr0xyS secret`.
    let users = eqproxy_core::auth::BasicUsers::parse(&[
        "alice:$apr1$eqpr0xyS$DDjQzF4.2qDil6v9iW4Xo1".to_owned(),
    ])
    .expect("users parse");
    let routes = vec![auth_rule(
        "basic",
        "/private/",
        echo,
        ResolvedAuth {
            url: None,
            basic: Some(Arc::new(users)),
            realm: "test".to_owned(),
        },
    )];
    let cfg = routing_listener("127.0.0.1:0".parse().expect("addr"), echo, routes);
    let metrics = Arc::new(Metrics::default());
    let (proxy, _handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let response = request_response(proxy, &get("svc.example", "/private/x")).await;
    assert!(response.starts_with("HTTP/1.1 401 "), "{response}");
    assert!(
        response.contains("www-authenticate: Basic realm=\"test\""),
        "{response}"
    );

    let blob = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        "alice:wrongpass",
    );
    let response = request_response(
        proxy,
        &format!("GET /private/x HTTP/1.1\r\nHost: svc.example\r\nAuthorization: Basic {blob}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 401 "), "{response}");

    let blob = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "alice:secret");
    let response = request_response(
        proxy,
        &format!("GET /private/x HTTP/1.1\r\nHost: svc.example\r\nAuthorization: Basic {blob}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
    assert!(response.ends_with("api"), "{response}");
    assert_eq!(metrics.snapshot().auth_denied, 2, "two explicit denials");

    _handle.trigger();
    serve.await.expect("serve ends");
}

/// External auth subrequest (B-N9/B-I9, `auth-url`): 2xx allows, a
/// 401/403 denies with the auth response reaching the client, any other
/// status fails closed with 500 and an unreachable auth service with
/// 502. Basic runs first when both are set.
#[tokio::test]
async fn auth_subrequest_allows_on_2xx_and_fails_closed() {
    let echo = start_identity_backend("api").await;
    let (ok_addr, ok_seen) = start_auth_backend(200, "OK", "", "").await;
    let (deny_addr, _) = start_auth_backend(
        401,
        "Unauthorized",
        "www-authenticate: Basic realm=\"ext\"\r\n",
        "denied-by-auth",
    )
    .await;
    let (error_addr, _) = start_auth_backend(500, "Internal Server Error", "", "boom").await;
    let subrequest_auth = |addr: SocketAddr| ResolvedAuth {
        url: Some(AuthUrl {
            host: "127.0.0.1".to_owned(),
            port: addr.port(),
            path: "/verify".to_owned(),
        }),
        basic: None,
        realm: "EQProxy".to_owned(),
    };
    let routes = vec![
        auth_rule("ok", "/ok/", echo, subrequest_auth(ok_addr)),
        auth_rule("deny", "/deny/", echo, subrequest_auth(deny_addr)),
        auth_rule("error", "/error/", echo, subrequest_auth(error_addr)),
        auth_rule(
            "down",
            "/down/",
            echo,
            subrequest_auth("127.0.0.1:1".parse().expect("addr")),
        ),
        auth_rule(
            "both",
            "/both/",
            echo,
            ResolvedAuth {
                url: Some(AuthUrl {
                    host: "127.0.0.1".to_owned(),
                    port: ok_addr.port(),
                    path: "/verify".to_owned(),
                }),
                basic: Some(Arc::new(
                    eqproxy_core::auth::BasicUsers::parse(&[
                        "alice:$apr1$eqpr0xyS$DDjQzF4.2qDil6v9iW4Xo1".to_owned(),
                    ])
                    .expect("users parse"),
                )),
                realm: "EQProxy".to_owned(),
            },
        ),
    ];
    let cfg = routing_listener("127.0.0.1:0".parse().expect("addr"), echo, routes);
    let metrics = Arc::new(Metrics::default());
    let (proxy, _handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    // 2xx from the auth service: proxied, and the subrequest named the
    // original request.
    let body = request_body(
        proxy,
        "GET /ok/x HTTP/1.1\r\nHost: svc.example\r\nx-token: t\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(body, "api");
    let seen = ok_seen.lock().expect("auth seen lock").clone();
    assert!(seen.starts_with("GET /verify HTTP/1.1\r\n"), "{seen}");
    assert!(seen.contains("x-original-method: GET\r\n"), "{seen}");
    assert!(seen.contains("x-original-url: /ok/x\r\n"), "{seen}");
    assert!(seen.contains("x-token: t\r\n"), "{seen}");

    // 401 from the auth service: its response reaches the client.
    let response = request_response(proxy, &get("svc.example", "/deny/x")).await;
    assert!(response.starts_with("HTTP/1.1 401 "), "{response}");
    assert!(
        response.contains("www-authenticate: Basic realm=\"ext\""),
        "{response}"
    );
    assert!(response.ends_with("denied-by-auth"), "{response}");

    // A status that is not a decision fails closed (500).
    let response = request_response(proxy, &get("svc.example", "/error/x")).await;
    assert!(response.starts_with("HTTP/1.1 500 "), "{response}");
    assert!(response.ends_with("auth check failed"), "{response}");

    // An unreachable auth service fails closed too (502), never passes.
    let response = request_response(proxy, &get("svc.example", "/down/x")).await;
    assert!(response.starts_with("HTTP/1.1 502 "), "{response}");
    assert!(response.ends_with("auth service unavailable"), "{response}");

    // Both mechanisms: Basic runs first, so no credentials never reach
    // the auth service.
    let response = request_response(proxy, &get("svc.example", "/both/x")).await;
    assert!(response.starts_with("HTTP/1.1 401 "), "{response}");
    let blob = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "alice:secret");
    let body = request_body(
        proxy,
        &format!("GET /both/x HTTP/1.1\r\nHost: svc.example\r\nAuthorization: Basic {blob}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert_eq!(body, "api");

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.auth_denied, 2, "401 auth + missing basic");
    assert_eq!(
        snapshot.auth_service_errors, 2,
        "the 500 + the unreachable auth"
    );

    _handle.trigger();
    serve.await.expect("serve ends");
}

// --- B-I11 (canary y tráfico ponderado) + C10 (hot maps) ---

/// Weighted traffic split (B-I11; Envoy `weighted_clusters`, ingress
/// `canary-weight`): one rule fans requests out across backends by
/// weight (3:1 = exact shares in rotation) and a `weight = 0` target is
/// never picked (canary rollback without touching the rest).
#[tokio::test]
async fn split_traffic_shares_requests_by_weight_across_backends() {
    let stable = start_identity_backend("stable").await;
    let canary = start_identity_backend("canary").await;
    let split_rule = |targets: Vec<eqproxy_net::SplitTarget>| ResolvedRoute {
        rule: Rule::compile(&RuleSpec {
            name: "split".to_owned(),
            path_prefix: Some("/".to_owned()),
            ..RuleSpec::default()
        })
        .expect("rule compiles"),
        action: RouteAction::Split {
            targets: Arc::new(eqproxy_net::SplitTargets::new(targets)),
            rewrite: None,
        },
        headers: None,
    };
    let target = |name: &str, addr: SocketAddr, weight: u32| eqproxy_net::SplitTarget {
        backend: Arc::new(ResolvedBackend::single(name, addr)),
        weight,
    };

    let cfg = routing_listener(
        "127.0.0.1:0".parse().expect("addr"),
        stable,
        vec![split_rule(vec![
            target("stable", stable, 3),
            target("canary", canary, 1),
        ])],
    );
    let metrics = Arc::new(Metrics::default());
    let (proxy, _handle, serve) = start_proxy(cfg, metrics).await;

    let mut counts = std::collections::BTreeMap::new();
    for _ in 0..8 {
        let body = request_body(proxy, &get("svc.example", "/")).await;
        *counts.entry(body).or_insert(0usize) += 1;
    }
    assert_eq!(
        counts.get("stable"),
        Some(&6),
        "3:1 over 8 requests: {counts:?}"
    );
    assert_eq!(counts.get("canary"), Some(&2), "3:1 over 8: {counts:?}");
    _handle.trigger();
    serve.await.expect("serve ends");

    // Canary rollback: weight 0 drops the target out without touching
    // the rest of the split.
    let cfg = routing_listener(
        "127.0.0.1:0".parse().expect("addr"),
        stable,
        vec![split_rule(vec![
            target("stable", stable, 5),
            target("canary", canary, 0),
        ])],
    );
    let metrics = Arc::new(Metrics::default());
    let (proxy, _handle, serve) = start_proxy(cfg, metrics).await;
    for _ in 0..10 {
        assert_eq!(
            request_body(proxy, &get("svc.example", "/")).await,
            "stable",
            "a weight-0 target must never receive a request"
        );
    }
    _handle.trigger();
    serve.await.expect("serve ends");
}

/// Canary by header and by cookie (B-I11, ingress `canary-by-header`/
/// `canary-by-cookie`): the override routes 100 % of the matching
/// requests to the canary and falls through to the default backend
/// otherwise (first match wins).
#[tokio::test]
async fn canary_by_cookie_and_header_overrides_route_to_the_canary() {
    let stable = start_identity_backend("stable").await;
    let canary = start_identity_backend("canary").await;
    let to_canary = |spec: RuleSpec| ResolvedRoute {
        rule: Rule::compile(&spec).expect("rule compiles"),
        action: RouteAction::Backend {
            backend: Arc::new(ResolvedBackend::single("canary", canary)),
            rewrite: None,
        },
        headers: None,
    };
    let routes = vec![
        to_canary(RuleSpec {
            name: "by-header".to_owned(),
            headers: vec![HeaderSpec {
                name: "x-canary".to_owned(),
                exact: Some("always".to_owned()),
                regex: None,
                present: false,
            }],
            ..RuleSpec::default()
        }),
        to_canary(RuleSpec {
            name: "by-cookie".to_owned(),
            cookies: vec![eqproxy_core::rules::CookieSpec {
                name: "canary".to_owned(),
                exact: Some("always".to_owned()),
                regex: None,
                present: false,
            }],
            ..RuleSpec::default()
        }),
    ];
    let cfg = routing_listener("127.0.0.1:0".parse().expect("addr"), stable, routes);
    let metrics = Arc::new(Metrics::default());
    let (proxy, _handle, serve) = start_proxy(cfg, metrics).await;

    let request = |head: &'static str| request_body(proxy, head);
    // Header override: present with the right value -> canary.
    assert_eq!(
        request("GET / HTTP/1.1\r\nHost: x\r\nx-canary: always\r\nConnection: close\r\n\r\n").await,
        "canary"
    );
    assert_eq!(
        request("GET / HTTP/1.1\r\nHost: x\r\nx-canary: never\r\nConnection: close\r\n\r\n").await,
        "stable",
        "a wrong header value falls through"
    );
    // Cookie override (RFC 6265 pair parsing inside the Cookie header).
    assert_eq!(
        request(
            "GET / HTTP/1.1\r\nHost: x\r\nCookie: sid=1; canary=always\r\nConnection: close\r\n\r\n"
        )
        .await,
        "canary"
    );
    assert_eq!(
        request("GET / HTTP/1.1\r\nHost: x\r\nCookie: canary=never\r\nConnection: close\r\n\r\n")
            .await,
        "stable",
        "a wrong cookie value falls through"
    );
    assert_eq!(
        request("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await,
        "stable",
        "no override -> the default backend"
    );
    // Both overrides present: the first rule (header) wins.
    assert_eq!(
        request("GET / HTTP/1.1\r\nHost: x\r\nx-canary: always\r\nCookie: canary=always\r\nConnection: close\r\n\r\n").await,
        "canary"
    );

    _handle.trigger();
    serve.await.expect("serve ends");
}

/// Hot data maps (C10/PP-02): a `map` rule condition consults the map
/// data, and a hot swap changes what routes where **under the running
/// dataplane** — same listener, same sockets, same compiled rules.
#[tokio::test]
async fn map_condition_consults_hot_data_and_swaps_in_hot() {
    use eqproxy_core::maps::{HotMap, MapData, MapRegistry};
    use eqproxy_core::rules::MapConditionSpec;

    let stable = start_identity_backend("stable").await;
    let vip = start_identity_backend("vip").await;
    let gate = HotMap::new(
        "gate",
        MapData::parse("let-me-in 1\n", None).expect("map parses"),
        None,
        Duration::ZERO,
    );
    let mut registry = MapRegistry::new();
    registry.insert(Arc::clone(&gate));
    let routes = vec![ResolvedRoute {
        rule: Rule::compile(&RuleSpec {
            name: "vip-gate".to_owned(),
            map: Some(MapConditionSpec {
                name: "gate".to_owned(),
                key: None,
                header: Some("x-ticket".to_owned()),
                equals: Some("1".to_owned()),
            }),
            ..RuleSpec::default()
        })
        .expect("rule compiles"),
        action: RouteAction::Backend {
            backend: Arc::new(ResolvedBackend::single("vip", vip)),
            rewrite: None,
        },
        headers: None,
    }];
    let cfg = routing_listener("127.0.0.1:0".parse().expect("addr"), stable, routes)
        .with_maps(Arc::new(registry));
    let metrics = Arc::new(Metrics::default());
    let (proxy, _handle, serve) = start_proxy(cfg, metrics).await;

    let request = |head: &'static str| request_body(proxy, head);
    assert_eq!(
        request("GET / HTTP/1.1\r\nHost: x\r\nx-ticket: let-me-in\r\nConnection: close\r\n\r\n")
            .await,
        "vip",
        "the mapped ticket routes to the vip backend"
    );
    assert_eq!(
        request("GET / HTTP/1.1\r\nHost: x\r\nx-ticket: nope\r\nConnection: close\r\n\r\n").await,
        "stable"
    );

    // Hot swap (C10): new data, same dataplane.
    gate.replace(MapData::parse("nope 1\n", None).expect("map parses"));
    assert_eq!(
        request("GET / HTTP/1.1\r\nHost: x\r\nx-ticket: nope\r\nConnection: close\r\n\r\n").await,
        "vip",
        "the swapped data takes effect immediately"
    );
    assert_eq!(
        request("GET / HTTP/1.1\r\nHost: x\r\nx-ticket: let-me-in\r\nConnection: close\r\n\r\n")
            .await,
        "stable",
        "the old data is gone after the swap"
    );

    _handle.trigger();
    serve.await.expect("serve ends");
}
