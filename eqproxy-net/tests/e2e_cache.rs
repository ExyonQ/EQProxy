//! HTTP response cache E2E journeys (B-N7/H1, ADR-0034) with real sockets.
//!
//! The origin is a real TCP server with programmable routes; "served from
//! the cache" is a fact about the socket (the origin saw one request), not
//! a mock. Every H1 guarantee has a journey: session isolation, `Set-Cookie`
//! exclusion, `Vary` variants, `ETag`/`304` revalidation, the cache lock,
//! disk persistence across a restart, and the admin inventory.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use eqproxy_core::Metrics;
use eqproxy_core::shutdown;
use eqproxy_net::{
    BoundProxy, Cache, CacheSettings, ProxyMode, ResolvedBackend, ResolvedListener, ResolvedServer,
    bind, cache,
};

const WAIT: Duration = Duration::from_secs(10);

/// Programmable origin route.
#[derive(Clone)]
struct Behavior {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    etag: Option<String>,
    delay: Duration,
}

impl Behavior {
    fn ok(body: &str) -> Self {
        Self {
            status: 200,
            headers: vec![
                ("content-type".to_owned(), "text/plain".to_owned()),
                ("content-length".to_owned(), body.len().to_string()),
            ],
            body: body.as_bytes().to_vec(),
            etag: None,
            delay: Duration::ZERO,
        }
    }
}

struct Origin {
    addr: SocketAddr,
    dials: Arc<AtomicUsize>,
    /// Requests per path.
    path_hits: Arc<Mutex<HashMap<String, usize>>>,
    /// `If-None-Match` values the origin saw, in order.
    conditionals: Arc<Mutex<Vec<String>>>,
    behaviors: Arc<Mutex<HashMap<String, Behavior>>>,
}

impl Origin {
    fn dials(&self) -> usize {
        self.dials.load(Ordering::Relaxed)
    }

    fn hits(&self, path: &str) -> usize {
        self.path_hits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(path)
            .copied()
            .unwrap_or(0)
    }

    fn set_body(&self, path: &str, body: &str, etag: Option<&str>) {
        let mut behaviors = self
            .behaviors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(behavior) = behaviors.get_mut(path) {
            behavior.body = body.as_bytes().to_vec();
            behavior.etag = etag.map(str::to_owned);
            for (name, value) in &mut behavior.headers {
                if name == "content-length" {
                    *value = body.len().to_string();
                }
            }
        }
    }
}

fn head_value(head: &str, name: &str) -> Option<String> {
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim().eq_ignore_ascii_case(name)).then(|| value.trim().to_owned())
    })
}

fn head_path(head: &str) -> String {
    head.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_owned()
}

/// Real TCP origin: programmable per-path responses with `ETag`/`304`
/// support, per-path counters and conditional-header recording.
async fn start_origin() -> Origin {
    let behaviors: Arc<Mutex<HashMap<String, Behavior>>> = Arc::new(Mutex::new(HashMap::from([
        (
            "/static".to_owned(),
            Behavior {
                etag: Some("\"v1\"".to_owned()),
                ..Behavior::ok("static-body-v1")
            },
        ),
        (
            "/login".to_owned(),
            Behavior {
                status: 200,
                headers: vec![
                    ("content-type".to_owned(), "text/plain".to_owned()),
                    ("content-length".to_owned(), "5".to_owned()),
                    ("set-cookie".to_owned(), "session=abc; Path=/".to_owned()),
                ],
                body: b"login".to_vec(),
                etag: None,
                delay: Duration::ZERO,
            },
        ),
        (
            "/vary".to_owned(),
            Behavior {
                status: 200,
                headers: vec![("vary".to_owned(), "accept-language".to_owned())],
                body: Vec::new(),
                etag: None,
                delay: Duration::ZERO,
            },
        ),
        (
            "/slow".to_owned(),
            Behavior {
                delay: Duration::from_millis(300),
                ..Behavior::ok("slow-body")
            },
        ),
        (
            "/nostore".to_owned(),
            Behavior {
                status: 200,
                headers: vec![
                    ("content-type".to_owned(), "text/plain".to_owned()),
                    ("cache-control".to_owned(), "no-store".to_owned()),
                ],
                body: b"nostore".to_vec(),
                etag: None,
                delay: Duration::ZERO,
            },
        ),
        (
            "/flaky".to_owned(),
            Behavior {
                status: 500,
                headers: vec![("content-length".to_owned(), "5".to_owned())],
                body: b"error".to_vec(),
                etag: None,
                delay: Duration::ZERO,
            },
        ),
    ])));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    let dials = Arc::new(AtomicUsize::new(0));
    let path_hits = Arc::new(Mutex::new(HashMap::new()));
    let conditionals = Arc::new(Mutex::new(Vec::new()));
    let task_dials = Arc::clone(&dials);
    let task_hits = Arc::clone(&path_hits);
    let task_conditionals = Arc::clone(&conditionals);
    let task_behaviors = Arc::clone(&behaviors);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            task_dials.fetch_add(1, Ordering::Relaxed);
            let hits = Arc::clone(&task_hits);
            let conditionals = Arc::clone(&task_conditionals);
            let behaviors = Arc::clone(&task_behaviors);
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
                let head_text = String::from_utf8_lossy(&head).into_owned();
                let path = head_path(&head_text);
                hits.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .entry(path.clone())
                    .and_modify(|count| *count += 1)
                    .or_insert(1);
                if let Some(value) = head_value(&head_text, "if-none-match") {
                    conditionals
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(value);
                }
                let behavior = behaviors
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&path)
                    .cloned()
                    .unwrap_or_else(|| Behavior::ok("default"));
                if !behavior.delay.is_zero() {
                    tokio::time::sleep(behavior.delay).await;
                }
                // Conditional request against a matching ETag: 304 with the
                // validators, no body — the exact exchange the proxy must
                // turn into a refresh instead of a download.
                let inm = head_value(&head_text, "if-none-match");
                if let (Some(inm), Some(etag)) = (inm, behavior.etag.clone())
                    && cache::client_fresh(&inm, Some(&etag))
                {
                    let reply = format!(
                        "HTTP/1.1 304 Not Modified\r\netag: {etag}\r\ncontent-length: 0\r\n\r\n"
                    );
                    let _ = socket.write_all(reply.as_bytes()).await;
                    let _ = socket.shutdown().await;
                    return;
                }
                // `/vary` answers in the client's language: the proxy must
                // key the variants, not the path alone.
                let mut body = behavior.body.clone();
                let mut headers = behavior.headers.clone();
                if path == "/vary" {
                    let lang = head_value(&head_text, "accept-language").unwrap_or_default();
                    body = format!("lang={lang}").into_bytes();
                    headers.push(("content-length".to_owned(), body.len().to_string()));
                }
                if let Some(etag) = &behavior.etag {
                    headers.push(("etag".to_owned(), etag.clone()));
                }
                let mut reply = format!("HTTP/1.1 {} test\r\n", behavior.status).into_bytes();
                for (name, value) in &headers {
                    reply.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
                }
                if !headers.iter().any(|(n, _)| n == "content-length") {
                    reply.extend_from_slice(
                        format!("content-length: {}\r\n", body.len()).as_bytes(),
                    );
                }
                reply.extend_from_slice(b"\r\n");
                reply.extend_from_slice(&body);
                let _ = socket.write_all(&reply).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    Origin {
        addr,
        dials,
        path_hits,
        conditionals,
        behaviors,
    }
}

fn cache_settings(listener: &str) -> CacheSettings {
    CacheSettings {
        listener: listener.to_owned(),
        ..CacheSettings::test_defaults()
    }
}

async fn start_proxy(
    origin: SocketAddr,
    cache: CacheSettings,
) -> (
    SocketAddr,
    Arc<Metrics>,
    shutdown::ShutdownHandle,
    tokio::task::JoinHandle<()>,
) {
    start_proxy_with(origin, cache, None).await
}

async fn start_proxy_with(
    origin: SocketAddr,
    cache: CacheSettings,
    backend: Option<Arc<ResolvedBackend>>,
) -> (
    SocketAddr,
    Arc<Metrics>,
    shutdown::ShutdownHandle,
    tokio::task::JoinHandle<()>,
) {
    let metrics = Arc::new(Metrics::default());
    let cache = Cache::load(cache, Arc::clone(&metrics)).expect("cache builds");
    let mut cfg = ResolvedListener::new(
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
    .with_cache(cache);
    if let Some(backend) = backend {
        cfg = cfg.with_backend(backend);
    }
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

fn cookie_backend(origin: SocketAddr) -> Arc<ResolvedBackend> {
    use eqproxy_net::{AffinityMode, ResolvedAffinity};
    Arc::new(
        ResolvedBackend::new(
            "api",
            vec![ResolvedServer {
                addr: origin.into(),
                weight: 1,
                backup: false,
                priority: 0,
            }],
            3,
            2,
        )
        .with_affinity(ResolvedAffinity {
            mode: AffinityMode::Cookie,
            cookie: "eq_aff".to_owned(),
        }),
    )
}

/// Sends one request with `connection: close` and returns status, head and
/// body separately.
async fn fetch(
    addr: SocketAddr,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
) -> (u16, String, Vec<u8>) {
    let mut socket = TcpStream::connect(addr).await.expect("connect proxy");
    let mut request = format!("{method} {path} HTTP/1.1\r\nhost: api\r\nconnection: close\r\n");
    for (name, value) in extra {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    socket
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    tokio::time::timeout(WAIT, socket.read_to_end(&mut response))
        .await
        .expect("response in time")
        .expect("read response");
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|pos| pos + 4)
        .unwrap_or(response.len());
    let head = String::from_utf8_lossy(&response[..split]).into_owned();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .expect("status line");
    (status, head, response[split..].to_vec())
}

fn header(head: &str, name: &str) -> Option<String> {
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim().eq_ignore_ascii_case(name)).then(|| value.trim().to_owned())
    })
}

#[tokio::test]
async fn miss_then_hit_serves_identical_bytes() {
    let origin = start_origin().await;
    let (proxy, metrics, _handle, _serve) = start_proxy(origin.addr, cache_settings("web")).await;

    let (status, head, first) = fetch(proxy, "GET", "/static", &[]).await;
    assert_eq!(status, 200);
    assert_eq!(header(&head, "x-cache"), Some("MISS".to_owned()));
    assert_eq!(origin.hits("/static"), 1);

    let (status, head, second) = fetch(proxy, "GET", "/static", &[]).await;
    assert_eq!(status, 200);
    assert_eq!(first, second);
    assert_eq!(header(&head, "x-cache"), Some("HIT".to_owned()));
    assert!(header(&head, "age").is_some(), "a hit carries its age");
    assert_eq!(origin.hits("/static"), 1, "the second request never dialed");

    let snap = metrics.snapshot();
    assert_eq!(snap.cache_hits, 1);
    assert_eq!(snap.cache_misses, 1);
    assert_eq!(snap.cache_stores, 1);
    assert_eq!(snap.http_requests_proxied, 2);
}

#[tokio::test]
async fn sessions_never_share_an_entry() {
    let origin = start_origin().await;
    let (proxy, _, _handle, _serve) = start_proxy(origin.addr, cache_settings("web")).await;

    // Ten concurrent sessions plus one anonymous request: every sessioned
    // request bypasses, so the origin sees all eleven.
    let mut tasks = Vec::new();
    for index in 0..10 {
        tasks.push(tokio::spawn(async move {
            fetch(
                proxy,
                "GET",
                "/static",
                &[("cookie", &format!("session={index}"))],
            )
            .await
        }));
    }
    tasks.push(tokio::spawn(async move {
        fetch(proxy, "GET", "/static", &[]).await
    }));
    for task in tasks {
        let (status, _, _) = task.await.expect("request finishes");
        assert_eq!(status, 200);
    }
    assert_eq!(origin.hits("/static"), 11, "no session saw another's bytes");

    // The anonymous request stored its entry: the next one hits.
    let (_, head, _) = fetch(proxy, "GET", "/static", &[]).await;
    assert_eq!(header(&head, "x-cache"), Some("HIT".to_owned()));
    assert_eq!(origin.hits("/static"), 11);
}

#[tokio::test]
async fn set_cookie_responses_are_never_stored() {
    let origin = start_origin().await;
    let (proxy, metrics, _handle, _serve) = start_proxy(origin.addr, cache_settings("web")).await;

    for _ in 0..2 {
        let (status, head, _) = fetch(proxy, "GET", "/login", &[]).await;
        assert_eq!(status, 200);
        assert_eq!(header(&head, "x-cache"), Some("MISS".to_owned()));
    }
    assert_eq!(origin.hits("/login"), 2);
    assert_eq!(metrics.snapshot().cache_stores, 0);
}

#[tokio::test]
async fn vary_selects_the_variant() {
    let origin = start_origin().await;
    let (proxy, _, _handle, _serve) = start_proxy(origin.addr, cache_settings("web")).await;

    let (_, _, english) = fetch(proxy, "GET", "/vary", &[("accept-language", "en")]).await;
    assert_eq!(english, b"lang=en");
    let (_, head, english_again) = fetch(proxy, "GET", "/vary", &[("accept-language", "en")]).await;
    assert_eq!(english_again, b"lang=en");
    assert_eq!(header(&head, "x-cache"), Some("HIT".to_owned()));

    let (_, _, french) = fetch(proxy, "GET", "/vary", &[("accept-language", "fr")]).await;
    assert_eq!(french, b"lang=fr");
    assert_eq!(origin.hits("/vary"), 2, "one fetch per variant");

    // No language at all is its own variant, not the English one.
    let (_, _, empty) = fetch(proxy, "GET", "/vary", &[]).await;
    assert_eq!(empty, b"lang=");
    assert_eq!(origin.hits("/vary"), 3);
}

#[tokio::test]
async fn etag_revalidation_refreshes_without_a_body() {
    let origin = start_origin().await;
    let (proxy, metrics, _handle, _serve) = start_proxy(origin.addr, cache_settings("web")).await;

    let (_, _, first) = fetch(proxy, "GET", "/static", &[]).await;
    assert_eq!(first, b"static-body-v1");

    // A client `no-cache` forces the revalidation path deterministically
    // (no sleeps): the origin answers `304`, the client keeps the body.
    let (_, head, second) = fetch(proxy, "GET", "/static", &[("cache-control", "no-cache")]).await;
    assert_eq!(second, b"static-body-v1");
    assert_eq!(header(&head, "x-cache"), Some("REVALIDATED".to_owned()));
    assert_eq!(origin.hits("/static"), 2);
    let conditionals = origin
        .conditionals
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(conditionals, vec!["\"v1\"".to_owned()]);
    assert_eq!(metrics.snapshot().cache_revalidations, 1);

    // The origin rotates the representation: the next revalidation
    // replaces the entry instead of refreshing it.
    origin.set_body("/static", "static-body-v2", Some("\"v2\""));
    let (_, _, third) = fetch(proxy, "GET", "/static", &[("cache-control", "no-cache")]).await;
    assert_eq!(third, b"static-body-v2");
    assert_eq!(origin.hits("/static"), 3);

    // And the new representation serves from the store now.
    let (_, head, fourth) = fetch(proxy, "GET", "/static", &[]).await;
    assert_eq!(fourth, b"static-body-v2");
    assert_eq!(header(&head, "x-cache"), Some("HIT".to_owned()));
    assert_eq!(origin.hits("/static"), 3);
}

#[tokio::test]
async fn entries_expire_after_their_ttl() {
    let origin = start_origin().await;
    let (proxy, _, _handle, _serve) = start_proxy(
        origin.addr,
        CacheSettings {
            default_ttl: Duration::from_secs(1),
            ..cache_settings("web")
        },
    )
    .await;

    fetch(proxy, "GET", "/static", &[]).await;
    let (_, head, _) = fetch(proxy, "GET", "/static", &[]).await;
    assert_eq!(header(&head, "x-cache"), Some("HIT".to_owned()));
    tokio::time::sleep(Duration::from_secs(2)).await;
    // Expired with validators: the origin revalidates with a `304` and the
    // client never sees the expiry.
    let (status, head, body) = fetch(proxy, "GET", "/static", &[]).await;
    assert_eq!(status, 200);
    assert_eq!(body, b"static-body-v1");
    assert_eq!(header(&head, "x-cache"), Some("REVALIDATED".to_owned()));
    assert_eq!(origin.hits("/static"), 2);
}

#[tokio::test]
async fn concurrent_requests_share_one_origin_fetch() {
    let origin = start_origin().await;
    let (proxy, _, _handle, _serve) = start_proxy(origin.addr, cache_settings("web")).await;

    let mut tasks = Vec::new();
    for _ in 0..10 {
        tasks.push(tokio::spawn(async move {
            fetch(proxy, "GET", "/slow", &[]).await
        }));
    }
    let mut hits = 0;
    for task in tasks {
        let (status, head, body) = task.await.expect("request finishes");
        assert_eq!(status, 200);
        assert_eq!(body, b"slow-body");
        if header(&head, "x-cache") == Some("HIT".to_owned()) {
            hits += 1;
        }
    }
    assert_eq!(origin.hits("/slow"), 1, "the lock coalesced the burst");
    assert_eq!(origin.dials(), 1, "one pooled connection served the burst");
    assert_eq!(hits, 9, "every waiter served from the store");
}

#[tokio::test]
async fn head_is_served_from_the_get_entry() {
    let origin = start_origin().await;
    let (proxy, _, _handle, _serve) = start_proxy(origin.addr, cache_settings("web")).await;

    fetch(proxy, "GET", "/static", &[]).await;
    let (status, head, body) = fetch(proxy, "HEAD", "/static", &[]).await;
    assert_eq!(status, 200);
    assert!(body.is_empty(), "a HEAD has no body");
    assert_eq!(header(&head, "x-cache"), Some("HIT".to_owned()));
    assert_eq!(
        header(&head, "content-length"),
        Some("static-body-v1".len().to_string())
    );
    assert_eq!(origin.hits("/static"), 1);
}

#[tokio::test]
async fn authorization_and_ranges_bypass() {
    let origin = start_origin().await;
    let (proxy, metrics, _handle, _serve) = start_proxy(origin.addr, cache_settings("web")).await;

    for _ in 0..2 {
        let (status, head, _) = fetch(
            proxy,
            "GET",
            "/static",
            &[("authorization", "Bearer secret")],
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(header(&head, "x-cache"), None);
    }
    let (status, _, _) = fetch(proxy, "GET", "/static", &[("range", "bytes=0-3")]).await;
    assert_eq!(status, 200);
    assert_eq!(origin.hits("/static"), 3, "nothing was served nor stored");
    assert_eq!(metrics.snapshot().cache_bypasses, 3);
    assert_eq!(metrics.snapshot().cache_stores, 0);

    // The bypasses poisoned nothing: a plain request stores and hits.
    fetch(proxy, "GET", "/static", &[]).await;
    let (_, head, _) = fetch(proxy, "GET", "/static", &[]).await;
    assert_eq!(header(&head, "x-cache"), Some("HIT".to_owned()));
}

#[tokio::test]
async fn unstorable_statuses_and_directives_stream_through() {
    let origin = start_origin().await;
    let (proxy, metrics, _handle, _serve) = start_proxy(origin.addr, cache_settings("web")).await;

    for _ in 0..2 {
        let (status, _, _) = fetch(proxy, "GET", "/flaky", &[]).await;
        assert_eq!(status, 500);
    }
    assert_eq!(origin.hits("/flaky"), 2, "errors are never stored");
    for _ in 0..2 {
        fetch(proxy, "GET", "/nostore", &[]).await;
    }
    assert_eq!(origin.hits("/nostore"), 2);
    assert_eq!(metrics.snapshot().cache_stores, 0);
}

#[tokio::test]
async fn oversized_bodies_stream_through_uncached() {
    let origin = start_origin().await;
    let (proxy, _, _handle, _serve) = start_proxy(
        origin.addr,
        CacheSettings {
            // Below the 14-byte `/static` body: nothing is ever stored.
            max_entry_bytes: 4,
            ..cache_settings("web")
        },
    )
    .await;

    let (_, head, body) = fetch(proxy, "GET", "/static", &[]).await;
    assert_eq!(body, b"static-body-v1");
    assert_eq!(header(&head, "x-cache"), Some("MISS".to_owned()));
    let (_, head, _) = fetch(proxy, "GET", "/static", &[]).await;
    assert_eq!(header(&head, "x-cache"), Some("MISS".to_owned()));
    assert_eq!(origin.hits("/static"), 2);
}

#[tokio::test]
async fn cookie_affinity_disables_the_cache_at_runtime() {
    let origin = start_origin().await;
    let (proxy, metrics, _handle, _serve) = start_proxy_with(
        origin.addr,
        cache_settings("web"),
        Some(cookie_backend(origin.addr)),
    )
    .await;

    for _ in 0..3 {
        let (status, head, _) = fetch(proxy, "GET", "/static", &[]).await;
        assert_eq!(status, 200);
        // No marker at all: the lookup never ran, so the answer is not a
        // "miss" either — it bypassed entirely.
        assert_eq!(header(&head, "x-cache"), None);
    }
    assert_eq!(origin.hits("/static"), 3);
    assert_eq!(metrics.snapshot().cache_bypasses, 3);
    assert_eq!(metrics.snapshot().cache_stores, 0);
}

#[tokio::test]
async fn disk_entries_survive_a_restart() {
    let dir = std::env::temp_dir().join(format!("eqproxy-cache-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let origin = start_origin().await;

    let (proxy, _, handle, serve) = start_proxy(
        origin.addr,
        CacheSettings {
            disk_dir: Some(dir.clone()),
            ..cache_settings("web")
        },
    )
    .await;
    let (_, _, first) = fetch(proxy, "GET", "/static", &[]).await;
    assert_eq!(first, b"static-body-v1");
    handle.trigger();
    serve.await.expect("proxy stops");

    // "Restart": a new cache on the same directory, with the origin gone
    // dark (every dial fails). A hit proves the bytes came from disk.
    origin.set_body("/static", "static-body-v2", Some("\"v2\""));
    let failing = {
        use eqproxy_net::ResolvedServer;
        Arc::new(ResolvedBackend::new(
            "api",
            vec![ResolvedServer {
                addr: eqproxy_net::ServerAddr::Ip(
                    "127.0.0.2:9".parse::<SocketAddr>().expect("dead addr"),
                ),
                weight: 1,
                backup: false,
                priority: 0,
            }],
            3,
            2,
        ))
    };
    let metrics = Arc::new(Metrics::default());
    let cache = Cache::load(
        CacheSettings {
            disk_dir: Some(dir.clone()),
            ..cache_settings("web")
        },
        Arc::clone(&metrics),
    )
    .expect("disk reloads");
    let cfg = ResolvedListener::new(
        "web",
        "127.0.0.1:0".parse().expect("listen"),
        "api",
        origin.addr,
        ProxyMode::Http,
        64,
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .with_cache(cache)
    .with_backend(failing);
    let bound: BoundProxy = bind(vec![cfg], Arc::clone(&metrics))
        .await
        .expect("bind proxy");
    let addr = bound.local_addrs()[0].1;
    let (handle, signal) = shutdown::channel();
    let serve = tokio::spawn(async move {
        bound.serve(signal, WAIT).await.expect("serve");
    });
    let (status, head, body) = fetch(addr, "GET", "/static", &[]).await;
    assert_eq!(status, 200);
    assert_eq!(body, b"static-body-v1", "the bytes came from disk, not v2");
    assert_eq!(header(&head, "x-cache"), Some("HIT".to_owned()));
    assert!(
        metrics.snapshot().cache_disk_loads >= 1,
        "the reload restored the entry"
    );
    handle.trigger();
    serve.await.expect("proxy stops");
    let _ = std::fs::remove_dir_all(&dir);
}
