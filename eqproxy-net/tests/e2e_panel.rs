//! E2E of the web panel with **real sockets** (v0.8 / D6, ADR-0029): the
//! bearer token buys a session, the session drives the same write path the
//! JSON API drives, the CSRF token is the only thing that authorises a form
//! `POST`, a read session really cannot write, and a plane without
//! `[admin] panel` does not serve the pages at all.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use eqproxy_core::Metrics;
use eqproxy_net::admin::{
    self, AdminEndpoint, AdminHandle, AdminState, AdminTopology, ListenerInfo, UnixSocketOptions,
};
use eqproxy_net::{Panel, ResolvedBackend, ResolvedServer, ServerAddr, ServerModes};

const TOKEN: &str = "e2e-panel-token-0123456789";
const WRITE: &str = "e2e-panel-write-token-9876543210";
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
                    maxconn: 0,
                },
                ResolvedServer {
                    addr: ServerAddr::Ip(SERVER_B.parse().expect("addr b")),
                    weight: 1,
                    backup: false,
                    priority: 0,
                    maxconn: 0,
                },
            ],
            3,
            2,
        )
        .with_server_modes(Arc::clone(modes)),
    )
}

fn state(metrics: Arc<Metrics>, modes: Arc<ServerModes>, panel: bool) -> AdminState {
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
            backends: vec![backend(&modes)],
            caches: Vec::new(),
        })),
        modes,
        metrics,
        apply: None,
        panel: panel.then(|| Arc::new(Panel::new())),
    }
}

/// Admin plane with `[admin] panel` on (or off) and **no** applier: the
/// configuration write routes answer `503 config_unavailable`, which the panel
/// turns into the `?error=` line the browser lands on.
async fn start_panel_admin(panel: bool) -> (SocketAddr, AdminHandle) {
    let cfg = admin::ResolvedAdmin {
        endpoint: AdminEndpoint::Tcp("127.0.0.1:0".parse().expect("addr")),
        unix: UnixSocketOptions::default(),
        token: Arc::from(TOKEN),
        write_token: Some(Arc::from(WRITE)),
        panel,
    };
    let handle = admin::bind(
        cfg,
        Arc::new(state(
            Arc::new(Metrics::default()),
            Arc::new(ServerModes::new()),
            panel,
        )),
    )
    .await
    .expect("bind admin");
    let addr = handle.local_addr().expect("tcp admin endpoint");
    (addr, handle)
}

/// Sends a raw head (and optional body) and reads the whole answer.
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

fn status_line(answer: &str) -> &str {
    answer.lines().next().unwrap_or("")
}

fn body(answer: &str) -> &str {
    answer
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("")
}

fn header<'a>(answer: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}:");
    answer
        .lines()
        .find_map(|line| line.strip_prefix(&needle))
        .map(str::trim)
}

/// A `GET` of the panel, with or without a session.
fn panel_get(path: &str, session: Option<&str>) -> String {
    let mut head = format!("GET {path} HTTP/1.1\r\nhost: admin\r\n");
    if let Some(sid) = session {
        head.push_str(&format!("cookie: eqproxy_session={sid}\r\n"));
    }
    head.push_str("\r\n");
    head
}

/// A panel form `POST`. `origin` and `site` are what a browser would send.
fn panel_post(
    path: &str,
    session: Option<&str>,
    fields: &[(&str, &str)],
    origin: Option<&str>,
    site: Option<&str>,
) -> String {
    let mut encoded = String::new();
    for (name, value) in fields {
        if !encoded.is_empty() {
            encoded.push('&');
        }
        encoded.push_str(&format!("{name}={value}"));
    }
    let mut head = format!(
        "POST {path} HTTP/1.1\r\nhost: admin\r\ncontent-type: \
         application/x-www-form-urlencoded\r\ncontent-length: {}\r\n",
        encoded.len()
    );
    if let Some(sid) = session {
        head.push_str(&format!("cookie: eqproxy_session={sid}\r\n"));
    }
    if let Some(origin) = origin {
        head.push_str(&format!("origin: {origin}\r\n"));
    }
    if let Some(site) = site {
        head.push_str(&format!("sec-fetch-site: {site}\r\n"));
    }
    head.push_str(&format!("\r\n{encoded}"));
    head
}

/// The `eqproxy_session` value of a `set-cookie` answer.
fn session_of(answer: &str) -> Option<String> {
    let cookie = header(answer, "set-cookie")?;
    cookie
        .split(';')
        .next()?
        .strip_prefix("eqproxy_session=")
        .map(str::to_owned)
        .filter(|sid| !sid.is_empty())
}

/// The value of a hidden form field (`name="csrf" value="…"`).
fn hidden(html: &str, name: &str) -> String {
    let needle = format!("name=\"{name}\" value=\"");
    html.split_once(&needle)
        .and_then(|(_, rest)| rest.split_once('"').map(|(value, _)| value.to_owned()))
        .unwrap_or_else(|| panic!("no hidden field {name} in the page"))
}

async fn login(addr: SocketAddr, token: &str) -> String {
    let answer = request(
        addr,
        &panel_post("/panel/login", None, &[("token", token)], None, None),
    )
    .await;
    assert!(
        status_line(&answer).starts_with("HTTP/1.1 303"),
        "login: {answer}"
    );
    session_of(&answer).expect("session cookie")
}

#[tokio::test]
async fn the_login_flow_opens_a_session_and_the_token_never_leaks() {
    let (addr, _handle) = start_panel_admin(true).await;

    // A browser with no session gets the form, never a dashboard.
    let answer = request(addr, &panel_get("/panel", None)).await;
    assert!(status_line(&answer).starts_with("HTTP/1.1 200"), "{answer}");
    assert!(body(&answer).contains("<form method=\"post\" action=\"/panel/login\">"));
    assert!(
        !body(&answer).contains("/panel/servers/"),
        "the login page never shows the topology: {answer}"
    );
    let policy = header(&answer, "content-security-policy").expect("csp");
    assert!(policy.contains("default-src 'none'"), "{policy}");
    assert!(
        !policy.contains("script-src"),
        "no script is granted: {policy}"
    );
    assert_eq!(header(&answer, "referrer-policy"), Some("no-referrer"));
    assert_eq!(header(&answer, "x-content-type-options"), Some("nosniff"));
    assert_eq!(session_of(&answer), None, "no session before a token");

    let css = request(addr, &panel_get("/panel/app.css", None)).await;
    assert!(status_line(&css).starts_with("HTTP/1.1 200"), "{css}");
    assert!(css.contains("text/css"), "{css}");

    // An unknown page under the panel is a 404, and the API is untouched.
    let missing = request(addr, &panel_get("/panel/nope", None)).await;
    assert!(
        status_line(&missing).starts_with("HTTP/1.1 404"),
        "{missing}"
    );
    let api = request(addr, &panel_get("/api/v1/status", None)).await;
    assert!(status_line(&api).starts_with("HTTP/1.1 401"), "{api}");

    // A wrong token is refused and opens nothing.
    let refused = request(
        addr,
        &panel_post(
            "/panel/login",
            None,
            &[("token", "not-the-token")],
            None,
            None,
        ),
    )
    .await;
    assert!(
        status_line(&refused).starts_with("HTTP/1.1 401"),
        "{refused}"
    );
    assert_eq!(session_of(&refused), None, "a refusal opens no session");
    assert!(body(&refused).contains("The token was refused."));
    assert!(
        !refused.contains("not-the-token"),
        "the refused value is never echoed: {refused}"
    );

    // The read token opens a read-only session.
    let sid = login(addr, TOKEN).await;
    let answer = request(addr, &panel_get("/panel", Some(&sid))).await;
    assert!(status_line(&answer).starts_with("HTTP/1.1 200"), "{answer}");
    let page = body(&answer);
    assert!(page.contains("role read"), "{page}");
    assert!(page.contains("Read-only session"), "{page}");
    assert!(page.contains("127.0.0.1:19000"), "{page}");
    assert!(page.contains("v1"), "the revision is on the page: {page}");
    assert!(
        !page.contains("/panel/servers/"),
        "a read session is offered no action"
    );
    assert!(!answer.contains(TOKEN), "the token never reaches the page");
    assert!(!answer.contains(WRITE), "no other secret either");

    // And the write token a full one.
    let sid = login(addr, WRITE).await;
    let answer = request(addr, &panel_get("/panel", Some(&sid))).await;
    let page = body(&answer);
    assert!(page.contains("role operate"), "{page}");
    // The action of every row is the encoded path the browser posts back.
    assert!(
        page.contains("/panel/servers/api/127.0.0.1%3A19000/state"),
        "{page}"
    );
    assert!(page.contains("value=\"maintenance\""), "{page}");
    assert!(page.contains("/panel/certificates/reload"), "{page}");
    assert!(!page.contains("Read-only session"), "{page}");
}

#[tokio::test]
async fn a_session_is_required_and_a_stale_cookie_is_cleared() {
    let (addr, _handle) = start_panel_admin(true).await;

    // No session at all: a state change is sent back to the login page.
    let answer = request(
        addr,
        &panel_post(
            "/panel/servers/api/127.0.0.1:19000/state",
            None,
            &[("state", "drain")],
            None,
            None,
        ),
    )
    .await;
    assert!(status_line(&answer).starts_with("HTTP/1.1 303"), "{answer}");
    assert_eq!(header(&answer, "location"), Some("/panel"));

    // An invented session id is treated exactly like an expired one.
    let answer = request(
        addr,
        &panel_get("/panel", Some("00000000000000000000000000000000")),
    )
    .await;
    assert!(body(&answer).contains("Log in"), "{answer}");

    // Logging out revokes the session and clears the cookie.
    let sid = login(addr, WRITE).await;
    let page = body(&request(addr, &panel_get("/panel", Some(&sid))).await).to_owned();
    let csrf = hidden(&page, "csrf");
    let answer = request(
        addr,
        &panel_post("/panel/logout", Some(&sid), &[("csrf", &csrf)], None, None),
    )
    .await;
    assert!(status_line(&answer).starts_with("HTTP/1.1 303"), "{answer}");
    assert!(
        header(&answer, "set-cookie")
            .expect("cleared cookie")
            .contains("Max-Age=0"),
        "{answer}"
    );
    let after = request(addr, &panel_get("/panel", Some(&sid))).await;
    assert!(
        body(&after).contains("Log in"),
        "the session is gone: {after}"
    );

    // A second logout with the same cookie cannot even find the session.
    let answer = request(
        addr,
        &panel_post("/panel/logout", Some(&sid), &[("csrf", &csrf)], None, None),
    )
    .await;
    assert!(status_line(&answer).starts_with("HTTP/1.1 303"), "{answer}");
    assert_eq!(header(&answer, "location"), Some("/panel"));
}

#[tokio::test]
async fn the_csrf_token_and_the_origin_are_what_authorise_a_form_post() {
    let (addr, _handle) = start_panel_admin(true).await;
    let sid = login(addr, WRITE).await;
    let page = body(&request(addr, &panel_get("/panel", Some(&sid))).await).to_owned();
    let csrf = hidden(&page, "csrf");
    let action = "/panel/servers/api/127.0.0.1:19000/state";

    // No CSRF token: refused, and the slot is untouched.
    let answer = request(
        addr,
        &panel_post(action, Some(&sid), &[("state", "drain")], None, None),
    )
    .await;
    assert!(status_line(&answer).starts_with("HTTP/1.1 403"), "{answer}");
    assert!(body(&answer).contains("csrf_required"), "{answer}");

    // A wrong CSRF token: same answer.
    let answer = request(
        addr,
        &panel_post(
            action,
            Some(&sid),
            &[("state", "drain"), ("csrf", "0")],
            None,
            None,
        ),
    )
    .await;
    assert!(status_line(&answer).starts_with("HTTP/1.1 403"), "{answer}");
    assert!(body(&answer).contains("csrf_required"), "{answer}");

    // A foreign origin: refused before the token is even looked at.
    let answer = request(
        addr,
        &panel_post(
            action,
            Some(&sid),
            &[("state", "drain"), ("csrf", &csrf)],
            Some("http://evil.example"),
            None,
        ),
    )
    .await;
    assert!(status_line(&answer).starts_with("HTTP/1.1 403"), "{answer}");
    assert!(body(&answer).contains("cross_site_forbidden"), "{answer}");
    let answer = request(
        addr,
        &panel_post(
            action,
            Some(&sid),
            &[("state", "drain"), ("csrf", &csrf)],
            None,
            Some("cross-site"),
        ),
    )
    .await;
    assert!(status_line(&answer).starts_with("HTTP/1.1 403"), "{answer}");
    assert!(body(&answer).contains("cross_site_forbidden"), "{answer}");

    // With the session's own token it goes through, and the answer is the
    // `303` the browser follows.
    let answer = request(
        addr,
        &panel_post(
            action,
            Some(&sid),
            &[("state", "drain"), ("csrf", &csrf)],
            Some("http://admin"),
            None,
        ),
    )
    .await;
    assert!(status_line(&answer).starts_with("HTTP/1.1 303"), "{answer}");
    assert_eq!(header(&answer, "location"), Some("/panel?applied=drain"));

    // The slot really is in `drain`, on the API and on the page.
    let status = request(
        addr,
        &format!(
            "GET /api/v1/status HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {TOKEN}\r\n\r\n"
        ),
    )
    .await;
    assert!(
        body(&status).contains("\"state\":\"drain\""),
        "the shared write path ran: {status}"
    );
    // The browser lands on the `303` target: the revision the write left and
    // the action that was applied are on the page.
    let page =
        body(&request(addr, &panel_get("/panel?applied=drain", Some(&sid))).await).to_owned();
    assert!(page.contains("Applied: drain"), "{page}");
    let metrics = request(
        addr,
        &format!("GET /metrics HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {TOKEN}\r\n\r\n"),
    )
    .await;
    assert!(
        body(&metrics).contains("eqproxy_backend_servers_draining 1"),
        "{metrics}"
    );

    // A refused candidate on a plane with no applier: the panel lands on the
    // applier's own error code instead of a JSON body.
    let answer = request(
        addr,
        &panel_post(
            "/panel/backends/api",
            Some(&sid),
            &[
                ("csrf", &csrf),
                ("revision", "v1"),
                ("table", "server = \"127.0.0.1:1\""),
            ],
            None,
            None,
        ),
    )
    .await;
    assert!(status_line(&answer).starts_with("HTTP/1.1 303"), "{answer}");
    assert_eq!(
        header(&answer, "location"),
        Some("/panel?error=config_unavailable")
    );
}

#[tokio::test]
async fn a_read_session_reads_and_cannot_write_anything() {
    let (addr, _handle) = start_panel_admin(true).await;
    let sid = login(addr, TOKEN).await;
    let page = body(&request(addr, &panel_get("/panel", Some(&sid))).await).to_owned();
    // The only form a read session is shown is the logout one; its token is
    // the session's own, which is exactly what a hostile page would have to
    // steal — and it still cannot write.
    let csrf = hidden(&page, "csrf");
    let answer = request(
        addr,
        &panel_post(
            "/panel/servers/api/127.0.0.1:19000/state",
            Some(&sid),
            &[("state", "drain"), ("csrf", &csrf)],
            None,
            None,
        ),
    )
    .await;
    assert!(status_line(&answer).starts_with("HTTP/1.1 403"), "{answer}");
    assert!(body(&answer).contains("read_only_session"), "{answer}");

    let answer = request(
        addr,
        &panel_post(
            "/panel/backends/api",
            Some(&sid),
            &[
                ("csrf", &csrf),
                ("revision", "v1"),
                ("table", "all_backups = true"),
            ],
            None,
            None,
        ),
    )
    .await;
    assert!(status_line(&answer).starts_with("HTTP/1.1 403"), "{answer}");
    assert!(body(&answer).contains("read_only_session"), "{answer}");

    let answer = request(
        addr,
        &panel_post(
            "/panel/certificates/reload",
            Some(&sid),
            &[("csrf", &csrf)],
            None,
            None,
        ),
    )
    .await;
    assert!(status_line(&answer).starts_with("HTTP/1.1 403"), "{answer}");
    assert!(body(&answer).contains("read_only_session"), "{answer}");

    // And the dashboard still reads.
    let answer = request(addr, &panel_get("/panel", Some(&sid))).await;
    assert!(status_line(&answer).starts_with("HTTP/1.1 200"), "{answer}");
    assert!(body(&answer).contains("Backend api"), "{answer}");
}

#[tokio::test]
async fn the_panel_is_not_served_unless_the_config_turns_it_on() {
    let (addr, _handle) = start_panel_admin(false).await;

    // With the panel off there is no page at all: the route is unknown, so an
    // anonymous request gets the plane's ordinary `401` and a authenticated
    // one a `404` — never a rendered page and never a cookie.
    let answer = request(addr, &panel_get("/panel", None)).await;
    assert!(
        status_line(&answer).starts_with("HTTP/1.1 401"),
        "the panel is off: {answer}"
    );
    assert!(!answer.contains("<html"), "no page is rendered: {answer}");
    let answer = request(
        addr,
        &format!("GET /panel HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {TOKEN}\r\n\r\n"),
    )
    .await;
    assert!(
        status_line(&answer).starts_with("HTTP/1.1 404"),
        "an unknown route for a known role: {answer}"
    );
    let login = request(
        addr,
        &panel_post("/panel/login", None, &[("token", WRITE)], None, None),
    )
    .await;
    assert!(
        status_line(&login).starts_with("HTTP/1.1 401")
            || status_line(&login).starts_with("HTTP/1.1 404"),
        "no session route either: {login}"
    );
    assert_eq!(session_of(&login), None);

    // The API is exactly as it was.
    let answer = request(
        addr,
        &format!(
            "GET /api/v1/status HTTP/1.1\r\nhost: admin\r\nauthorization: Bearer {WRITE}\r\n\r\n"
        ),
    )
    .await;
    assert!(status_line(&answer).starts_with("HTTP/1.1 200"), "{answer}");
}
