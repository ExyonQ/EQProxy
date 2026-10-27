//! Web panel (v0.8 / D6, ADR-0029): a server-rendered client of the
//! administration API.
//!
//! Four rules shape this module:
//!
//! - **One implementation.** Every action the panel offers calls the same
//!   function the JSON API calls ([`crate::admin::apply_server_state`], the
//!   same [`Outcome::Apply`] for the configuration writes and the certificate
//!   action), so "what `maintenance` does" cannot drift between a CLI client
//!   and the browser.
//! - **No JavaScript.** The page is HTML and a stylesheet, and every action is
//!   a plain `POST` form. The whole panel is therefore verifiable with an HTTP
//!   client, and there is no script to audit and no `script-src` to grant: the
//!   policy is `default-src 'none'; style-src 'self'`.
//! - **Sessions, not tokens in the browser.** The bearer token is exchanged
//!   once (`POST /panel/login`) for an `HttpOnly`, `SameSite=Strict` cookie
//!   scoped to `Path=/panel`, plus a CSRF token that every form carries and the
//!   server checks against that session. A cross-site `POST` cannot ride the
//!   cookie: it would need a token it cannot read. The JSON API never looks at
//!   a cookie, so its own contract (bearer token, no browser origin) is
//!   untouched.
//! - **Opt-in.** `[admin] panel = true`. Off by default, and with it off every
//!   `/panel` path is a `404` like any other unknown route.
//!
//! Sessions live in memory only: id, role, CSRF token and last-seen instant.
//! No request body is stored, nothing is persisted, and the lines the panel
//! writes are the same `AUDIT` records the API writes (they name the path, the
//! role and the peer, never the secret). Stopping the process ends every
//! session.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use crate::admin::{
    AdminState, AuditFields, ConfigChange, Outcome, Peer, Response, Role, Tokens,
    apply_server_state, audit, header_values, token_matches,
};
use crate::balancer::ServerMode;

/// Idle window of a panel session. A session that has not been used for this
/// long is gone, whatever the cookie still says.
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Sessions kept at once. An expired one goes first; past the bound the oldest
/// is evicted, so the panel cannot grow the process without limit.
pub const MAX_SESSIONS: usize = 16;

/// Body accepted by a panel form. A whole `[backend.*]` table fits
/// comfortably; anything larger is refused before it is read.
pub const MAX_PANEL_BODY_BYTES: usize = 64 * 1024;

/// Session cookie name. Scoped to `/panel`, so the API routes never see it
/// even from a browser that has one.
const COOKIE: &str = "eqproxy_session";

/// Content security policy of every panel page. No script is granted at all:
/// the panel does not ship one.
const CSP: &str = "default-src 'none'; style-src 'self'; form-action 'self'; \
                   base-uri 'none'; frame-ancestors 'none'";

const STYLESHEET: &str = "\
:root { color-scheme: light dark; }
body { font: 14px/1.5 ui-sans-serif, system-ui, sans-serif; margin: 2rem auto;
       max-width: 60rem; padding: 0 1rem; }
h1 { font-size: 1.35rem; } h2 { font-size: 1.1rem; margin-top: 2rem; }
table { border-collapse: collapse; width: 100%; margin: 0.5rem 0 1rem; }
th, td { border: 1px solid currentColor; padding: 0.3rem 0.5rem; text-align: left; }
th { font-weight: 600; }
form { display: inline-block; margin: 0 0.25rem 0.25rem 0; }
button { font: inherit; padding: 0.15rem 0.5rem; }
textarea { font: 12px/1.4 ui-monospace, monospace; width: 100%; height: 8rem; }
p.form-row { display: block; margin: 0.5rem 0; }
.muted { opacity: 0.7; }
.banner { padding: 0.5rem 0.75rem; border: 1px solid currentColor; margin: 1rem 0; }
input[type=text], input[type=password] { font: inherit; padding: 0.2rem; }
";

/// One authenticated panel session.
#[derive(Debug, Clone)]
struct Session {
    role: Role,
    /// Token bound to this session: a form field, never a cookie, because a
    /// cookie alone is exactly what a cross-site request can carry.
    csrf: String,
    last_seen: Instant,
}

/// The panel: a session table and the pages rendered from the live topology.
#[derive(Debug)]
pub struct Panel {
    sessions: Mutex<HashMap<String, Session>>,
    idle: Duration,
}

impl Default for Panel {
    fn default() -> Self {
        Self::new()
    }
}

impl Panel {
    /// Panel with the production idle window.
    #[must_use]
    pub fn new() -> Self {
        Self::with_idle(SESSION_IDLE_TIMEOUT)
    }

    /// Panel with a chosen idle window (tests shorten it).
    #[must_use]
    pub fn with_idle(idle: Duration) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            idle,
        }
    }

    /// Live sessions (tests assert the bound).
    #[must_use]
    pub fn len(&self) -> usize {
        let mut sessions = self.lock();
        let idle = self.idle;
        prune(&mut sessions, idle, None);
        sessions.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Session>> {
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Opens a session for `role`: the cookie value and the CSRF token. `None`
    /// when the system RNG fails — a session is never invented from a weak
    /// secret, the login is refused instead.
    fn start(&self, role: Role) -> Option<(String, String)> {
        let sid = secret()?;
        let csrf = secret()?;
        let mut sessions = self.lock();
        prune(&mut sessions, self.idle, Some(MAX_SESSIONS));
        sessions.insert(
            sid.clone(),
            Session {
                role,
                csrf: csrf.clone(),
                last_seen: Instant::now(),
            },
        );
        Some((sid, csrf))
    }

    /// Session of `sid`, refreshing its idle window. `None` for an unknown or
    /// expired id.
    fn touch(&self, sid: &str) -> Option<(Role, String)> {
        let mut sessions = self.lock();
        let idle = self.idle;
        prune(&mut sessions, idle, None);
        let session = sessions.get_mut(sid)?;
        session.last_seen = Instant::now();
        Some((session.role, session.csrf.clone()))
    }

    /// Ends one session (logout). `true` when there was one.
    fn revoke(&self, sid: &str) -> bool {
        self.lock().remove(sid).is_some()
    }
}

/// Drops expired sessions and, when `cap` is given, the oldest ones until the
/// table fits it.
fn prune(sessions: &mut HashMap<String, Session>, idle: Duration, cap: Option<usize>) {
    let now = Instant::now();
    sessions.retain(|_, session| now.duration_since(session.last_seen) < idle);
    let Some(cap) = cap else { return };
    while sessions.len() >= cap {
        let Some(oldest) = sessions
            .iter()
            .min_by_key(|(_, session)| session.last_seen)
            .map(|(sid, _)| sid.clone())
        else {
            break;
        };
        sessions.remove(&oldest);
    }
}

/// 32 random bytes as hex: the session id and the CSRF token. `None` when the
/// system RNG cannot answer.
fn secret() -> Option<String> {
    let mut bytes = [0u8; 32];
    SystemRandom::new().fill(&mut bytes).ok()?;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    Some(out)
}

/// Whether this request addresses the panel at all: the router in
/// [`crate::admin`] hands every `/panel` path here when the panel is on.
#[must_use]
pub fn wants(head: &str) -> bool {
    let Some(target) = head.split(' ').nth(1) else {
        return false;
    };
    let path = target.split('?').next().unwrap_or(target);
    path == "/panel" || path.starts_with("/panel/")
}

impl Panel {
    /// Routes one `/panel` request. Answers [`Outcome::Done`] for the pages and
    /// the actions it completes, and [`Outcome::Apply`] for the writes that go
    /// through the same configuration pipeline as the API.
    pub(crate) fn respond<'a>(
        &self,
        head: &'a str,
        body: Option<&[u8]>,
        tokens: &Tokens,
        state: &'a AdminState,
        peer: Peer,
    ) -> Outcome<'a> {
        let mut parts = head.split(' ').filter(|part| !part.is_empty());
        let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
            return Outcome::done(Response::text(400, "bad request"));
        };
        // Borrowed from the head on purpose: an `Apply` outcome carries the
        // path to the applier's audit line.
        let path = target.split('?').next().unwrap_or(target);
        let query = target.split_once('?').map(|(_, query)| query).unwrap_or("");
        match method {
            "GET" => self.get(path, head, state, query),
            "POST" => self.post(path, head, body, tokens, state, peer),
            _ => Outcome::done(
                Response::error(405, "method_not_allowed")
                    .with_header("allow", "GET, POST".to_owned()),
            ),
        }
    }

    /// `GET /panel` (the dashboard or the login page) and the stylesheet.
    fn get<'a>(&self, path: &str, head: &str, state: &'a AdminState, query: &str) -> Outcome<'a> {
        if path == "/panel/app.css" {
            return Outcome::done(panel_response(
                200,
                "text/css; charset=utf-8",
                STYLESHEET.to_owned(),
            ));
        }
        if path != "/panel" {
            return Outcome::done(Response::error(404, "not_found"));
        }
        let session = cookie(head).and_then(|sid| self.touch(&sid));
        match session {
            Some((role, csrf)) => Outcome::done(self.dashboard(state, role, &csrf, query)),
            None => Outcome::done(login_page(None)),
        }
    }

    /// `POST` of a form: login, logout, and the three actions.
    fn post<'a>(
        &self,
        path: &'a str,
        head: &'a str,
        body: Option<&[u8]>,
        tokens: &Tokens,
        state: &'a AdminState,
        peer: Peer,
    ) -> Outcome<'a> {
        let fields = match form(head, body) {
            Ok(fields) => fields,
            Err(response) => return Outcome::done(response),
        };
        if path == "/panel/login" {
            return self.login(head, tokens, peer, &fields);
        }
        // Everything else needs a live session.
        let session = match cookie(head) {
            Some(sid) => self.touch(&sid).map(|(role, csrf)| (sid, role, csrf)),
            None => None,
        };
        let Some((sid, role, csrf)) = session else {
            // No session, or one that expired: back to the login page. The
            // cookie is cleared so the browser stops sending a dead id.
            return Outcome::done(
                Response::redirect("/panel").with_header("set-cookie", expired_cookie()),
            );
        };
        let record = |status: u16| {
            Some(audit(
                peer,
                role,
                "POST",
                path,
                status,
                AuditFields::default(),
            ))
        };
        // Cross-site first: a browser that says it came from elsewhere is
        // refused whatever it carries.
        if !same_site(head) {
            return Outcome::done_with(audit_response(403, "cross_site_forbidden"), record(403));
        }
        let provided = fields.get("csrf").cloned().unwrap_or_default();
        if !token_matches(&csrf, &provided) {
            return Outcome::done_with(audit_response(403, "csrf_required"), record(403));
        }
        if path == "/panel/logout" {
            self.revoke(&sid);
            return Outcome::done_with(
                Response::redirect("/panel").with_header("set-cookie", expired_cookie()),
                record(303),
            );
        }
        if role != Role::Write {
            // A read session is a client of a read-only plane: it reads the
            // dashboard and cannot mutate anything.
            let code = if tokens.write_configured() {
                "read_only_session"
            } else {
                "write_disabled"
            };
            return Outcome::done_with(audit_response(403, code), record(403));
        }
        if let Some((backend, target)) = server_state_route(path) {
            return self.server_state(state, &backend, &target, &fields, peer, role);
        }
        if path == "/panel/certificates/reload" {
            return Outcome::Apply {
                change: ConfigChange::Reload,
                if_match: None,
                role,
                method: "POST",
                path,
                back_to_panel: true,
            };
        }
        if let Some((kind, name)) = config_route(path) {
            let Some(revision) = fields.get("revision").cloned() else {
                return Outcome::done_with(
                    audit_response(428, "precondition_required"),
                    record(428),
                );
            };
            let Some(table) = fields.get("table").cloned() else {
                return Outcome::done_with(audit_response(400, "invalid_body"), record(400));
            };
            let change = match kind {
                ConfigKind::Backend => ConfigChange::Backend { name, table },
                ConfigKind::Listener => ConfigChange::Listener { name, table },
            };
            return Outcome::Apply {
                change,
                if_match: Some(revision),
                role,
                method: "POST",
                path,
                back_to_panel: true,
            };
        }
        Outcome::done_with(Response::error(404, "not_found"), record(404))
    }

    /// `POST /panel/login`: the bearer token becomes a session. The token is
    /// checked exactly like the API checks it, and a failed attempt is audited
    /// with role `none`.
    fn login<'a>(
        &self,
        head: &'a str,
        tokens: &Tokens,
        peer: Peer,
        fields: &HashMap<String, String>,
    ) -> Outcome<'a> {
        let record = |role: Role, status: u16| {
            Some(audit(
                peer,
                role,
                "POST",
                "/panel/login",
                status,
                AuditFields::default(),
            ))
        };
        if !same_site(head) {
            return Outcome::done_with(
                audit_response(403, "cross_site_forbidden"),
                record(Role::None, 403),
            );
        }
        let role = tokens.role(fields.get("token").map(String::as_str));
        if role == Role::None {
            return Outcome::done_with(login_page(Some("invalid_token")), record(role, 401));
        }
        let Some((sid, _csrf)) = self.start(role) else {
            return Outcome::done_with(
                audit_response(500, "session_unavailable"),
                record(role, 500),
            );
        };
        Outcome::done_with(
            Response::redirect("/panel").with_header("set-cookie", cookie_header(&sid)),
            record(role, 303),
        )
    }

    /// Applies one state to one slot through the shared implementation.
    fn server_state<'a>(
        &self,
        state: &'a AdminState,
        backend: &str,
        target: &str,
        fields: &HashMap<String, String>,
        peer: Peer,
        role: Role,
    ) -> Outcome<'a> {
        let record = |status: u16| {
            Some(audit(
                peer,
                role,
                "POST",
                "/panel/servers/{backend}/{target}/state",
                status,
                AuditFields::default(),
            ))
        };
        let Some(mode) = fields
            .get("state")
            .and_then(|value| ServerMode::parse(value))
        else {
            return Outcome::done_with(audit_response(400, "invalid_state"), record(400));
        };
        match apply_server_state(state, backend, target, mode) {
            Ok(_) => Outcome::done_with(
                Response::redirect(&format!("/panel?applied={}", mode.as_str())),
                record(303),
            ),
            Err((status, code)) => Outcome::done_with(audit_response(status, code), record(status)),
        }
    }

    /// The page: live topology, the per-server actions and the table editors.
    fn dashboard(&self, state: &AdminState, role: Role, csrf: &str, query: &str) -> Response {
        let topology = state.read_topology();
        let write = role == Role::Write;
        let mut body = String::new();
        body.push_str(&format!(
            "<h1>EQProxy <span class=\"muted\">panel</span></h1>\n\
             <p class=\"muted\">version {} · uptime {}s · revision {} · role {}</p>\n",
            escape(state.version),
            state.started.elapsed().as_secs(),
            escape(&topology.revision),
            role.as_str()
        ));
        body.push_str(&format!(
            "<form method=\"post\" action=\"/panel/logout\">{}\
             <button type=\"submit\">Log out</button></form>\n",
            csrf_field(csrf)
        ));
        body.push_str(&notice(query));
        if !write {
            body.push_str(
                "<p class=\"banner\">Read-only session: log in with the write token to change \
                 server state, apply tables or reload certificates.</p>\n",
            );
        }

        body.push_str(
            "<h2>Listeners</h2>\n<table>\n<tr><th>name</th><th>listen</th><th>mode</th>\
             <th>backend</th><th>maxconn</th><th>TLS (sha256)</th></tr>\n",
        );
        for listener in &topology.listeners {
            body.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                escape(&listener.name),
                escape(&listener.listen),
                escape(&listener.mode),
                escape(&listener.backend),
                listener.maxconn,
                match &listener.tls_fingerprint {
                    Some(fingerprint) => escape(fingerprint),
                    None => "—".to_owned(),
                }
            ));
        }
        body.push_str("</table>\n");

        for backend in &topology.backends {
            body.push_str(&format!(
                "<h2>Backend {}</h2>\n<p class=\"muted\">balance {} · all_backups {} · \
                 health_check {}</p>\n<table>\n<tr><th>server</th><th>state</th>\
                 <th>healthy</th><th>active</th><th>drained</th><th>weight</th><th>backup</th>\
                 <th>priority</th><th>state change</th></tr>\n",
                escape(&backend.name),
                escape(backend.balancer.algorithm().as_str()),
                backend.balancer.all_backups(),
                backend.health_check.is_some(),
            ));
            for server in backend.balancer.servers_view() {
                let action = format!(
                    "/panel/servers/{}/{}/state",
                    escape_path(&backend.name),
                    escape_path(&server.target)
                );
                let buttons = if write {
                    let button = |label: &str, mode: &str| {
                        format!(
                            "<form method=\"post\" action=\"{action}\">{}<input type=\"hidden\" \
                             name=\"state\" value=\"{mode}\"><button type=\"submit\">{label}\
                             </button></form>",
                            csrf_field(csrf)
                        )
                    };
                    format!(
                        "{}{}{}",
                        button("ready", "ready"),
                        button("drain", "drain"),
                        button("maintenance", "maintenance")
                    )
                } else {
                    String::new()
                };
                body.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
                     <td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    escape(&server.target),
                    escape(server.mode.as_str()),
                    server.up,
                    server.active,
                    server.drained,
                    server.weight,
                    server.backup,
                    server.priority,
                    buttons
                ));
            }
            body.push_str("</table>\n");
        }

        body.push_str("<h2>Apply a table</h2>\n");
        if write {
            body.push_str(
                "<p class=\"muted\">The body is the whole table: a write replaces it, so a \
                 subtable left out really is removed. `If-Match` is the revision above.</p>\n",
            );
            for (kind, label) in [("backends", "backend"), ("listeners", "listener")] {
                body.push_str(&format!(
                    "<form method=\"post\" action=\"/panel/{kind}/{{name}}\">{}",
                    csrf_field(csrf)
                ));
                body.push_str(&format!(
                    "<p class=\"form-row\"><input type=\"text\" name=\"name\" value=\"\" \
                     placeholder=\"{label} name\" required> <input type=\"text\" name=\"revision\" \
                     value=\"{}\" readonly size=\"6\"> <button type=\"submit\">Apply {label}\
                     </button></p>\n",
                    escape(&topology.revision)
                ));
                body.push_str(&format!(
                    "<textarea name=\"table\" placeholder=\"[{label}.NAME]&#10;…\"></textarea></form>\n"
                ));
            }
            body.push_str(&format!(
                "<form method=\"post\" action=\"/panel/certificates/reload\">{}<button \
                 type=\"submit\">Reload certificates</button></form>\n",
                csrf_field(csrf)
            ));
        } else {
            body.push_str("<p class=\"muted\">Read-only session.</p>\n");
        }
        panel_page(200, &body)
    }
}

/// The line the `303` of an action lands on: what was applied, or the
/// applier's own error code. Only the two known shapes are printed, so a value
/// in the URL can never become markup.
fn notice(query: &str) -> String {
    let field = |name: &str| {
        query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.to_owned())
    };
    match (field("applied"), field("error")) {
        (Some(applied), _) => format!("<p class=\"banner\">Applied: {}</p>\n", escape(&applied)),
        (_, Some(error)) => format!(
            "<p class=\"banner\">Refused: {} (nothing changed)</p>\n",
            escape(&error)
        ),
        _ => String::new(),
    }
}

/// The login page. `error` is a short code chosen here, never a value taken
/// from the request.
fn login_page(error: Option<&str>) -> Response {
    let message = match error {
        Some("invalid_token") => "<p class=\"banner\">The token was refused.</p>\n",
        _ => "",
    };
    let page = format!(
        "<h1>EQProxy <span class=\"muted\">panel</span></h1>\n\
         {message}<p>Paste a bearer token to open a session. The read token opens a read-only \
         panel; the write token lets you change server state, apply tables and reload \
         certificates.</p>\n\
         <form method=\"post\" action=\"/panel/login\">\
         <p><input type=\"password\" name=\"token\" autocomplete=\"off\" required> \
         <button type=\"submit\">Log in</button></p></form>\n\
         <p class=\"muted\">The token is exchanged for a session cookie scoped to \
         <code>/panel</code>; it is never stored, echoed or logged.</p>\n"
    );
    panel_page(if error.is_some() { 401 } else { 200 }, &page)
}

/// One HTML answer with the panel's security headers.
fn panel_page(status: u16, body: &str) -> Response {
    let page = format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>EQProxy panel</title>\n<link rel=\"stylesheet\" href=\"/panel/app.css\">\n\
         </head>\n<body>\n{body}</body>\n</html>\n"
    );
    panel_response(status, "text/html; charset=utf-8", page)
}

/// A response with the panel's headers: no script, no framing, no referrer.
fn panel_response(status: u16, content_type: &'static str, body: String) -> Response {
    Response {
        status,
        content_type,
        extra: Vec::new(),
        body: body.into_bytes(),
    }
    .with_header("content-security-policy", CSP.to_owned())
    .with_header("x-content-type-options", "nosniff".to_owned())
    .with_header("referrer-policy", "no-referrer".to_owned())
}

/// A machine-readable refusal: the same `{"error":…}` document the API
/// answers, so a script that drives the panel reads the same codes.
fn audit_response(status: u16, code: &str) -> Response {
    Response::error(status, code)
}

fn cookie_header(sid: &str) -> String {
    format!(
        "{COOKIE}={sid}; HttpOnly; SameSite=Strict; Path=/panel; Max-Age={}",
        SESSION_IDLE_TIMEOUT.as_secs()
    )
}

fn expired_cookie() -> String {
    format!("{COOKIE}=; HttpOnly; SameSite=Strict; Path=/panel; Max-Age=0")
}

/// Session cookie value, if the request carries one.
fn cookie(head: &str) -> Option<String> {
    let prefix = format!("{COOKIE}=");
    for value in header_values(head, "cookie") {
        for part in value.split(';') {
            let part = part.trim();
            if let Some(sid) = part.strip_prefix(&prefix)
                && !sid.is_empty()
            {
                return Some(sid.to_owned());
            }
        }
    }
    None
}

/// Whether the request may be answered: a browser that declares a cross-site
/// fetch is refused, and a declared `Origin` must be this very host. A client
/// that declares neither (a script, `curl`) passes — the CSRF token is still
/// required for every state change.
fn same_site(head: &str) -> bool {
    if header_values(head, "sec-fetch-site")
        .iter()
        .any(|value| value.trim().eq_ignore_ascii_case("cross-site"))
    {
        return false;
    }
    let origins = header_values(head, "origin");
    let hosts = header_values(head, "host");
    let (Some(origin), Some(host)) = (origins.first(), hosts.first()) else {
        // No declared origin: a script, not a browser page. The CSRF token is
        // what gates the state changes either way.
        return origins.is_empty();
    };
    let Some(authority) = origin.split("://").nth(1) else {
        return false;
    };
    authority.trim().eq_ignore_ascii_case(host.trim())
}

/// Parses an `application/x-www-form-urlencoded` body. Any other declared
/// media type is refused, exactly like the JSON routes refuse theirs.
fn form(head: &str, body: Option<&[u8]>) -> Result<HashMap<String, String>, Response> {
    let media = header_values(head, "content-type")
        .first()
        .cloned()
        .unwrap_or_default();
    if !media.starts_with("application/x-www-form-urlencoded") {
        return Err(Response::error(415, "unsupported_media_type"));
    }
    let body = body.unwrap_or_default();
    if body.len() > MAX_PANEL_BODY_BYTES {
        return Err(Response::error(413, "content_too_large"));
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return Err(Response::error(400, "invalid_body"));
    };
    let mut fields = HashMap::new();
    for pair in text.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        fields.insert(percent_decode(name), percent_decode(value));
    }
    Ok(fields)
}

/// `+` is a space and `%XX` is one byte; an incomplete escape is kept
/// literally rather than guessed.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let digit = |byte: u8| (byte as char).to_digit(16);
                match (
                    digit(bytes[index + 1]).zip(digit(bytes[index + 2])),
                    index + 2 < bytes.len(),
                ) {
                    (Some((high, low)), true) => {
                        out.push((high * 16 + low) as u8);
                        index += 3;
                    }
                    _ => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `[backend.name]` / `[listener.name]` form paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigKind {
    Backend,
    Listener,
}

/// `/panel/backends/{name}` or `/panel/listeners/{name}`. The segment is
/// percent-decoded: the page encodes what it puts in an `action`, and a name
/// is a user value, not an escape sequence.
fn config_route(path: &str) -> Option<(ConfigKind, String)> {
    let segments: Vec<&str> = path.split('/').collect();
    let (kind, name) = match segments.as_slice() {
        ["", "panel", "backends", name] if !name.is_empty() => (ConfigKind::Backend, *name),
        ["", "panel", "listeners", name] if !name.is_empty() => (ConfigKind::Listener, *name),
        _ => return None,
    };
    Some((kind, percent_decode(name)))
}

/// `/panel/servers/{backend}/{target}/state`, both segments decoded for the
/// same reason (an `IP:PORT` target would otherwise arrive as `IP%3APORT`).
fn server_state_route(path: &str) -> Option<(String, String)> {
    match path.split('/').collect::<Vec<_>>().as_slice() {
        ["", "panel", "servers", backend, target, "state"]
            if !backend.is_empty() && !target.is_empty() =>
        {
            Some((percent_decode(backend), percent_decode(target)))
        }
        _ => None,
    }
}

/// Hidden CSRF field of every state-changing form.
fn csrf_field(csrf: &str) -> String {
    format!(
        "<input type=\"hidden\" name=\"csrf\" value=\"{}\">",
        escape(csrf)
    )
}

/// `encodeURIComponent`-equivalent for a path segment: everything outside the
/// unreserved set is escaped, so a target like `[::1]:9000` survives the round
/// trip through the form action.
fn escape_path(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*byte as char);
            }
            byte => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

/// HTML escaping for every value taken from the topology or a query string.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            character => out.push(character),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_is_only_valid_for_its_idle_window() {
        let panel = Panel::with_idle(Duration::from_millis(80));
        let (sid, _) = panel.start(Role::Read).expect("session");
        assert_eq!(panel.touch(&sid).map(|(role, _)| role), Some(Role::Read));
        std::thread::sleep(Duration::from_millis(120));
        assert!(panel.touch(&sid).is_none(), "an idle session is gone");
        assert!(panel.is_empty());
    }

    #[test]
    fn the_session_table_is_bounded_and_evicts_the_oldest() {
        let panel = Panel::with_idle(Duration::from_secs(60));
        let mut ids = Vec::new();
        for _ in 0..MAX_SESSIONS + 4 {
            let (sid, _) = panel.start(Role::Write).expect("session");
            ids.push(sid);
        }
        assert_eq!(panel.len(), MAX_SESSIONS);
        assert!(
            panel.touch(&ids[0]).is_none(),
            "the oldest session was evicted before the table overflowed"
        );
        assert!(panel.touch(ids.last().expect("last")).is_some());
    }

    #[test]
    fn logout_revokes_only_that_session() {
        let panel = Panel::with_idle(Duration::from_secs(60));
        let (first, _) = panel.start(Role::Read).expect("session");
        let (second, _) = panel.start(Role::Read).expect("session");
        assert!(panel.revoke(&first));
        assert!(panel.touch(&first).is_none());
        assert!(panel.touch(&second).is_some());
        assert!(!panel.revoke("not-a-session"));
    }

    #[test]
    fn an_id_and_its_csrf_token_are_independent_secrets() {
        let panel = Panel::with_idle(Duration::from_secs(60));
        let (sid, csrf) = panel.start(Role::Write).expect("session");
        assert_eq!(sid.len(), 64);
        assert_eq!(csrf.len(), 64);
        let (other_sid, other_csrf) = panel.start(Role::Write).expect("session");
        assert_ne!(sid, other_sid);
        assert_ne!(csrf, other_csrf);
        let (_, live) = panel.touch(&sid).expect("live session");
        assert!(token_matches(&live, &csrf));
        assert!(!token_matches(&live, &other_csrf));
    }

    #[test]
    fn the_panel_owns_the_panel_paths_only() {
        assert!(wants("GET /panel HTTP/1.1\r\n"));
        assert!(wants("GET /panel/app.css HTTP/1.1\r\n"));
        assert!(wants(
            "POST /panel/servers/api/127.0.0.1:9000/state HTTP/1.1\r\n"
        ));
        assert!(!wants("GET /api/v1/status HTTP/1.1\r\n"));
        assert!(!wants("GET /panelx HTTP/1.1\r\n"));
        assert!(!wants("GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn forms_are_decoded_and_only_a_declared_form_media_type_is_read() {
        let head = "POST /panel/login HTTP/1.1\r\ncontent-type: \
                    application/x-www-form-urlencoded\r\n\r\n";
        let fields = form(head, Some(b"token=a%3Db+c&csrf=0%2F1")).expect("form");
        assert_eq!(fields.get("token").map(String::as_str), Some("a=b c"));
        assert_eq!(fields.get("csrf").map(String::as_str), Some("0/1"));
        let json = "POST /panel/login HTTP/1.1\r\ncontent-type: application/json\r\n\r\n";
        assert_eq!(form(json, Some(b"{}")).map(|_| ()).unwrap_err().status, 415);
        // A partial escape is kept literally instead of guessed.
        let fields = form(head, Some(b"token=%zz&csrf=")).expect("form");
        assert_eq!(fields.get("token").map(String::as_str), Some("%zz"));
    }

    #[test]
    fn the_action_paths_of_the_page_are_routed_back_to_the_same_names() {
        // What the page renders (escaped) is what the browser posts back.
        let encoded = format!(
            "/panel/servers/{}/{}/state",
            escape_path("api"),
            escape_path("[::1]:9000")
        );
        assert_eq!(
            server_state_route(&encoded),
            Some(("api".to_owned(), "[::1]:9000".to_owned()))
        );
        assert_eq!(
            server_state_route("/panel/servers/api/127.0.0.1:9000/state"),
            Some(("api".to_owned(), "127.0.0.1:9000".to_owned()))
        );
        assert_eq!(
            config_route("/panel/backends/edge%20one"),
            Some((ConfigKind::Backend, "edge one".to_owned()))
        );
        assert_eq!(server_state_route("/panel/servers/api/x"), None);
    }

    #[test]
    fn a_cross_site_request_is_refused_and_a_same_host_one_is_not() {
        let cross = "POST /panel HTTP/1.1\r\nhost: 127.0.0.1:8080\r\n\
                     sec-fetch-site: cross-site\r\norigin: http://evil.example\r\n\r\n";
        assert!(!same_site(cross));
        let foreign = "POST /panel HTTP/1.1\r\nhost: 127.0.0.1:8080\r\n\
                       origin: http://127.0.0.1:9999\r\n\r\n";
        assert!(!same_site(foreign));
        let same = "POST /panel HTTP/1.1\r\nhost: 127.0.0.1:8080\r\n\
                    origin: http://127.0.0.1:8080\r\n\r\n";
        assert!(same_site(same));
        let script = "POST /panel HTTP/1.1\r\nhost: 127.0.0.1:8080\r\n\r\n";
        assert!(same_site(script));
        // A browser behind a TLS front end sends `https`; the authority is
        // what has to match.
        let fronted = "POST /panel HTTP/1.1\r\nhost: admin.example\r\n\
                       origin: https://admin.example\r\n\r\n";
        assert!(same_site(fronted));
    }

    #[test]
    fn the_session_cookie_is_scoped_and_never_echoed_as_a_value() {
        let header = cookie_header("abc123");
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("SameSite=Strict"));
        assert!(header.contains("Path=/panel"));
        let head = "GET /panel HTTP/1.1\r\ncookie: other=1; eqproxy_session=abc123\r\n\r\n";
        assert_eq!(cookie(head).as_deref(), Some("abc123"));
        assert_eq!(
            cookie("GET /panel HTTP/1.1\r\ncookie: eqproxy_session=\r\n\r\n"),
            None
        );
        assert_eq!(cookie("GET /panel HTTP/1.1\r\n\r\n"), None);
    }

    #[test]
    fn a_hostile_name_is_escaped_in_every_position() {
        let hostile = "\"><script>alert(1)</script>";
        let escaped = escape(hostile);
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('"'));
        assert!(escaped.contains("&lt;script&gt;"));
        assert_eq!(escape_path("[::1]:9000"), "%5B%3A%3A1%5D%3A9000");
        assert_eq!(escape_path("api"), "api");
    }

    #[test]
    fn the_notice_line_is_escaped_and_only_known_shapes_are_shown() {
        assert!(notice("applied=maintenance").contains("Applied: maintenance"));
        assert!(notice("error=swap_rejected").contains("Refused: swap_rejected"));
        assert!(notice("").is_empty());
        assert!(!notice("error=%3Cscript%3E").contains("<script>"));
    }
}
