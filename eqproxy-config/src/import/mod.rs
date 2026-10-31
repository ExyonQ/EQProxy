//! Reference-proxy configuration import (Phase 8, CE6/Q9/CE8).
//!
//! Converts an nginx, HAProxy, ingress-nginx or Envoy configuration into the
//! canonical `eqproxy.toml` and a Markdown report that classifies **every**
//! directive of the source as one of three outcomes:
//!
//! - **convertido** — the value has an equivalent field in the schema and was
//!   written to the output;
//! - **revisar** — an approximation, a cosmetic difference or a global
//!   directive: the operator must read it, nothing was invented;
//! - **rechazado** — EQProxy has no equivalent today (or the source value is
//!   untranslatable); the directive is named with what is lost.
//!
//! Two properties are enforced by construction rather than promised:
//!
//! 1. **No silent omission.** Each walked directive records at least one
//!    classification; [`Conv::touch`] fails the import for a directive that
//!    produced none, so a forgotten `continue` is a hard error, not a hole in
//!    the report. The report prints the counts it walked and it classified.
//! 2. **The output is a valid EQProxy configuration.** The generated TOML is
//!    parsed and semantically checked with this crate's own parser and
//!    validator ([`crate::parse_str`] + [`crate::validate::check`]) before it
//!    is returned: the importer can never hand back a file the product would
//!    reject. The Markdown report is honest about what the comparison is (a
//!    static reading of the source, not a traffic replay).
//!
//! Static analysis only: nothing from the source configuration is executed.

mod envoy;
mod haproxy;
mod ingress;
mod nginx;
mod report;
mod yaml;

pub use report::report_with_paths;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

pub use report::emit_toml;

/// Source configuration dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Nginx,
    Haproxy,
    Ingress,
    Envoy,
}

impl Source {
    /// Parses a `--from` value.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "nginx" => Some(Self::Nginx),
            "haproxy" => Some(Self::Haproxy),
            "ingress" | "ingress-nginx" => Some(Self::Ingress),
            "envoy" => Some(Self::Envoy),
            _ => None,
        }
    }

    /// Stable name used in the command line and the report.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nginx => "nginx",
            Self::Haproxy => "haproxy",
            Self::Ingress => "ingress",
            Self::Envoy => "envoy",
        }
    }

    /// Guesses the dialect from the text. Only a guess: `--from` overrides it,
    /// and the caller reports which one was used.
    #[must_use]
    pub fn detect(text: &str) -> Self {
        let lower = text.to_ascii_lowercase();
        if lower.contains("static_resources")
            || lower.contains("filter_chains")
            || lower.contains("typed_config")
        {
            return Self::Envoy;
        }
        if lower.contains("kind: ingress") || lower.contains("ingress.kubernetes.io/") {
            return Self::Ingress;
        }
        for line in text.lines() {
            let line = line.trim_start();
            for keyword in [
                "frontend ",
                "backend ",
                "defaults",
                "global",
                "default_backend",
                "default-server",
            ] {
                if line.starts_with(keyword) {
                    return Self::Haproxy;
                }
            }
        }
        Self::Nginx
    }
}

/// Severity of one classification. The three outcomes of the report are
/// [`Self::Done`] (convertido), [`Self::Info`]/[`Self::Review`] (revisar) and
/// [`Self::Gap`]/[`Self::Rejected`] (rechazado).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Converted into a schema field.
    Done,
    /// Walked, no translation needed (it does not affect `eqproxy.toml`).
    Info,
    /// Approximation or cosmetic difference: read it before switching.
    Review,
    /// EQProxy has no equivalent for this directive today.
    Gap,
    /// The source value cannot be translated as written.
    Rejected,
}

/// One classified source directive.
#[derive(Debug, Clone)]
pub struct Note {
    /// One of [`Severity`].
    pub severity: Severity,
    /// The original directive (verbatim, trimmed).
    pub directive: String,
    /// The source section it appears in (`backend bk_web`, `listener …`).
    pub context: String,
    /// What happened, in operator language.
    pub message: String,
}

/// Counts of the ternary classification printed in the report header.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// Directives with an equivalent field.
    pub converted: usize,
    /// Directives to review (approximation, cosmetic, global).
    pub review: usize,
    /// Directives EQProxy cannot serve today.
    pub rejected: usize,
}

/// Result of a successful conversion.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// Generated `eqproxy.toml`, already parsed and validated.
    pub toml: String,
    /// Markdown report classifying every source directive.
    pub report: String,
    /// Ternary counts.
    pub counts: Counts,
}

/// Import failure. The message names the cause; nothing is written on error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportError {
    /// Operator-facing cause.
    pub message: String,
}

impl ImportError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ImportError {}

// ---------------------------------------------------------------------------
// Intermediate representation (mirrors the v1 schema the emitter writes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct Server {
    addr: String,
    weight: u32,
    backup: bool,
    /// HAProxy `server … maxconn` (B-H16); `0` = no per-server cap.
    maxconn: u32,
}

#[derive(Debug, Clone, Default)]
struct HealthCheck {
    interval: String,
    timeout: String,
    fall: u32,
    rise: u32,
    /// `Some("http")` for an HTTP check (B-H6).
    kind: Option<&'static str>,
    http_path: Option<String>,
    expect_status: Option<String>,
    http_host: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct BackendTls {
    verify: bool,
    ca_file: Option<String>,
    server_name: Option<String>,
    alpn: Vec<String>,
    min_version: Option<&'static str>,
}

#[derive(Debug, Clone, Default)]
struct Affinity {
    mode: String,
    cookie: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct Backend {
    servers: Vec<Server>,
    /// Empty = the schema default (`roundrobin`).
    balance: String,
    proxy_protocol_v1: bool,
    health_check: Option<HealthCheck>,
    tls: Option<BackendTls>,
    affinity: Option<Affinity>,
    retries: u32,
    maxqueue: u32,
    slow_start: Option<String>,
    /// Source timeouts (`client`, `server`, `connect`, `check`, …).
    timeouts: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default)]
struct ListenerTls {
    cert: String,
    key: String,
    alpn: Vec<String>,
    min_version: Option<&'static str>,
    client_ca: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct HeaderOp {
    name: String,
    value: String,
}

#[derive(Debug, Clone, Default)]
struct Rule {
    name: String,
    use_backend: Option<String>,
    path_prefix: Option<String>,
    path: Option<String>,
    host: Option<String>,
    host_regex: Option<String>,
    methods: Vec<String>,
    ip: Vec<String>,
    set_headers: Vec<HeaderOp>,
    add_headers: Vec<HeaderOp>,
    response_headers: Vec<HeaderOp>,
    direct_response: Option<(u16, Option<String>)>,
    redirect: Option<(Option<u16>, String)>,
    /// `CorsConfig.allow_origin` (ingress-nginx `enable-cors`).
    cors_origin: Option<String>,
    /// `RateLimitConfig`: (rate, per, burst).
    rate_limit: Option<(u32, String, Option<u32>)>,
    /// `RewriteConfig.path_prefix_rewrite`.
    rewrite_prefix: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct Listener {
    listen: String,
    mode: String,
    backend: String,
    maxconn: u32,
    connect_timeout: Option<String>,
    idle_timeout: Option<String>,
    client_header_timeout: Option<String>,
    server_header_timeout: Option<String>,
    tls: Option<ListenerTls>,
    quic: bool,
    forwarded_headers: Option<&'static str>,
    compression_gzip: bool,
    compression_level: Option<u32>,
    compression_min_size: Option<u64>,
    max_body_bytes: Option<u64>,
    cache: bool,
    proxy_receive: bool,
    rules: Vec<Rule>,
}

impl Listener {
    fn new(listen: impl Into<String>, mode: &str, backend: impl Into<String>) -> Self {
        Self {
            listen: listen.into(),
            mode: mode.to_owned(),
            backend: backend.into(),
            // The schema default; the emitter omits it while it stays 1024.
            maxconn: 1024,
            ..Self::default()
        }
    }
}

/// Accumulator shared by the four converters: the IR being built plus the
/// classification log the report is rendered from.
#[derive(Debug, Default)]
pub struct Conv {
    listeners: BTreeMap<String, Listener>,
    backends: BTreeMap<String, Backend>,
    notes: Vec<Note>,
    /// Source units walked (directives, lines, nodes). Compared with the
    /// number of units that produced a classification.
    walked: usize,
}

impl Conv {
    fn new() -> Self {
        Self::default()
    }

    /// Records one classification.
    fn note(
        &mut self,
        severity: Severity,
        directive: impl Into<String>,
        context: &str,
        message: impl Into<String>,
    ) {
        self.notes.push(Note {
            severity,
            directive: directive.into(),
            context: context.to_owned(),
            message: message.into(),
        });
    }

    /// Counts one walked source unit and records its classification.
    ///
    /// `units` is 1 for a directive and >1 when one source line expands to
    /// several dispositions (`server … check weight 5`).
    fn done(
        &mut self,
        units: usize,
        directive: impl Into<String>,
        context: &str,
        message: impl Into<String>,
    ) {
        self.walked += units;
        self.note(Severity::Done, directive, context, message);
    }

    fn info(
        &mut self,
        units: usize,
        directive: impl Into<String>,
        context: &str,
        message: impl Into<String>,
    ) {
        self.walked += units;
        self.note(Severity::Info, directive, context, message);
    }

    fn review(
        &mut self,
        units: usize,
        directive: impl Into<String>,
        context: &str,
        message: impl Into<String>,
    ) {
        self.walked += units;
        self.note(Severity::Review, directive, context, message);
    }

    fn gap(
        &mut self,
        units: usize,
        directive: impl Into<String>,
        context: &str,
        message: impl Into<String>,
    ) {
        self.walked += units;
        self.note(Severity::Gap, directive, context, message);
    }

    fn reject(
        &mut self,
        units: usize,
        directive: impl Into<String>,
        context: &str,
        message: impl Into<String>,
    ) {
        self.walked += units;
        self.note(Severity::Rejected, directive, context, message);
    }

    /// Fails when a walked directive produced no classification.
    ///
    /// `before` is `self.notes.len()` taken before the directive was handled;
    /// a handler that returns early without a note is a silent omission, which
    /// this turns into an error naming the directive.
    fn touch(&self, directive: &str, context: &str, before: usize) -> Result<(), ImportError> {
        if self.notes.len() == before {
            return Err(ImportError::new(format!(
                "{context}: directive «{directive}» was walked but not classified — the importer never drops a directive silently"
            )));
        }
        Ok(())
    }

    fn classify(&self) -> Counts {
        let mut counts = Counts::default();
        for note in &self.notes {
            match note.severity {
                Severity::Done => counts.converted += 1,
                Severity::Info | Severity::Review => counts.review += 1,
                Severity::Gap | Severity::Rejected => counts.rejected += 1,
            }
        }
        counts
    }

    fn free_backend_name(&self, base: &str) -> String {
        unique_name(base, self.backends.keys().map(String::as_str))
    }

    fn free_listener_name(&self, base: &str) -> String {
        unique_name(base, self.listeners.keys().map(String::as_str))
    }

    fn has_backend(&self, name: &str) -> bool {
        self.backends.contains_key(name)
    }

    /// Number of listeners generated so far.
    fn listener_count(&self) -> usize {
        self.listeners.len()
    }

    /// The only backend defined so far, when there is exactly one.
    fn only_backend(&self) -> Option<String> {
        if self.backends.len() == 1 {
            self.backends.keys().next().cloned()
        } else {
            None
        }
    }

    fn add_backend(&mut self, name: String, backend: Backend) {
        self.backends.insert(name, backend);
    }

    fn add_listener(&mut self, name: String, listener: Listener) {
        self.listeners.insert(name, listener);
    }

    /// Default health check (`interval 2s`, `timeout 1s`, `fall 3`, `rise 2`).
    fn default_health_check() -> HealthCheck {
        HealthCheck {
            interval: "2s".to_owned(),
            timeout: "1s".to_owned(),
            fall: 3,
            rise: 2,
            ..HealthCheck::default()
        }
    }
}

/// `base` sanitized, with `_2`, `_3`… appended when the name is taken.
fn unique_name<'a>(base: &str, taken: impl Iterator<Item = &'a str>) -> String {
    let base = {
        let cleaned = sanitize_name(base);
        if cleaned.is_empty() {
            "sin_nombre".to_owned()
        } else {
            cleaned
        }
    };
    let used: Vec<&str> = taken.collect();
    if !used.contains(&base.as_str()) {
        return base;
    }
    let mut index = 2;
    loop {
        let candidate = format!("{base}_{index}");
        if !used.contains(&candidate.as_str()) {
            return candidate;
        }
        index += 1;
    }
}

/// Restricts a name to `A-Za-z0-9_-` (TOML bare-key and section names).
#[must_use]
pub fn sanitize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    out.trim_matches('_').to_owned()
}

/// Converts a reference duration to the `eqproxy.toml` spelling
/// (`<integer><ms|s|m|h>`).
///
/// nginx: a bare number is seconds. HAProxy: a bare number is milliseconds.
/// Anything else (`10m30s`, `1d`) is summed when every part is recognised and
/// reviewed with a note reading it, never guessed.
fn convert_duration(
    conv: &mut Conv,
    raw: &str,
    default_unit: &str,
    directive: &str,
    context: &str,
) -> Option<String> {
    let raw = raw.trim();
    let mut total_ms: u64 = 0;
    let mut rest = raw;
    let mut parts = 0usize;
    while !rest.is_empty() {
        let digits: String = rest
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        if digits.is_empty() || digits == "." {
            break;
        }
        let after = &rest[digits.len()..];
        let (unit, consumed) = if let Some(tail) = after.strip_prefix("ms") {
            ("ms", after.len() - tail.len())
        } else if let Some(tail) = after.strip_prefix('s') {
            ("s", after.len() - tail.len())
        } else if let Some(tail) = after.strip_prefix('m') {
            ("m", after.len() - tail.len())
        } else if let Some(tail) = after.strip_prefix('h') {
            ("h", after.len() - tail.len())
        } else if let Some(tail) = after.strip_prefix('d') {
            ("d", after.len() - tail.len())
        } else {
            (default_unit, 0)
        };
        let Ok(value) = digits.parse::<f64>() else {
            break;
        };
        let factor: u64 = match unit {
            "ms" => 1,
            "s" => 1_000,
            "m" => 60_000,
            "h" => 3_600_000,
            "d" => 86_400_000,
            _ => 1,
        };
        total_ms += (value * factor as f64) as u64;
        rest = &after[consumed..];
        parts += 1;
    }
    if parts == 0 || !rest.is_empty() || total_ms == 0 {
        conv.review(
            1,
            directive,
            context,
            format!("duración no reconocida «{raw}»: se usa el valor por defecto de EQProxy"),
        );
        return None;
    }
    if total_ms.is_multiple_of(3_600_000) {
        Some(format!("{}h", total_ms / 3_600_000))
    } else if total_ms.is_multiple_of(60_000) {
        Some(format!("{}m", total_ms / 60_000))
    } else if total_ms.is_multiple_of(1_000) {
        Some(format!("{}s", total_ms / 1_000))
    } else {
        Some(format!("{total_ms}ms"))
    }
}

/// Parses a size with an optional unit suffix (`8m`, `1k`, `1024`).
///
/// nginx and ingress-nginx spell sizes with `k`/`m`/`g`; anything else is
/// `None` and becomes a classified review note, never a guess.
#[must_use]
pub fn parse_size(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let (digits, factor) = match raw.chars().last()? {
        'k' | 'K' => (&raw[..raw.len() - 1], 1_024u64),
        'm' | 'M' => (&raw[..raw.len() - 1], 1_024 * 1_024),
        'g' | 'G' => (&raw[..raw.len() - 1], 1_024 * 1_024 * 1_024),
        _ => (raw, 1),
    };
    let value: u64 = digits.trim().parse().ok()?;
    value.checked_mul(factor)
}

/// True when `value` is `IP:PORT` or `HOSTNAME:PORT` — what the schema
/// accepts (`parse_server_target`).
#[must_use]
pub fn is_addr(value: &str) -> bool {
    crate::schema::parse_server_target(value).is_ok()
}

/// Normalises a bind/server address to `IP:PORT` or `HOSTNAME:PORT`.
///
/// EQProxy v0.8 accepts literal IPs and hostnames (resolved in the
/// background, B-H13); Unix sockets and `fd@` are still refused, and a missing
/// port is filled from `default_port` when the source dialect allows it.
fn normalize_addr(
    conv: &mut Conv,
    raw: &str,
    default_port: Option<u16>,
    directive: &str,
    context: &str,
) -> Option<String> {
    let mut addr = raw.trim().trim_matches(['"', '\'']).to_owned();
    if addr.starts_with("unix:")
        || addr.starts_with("unix@")
        || addr.starts_with("fd@")
        || addr.starts_with('/')
    {
        conv.reject(
            1,
            directive,
            context,
            format!(
                "«{addr}»: sockets Unix/FD sin soporte en EQProxy (solo IP:PORT o HOSTNAME:PORT)"
            ),
        );
        return None;
    }
    if let Some(port) = addr.strip_prefix("*:") {
        addr = format!("0.0.0.0:{port}");
    } else if let Some(port) = addr.strip_prefix(':') {
        addr = format!("0.0.0.0:{port}");
    }
    if !addr.contains(':') {
        if addr.chars().all(|c| c.is_ascii_digit()) {
            addr = format!("0.0.0.0:{addr}");
        } else if let Some(port) = default_port {
            addr = format!("{addr}:{port}");
        } else {
            conv.reject(
                1,
                directive,
                context,
                format!("«{addr}»: falta el puerto y no hay uno por defecto en este contexto"),
            );
            return None;
        }
    }
    // A bare `HOST:` gains the default port; a bracketed IPv6 keeps its shape.
    if addr.ends_with(':')
        && let Some(port) = default_port
    {
        addr = format!("{addr}{port}");
    }
    if is_addr(&addr) {
        return Some(addr);
    }
    conv.reject(
        1,
        directive,
        context,
        format!("«{raw}»: no es IP:PORT ni HOSTNAME:PORT válido para EQProxy"),
    );
    None
}

/// Escapes a TOML basic string.
fn toml_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn toml_key(name: &str) -> String {
    if !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        name.to_owned()
    } else {
        toml_string(name)
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Converts `text` (a configuration in dialect `source`) into `eqproxy.toml`
/// plus its Markdown report.
///
/// Fails when the source cannot be read as that dialect, when it yields no
/// listener, or when the generated document does not pass this crate's own
/// parser and validator. Nothing partial is ever returned.
pub fn convert(source: Source, text: &str) -> Result<Outcome, ImportError> {
    if text.len() > crate::MAX_CONFIG_BYTES {
        return Err(ImportError::new(format!(
            "source configuration too large: {} bytes (maximum {})",
            text.len(),
            crate::MAX_CONFIG_BYTES
        )));
    }
    let mut conv = Conv::new();
    match source {
        Source::Nginx => nginx::convert(&mut conv, text)?,
        Source::Haproxy => haproxy::convert(&mut conv, text)?,
        Source::Ingress => ingress::convert(&mut conv, text)?,
        Source::Envoy => envoy::convert(&mut conv, text)?,
    }
    if conv.listeners.is_empty() {
        return Err(ImportError::new(
            "the source configuration produced no listener: nothing to write. Check that the file declares a proxy_section/listen (nginx), frontend or listen (HAProxy), an Ingress rule or an Envoy listener with a route"
                .to_owned(),
        ));
    }
    let toml = emit_toml(&conv);
    let file = Path::new("<import>");
    let config = crate::parse_str(&toml, file).map_err(|err| {
        ImportError::new(format!(
            "internal: the generated configuration does not parse ({}) — please report it",
            err.cause
        ))
    })?;
    let check = crate::validate::check(&config, &toml, file);
    if !check.is_valid() {
        let details: Vec<String> = check
            .errors
            .iter()
            .map(|err| {
                format!(
                    "{}: {}",
                    err.field.clone().unwrap_or_else(|| "-".to_owned()),
                    err.cause
                )
            })
            .collect();
        return Err(ImportError::new(format!(
            "internal: the generated configuration does not validate: {}",
            details.join("; ")
        )));
    }
    let counts = conv.classify();
    let report = report::render(source, &conv, counts);
    Ok(Outcome {
        toml,
        report,
        counts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_follow_each_dialect_default() {
        let mut conv = Conv::new();
        assert_eq!(
            convert_duration(&mut conv, "4", "ms", "timeout", "x"),
            Some("4ms".to_owned())
        );
        assert_eq!(
            convert_duration(&mut conv, "30s", "ms", "timeout", "x"),
            Some("30s".to_owned())
        );
        assert_eq!(
            convert_duration(&mut conv, "10", "s", "timeout", "x"),
            Some("10s".to_owned())
        );
        assert_eq!(
            convert_duration(&mut conv, "10m", "ms", "timeout", "x"),
            Some("10m".to_owned())
        );
        assert_eq!(
            convert_duration(&mut conv, "1h", "ms", "timeout", "x"),
            Some("1h".to_owned())
        );
        assert_eq!(
            convert_duration(&mut conv, "1500ms", "ms", "timeout", "x"),
            Some("1500ms".to_owned())
        );
        assert!(conv.notes.is_empty(), "recognised durations are not noted");
    }

    #[test]
    fn a_compound_duration_is_summed_and_nonsense_is_reviewed() {
        let mut conv = Conv::new();
        assert_eq!(
            convert_duration(&mut conv, "10m30s", "ms", "timeout", "x"),
            Some("630s".to_owned()),
            "both parts are recognised: the sum is exact"
        );
        assert!(conv.notes.is_empty());
        assert_eq!(
            convert_duration(&mut conv, "soon", "ms", "timeout", "x"),
            None
        );
        assert_eq!(conv.notes.len(), 1);
        assert!(matches!(conv.notes[0].severity, Severity::Review));
        assert!(conv.notes[0].message.contains("no reconocida"));
    }

    #[test]
    fn addresses_accept_ips_and_hostnames_and_refuse_sockets() {
        let mut conv = Conv::new();
        assert_eq!(
            normalize_addr(&mut conv, "10.0.0.1:80", None, "bind", "x").as_deref(),
            Some("10.0.0.1:80")
        );
        assert_eq!(
            normalize_addr(&mut conv, ":8080", None, "bind", "x").as_deref(),
            Some("0.0.0.0:8080")
        );
        assert_eq!(
            normalize_addr(&mut conv, "app.local:8080", None, "server", "x").as_deref(),
            Some("app.local:8080"),
            "B-H13: hostnames are accepted and resolved in the background"
        );
        assert_eq!(
            normalize_addr(&mut conv, "example.com", Some(443), "server", "x").as_deref(),
            Some("example.com:443")
        );
        assert_eq!(
            normalize_addr(&mut conv, "unix@/run/app.sock", None, "server", "x"),
            None
        );
        assert_eq!(
            normalize_addr(&mut conv, "[::1]:8443", None, "bind", "x").as_deref(),
            Some("[::1]:8443")
        );
        assert!(conv.notes.iter().any(|n| n.severity == Severity::Rejected));
    }

    #[test]
    fn every_walked_directive_must_be_classified() {
        let mut conv = Conv::new();
        let before = conv.notes.len();
        conv.info(1, "worker_processes", "global", "sin traducción");
        conv.touch("worker_processes", "global", before)
            .expect("classified");

        let before = conv.notes.len();
        conv.touch("forgotten", "http", before)
            .expect_err("an unclassified directive must fail the import");
    }

    #[test]
    fn name_sanitising_and_uniqueness_are_deterministic() {
        assert_eq!(sanitize_name("fe_https.1"), "fe_https_1");
        assert_eq!(sanitize_name("__x__"), "x");
        assert_eq!(unique_name("api", ["api"].into_iter()), "api_2");
        assert_eq!(unique_name("api", ["api", "api_2"].into_iter()), "api_3");
        assert_eq!(unique_name("", [].into_iter()), "sin_nombre");
    }

    #[test]
    fn dialect_detection_reads_the_shape_of_the_file() {
        assert_eq!(
            Source::detect("static_resources:\n  clusters: []\n"),
            Source::Envoy
        );
        assert_eq!(Source::detect("kind: Ingress\n"), Source::Ingress);
        assert_eq!(Source::detect("global\n    maxconn 9\n"), Source::Haproxy);
        assert_eq!(Source::detect("http {\n server { }\n}\n"), Source::Nginx);
        assert_eq!(Source::parse("ingress-nginx"), Some(Source::Ingress));
        assert_eq!(Source::parse("apache"), None);
    }
}
