//! Typed routing rules (v0.6 — B-H3/B-H4): explicit match conditions over
//! one request, evaluated in declaration order, first match wins.
//!
//! Semantics are defined once here (Q8) and never silently changed:
//!
//! - `host`/`host_prefix`: case-insensitive, compared against the Host
//!   header **without** any `:port` suffix (IPv6 literals are compared
//!   without brackets).
//! - `host_regex`: unanchored match (as with `expect rstring`) against the
//!   same lowercased, port-free host; anchor with `^…$` for a full match.
//! - `path`/`path_prefix`: case-sensitive and **literal** — no
//!   normalization of any kind, so the prefix `/v1` also matches `/v10`
//!   (write `/v1/` to avoid it), applied to the target with the query
//!   string removed.
//! - `path_regex`: unanchored match against that same path.
//! - `methods`: exact, case-sensitive tokens (HTTP methods are
//!   case-sensitive).
//! - `headers`: the name is case-insensitive; `present` only checks
//!   existence, `exact` compares the value byte-for-byte and `regex` is
//!   unanchored. Several header conditions are ANDed.
//! - `ip`: the effective source address (the PROXY v1 claim when enabled)
//!   must fall inside one of the CIDR blocks.
//! - `cookies` (B-I11): the `cookie` request header is parsed RFC 6265
//!   style (`;`-separated pairs; parts without `=` are ignored; the
//!   first occurrence of a name wins). Cookie **names** are compared
//!   case-insensitively (like header names in this engine), values are
//!   `exact` (byte-for-byte) or `regex` (unanchored).
//! - `map` (C10): the key selected from the request (`ip`, `host`,
//!   `path`, `method` or a header value) must exist in the named hot
//!   data map and — when `equals` is set — map to that exact value.
//!
//! All conditions of one rule are ANDed. A rule with no conditions is
//! rejected at the config gate: the catch-all case is the listener's
//! default backend.

use std::net::IpAddr;

use crate::expectation::{IpAllowlist, RegexMatcher};
use crate::maps::{MapKey, MapRegistry};

/// Facts of the request being routed. `host` is the Host header as
/// received (may carry `:port`); `path` is the request target with the
/// query string removed (both are normalized by [`Rule`]).
#[derive(Debug, Clone, Copy)]
pub struct RequestFacts<'a> {
    /// Request method (case-sensitive token).
    pub method: &'a str,
    /// Host header value as received (may include `:port`, may be empty).
    pub host: &'a str,
    /// Request target path, query string excluded.
    pub path: &'a str,
    /// All request headers (names lowercased by the parser).
    pub headers: &'a [(String, String)],
    /// Effective source address (PROXY v1 claim when reception is on).
    pub peer: IpAddr,
    /// Data maps in force (C10): what `map` conditions consult.
    /// `MapRegistry::empty()` for code paths without maps.
    pub maps: &'a MapRegistry,
}

/// Compile-time problem in a rule, with the field it lives in (so the
/// config gate can name `listener.web.rules[0].host_regex`, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleError {
    /// Rule-relative field path (`""` = the rule itself).
    pub field: String,
    /// Why it is invalid.
    pub cause: String,
    /// A concrete valid value (actionable errors, never a bare dump).
    pub example: String,
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.cause)
    }
}

impl std::error::Error for RuleError {}

/// Header condition as authored in the config (exactly one of `exact`,
/// `regex` or `present`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderSpec {
    /// Header name (case-insensitive).
    pub name: String,
    /// Exact value match (byte-for-byte).
    pub exact: Option<String>,
    /// Unanchored regex over the value.
    pub regex: Option<String>,
    /// `true` = presence check (value irrelevant).
    pub present: bool,
}

/// Cookie condition as authored in the config (B-I11 canary-by-cookie;
/// exactly one of `exact`, `regex` or `present`, like [`HeaderSpec`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieSpec {
    /// Cookie name (case-insensitive; RFC 6265 pair parsing).
    pub name: String,
    /// Exact value match (byte-for-byte).
    pub exact: Option<String>,
    /// Unanchored regex over the value.
    pub regex: Option<String>,
    /// `true` = presence check (any value, including empty).
    pub present: bool,
}

/// Map-backed condition as authored in the config (C10; exactly one of
/// `key` or `header` selects the lookup key).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MapConditionSpec {
    /// Name of the `[maps.*]` table consulted.
    pub name: String,
    /// Key source: `"ip"`, `"host"`, `"path"` or `"method"`.
    pub key: Option<String>,
    /// Key source: first value of this request header.
    pub header: Option<String>,
    /// Required mapped value (absent = presence match).
    pub equals: Option<String>,
}

/// One routing rule as authored in the config (raw strings; [`Rule::compile`]
/// validates and compiles it once, at the gate).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSpec {
    /// Display name for `explain` and logs.
    pub name: String,
    /// Exact host.
    pub host: Option<String>,
    /// Host prefix.
    pub host_prefix: Option<String>,
    /// Host regex.
    pub host_regex: Option<String>,
    /// Exact path.
    pub path: Option<String>,
    /// Path prefix (literal).
    pub path_prefix: Option<String>,
    /// Path regex.
    pub path_regex: Option<String>,
    /// Accepted methods (empty = any).
    pub methods: Vec<String>,
    /// Header conditions (all must hold).
    pub headers: Vec<HeaderSpec>,
    /// Cookie conditions (all must hold; B-I11).
    pub cookies: Vec<CookieSpec>,
    /// Source CIDR blocks (empty = any).
    pub ip: Vec<String>,
    /// Map-backed condition (C10).
    pub map: Option<MapConditionSpec>,
}

#[derive(Debug, Clone)]
enum HostMatch {
    Exact(String),
    Prefix(String),
    Regex(RegexMatcher),
}

#[derive(Debug, Clone)]
enum PathMatch {
    Exact(String),
    Prefix(String),
    Regex(RegexMatcher),
}

#[derive(Debug, Clone)]
enum ValueMatch {
    Present,
    Exact(String),
    Regex(RegexMatcher),
}

/// Compiled map condition (C10): name + key selector + expected value.
#[derive(Debug, Clone)]
struct MapMatch {
    name: String,
    key: MapKey,
    equals: Option<String>,
}

/// Compiled rule: conditions ANDed, evaluated by [`Self::matches`] /
/// [`Self::explain`].
#[derive(Debug, Clone)]
pub struct Rule {
    /// Display name (for `explain` and logs).
    pub name: String,
    host: Option<HostMatch>,
    path: Option<PathMatch>,
    methods: Vec<String>,
    headers: Vec<(String, ValueMatch)>,
    cookies: Vec<(String, ValueMatch)>,
    ip: Option<IpAllowlist>,
    map: Option<MapMatch>,
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn err(field: &str, cause: impl Into<String>, example: impl Into<String>) -> RuleError {
    RuleError {
        field: field.to_owned(),
        cause: cause.into(),
        example: example.into(),
    }
}

impl Rule {
    /// Compiles and validates a rule. Every error names its field.
    pub fn compile(spec: &RuleSpec) -> Result<Self, RuleError> {
        let host_variants = [
            spec.host.is_some(),
            spec.host_prefix.is_some(),
            spec.host_regex.is_some(),
        ];
        if host_variants.iter().filter(|v| **v).count() > 1 {
            return Err(err(
                "host",
                "at most one of host, host_prefix, host_regex",
                "host = \"api.example.com\" (pick exactly one host condition)",
            ));
        }
        let path_variants = [
            spec.path.is_some(),
            spec.path_prefix.is_some(),
            spec.path_regex.is_some(),
        ];
        if path_variants.iter().filter(|v| **v).count() > 1 {
            return Err(err(
                "path",
                "at most one of path, path_prefix, path_regex",
                "path_prefix = \"/v1/\" (pick exactly one path condition)",
            ));
        }
        let has_condition = spec.host.is_some()
            || spec.host_prefix.is_some()
            || spec.host_regex.is_some()
            || spec.path.is_some()
            || spec.path_prefix.is_some()
            || spec.path_regex.is_some()
            || !spec.methods.is_empty()
            || !spec.headers.is_empty()
            || !spec.cookies.is_empty()
            || !spec.ip.is_empty()
            || spec.map.is_some();
        if !has_condition {
            return Err(err(
                "",
                "a rule needs at least one match condition",
                "host = \"api.example.com\" (the catch-all case is the listener's default backend)",
            ));
        }

        let host = if let Some(exact) = &spec.host {
            Some(HostMatch::Exact(exact.to_ascii_lowercase()))
        } else if let Some(prefix) = &spec.host_prefix {
            Some(HostMatch::Prefix(prefix.to_ascii_lowercase()))
        } else if let Some(pattern) = &spec.host_regex {
            Some(HostMatch::Regex(RegexMatcher::parse(pattern).map_err(
                |why| err("host_regex", why, "host_regex = \"^api-[0-9]+\\\\.\""),
            )?))
        } else {
            None
        };

        let path = if let Some(exact) = &spec.path {
            Some(PathMatch::Exact(exact.clone()))
        } else if let Some(prefix) = &spec.path_prefix {
            Some(PathMatch::Prefix(prefix.clone()))
        } else if let Some(pattern) = &spec.path_regex {
            Some(PathMatch::Regex(RegexMatcher::parse(pattern).map_err(
                |why| err("path_regex", why, "path_regex = \"\\\\.json$\""),
            )?))
        } else {
            None
        };

        let mut methods = Vec::with_capacity(spec.methods.len());
        for method in &spec.methods {
            if method.is_empty() || !method.bytes().all(is_tchar) {
                return Err(err(
                    "methods",
                    format!("\"{method}\" is not a valid HTTP method token"),
                    "methods = [\"GET\", \"POST\"]",
                ));
            }
            methods.push(method.clone());
        }

        let mut headers = Vec::with_capacity(spec.headers.len());
        for (i, header) in spec.headers.iter().enumerate() {
            let field = format!("headers[{i}]");
            if header.name.is_empty() || !header.name.bytes().all(is_tchar) {
                return Err(err(
                    &field,
                    format!("\"{}\" is not a valid header name", header.name),
                    "headers = [{ name = \"x-tenant\", exact = \"acme\" }]",
                ));
            }
            let kinds = u8::from(header.exact.is_some())
                + u8::from(header.regex.is_some())
                + u8::from(header.present);
            if kinds != 1 {
                return Err(err(
                    &field,
                    "set exactly one of exact, regex or present = true",
                    "headers = [{ name = \"x-tenant\", exact = \"acme\" }]",
                ));
            }
            let value = if header.present {
                ValueMatch::Present
            } else if let Some(exact) = &header.exact {
                ValueMatch::Exact(exact.clone())
            } else {
                let pattern = header.regex.as_deref().unwrap_or_default();
                ValueMatch::Regex(
                    RegexMatcher::parse(pattern)
                        .map_err(|why| err(&format!("{field}.regex"), why, "regex = \"^acme-\""))?,
                )
            };
            headers.push((header.name.to_ascii_lowercase(), value));
        }

        let mut cookies = Vec::with_capacity(spec.cookies.len());
        for (i, cookie) in spec.cookies.iter().enumerate() {
            let field = format!("cookies[{i}]");
            if cookie.name.is_empty() || !cookie.name.bytes().all(is_tchar) {
                return Err(err(
                    &field,
                    format!("\"{}\" is not a valid cookie name", cookie.name),
                    "cookies = [{ name = \"canary\", exact = \"always\" }]",
                ));
            }
            let kinds = u8::from(cookie.exact.is_some())
                + u8::from(cookie.regex.is_some())
                + u8::from(cookie.present);
            if kinds != 1 {
                return Err(err(
                    &field,
                    "set exactly one of exact, regex or present = true",
                    "cookies = [{ name = \"canary\", exact = \"always\" }]",
                ));
            }
            let value =
                if cookie.present {
                    ValueMatch::Present
                } else if let Some(exact) = &cookie.exact {
                    ValueMatch::Exact(exact.clone())
                } else {
                    let pattern = cookie.regex.as_deref().unwrap_or_default();
                    ValueMatch::Regex(RegexMatcher::parse(pattern).map_err(|why| {
                        err(&format!("{field}.regex"), why, "regex = \"^v[0-9]+\"")
                    })?)
                };
            cookies.push((cookie.name.to_ascii_lowercase(), value));
        }

        let ip = if spec.ip.is_empty() {
            None
        } else {
            Some(
                IpAllowlist::parse(&spec.ip)
                    .map_err(|why| err("ip", why, "ip = [\"10.0.0.0/8\"]"))?,
            )
        };

        let map = spec.map.as_ref().map(|map| -> Result<MapMatch, RuleError> {
            if map.name.is_empty() {
                return Err(err(
                    "map.name",
                    "the map name is empty",
                    "map = { name = \"tenants\", key = \"host\", equals = \"vip\" }",
                ));
            }
            let key = match (&map.key, &map.header) {
                (Some(raw), None) => MapKey::parse(raw).map_err(|why| err("map.key", why, "map = { name = \"tenants\", key = \"host\" }"))?,
                (None, Some(name)) => {
                    if name.is_empty() || !name.bytes().all(is_tchar) {
                        return Err(err(
                            "map.header",
                            format!("\"{name}\" is not a valid header name"),
                            "map = { name = \"tenants\", header = \"x-tenant\" }",
                        ));
                    }
                    MapKey::Header(name.to_ascii_lowercase())
                }
                _ => {
                    return Err(err(
                        "map.key",
                        "set exactly one of key or header (the lookup key source)",
                        "map = { name = \"tenants\", key = \"host\" } or map = { name = \"tenants\", header = \"x-tenant\" }",
                    ));
                }
            };
            if let Some(equals) = &map.equals {
                crate::maps::validate_value(equals).map_err(|why| {
                    err("map.equals", why, "map = { name = \"tenants\", key = \"host\", equals = \"vip\" }")
                })?;
            }
            Ok(MapMatch {
                name: map.name.clone(),
                key,
                equals: map.equals.clone(),
            })
        })
        .transpose()?;

        Ok(Self {
            name: spec.name.clone(),
            host,
            path,
            methods,
            headers,
            cookies,
            ip,
            map,
        })
    }

    /// True when every condition holds.
    #[must_use]
    pub fn matches(&self, facts: &RequestFacts<'_>) -> bool {
        self.explain(facts).is_ok()
    }

    /// `Ok(())` when the rule matches; `Err(reason)` names the first
    /// condition that failed (the "why not", for `config explain`).
    pub fn explain(&self, facts: &RequestFacts<'_>) -> Result<(), String> {
        if let Some(host) = &self.host {
            let got = host_key(facts.host);
            let reason = match host {
                HostMatch::Exact(want) => {
                    if &got == want {
                        None
                    } else {
                        Some(format!("host: expected {want:?}, got {got:?}"))
                    }
                }
                HostMatch::Prefix(want) => {
                    if got.starts_with(want.as_str()) {
                        None
                    } else {
                        Some(format!("host: expected prefix {want:?}, got {got:?}"))
                    }
                }
                HostMatch::Regex(regex) => {
                    if regex.is_match(&got) {
                        None
                    } else {
                        Some(format!("host: pattern does not match {got:?}"))
                    }
                }
            };
            if let Some(reason) = reason {
                return Err(reason);
            }
        }
        if let Some(path) = &self.path {
            let got = facts.path;
            let reason = match path {
                PathMatch::Exact(want) => {
                    if got == want {
                        None
                    } else {
                        Some(format!("path: expected {want:?}, got {got:?}"))
                    }
                }
                PathMatch::Prefix(want) => {
                    if got.starts_with(want.as_str()) {
                        None
                    } else {
                        Some(format!("path: expected prefix {want:?}, got {got:?}"))
                    }
                }
                PathMatch::Regex(regex) => {
                    if regex.is_match(got) {
                        None
                    } else {
                        Some(format!("path: pattern does not match {got:?}"))
                    }
                }
            };
            if let Some(reason) = reason {
                return Err(reason);
            }
        }
        if !self.methods.is_empty() && !self.methods.iter().any(|m| m == facts.method) {
            return Err(format!(
                "method: {:?} not in {:?}",
                facts.method, self.methods
            ));
        }
        for (name, want) in &self.headers {
            let got = facts
                .headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str());
            if let Some(reason) = value_match_reason("header", name, want, got) {
                return Err(reason);
            }
        }
        for (name, want) in &self.cookies {
            let got = cookie_value(facts.headers, name);
            if let Some(reason) = value_match_reason("cookie", name, want, got) {
                return Err(reason);
            }
        }
        if let Some(allowlist) = &self.ip
            && !allowlist.contains(facts.peer)
        {
            return Err(format!(
                "ip: {} is not inside the rule's blocks",
                facts.peer
            ));
        }
        if let Some(map) = &self.map {
            let key = map.key.select(facts);
            let Some(hot) = facts.maps.get(&map.name) else {
                return Err(format!("map {:?}: not loaded", map.name));
            };
            let data = hot.get();
            let Some(value) = data.lookup(&key) else {
                return Err(format!("map {:?}: key {:?} has no entry", map.name, key));
            };
            if let Some(want) = &map.equals
                && value != want
            {
                return Err(format!(
                    "map {:?}: key {:?} -> {value:?}, expected {want:?}",
                    map.name, key
                ));
            }
        }
        Ok(())
    }
}

/// The "why not" of one exact/regex/present match (shared by header and
/// cookie conditions so both read the same way in `config explain`).
fn value_match_reason(
    kind: &str,
    name: &str,
    want: &ValueMatch,
    got: Option<&str>,
) -> Option<String> {
    match (want, got) {
        (ValueMatch::Present, Some(_)) => None,
        (ValueMatch::Exact(want), Some(got)) if got == want => None,
        (ValueMatch::Regex(regex), Some(got)) if regex.is_match(got) => None,
        (ValueMatch::Present, None) => Some(format!("{kind} {name:?}: not present")),
        (ValueMatch::Exact(want), Some(got)) => {
            Some(format!("{kind} {name:?}: expected {want:?}, got {got:?}"))
        }
        (ValueMatch::Regex(_), Some(got)) => {
            Some(format!("{kind} {name:?}: pattern does not match {got:?}"))
        }
        (_, None) => Some(format!("{kind} {name:?}: not present")),
    }
}

/// First value of the cookie `name` in the request headers (B-I11).
///
/// RFC 6265 pair parsing (defined once, Q8): each `cookie` header value
/// is split at `;`, parts are trimmed, a part without `=` is ignored and
/// the first `=` separates name from value (the value keeps everything
/// after it, trimmed of surrounding whitespace). Names are compared
/// case-insensitively and the **first** occurrence of a name wins.
#[must_use]
pub fn cookie_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    for (header, value) in headers {
        if !header.eq_ignore_ascii_case("cookie") {
            continue;
        }
        for part in value.split(';') {
            let Some((key, val)) = part.trim().split_once('=') else {
                continue;
            };
            if key.trim().eq_ignore_ascii_case(name) {
                return Some(val.trim());
            }
        }
    }
    None
}

/// Lowercased host with any `:port` suffix removed (bracket-aware for
/// IPv6 literals, which lose the brackets too).
#[must_use]
pub fn host_key(host: &str) -> String {
    let without_port = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        host.split(':').next().unwrap_or(host)
    };
    without_port.to_ascii_lowercase()
}

/// The request target path: everything before the first `?`.
#[must_use]
pub fn path_of(target: &str) -> &str {
    target.split('?').next().unwrap_or(target)
}

// --- Rule actions (v0.6 slice 2: rewrite / redirect / direct_response) ---
//
// Semantics, defined once (Q8) and never silently changed:
//
// - **rewrite** (with `use_backend`): `path_prefix_rewrite` replaces the
//   rule's matched `path_prefix` in the forwarded target — literal, no
//   regex (write `""` to strip the prefix) — keeping the query string
//   untouched; `host_rewrite` replaces the upstream `Host` header with
//   that exact value. (Envoy `prefix_rewrite` / `host_rewrite`.)
// - **redirect**: the client gets that 3xx + `Location` rendered per
//   request from a template with exactly three placeholders:
//   `$host` (Host header as received, may carry `:port`), `$uri`
//   (request path, query excluded) and `$request_uri` (the full target
//   as received). Any other `$…` sequence is a config error; a literal
//   `$` is written percent-encoded (`%24`).
// - **direct_response**: that status + body, served locally; the
//   backend is never contacted.

/// Validates a redirect `location` template (placeholders only, no
/// control characters). Called by the config gate, once per rule.
pub fn validate_location(template: &str) -> Result<(), String> {
    if template.is_empty() {
        return Err(
            "location is empty (example: location = \"https://$host$request_uri\")".to_owned(),
        );
    }
    if template.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("location contains control characters".to_owned());
    }
    let mut rest = template;
    while let Some(pos) = rest.find('$') {
        rest = &rest[pos..];
        if rest.starts_with("$request_uri") {
            rest = &rest["$request_uri".len()..];
        } else if rest.starts_with("$host") {
            rest = &rest["$host".len()..];
        } else if rest.starts_with("$uri") {
            rest = &rest["$uri".len()..];
        } else {
            let shown: String = rest.chars().take(12).collect();
            return Err(format!(
                "unknown placeholder in location: {shown:?} (only $host, $uri and $request_uri exist)"
            ));
        }
    }
    Ok(())
}

/// Renders a validated `location` template against one request: `host`
/// is the Host header as received (may carry `:port`) and `target` the
/// full request target as received (path + query). Errors only on an
/// unvalidated template (defense in depth at runtime).
pub fn render_location(template: &str, host: &str, target: &str) -> Result<String, String> {
    validate_location(template)?;
    let mut out = String::with_capacity(template.len() + 16);
    let mut rest = template;
    while let Some(pos) = rest.find('$') {
        out.push_str(&rest[..pos]);
        rest = &rest[pos..];
        if rest.starts_with("$request_uri") {
            out.push_str(target);
            rest = &rest["$request_uri".len()..];
        } else if rest.starts_with("$host") {
            out.push_str(host);
            rest = &rest["$host".len()..];
        } else {
            out.push_str(path_of(target));
            rest = &rest["$uri".len()..];
        }
    }
    out.push_str(rest);
    Ok(out)
}

/// Validates a header value template (B-E17): literal text plus
/// `$remote_addr`, `$host` and `$scheme`, with no control characters
/// (CR/LF in a value would smuggle headers). Every `$` must start one
/// of those placeholders — a literal `$` has no escape, write the value
/// without one. Called by the config gate, once per header action.
pub fn validate_header_value(template: &str) -> Result<(), String> {
    if template.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("value contains control characters".to_owned());
    }
    for after in template.split('$').skip(1) {
        if !["remote_addr", "scheme", "host"]
            .into_iter()
            .any(|placeholder| after.starts_with(placeholder))
        {
            let shown: String = after.chars().take(12).collect();
            return Err(format!(
                "unknown placeholder in value: {shown:?} (only $remote_addr, $host and $scheme exist)"
            ));
        }
    }
    Ok(())
}

/// Renders a validated header value template against one request:
/// `remote_addr` is the effective client address (PROXY v1 claim when
/// reception is on), `host` the Host header as received and `scheme`
/// the client-facing scheme (`http`/`https`). Errors only on an
/// unvalidated template (defense in depth at runtime).
pub fn render_header_value(
    template: &str,
    remote_addr: &str,
    host: &str,
    scheme: &str,
) -> Result<String, String> {
    validate_header_value(template)?;
    let values = [
        ("remote_addr", remote_addr),
        ("scheme", scheme),
        ("host", host),
    ];
    let mut out = String::with_capacity(template.len() + 16);
    let mut rest = template;
    while let Some((before, after)) = rest.split_once('$') {
        out.push_str(before);
        let (value, tail) = values
            .into_iter()
            .find_map(|(placeholder, value)| {
                after.strip_prefix(placeholder).map(|tail| (value, tail))
            })
            .ok_or_else(|| "unknown placeholder in value".to_owned())?;
        out.push_str(value);
        rest = tail;
    }
    out.push_str(rest);
    Ok(out)
}

/// Replaces the matched `prefix` at the start of `path` with
/// `replacement` (literal; `""` strips the prefix). The caller guarantees
/// `path` starts with `prefix` (the rule matched on it).
#[must_use]
pub fn rewrite_prefix(path: &str, prefix: &str, replacement: &str) -> String {
    match path.strip_prefix(prefix) {
        Some(rest) => format!("{replacement}{rest}"),
        None => path.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_value_placeholders_render_per_request() {
        assert_eq!(
            render_header_value(
                "$scheme://$host/hint=$remote_addr",
                "10.0.0.9",
                "ex.com:8443",
                "https"
            )
            .unwrap(),
            "https://ex.com:8443/hint=10.0.0.9"
        );
        assert_eq!(
            render_header_value("on", "1.1.1.1", "x", "http").unwrap(),
            "on"
        );
    }

    #[test]
    fn header_value_rejects_unknown_placeholders_and_control_chars() {
        assert!(validate_header_value("$request_uri").is_err());
        assert!(validate_header_value("a\r\nb: c").is_err());
        // Every `$` starts a placeholder: a bare one is a config error.
        assert!(validate_header_value("100$ ok").is_err());
    }

    fn facts<'a>(method: &'a str, host: &'a str, path: &'a str) -> RequestFacts<'a> {
        RequestFacts {
            method,
            host,
            path,
            headers: &[],
            peer: "127.0.0.1".parse().expect("ip"),
            maps: MapRegistry::empty(),
        }
    }

    fn compile(spec: RuleSpec) -> Rule {
        Rule::compile(&spec).expect("rule compiles")
    }

    #[test]
    fn host_exact_ignores_case_and_port() {
        let rule = compile(RuleSpec {
            name: "api".to_owned(),
            host: Some("API.Example.com".to_owned()),
            ..RuleSpec::default()
        });
        assert!(rule.matches(&facts("GET", "api.example.com:8443", "/")));
        assert!(rule.matches(&facts("GET", "API.EXAMPLE.COM", "/")));
        assert!(!rule.matches(&facts("GET", "web.example.com", "/")));
        assert!(!rule.matches(&facts("GET", "", "/")));
    }

    #[test]
    fn host_prefix_and_regex() {
        let prefix = compile(RuleSpec {
            name: "p".to_owned(),
            host_prefix: Some("api.".to_owned()),
            ..RuleSpec::default()
        });
        assert!(prefix.matches(&facts("GET", "api.example.com", "/")));
        assert!(!prefix.matches(&facts("GET", "xapi.example.com", "/")));

        let regex = compile(RuleSpec {
            name: "r".to_owned(),
            host_regex: Some(r"^api-[0-9]+\.".to_owned()),
            ..RuleSpec::default()
        });
        assert!(regex.matches(&facts("GET", "api-7.example.com", "/")));
        assert!(!regex.matches(&facts("GET", "api.example.com", "/")));
    }

    #[test]
    fn path_matching_is_literal_and_case_sensitive() {
        let exact = compile(RuleSpec {
            name: "e".to_owned(),
            path: Some("/Health".to_owned()),
            ..RuleSpec::default()
        });
        assert!(exact.matches(&facts("GET", "x", "/Health")));
        assert!(!exact.matches(&facts("GET", "x", "/health")));

        // Literal prefix: `/v1` reaches `/v10` too (documented ceiling).
        let prefix = compile(RuleSpec {
            name: "p".to_owned(),
            path_prefix: Some("/v1".to_owned()),
            ..RuleSpec::default()
        });
        assert!(prefix.matches(&facts("GET", "x", "/v1")));
        assert!(prefix.matches(&facts("GET", "x", "/v10")));
        assert!(prefix.matches(&facts("GET", "x", "/v1/users")));
        assert!(!prefix.matches(&facts("GET", "x", "/v0")));

        let regex = compile(RuleSpec {
            name: "r".to_owned(),
            path_regex: Some(r"\.json$".to_owned()),
            ..RuleSpec::default()
        });
        assert!(regex.matches(&facts("GET", "x", "/data.json")));
        assert!(!regex.matches(&facts("GET", "x", "/data.jsonx")));
    }

    #[test]
    fn methods_headers_and_ip_conditions_and_with_the_rest() {
        let rule = compile(RuleSpec {
            name: "all".to_owned(),
            methods: vec!["GET".to_owned(), "HEAD".to_owned()],
            headers: vec![
                HeaderSpec {
                    name: "X-Tenant".to_owned(),
                    exact: Some("acme".to_owned()),
                    regex: None,
                    present: false,
                },
                HeaderSpec {
                    name: "x-beta".to_owned(),
                    exact: None,
                    regex: None,
                    present: true,
                },
                HeaderSpec {
                    name: "x-trace".to_owned(),
                    exact: None,
                    regex: Some("^req-".to_owned()),
                    present: false,
                },
            ],
            ip: vec!["10.0.0.0/8".to_owned()],
            ..RuleSpec::default()
        });
        let headers = vec![
            ("x-tenant".to_owned(), "acme".to_owned()),
            ("x-beta".to_owned(), "1".to_owned()),
            ("x-trace".to_owned(), "req-42".to_owned()),
        ];
        let mut good = facts("GET", "x", "/");
        good.headers = &headers;
        good.peer = "10.1.2.3".parse().expect("ip");
        assert!(rule.matches(&good));

        let mut bad_method = good;
        bad_method.method = "POST";
        assert_eq!(
            rule.explain(&bad_method),
            Err("method: \"POST\" not in [\"GET\", \"HEAD\"]".to_owned())
        );

        let mut bad_peer = good;
        bad_peer.peer = "192.0.2.1".parse().expect("ip");
        assert!(
            rule.explain(&bad_peer)
                .expect_err("peer outside blocks")
                .starts_with("ip:")
        );

        let mut missing = good;
        missing.headers = &headers[..2];
        assert_eq!(
            rule.explain(&missing),
            Err("header \"x-trace\": not present".to_owned())
        );
    }

    #[test]
    fn explain_names_the_first_failing_condition() {
        let rule = compile(RuleSpec {
            name: "api".to_owned(),
            host: Some("api.example.com".to_owned()),
            path_prefix: Some("/v1/".to_owned()),
            ..RuleSpec::default()
        });
        assert_eq!(
            rule.explain(&facts("GET", "web.example.com", "/v1/x")),
            Err("host: expected \"api.example.com\", got \"web.example.com\"".to_owned())
        );
        assert_eq!(
            rule.explain(&facts("GET", "api.example.com", "/other")),
            Err("path: expected prefix \"/v1/\", got \"/other\"".to_owned())
        );
        assert!(rule.matches(&facts("GET", "api.example.com", "/v1/x")));
    }

    #[test]
    fn compile_rejects_ambiguous_and_empty_rules_with_named_fields() {
        let err = Rule::compile(&RuleSpec {
            name: "x".to_owned(),
            host: Some("a".to_owned()),
            host_regex: Some("b".to_owned()),
            ..RuleSpec::default()
        })
        .expect_err("two host conditions");
        assert_eq!(err.field, "host");

        let err = Rule::compile(&RuleSpec::default()).expect_err("no conditions");
        assert_eq!(err.field, "");
        assert!(err.cause.contains("at least one match condition"));

        let err = Rule::compile(&RuleSpec {
            name: "x".to_owned(),
            host_regex: Some("(".to_owned()),
            ..RuleSpec::default()
        })
        .expect_err("bad regex");
        assert_eq!(err.field, "host_regex");

        let err = Rule::compile(&RuleSpec {
            name: "x".to_owned(),
            ip: vec!["not-an-ip".to_owned()],
            ..RuleSpec::default()
        })
        .expect_err("bad cidr");
        assert_eq!(err.field, "ip");

        let err = Rule::compile(&RuleSpec {
            name: "x".to_owned(),
            headers: vec![HeaderSpec {
                name: "x-a".to_owned(),
                exact: Some("1".to_owned()),
                regex: Some("2".to_owned()),
                present: true,
            }],
            ..RuleSpec::default()
        })
        .expect_err("three header kinds");
        assert_eq!(err.field, "headers[0]");
    }

    /// Property: `matches` and `explain` never disagree, whatever the
    /// request looks like (the explain path is what operators read).
    #[test]
    fn matches_agrees_with_explain_on_a_generated_cross_product() {
        let rule = compile(RuleSpec {
            name: "prop".to_owned(),
            host_prefix: Some("api.".to_owned()),
            path_regex: Some("^/v[0-9]/".to_owned()),
            methods: vec!["GET".to_owned(), "PUT".to_owned()],
            ..RuleSpec::default()
        });
        let host_headers = [
            vec![],
            vec![("x-a".to_owned(), "1".to_owned())],
            vec![("x-a".to_owned(), "2".to_owned())],
        ];
        let mut checks = 0usize;
        for method in ["GET", "PUT", "POST", ""] {
            for host in ["api.x", "API.X:443", "web.x", "", "[::1]:80"] {
                for path in ["/", "/v1/a", "/v10", "/V1/a", "*"] {
                    for headers in &host_headers {
                        for peer in ["127.0.0.1", "10.0.0.9"] {
                            let facts = RequestFacts {
                                method,
                                host,
                                path,
                                headers,
                                peer: peer.parse().expect("ip"),
                                maps: MapRegistry::empty(),
                            };
                            assert_eq!(
                                rule.matches(&facts),
                                rule.explain(&facts).is_ok(),
                                "matches/explain disagree for {facts:?}",
                            );
                            checks += 1;
                        }
                    }
                }
            }
        }
        assert!(checks >= 400, "cross product too small: {checks}");
    }

    // --- B-I11 cookie conditions + C10 map conditions ---

    #[test]
    fn cookie_pairs_follow_rfc6265_parsing() {
        let headers = vec![(
            "cookie".to_owned(),
            "sid=abc; canary = always ; broken; empty=; other=x".to_owned(),
        )];
        assert_eq!(cookie_value(&headers, "sid"), Some("abc"));
        assert_eq!(cookie_value(&headers, "canary"), Some("always"));
        assert_eq!(
            cookie_value(&headers, "Canary"),
            Some("always"),
            "names are case-insensitive"
        );
        assert_eq!(
            cookie_value(&headers, "empty"),
            Some(""),
            "an empty value is a value"
        );
        assert_eq!(
            cookie_value(&headers, "broken"),
            None,
            "pairs without = are ignored"
        );
        assert_eq!(cookie_value(&headers, "missing"), None);
        // Several cookie headers: the first occurrence wins.
        let headers = vec![
            ("cookie".to_owned(), "a=1".to_owned()),
            ("cookie".to_owned(), "a=2".to_owned()),
        ];
        assert_eq!(cookie_value(&headers, "a"), Some("1"));
    }

    #[test]
    fn cookie_conditions_match_and_explain() {
        let rule = compile(RuleSpec {
            name: "canary".to_owned(),
            cookies: vec![
                CookieSpec {
                    name: "Canary".to_owned(),
                    exact: Some("always".to_owned()),
                    regex: None,
                    present: false,
                },
                CookieSpec {
                    name: "beta".to_owned(),
                    exact: None,
                    regex: None,
                    present: true,
                },
            ],
            ..RuleSpec::default()
        });
        let headers = vec![("cookie".to_owned(), "canary=always; beta=1".to_owned())];
        let mut good = facts("GET", "x", "/");
        good.headers = &headers;
        assert!(rule.matches(&good));

        let wrong = vec![("cookie".to_owned(), "canary=never; beta=1".to_owned())];
        let mut bad = good;
        bad.headers = &wrong;
        assert_eq!(
            rule.explain(&bad),
            Err("cookie \"canary\": expected \"always\", got \"never\"".to_owned())
        );
        let missing = vec![("cookie".to_owned(), "canary=always".to_owned())];
        let mut absent = good;
        absent.headers = &missing;
        assert_eq!(
            rule.explain(&absent),
            Err("cookie \"beta\": not present".to_owned())
        );
    }

    #[test]
    fn cookie_compile_rejects_bad_names_and_three_kinds() {
        let err = Rule::compile(&RuleSpec {
            name: "x".to_owned(),
            cookies: vec![CookieSpec {
                name: "bad name".to_owned(),
                exact: Some("1".to_owned()),
                regex: None,
                present: false,
            }],
            ..RuleSpec::default()
        })
        .expect_err("name with space");
        assert_eq!(err.field, "cookies[0]");

        let err = Rule::compile(&RuleSpec {
            name: "x".to_owned(),
            cookies: vec![CookieSpec {
                name: "ok".to_owned(),
                exact: Some("1".to_owned()),
                regex: Some("2".to_owned()),
                present: true,
            }],
            ..RuleSpec::default()
        })
        .expect_err("three kinds");
        assert_eq!(err.field, "cookies[0]");
    }

    fn registry_with(name: &str, text: &str) -> MapRegistry {
        let mut registry = MapRegistry::new();
        registry.insert(crate::maps::HotMap::new(
            name,
            crate::maps::MapData::parse(text, None).expect("map parses"),
            None,
            std::time::Duration::ZERO,
        ));
        registry
    }

    #[test]
    fn map_condition_matches_presence_and_equals_with_named_reasons() {
        let registry = registry_with(
            "tenants",
            "acme.example vip\nother.example free\nacme tenant\n",
        );
        let rule = compile(RuleSpec {
            name: "vip".to_owned(),
            map: Some(MapConditionSpec {
                name: "tenants".to_owned(),
                key: Some("host".to_owned()),
                header: None,
                equals: Some("vip".to_owned()),
            }),
            ..RuleSpec::default()
        });
        let mut hit = facts("GET", "ACME.EXAMPLE:8443", "/");
        hit.maps = &registry;
        assert!(
            rule.matches(&hit),
            "host key is lowercased and port-free like host rules"
        );

        let mut wrong_value = facts("GET", "other.example", "/");
        wrong_value.maps = &registry;
        assert_eq!(
            rule.explain(&wrong_value),
            Err("map \"tenants\": key \"other.example\" -> \"free\", expected \"vip\"".to_owned())
        );
        let mut absent = facts("GET", "nowhere.example", "/");
        absent.maps = &registry;
        assert_eq!(
            rule.explain(&absent),
            Err("map \"tenants\": key \"nowhere.example\" has no entry".to_owned())
        );
        let mut missing_map = facts("GET", "acme.example", "/");
        missing_map.maps = MapRegistry::empty();
        assert_eq!(
            rule.explain(&missing_map),
            Err("map \"tenants\": not loaded".to_owned())
        );

        // Presence-only form (no `equals`): any entry matches.
        let rule = compile(RuleSpec {
            name: "known".to_owned(),
            map: Some(MapConditionSpec {
                name: "tenants".to_owned(),
                key: None,
                header: Some("X-Tenant".to_owned()),
                equals: None,
            }),
            ..RuleSpec::default()
        });
        let headers = vec![("x-tenant".to_owned(), "acme".to_owned())];
        let mut hit = facts("GET", "x", "/");
        hit.maps = &registry;
        hit.headers = &headers;
        assert!(rule.matches(&hit));
        let no_header = vec![];
        let mut miss = hit;
        miss.headers = &no_header;
        assert_eq!(
            rule.explain(&miss),
            Err("map \"tenants\": key \"\" has no entry".to_owned())
        );
    }

    #[test]
    fn map_compile_rejects_ambiguous_keys_and_unknown_sources() {
        let err = Rule::compile(&RuleSpec {
            name: "x".to_owned(),
            map: Some(MapConditionSpec {
                name: "m".to_owned(),
                key: Some("host".to_owned()),
                header: Some("x-a".to_owned()),
                equals: None,
            }),
            ..RuleSpec::default()
        })
        .expect_err("key and header");
        assert_eq!(err.field, "map.key");

        let err = Rule::compile(&RuleSpec {
            name: "x".to_owned(),
            map: Some(MapConditionSpec {
                name: "m".to_owned(),
                key: Some("uri".to_owned()),
                header: None,
                equals: None,
            }),
            ..RuleSpec::default()
        })
        .expect_err("unknown key source");
        assert_eq!(err.field, "map.key");

        let err = Rule::compile(&RuleSpec {
            name: "x".to_owned(),
            map: Some(MapConditionSpec {
                name: "".to_owned(),
                key: Some("ip".to_owned()),
                header: None,
                equals: None,
            }),
            ..RuleSpec::default()
        })
        .expect_err("empty map name");
        assert_eq!(err.field, "map.name");
    }

    /// Property (B-I11/C10): with cookies and a map condition in play,
    /// `matches` and `explain` still never disagree.
    #[test]
    fn matches_agrees_with_explain_with_cookies_and_maps() {
        let registry = registry_with("t", "api.example.com on\n");
        let rule = compile(RuleSpec {
            name: "prop".to_owned(),
            cookies: vec![CookieSpec {
                name: "canary".to_owned(),
                exact: None,
                regex: Some("^v[0-9]+$".to_owned()),
                present: false,
            }],
            map: Some(MapConditionSpec {
                name: "t".to_owned(),
                key: Some("host".to_owned()),
                header: None,
                equals: Some("on".to_owned()),
            }),
            ..RuleSpec::default()
        });
        let cookie_headers = [
            vec![],
            vec![("cookie".to_owned(), "canary=v2".to_owned())],
            vec![("cookie".to_owned(), "canary=beta".to_owned())],
        ];
        let mut checks = 0usize;
        for host in ["api.example.com", "other.example.com"] {
            for headers in &cookie_headers {
                let facts = RequestFacts {
                    method: "GET",
                    host,
                    path: "/",
                    headers,
                    peer: "127.0.0.1".parse().expect("ip"),
                    maps: &registry,
                };
                assert_eq!(
                    rule.matches(&facts),
                    rule.explain(&facts).is_ok(),
                    "matches/explain disagree for {facts:?}",
                );
                checks += 1;
            }
        }
        assert_eq!(checks, 6);
    }

    #[test]
    fn host_key_and_path_of_normalize() {
        assert_eq!(host_key("API.Example.com:8443"), "api.example.com");
        assert_eq!(host_key("[::1]:8080"), "::1");
        assert_eq!(host_key("plain"), "plain");
        assert_eq!(path_of("/a/b?x=1&y=2"), "/a/b");
        assert_eq!(path_of("/a/b"), "/a/b");
        assert_eq!(path_of("*"), "*");
    }

    // --- action semantics: location templates + prefix rewrite ---

    #[test]
    fn location_placeholders_render_per_request() {
        assert_eq!(
            render_location("https://$host$request_uri", "example.com:8443", "/a/b?x=1").unwrap(),
            "https://example.com:8443/a/b?x=1"
        );
        // `$uri` drops the query, `$request_uri` keeps it.
        assert_eq!(
            render_location("/moved$uri", "h", "/a?x=1").unwrap(),
            "/moved/a"
        );
        assert_eq!(
            render_location("/moved$request_uri", "h", "/a?x=1").unwrap(),
            "/moved/a?x=1"
        );
        // Literal text passes through untouched.
        assert_eq!(
            render_location("https://fixed.example/", "h", "/a").unwrap(),
            "https://fixed.example/"
        );
    }

    #[test]
    fn location_rejects_unknown_placeholders_and_controls() {
        assert!(validate_location("https://$http_host/").is_err());
        assert!(validate_location("https://$host$").is_err());
        assert!(validate_location("/ok$uri").is_ok());
        assert!(validate_location("/bad\r\nX: 1").is_err());
        assert!(validate_location("").is_err());
        // Runtime render applies the same validation.
        assert!(render_location("/$nope", "h", "/a").is_err());
    }

    #[test]
    fn prefix_rewrite_is_literal_and_query_preserving() {
        // Replace the matched prefix (Envoy `prefix_rewrite`).
        assert_eq!(rewrite_prefix("/api/x", "/api", "/v2"), "/v2/x");
        assert_eq!(rewrite_prefix("/api", "/api", "/v2"), "/v2");
        // Empty replacement strips the prefix.
        assert_eq!(rewrite_prefix("/api/x", "/api", ""), "/x");
        // Same literal prefix semantics as the match (no normalization):
        // `/api` also matched `/api2`, so the remainder `2` is kept.
        assert_eq!(rewrite_prefix("/api2", "/api", "/v2"), "/v22");
        // A path without the prefix is untouched (defense in depth).
        assert_eq!(rewrite_prefix("/x", "/api", "/v2"), "/x");
    }
}
