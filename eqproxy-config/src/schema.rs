//! Versioned schema of the canonical configuration (TOML).
//!
//! Strict types + `deny_unknown_fields`: an unknown field is an error, never
//! silently ignored (the converter rule applied to our own format).

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Deserialize;

use crate::duration;

/// Schema version supported by this binary.
pub const SCHEMA_VERSION: u32 = 1;

/// Resource budget (ADR-0002): maximum configuration file size.
/// A larger config is rejected before parsing.
pub const MAX_CONFIG_BYTES: usize = 1_048_576;

/// Resource budget (ADR-0002): maximum combined
/// `[listener.*]` + `[backend.*]` sections.
pub const MAX_SECTIONS: usize = 1024;

/// Resource budget: maximum size of a `local_response.body`.
pub const MAX_LOCAL_RESPONSE_BYTES: usize = 8192;

/// Resource budget: maximum `maxqueue` per backend (B-H7).
pub const MAX_QUEUE: u32 = 10_000;

/// Resource budget (v0.6): maximum routing rules per listener.
pub const MAX_RULES: usize = 256;

/// Maximum `retries` per backend (B-H7).
pub const MAX_RETRIES: u32 = 5;

fn default_maxconn() -> u32 {
    1024
}

fn default_connect_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_idle_timeout() -> Duration {
    Duration::from_secs(60)
}

fn default_shutdown_grace() -> Duration {
    Duration::from_secs(10)
}

fn default_client_header_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_server_header_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_weight() -> u32 {
    1
}

fn default_true() -> bool {
    true
}

fn default_health_interval() -> Duration {
    Duration::from_secs(2)
}

fn default_health_timeout() -> Duration {
    Duration::from_secs(1)
}

fn default_fall() -> u32 {
    3
}

fn default_rise() -> u32 {
    2
}

fn default_expect_status() -> String {
    "200-299".to_owned()
}

fn default_http_path() -> String {
    "/".to_owned()
}

fn default_queue_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_no_server_status() -> u16 {
    503
}

fn default_content_type() -> String {
    "text/plain; charset=utf-8".to_owned()
}

/// Maximum weight per server (HAProxy `weight` range, cfg 3.4 "server").
pub const MAX_SERVER_WEIGHT: u32 = 256;

/// Proxy mode of a listener (A1 `tcp`, A2 `http`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListenerMode {
    /// TCP tunnel without interpretation (Phase 1).
    #[default]
    Tcp,
    /// HTTP/1.1 proxy with strict framing (Phase 2a).
    Http,
}

/// Balancing algorithm (Phase 2b: `roundrobin` only; B2–B5 in later phases).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BalanceAlgorithm {
    /// Smooth weighted round-robin (B1 + B7).
    #[default]
    RoundRobin,
}

/// PROXY protocol send to the backend (A9; reception in Phase 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocolMode {
    /// No PROXY header (default).
    #[default]
    None,
    /// PROXY protocol v1 header (`PROXY TCP4/TCP6 …`).
    V1,
}

/// Minimum accepted TLS version (A11/A12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum TlsVersion {
    /// TLS 1.2 (default; TLS 1.0/1.1 are never accepted).
    #[default]
    #[serde(rename = "1.2")]
    V1_2,
    /// TLS 1.3.
    #[serde(rename = "1.3")]
    V1_3,
}

/// TLS termination at the listener (A11): certificate, key and ALPN.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsServerConfig {
    /// Path to the PEM certificate chain (leaf first).
    pub cert: String,
    /// Path to the PEM private key (PKCS#8, PKCS#1 or SEC1).
    pub key: String,
    /// Offered ALPN protocols (e.g. `["http/1.1"]`); empty = no ALPN.
    #[serde(default)]
    pub alpn: Vec<String>,
    /// Minimum TLS version (default 1.2).
    #[serde(default)]
    pub min_version: TlsVersion,
    /// Client CA PEM: present = mTLS (A15) — client certificates are
    /// required and verified against this bundle.
    pub client_ca: Option<String>,
}

/// TLS to the backend (A12): verification on by default.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsClientConfig {
    /// Server certificate and name verification (default `true`).
    #[serde(default = "default_true")]
    pub verify: bool,
    /// Extra CA PEM to verify the backend (private CAs, tests).
    pub ca_file: Option<String>,
    /// Name to verify/SNI; defaults to the host part of the address.
    pub server_name: Option<String>,
    /// ALPN protocols to offer in the handshake; empty = no ALPN.
    #[serde(default)]
    pub alpn: Vec<String>,
    /// Minimum TLS version (default 1.2).
    #[serde(default)]
    pub min_version: TlsVersion,
}

/// One backend server with its weight (B7).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Server `IP:PORT` address.
    pub addr: String,
    /// Balancing weight (0 = drained: never selected, still health-checked).
    #[serde(default = "default_weight")]
    pub weight: u32,
}

/// Active TCP health check (B11 TCP): `fall` consecutive failures drop the
/// server, `rise` consecutive successes raise it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    /// Interval between check cycles.
    #[serde(default = "default_health_interval", with = "duration")]
    pub interval: Duration,
    /// Timeout of each TCP connection attempt.
    #[serde(default = "default_health_timeout", with = "duration")]
    pub timeout: Duration,
    /// Consecutive failures to mark a server down.
    #[serde(default = "default_fall")]
    pub fall: u32,
    /// Consecutive successes to mark a server up.
    #[serde(default = "default_rise")]
    pub rise: u32,
    /// Check type (`"type"` key): `"tcp"` (connect only, default) or
    /// `"http"` (B-H6: request + `expect` matching).
    #[serde(rename = "type", default)]
    pub kind: HealthCheckKind,
    /// HTTP check: request path (default `/`).
    #[serde(default = "default_http_path")]
    pub http_path: String,
    /// HTTP check: request method (default `"GET"`; GET or HEAD only).
    #[serde(default)]
    pub http_method: HealthCheckMethod,
    /// HTTP check: expected status codes/ranges (default `"200-299"`).
    #[serde(default = "default_expect_status")]
    pub expect_status: String,
    /// HTTP check: regex that must match somewhere in the response body
    /// (optional; the body is read up to 64 KiB).
    pub expect_rstring: Option<String>,
    /// HTTP check: Host header (default: the server address).
    pub http_host: Option<String>,
    /// Passive detection (B-N10): live-traffic connect failures also feed
    /// the `fall`/`rise` machine (default `false` = active checks only).
    #[serde(default)]
    pub passive: bool,
}

/// Health check type (`"type"` key of `[backend.*.health_check]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthCheckKind {
    /// TCP connect only (B11; default).
    #[default]
    Tcp,
    /// HTTP request with `expect status`/`expect rstring` (B-H6).
    Http,
}

/// HTTP health-check request method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthCheckMethod {
    #[default]
    Get,
    Head,
}

/// `X-Forwarded-For` / `X-Real-IP` handling (B-N4 first step).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardedHeaders {
    /// No forwarded headers (default; explicit opt-in).
    #[default]
    Off,
    /// Append the client address to `X-Forwarded-For`.
    Append,
    /// Replace `X-Forwarded-For`/`X-Real-IP` with the client address.
    Replace,
}

/// Custom local response when no server is available (C9 minimal).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalResponseConfig {
    /// Status code (400-599).
    #[serde(default = "default_no_server_status")]
    pub status: u16,
    /// Content-Type of the body (default `text/plain; charset=utf-8`).
    #[serde(default = "default_content_type")]
    pub content_type: String,
    /// Response body (bounded: [`MAX_LOCAL_RESPONSE_BYTES`]).
    pub body: String,
}

/// Metrics options (D1): cardinality stays bounded; detailed per-server
/// counters are opt-in (CE4).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Per-server counters (bounded by [`MAX_SECTIONS`]).
    #[serde(default)]
    pub detailed: bool,
}

/// One header condition of a routing rule (exactly one of `exact`,
/// `regex` or `present = true`; v0.6, B-H3/B-N3).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderConditionConfig {
    /// Header name (case-insensitive).
    pub name: String,
    /// Exact value (byte-for-byte).
    pub exact: Option<String>,
    /// Unanchored regex over the value.
    pub regex: Option<String>,
    /// Presence check (`true`; the value is irrelevant).
    #[serde(default)]
    pub present: bool,
}

/// Rewrite applied to the forwarded request when the rule routes to a
/// backend (v0.6 slice 2; Envoy `prefix_rewrite`/`host_rewrite`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewriteConfig {
    /// Replaces the rule's matched `path_prefix` in the forwarded target
    /// (literal, no regex; `""` strips the prefix). Query untouched.
    pub path_prefix_rewrite: Option<String>,
    /// Exact value of the upstream `Host` header.
    pub host_rewrite: Option<String>,
}

/// Local 3xx response (v0.6 slice 2; nginx `return 301`, Envoy `redirect`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedirectConfig {
    /// 301 (default), 302, 303, 307 or 308.
    pub status: Option<u16>,
    /// Location template: literal text plus `$host`, `$uri`, `$request_uri`.
    pub location: String,
}

/// Local response served without contacting a backend (v0.6 slice 2;
/// Envoy `direct_response`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectResponseConfig {
    /// Status code (200-599).
    pub status: u16,
    /// Content type (default `text/plain`).
    pub content_type: Option<String>,
    /// Body (default empty; bounded by the local-response budget).
    pub body: Option<String>,
}

/// One routing rule (v0.6, B-H3/B-H4): ordered match conditions plus
/// exactly one action (`use_backend`, `redirect` or `direct_response`).
/// Rules run in array order, first match wins; the listener's `backend`
/// is the fallback when no rule matches. All conditions of a rule are
/// ANDed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    /// Display name for `explain`/logs (default `"rule-N"`).
    pub name: Option<String>,
    /// Action: backend that receives the matching requests.
    pub use_backend: Option<String>,
    /// Rewrite applied to the forwarded request (`use_backend` only).
    #[serde(default)]
    pub rewrite: Option<RewriteConfig>,
    /// Action: answer locally with 3xx + `Location` (no backend).
    #[serde(default)]
    pub redirect: Option<RedirectConfig>,
    /// Action: answer locally with the configured response (no backend).
    #[serde(default)]
    pub direct_response: Option<DirectResponseConfig>,
    /// Exact host (case-insensitive, port-free).
    pub host: Option<String>,
    /// Host prefix (case-insensitive).
    pub host_prefix: Option<String>,
    /// Host regex (unanchored).
    pub host_regex: Option<String>,
    /// Exact path (query string excluded, case-sensitive).
    pub path: Option<String>,
    /// Literal path prefix (no normalization: `/v1` also matches `/v10`).
    pub path_prefix: Option<String>,
    /// Path regex (unanchored).
    pub path_regex: Option<String>,
    /// Accepted methods (empty = any).
    #[serde(default)]
    pub methods: Vec<String>,
    /// Header conditions (all must hold).
    #[serde(default)]
    pub headers: Vec<HeaderConditionConfig>,
    /// Source CIDR blocks (empty = any).
    #[serde(default)]
    pub ip: Vec<String>,
}

impl RuleConfig {
    /// Compile input for [`eqproxy_core::rules::Rule::compile`]; `index`
    /// positions the rule in its listener (default name `"rule-N"`).
    #[must_use]
    pub fn to_spec(&self, index: usize) -> eqproxy_core::rules::RuleSpec {
        eqproxy_core::rules::RuleSpec {
            name: self
                .name
                .clone()
                .unwrap_or_else(|| format!("rule-{}", index + 1)),
            host: self.host.clone(),
            host_prefix: self.host_prefix.clone(),
            host_regex: self.host_regex.clone(),
            path: self.path.clone(),
            path_prefix: self.path_prefix.clone(),
            path_regex: self.path_regex.clone(),
            methods: self.methods.clone(),
            headers: self
                .headers
                .iter()
                .map(|h| eqproxy_core::rules::HeaderSpec {
                    name: h.name.clone(),
                    exact: h.exact.clone(),
                    regex: h.regex.clone(),
                    present: h.present,
                })
                .collect(),
            ip: self.ip.clone(),
        }
    }
}

/// Full EQProxy configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Schema version; must be [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// TCP/HTTP frontends defined by name.
    #[serde(default)]
    pub listener: BTreeMap<String, ListenerConfig>,
    /// Backends defined by name.
    #[serde(default)]
    pub backend: BTreeMap<String, BackendConfig>,
    /// Drain window on shutdown: live connections may finish.
    #[serde(default = "default_shutdown_grace", with = "duration")]
    pub shutdown_grace: Duration,
    /// Metrics options (D1/D5): detailed counters are opt-in (CE4).
    #[serde(default)]
    pub metrics: MetricsConfig,
}

/// A frontend: where to listen and which backend to send to.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    /// Listen `IP:PORT` address (port 0 = ephemeral, useful in tests).
    pub listen: String,
    /// Mode: `"tcp"` (tunnel, default) or `"http"` (strict HTTP/1.1).
    #[serde(default)]
    pub mode: ListenerMode,
    /// Backend name ([`BackendConfig`] in `Config::backend`).
    pub backend: String,
    /// Maximum concurrent connections; newcomers are explicitly refused when full.
    #[serde(default = "default_maxconn")]
    pub maxconn: u32,
    /// Timeout for connecting to the backend.
    #[serde(default = "default_connect_timeout", with = "duration")]
    pub connect_timeout: Duration,
    /// Inactivity timeout per direction (no bytes in either direction).
    #[serde(default = "default_idle_timeout", with = "duration")]
    pub idle_timeout: Duration,
    /// Client phase: maximum to receive the request head (`http` only).
    #[serde(default = "default_client_header_timeout", with = "duration")]
    pub client_header_timeout: Duration,
    /// Server phase: maximum to receive the response head (`http` only).
    #[serde(default = "default_server_header_timeout", with = "duration")]
    pub server_header_timeout: Duration,
    /// TLS termination at this listener (A11). Absent = plain TCP.
    #[serde(default)]
    pub tls: Option<TlsServerConfig>,
    /// Receive PROXY protocol v1 from trusted proxies (B-H9/B-E10).
    #[serde(default)]
    pub proxy_receive: bool,
    /// Trusted PROXY origins (IP or CIDR; required non-empty with
    /// `proxy_receive = true`).
    #[serde(default)]
    pub proxy_allow: Vec<String>,
    /// `X-Forwarded-For`/`X-Real-IP` handling (`http` only; B-N4).
    #[serde(default)]
    pub forwarded_headers: ForwardedHeaders,
    /// Custom response when no server is available (C9 minimal).
    #[serde(default)]
    pub local_response: Option<LocalResponseConfig>,
    /// Ordered routing rules (v0.6, B-H3/B-H4): first match wins, the
    /// `backend` above is the fallback. `http` mode only.
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

/// A backend: one or more origin servers with balancing (Phase 2b).
///
/// `server` (one server, compat 0.1) and `servers` (weighted list) are
/// mutually exclusive: exactly one must be present (validated in [`crate::check`]).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendConfig {
    /// Origin server `IP:PORT` address (compat 0.1.0).
    pub server: Option<String>,
    /// Weighted servers (B1/B7). Mutually exclusive with `server`.
    pub servers: Option<Vec<ServerConfig>>,
    /// Balancing algorithm (Phase 2b: `"roundrobin"`).
    #[serde(default)]
    pub balance: BalanceAlgorithm,
    /// PROXY protocol v1 send to the servers (A9).
    #[serde(default)]
    pub proxy_protocol: ProxyProtocolMode,
    /// Active TCP health check (B11). Absent = all servers operational.
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
    /// TLS to the servers (A12). Absent = plain TCP.
    #[serde(default)]
    pub tls: Option<TlsClientConfig>,
    /// Bounded queue while no server is available (B-H7; 0 = reject now).
    #[serde(default)]
    pub maxqueue: u32,
    /// Maximum wait in the queue (used when `maxqueue > 0`).
    #[serde(default = "default_queue_timeout", with = "duration")]
    pub timeout_queue: Duration,
    /// Connect-phase retries on dial failure (0 = disabled; B-H7).
    #[serde(default)]
    pub retries: u32,
    /// Allow retrying non-idempotent requests (default `false`).
    #[serde(default)]
    pub retry_non_idempotent: bool,
}

impl BackendConfig {
    /// Declared (address, weight) pairs, via `server` or `servers`.
    #[must_use]
    pub fn server_entries(&self) -> Vec<(&str, u32)> {
        match (&self.server, &self.servers) {
            (Some(addr), _) => vec![(addr.as_str(), 1)],
            (None, Some(servers)) => servers
                .iter()
                .map(|s| (s.addr.as_str(), s.weight))
                .collect(),
            (None, None) => Vec::new(),
        }
    }
}
