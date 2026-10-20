//! Versioned schema of the canonical configuration (TOML).
//!
//! Strict types + `deny_unknown_fields`: an unknown field is an error, never
//! silently ignored (the converter rule applied to our own format).

use std::collections::BTreeMap;
use std::net::SocketAddr;
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

/// Resource budget (B-N9): maximum Basic users per rule.
pub const MAX_AUTH_USERS: usize = 1024;

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

fn default_resolve_interval() -> Duration {
    Duration::from_secs(30)
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

/// Resource budget (B-I11): maximum targets of one `split` action.
pub const MAX_SPLIT_TARGETS: usize = 32;

/// Bounds of a map's `reload_interval` (C10): `"0s"` loads the file
/// once (static), otherwise the re-read period sits in this range.
pub const MIN_MAP_RELOAD_INTERVAL: Duration = Duration::from_millis(250);
/// Maximum map `reload_interval` (see [`MIN_MAP_RELOAD_INTERVAL`]).
pub const MAX_MAP_RELOAD_INTERVAL: Duration = Duration::from_secs(3_600);

/// Proxy mode of a listener (A1 `tcp`, A2 `http`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ListenerMode {
    /// TCP tunnel without interpretation (Phase 1).
    #[default]
    Tcp,
    /// HTTP/1.1 proxy with strict framing (Phase 2a).
    Http,
}

/// Balancing algorithm (B1/B7 `roundrobin`; B-H5/B-N12/B-E6 `leastconn`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum BalanceAlgorithm {
    /// Smooth weighted round-robin (B1 + B7).
    #[default]
    RoundRobin,
    /// Weighted least-connections (B-H5/B-N12/B-E6). The reference names
    /// `least_conn` (nginx) and `least_request` (Envoy `LEAST_REQUEST`)
    /// are accepted as aliases of `leastconn` (HAProxy).
    #[serde(alias = "least_conn", alias = "least_request")]
    LeastConn,
}

/// PROXY protocol send to the backend (A9; reception in Phase 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocolMode {
    /// No PROXY header (default).
    #[default]
    None,
    /// PROXY protocol v1 header (`PROXY TCP4/TCP6 …`).
    V1,
    /// PROXY protocol v2 binary header (A10).
    V2,
}

/// Minimum accepted TLS version (A11/A12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, schemars::JsonSchema)]
pub enum TlsVersion {
    /// TLS 1.2 (default; TLS 1.0/1.1 are never accepted).
    #[default]
    #[serde(rename = "1.2")]
    V1_2,
    /// TLS 1.3.
    #[serde(rename = "1.3")]
    V1_3,
}

/// One SNI certificate of a listener (B-I2/B-H10/B-E9; Envoy
/// `filter_chains` per SNI, nginx multiple `ssl_certificate`): the
/// listener serves it for the names it declares and the default
/// certificate for everything else.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SniCertConfig {
    /// Path to the PEM certificate chain (leaf first).
    pub cert: String,
    /// Path to the PEM private key of the leaf (PKCS#8, PKCS#1 or SEC1).
    pub key: String,
    /// SNI names answered by this certificate: exact DNS names or a
    /// wildcard `*.domain` (one extra label; `*.a.example` does not
    /// match `x.y.a.example`). Case-insensitive.
    pub names: Vec<String>,
}

/// TLS termination at the listener (A11): certificate, key and ALPN.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TlsServerConfig {
    /// Path to the PEM certificate chain (leaf first).
    pub cert: String,
    /// Path to the PEM private key (PKCS#8, PKCS#1 or SEC1).
    pub key: String,
    /// Additional certificates selected by SNI (B-I2/B-H10/B-E9). The
    /// `cert`/`key` pair above stays the default: it answers clients
    /// without SNI and names no entry claims.
    #[serde(default)]
    pub certs: Vec<SniCertConfig>,
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
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

/// A parsed server address: a literal `IP:PORT` or a `HOSTNAME:PORT`
/// that the dataplane resolves in the background (B-H13/B-N18/B-E15).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ServerTarget {
    /// Literal `IP:PORT` (v4 or bracketed v6): no DNS involved.
    Ip(SocketAddr),
    /// `HOSTNAME:PORT`: resolved non-blockingly and re-resolved at the
    /// backend's `resolve_interval`.
    Name { host: String, port: u16 },
}

/// Parses a server address (Q1: the error names the cause and the fix).
/// Accepts `IP:PORT`, `[IPv6]:PORT` and `HOSTNAME:PORT`; hostnames are
/// lowercased (DNS is case-insensitive) and limited to letters, digits,
/// `.`, `-` and `_`.
pub fn parse_server_target(raw: &str) -> Result<ServerTarget, String> {
    if let Ok(ip) = raw.parse::<SocketAddr>() {
        return Ok(ServerTarget::Ip(ip));
    }
    let Some((host, port)) = raw.rsplit_once(':') else {
        return Err(format!(
            "\"{raw}\" is missing the :PORT part (expected HOSTNAME:PORT or IP:PORT)"
        ));
    };
    if host.contains(':') {
        return Err(format!(
            "\"{raw}\": a raw IPv6 literal must be in brackets (expected [::1]:PORT)"
        ));
    }
    if host.is_empty() {
        return Err(format!(
            "\"{raw}\": the host part is empty (expected HOSTNAME:PORT)"
        ));
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err(format!(
            "\"{raw}\": the host must be letters, digits, '.', '-' or '_' (got \"{host}\")"
        ));
    }
    let port: u16 = port.parse().map_err(|_| {
        format!("\"{raw}\": the port must be a number between 0 and 65535 (got \"{port}\")")
    })?;
    Ok(ServerTarget::Name {
        host: host.to_ascii_lowercase(),
        port,
    })
}

/// One backend server with its weight (B7).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Server `IP:PORT` or `HOSTNAME:PORT` address (B-H13/B-N18/B-E15:
    /// hostnames are resolved in the background, never on the request
    /// path; listeners serve from the first moment whatever DNS does).
    pub addr: String,
    /// Balancing weight (0 = drained: never selected, still health-checked).
    #[serde(default = "default_weight")]
    pub weight: u32,
}

/// Active TCP health check (B11 TCP): `fall` consecutive failures drop the
/// server, `rise` consecutive successes raise it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    /// Interval between check cycles.
    #[serde(default = "default_health_interval", with = "duration")]
    #[schemars(with = "String")]
    pub interval: Duration,
    /// Timeout of each TCP connection attempt.
    #[serde(default = "default_health_timeout", with = "duration")]
    #[schemars(with = "String")]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum HealthCheckKind {
    /// TCP connect only (B11; default).
    #[default]
    Tcp,
    /// HTTP request with `expect status`/`expect rstring` (B-H6).
    Http,
}

/// HTTP health-check request method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum HealthCheckMethod {
    #[default]
    Get,
    Head,
}

/// `X-Forwarded-For` / `X-Real-IP` handling (B-N4 first step).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Per-server counters (bounded by [`MAX_SECTIONS`]).
    #[serde(default)]
    pub detailed: bool,
}

/// One header condition of a routing rule (exactly one of `exact`,
/// `regex` or `present = true`; v0.6, B-H3/B-N3).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
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

/// CORS policy of a matched rule (B-I10; ingress-nginx `cors-*`):
/// preflight `OPTIONS` is answered locally and every response of the
/// rule carries the CORS headers.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CorsConfig {
    /// Exact allowed origin (`Access-Control-Allow-Origin`). `"*"` is
    /// rejected together with `allow_credentials` (the browser does too).
    pub allow_origin: String,
    /// `Access-Control-Allow-Methods` (default `GET, HEAD, POST, OPTIONS`).
    pub allow_methods: Option<String>,
    /// `Access-Control-Allow-Headers` (omitted when absent).
    pub allow_headers: Option<String>,
    /// `Access-Control-Expose-Headers` (omitted when absent).
    pub expose_headers: Option<String>,
    /// Preflight cache time (`Access-Control-Max-Age`; `"0s"` omits it).
    #[serde(default, with = "duration")]
    #[schemars(with = "String")]
    pub max_age: Duration,
    /// `Access-Control-Allow-Credentials: true`.
    #[serde(default)]
    pub allow_credentials: bool,
}

/// Token-bucket rate limit of a rule (B-N8/B-I7/B-E16; nginx `limit_req`,
/// ingress `limit-rps`/`limit-rpm`, Envoy `local_ratelimit`): per client
/// IP, in-memory — no network in the hot path (Q6).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Tokens added per `per` window (>= 1).
    pub rate: u32,
    /// Window for `rate` (default `"1s"`); `"60s"` expresses rpm.
    #[serde(default = "one_second", with = "duration")]
    #[schemars(with = "String")]
    pub per: Duration,
    /// Bucket capacity (default = `rate`); a request over the limit gets
    /// an explicit 429, never a silent drop.
    pub burst: Option<u32>,
}

fn one_second() -> Duration {
    Duration::from_secs(1)
}

fn default_map_reload() -> Duration {
    Duration::from_secs(5)
}

/// Authentication type (`"type"` key of `[listener.*.rules.auth]`,
/// ingress-nginx `auth-type`): `"basic"` only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuthType {
    /// HTTP Basic against htpasswd-format users (ingress `auth-secret`).
    Basic,
}

/// Authentication of a matched rule (B-N9/B-I9; nginx `auth_basic` +
/// `auth_request`, ingress-nginx `auth-type`/`auth-url`): HTTP Basic
/// against htpasswd-format users and/or an external auth subrequest.
/// Both run when both are set: Basic first (local), then `url`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// External auth subrequest (ingress `auth-url`, nginx
    /// `auth_request`): `http://HOST[:PORT][/PATH]`. 2xx allows the
    /// request, 401/403 denies it (the auth response reaches the
    /// client), anything else fails closed with an explicit error.
    pub url: Option<String>,
    /// Auth type (`"type"` key, ingress `auth-type`): `"basic"` only.
    #[serde(rename = "type")]
    pub kind: Option<AuthType>,
    /// `WWW-Authenticate` realm (default `"EQProxy"`).
    pub realm: Option<String>,
    /// htpasswd-format entries `user:hash` (`$apr1$…` or plain).
    #[serde(default)]
    pub users: Vec<String>,
}

/// One header action (B-N4/B-I4/B-E17): name + value template.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HeaderOpConfig {
    /// Header name (case-insensitive; no spaces or `:`).
    pub name: String,
    /// Value template: literal text plus `$remote_addr`, `$host`, `$scheme`.
    pub value: String,
}

/// Rewrite applied to the forwarded request when the rule routes to a
/// backend (v0.6 slice 2; Envoy `prefix_rewrite`/`host_rewrite`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RewriteConfig {
    /// Replaces the rule's matched `path_prefix` in the forwarded target
    /// (literal, no regex; `""` strips the prefix). Query untouched.
    pub path_prefix_rewrite: Option<String>,
    /// Exact value of the upstream `Host` header.
    pub host_rewrite: Option<String>,
}

/// Local 3xx response (v0.6 slice 2; nginx `return 301`, Envoy `redirect`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RedirectConfig {
    /// 301 (default), 302, 303, 307 or 308.
    pub status: Option<u16>,
    /// Location template: literal text plus `$host`, `$uri`, `$request_uri`.
    pub location: String,
}

/// Local response served without contacting a backend (v0.6 slice 2;
/// Envoy `direct_response`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectResponseConfig {
    /// Status code (200-599).
    pub status: u16,
    /// Content type (default `text/plain`).
    pub content_type: Option<String>,
    /// Body (default empty; bounded by the local-response budget).
    pub body: Option<String>,
}

/// One cookie condition of a routing rule (B-I11 canary-by-cookie;
/// exactly one of `exact`, `regex` or `present = true`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CookieConditionConfig {
    /// Cookie name (case-insensitive; RFC 6265 pair parsing).
    pub name: String,
    /// Exact value (byte-for-byte).
    pub exact: Option<String>,
    /// Unanchored regex over the value.
    pub regex: Option<String>,
    /// Presence check (`true`; the value is irrelevant).
    #[serde(default)]
    pub present: bool,
}

/// Map-backed match condition (C10 hot maps; exactly one of `key` or
/// `header` selects the lookup key).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MapConditionConfig {
    /// Name of the `[maps.*]` table consulted.
    pub name: String,
    /// Key source: `"ip"`, `"host"`, `"path"` or `"method"`.
    pub key: Option<String>,
    /// Key source: first value of this request header.
    pub header: Option<String>,
    /// Required mapped value (absent = presence match).
    pub equals: Option<String>,
}

/// Hash policy of a `split` action (B-H3; Envoy `hash_policy` +
/// `RING_HASH`): the target is chosen by a hash of the request key
/// instead of the weighted rotation, so the same key keeps the same
/// target while targets come and go.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HashPolicyConfig {
    /// Request key: `"source"` (client IP), `"path"`, `"host"`,
    /// `"cookie:NAME"` or `"header:NAME"` (headers and cookie names are
    /// case-insensitive).
    pub key: String,
}

/// One mirrored fraction of the matched traffic (B-H3; Envoy
/// `request_mirror_policies`): a copy of the request goes to another
/// backend, fire-and-forget — its response never reaches the client and
/// a mirror failure never changes the client's answer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestMirrorConfig {
    /// Backend that receives the mirrored copy.
    pub backend: String,
    /// Percentage of the matching requests to mirror (1-100, default 100).
    #[serde(default = "default_mirror_percentage")]
    pub percentage: u32,
}

fn default_mirror_percentage() -> u32 {
    100
}

/// One weighted target of a `split` action (B-I11; Envoy
/// `weighted_clusters`, ingress-nginx `canary-weight`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SplitTargetConfig {
    /// Backend that receives this share of the requests.
    pub backend: String,
    /// Share weight (0 = target disabled: canary rollback without
    /// touching the rest; at least one target must have weight > 0).
    #[serde(default = "default_weight")]
    pub weight: u32,
}

/// A named data map (C10 / PP-02): `key → value` tables that rules
/// consult, updatable **in hot** without a config reload and without
/// losing any other dataplane state.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MapConfig {
    /// Map data file (relative to the config file): one `key value`
    /// pair per line, `#` comments at line start, a bare `key` maps to
    /// `""`. Re-read every `reload_interval` (watched in hot).
    pub file: Option<String>,
    /// Inline entries (static; mutually exclusive with `file`).
    pub entries: Option<BTreeMap<String, String>>,
    /// Value for keys without an entry (nginx `map` `default`).
    pub default: Option<String>,
    /// File re-read period (default `"5s"`; `"0s"` = load once).
    #[serde(default = "default_map_reload", with = "duration")]
    #[schemars(with = "String")]
    pub reload_interval: Duration,
}

/// One routing rule (v0.6, B-H3/B-H4): ordered match conditions plus
/// exactly one action (`use_backend`, `split`, `redirect` or
/// `direct_response`). Rules run in array order, first match wins; the
/// listener's `backend` is the fallback when no rule matches. All
/// conditions of a rule are ANDed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    /// Display name for `explain`/logs (default `"rule-N"`).
    pub name: Option<String>,
    /// Action: backend that receives the matching requests.
    pub use_backend: Option<String>,
    /// Action: weighted traffic split across backends (B-I11 canary;
    /// Envoy `weighted_clusters`). Mutually exclusive with the other
    /// actions.
    pub split: Option<Vec<SplitTargetConfig>>,
    /// Hash policy of the split (B-H3; Envoy `hash_policy`): with it the
    /// target is chosen by the request key, not by the weighted rotation.
    /// Needs a `split` with at least two active targets.
    pub hash_policy: Option<HashPolicyConfig>,
    /// Mirror policy (B-H3; Envoy `request_mirror_policies`): copy a
    /// percentage of the matching requests to another backend without
    /// affecting the client's response.
    pub request_mirror: Option<RequestMirrorConfig>,
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
    /// Cookie conditions (all must hold; B-I11 canary-by-cookie).
    #[serde(default)]
    pub cookies: Vec<CookieConditionConfig>,
    /// Map-backed condition (C10 hot maps).
    #[serde(default)]
    pub map: Option<MapConditionConfig>,
    /// Request header actions (B-N4/B-I4/B-E17, `use_backend` only):
    /// `set` replaces (or inserts) one value, `add` appends another
    /// line keeping the client's, `del` removes the header before
    /// forwarding. Values support `$remote_addr`, `$host`, `$scheme`.
    #[serde(default)]
    pub set_headers: Vec<HeaderOpConfig>,
    #[serde(default)]
    pub add_headers: Vec<HeaderOpConfig>,
    #[serde(default)]
    pub del_headers: Vec<String>,
    /// Response header actions (any action): appended to the response
    /// the client sees. Same value templates.
    #[serde(default)]
    pub response_headers: Vec<HeaderOpConfig>,
    /// CORS policy (B-I10): preflight answered locally + response
    /// headers. `use_backend` rules only.
    #[serde(default)]
    pub cors: Option<CorsConfig>,
    /// Rate limit of the rule (B-N8/B-I7/B-E16), any action.
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    /// Authentication of the rule (B-N9/B-I9), any action.
    #[serde(default)]
    pub auth: Option<AuthConfig>,
    /// Source CIDR blocks (empty = any).
    #[serde(default)]
    pub ip: Vec<String>,
}

impl RuleConfig {
    /// True when the action forwards the request to a backend
    /// (`use_backend` or `split`): request-side header actions, CORS and
    /// `rewrite` apply to those only.
    #[must_use]
    pub fn forwards(&self) -> bool {
        self.use_backend.is_some() || self.split.is_some()
    }

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
            cookies: self
                .cookies
                .iter()
                .map(|c| eqproxy_core::rules::CookieSpec {
                    name: c.name.clone(),
                    exact: c.exact.clone(),
                    regex: c.regex.clone(),
                    present: c.present,
                })
                .collect(),
            ip: self.ip.clone(),
            map: self
                .map
                .as_ref()
                .map(|m| eqproxy_core::rules::MapConditionSpec {
                    name: m.name.clone(),
                    key: m.key.clone(),
                    header: m.header.clone(),
                    equals: m.equals.clone(),
                }),
        }
    }
}

/// Full EQProxy configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
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
    /// Named data maps (C10/PP-02), updatable in hot.
    #[serde(default)]
    pub maps: BTreeMap<String, MapConfig>,
    /// Drain window on shutdown: live connections may finish.
    #[serde(default = "default_shutdown_grace", with = "duration")]
    #[schemars(with = "String")]
    pub shutdown_grace: Duration,
    /// Metrics options (D1/D5): detailed counters are opt-in (CE4).
    #[serde(default)]
    pub metrics: MetricsConfig,
}

/// A frontend: where to listen and which backend to send to.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
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
    #[schemars(with = "String")]
    pub connect_timeout: Duration,
    /// Inactivity timeout per direction (no bytes in either direction).
    #[serde(default = "default_idle_timeout", with = "duration")]
    #[schemars(with = "String")]
    pub idle_timeout: Duration,
    /// Client phase: maximum to receive the request head (`http` only).
    #[serde(default = "default_client_header_timeout", with = "duration")]
    #[schemars(with = "String")]
    pub client_header_timeout: Duration,
    /// Server phase: maximum to receive the response head (`http` only).
    #[serde(default = "default_server_header_timeout", with = "duration")]
    #[schemars(with = "String")]
    pub server_header_timeout: Duration,
    /// Total duration cap for one forwarded exchange (`http` only;
    /// `"0s"` disables): request body + response head + response body.
    /// `max_stream_duration` (B-H11/B-E12) — complements `idle_timeout`:
    /// inactivity ≠ duration (Q5).
    #[serde(default, with = "duration")]
    #[schemars(with = "String")]
    pub max_stream_duration: Duration,
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

/// Session affinity of a backend (B-H8/B-N13/B-I8).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AffinityConfig {
    /// `"cookie"` (the proxy inserts a sticky cookie, HAProxy `cookie
    /// insert`) or `"source"` (hash of the client IP, nginx `ip_hash`).
    pub mode: String,
    /// Cookie name for `mode = "cookie"` (default `"eqproxy_affinity"`).
    pub cookie: Option<String>,
}

/// A backend: one or more origin servers with balancing (Phase 2b).
///
/// `server` (one server, compat 0.1) and `servers` (weighted list) are
/// mutually exclusive: exactly one must be present (validated in [`crate::check`]).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, schemars::JsonSchema)]
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
    /// Session affinity (B-H8/B-N13/B-I8): pin a client to the server
    /// that first served it.
    #[serde(default)]
    pub affinity: Option<AffinityConfig>,
    /// Bounded queue while no server is available (B-H7; 0 = reject now).
    #[serde(default)]
    pub maxqueue: u32,
    /// Maximum wait in the queue (used when `maxqueue > 0`).
    #[serde(default = "default_queue_timeout", with = "duration")]
    #[schemars(with = "String")]
    pub timeout_queue: Duration,
    /// Connect-phase retries on dial failure (0 = disabled; B-H7).
    #[serde(default)]
    pub retries: u32,
    /// Allow retrying non-idempotent requests (default `false`).
    #[serde(default)]
    pub retry_non_idempotent: bool,
    /// Slow start (B14): when a server becomes operational (startup or
    /// recovery) its effective weight ramps linearly from ~0 to `weight`
    /// over this window (dynamic weighting). `"0s"` (default) disables
    /// the ramp; maximum `"1h"` (HAProxy `slowstart` range).
    #[serde(default, with = "duration")]
    #[schemars(with = "String")]
    pub slow_start: Duration,
    /// Periodic re-resolution of `HOSTNAME:PORT` servers
    /// (B-H13/B-N18/B-E15; nginx `resolver valid=` / Envoy
    /// `dns_refresh_rate` semantics): the dataplane re-resolves each name
    /// at this rate and swaps addresses in hot. `"0s"` resolves once at
    /// startup only; maximum `"24h"`. Literal `IP:PORT` servers are
    /// unaffected (no DNS involved).
    #[serde(default = "default_resolve_interval", with = "duration")]
    #[schemars(with = "String")]
    pub resolve_interval: Duration,
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
