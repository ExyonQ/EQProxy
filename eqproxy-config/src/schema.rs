//! Versioned schema of the canonical configuration (TOML).
//!
//! Strict types + `deny_unknown_fields`: an unknown field is an error, never
//! silently ignored (the converter rule applied to our own format).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
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

/// Resource budget (CE4): maximum opt-in detail series (per server and per
/// route). The registry refuses anything past it and counts the refusal, so
/// this number is the hard ceiling of the labelled export.
pub const MAX_METRICS_SERIES: usize = 4096;

/// Resource budget (B-N9): maximum Basic users per rule.
pub const MAX_AUTH_USERS: usize = 1024;

/// Maximum `retries` per backend (B-H7).
pub const MAX_RETRIES: u32 = 5;

/// Minimum bearer-token length of the admin plane (v0.8): a short token is
/// brute-forceable by anyone who can reach the port.
pub const MIN_ADMIN_TOKEN_BYTES: usize = 16;

/// Named users allowed in one admin socket ACL (ADR-0023). The attribute the
/// kernel stores is `4 + 8 * (4 + n)` bytes, so 64 entries stay at 548 bytes,
/// far below the 64 KiB extended-attribute limit.
pub const MAX_ADMIN_ACL_UIDS: usize = 64;

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

/// Upper bound of `backup` failover order (`priority`), inclusive. EQProxy
/// extension: HAProxy 3.4 has no numeric priority on `server` lines, so the
/// ladder is ours and the range is deliberately a byte.
pub const MAX_SERVER_PRIORITY: u32 = 255;

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
    /// Offered ALPN protocols, e.g. `["h2", "http/1.1"]` (HTTP/2 and
    /// HTTP/1.1 served on this listener) or `["http/1.1"]`; empty = no ALPN.
    /// A `tcp` listener relays bytes and never parses them. `"h3"` is
    /// reserved for the QUIC endpoint, which offers it automatically when
    /// `quic = true`: listing it here is rejected.
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
    /// ALPN protocols to offer in the handshake; empty = no ALPN. Listing
    /// `"h2"` opts this backend into HTTP/2: a `mode = "http"` listener
    /// speaks real HTTP/2 to it when the handshake negotiates `h2`, and
    /// keeps HTTP/1.1 when it does not. A `tcp` listener relays bytes and
    /// never interprets ALPN.
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

/// One backend server with its weight and its rotation class (B7/B8).
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
    /// Backup server (B8): never selected while any primary server is
    /// eligible, and used when none is. It keeps being health-checked while
    /// unused, so the first request after a primary fails does not have to
    /// wait for a probe to discover it is alive.
    #[serde(default)]
    pub backup: bool,
    /// Failover order among backup servers (EQProxy extension, 0..=255):
    /// higher first, ties follow configuration order. Only the first
    /// operational rung serves at a time, so a recovered higher rung takes
    /// the traffic back. Rejected unless `backup = true`, and ignored by the
    /// reference, which has no such keyword (HAProxy 3.4 `server`).
    #[serde(default)]
    #[schemars(range(min = 0, max = 255))]
    pub priority: u32,
}

/// One entry of a backend's server list, as declared (`server` or
/// `servers`), with everything the resolver and `config diff` need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerEntry<'a> {
    pub addr: &'a str,
    pub weight: u32,
    pub backup: bool,
    pub priority: u32,
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

/// Metrics options (D1): cardinality stays bounded; detailed per-server and
/// per-route counters are opt-in (CE4).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Per-server and per-route counters: off by default.
    #[serde(default)]
    pub detailed: bool,
    /// Hard ceiling of the labelled export (per server + per route), 1 to
    /// [`MAX_METRICS_SERIES`]. A series that does not fit is refused and
    /// counted in `eqproxy_metrics_detail_dropped_total`.
    #[serde(default = "default_metrics_series")]
    pub max_series: usize,
}

fn default_metrics_series() -> usize {
    eqproxy_core::metrics::DEFAULT_DETAIL_BUDGET
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            detailed: false,
            max_series: default_metrics_series(),
        }
    }
}

/// Line format of the access log (ADR-0020).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AccessLogFormat {
    /// One JSON object per request (stable field names).
    #[default]
    Json,
    /// nginx combined shape, UTC timestamps.
    Combined,
}

/// Structured access log (v0.8, ADR-0020): one line per request, off by
/// default. The sink is opened once at startup; changing it needs a restart.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccessLogConfig {
    /// Destination file, opened in append mode. Absent = stdout.
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// Line format (default `json`).
    #[serde(default)]
    pub format: AccessLogFormat,
}

/// Administration plane (v0.8, D6): the status/metrics API, the write routes
/// and the optional web panel on their own listener, never on the proxy's
/// public address (SPEC §9). Absent = off.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// Listen `IP:PORT` for the admin plane. Loopback unless `allow_remote`.
    /// Exactly one of `listen` and `unix_socket` is required.
    #[serde(default)]
    pub listen: Option<String>,
    /// Unix domain socket path (ADR-0021). The socket is created with mode
    /// `0600`, so the filesystem is the access boundary in front of the
    /// bearer token. Exactly one of `listen` and `unix_socket` is required.
    /// A relative path is resolved against the configuration file.
    #[serde(default)]
    pub unix_socket: Option<PathBuf>,
    /// Socket mode: `"0600"` (default, owner only) or `"0660"` (owner and
    /// group; ADR-0022). No other mode is accepted.
    #[serde(default)]
    pub unix_socket_mode: Option<String>,
    /// Numeric gid that owns the socket, required with mode `0660` and
    /// refused with `0600`. Group *names* are not resolved: that needs NSS,
    /// which this crate does not call (`unsafe_code = forbid`).
    #[serde(default)]
    pub unix_socket_gid: Option<u32>,
    /// Peer uids allowed to use the socket (ADR-0022), checked against the
    /// kernel's `SO_PEERCRED`/`getpeereid` answer before any HTTP byte is
    /// read. Empty = any uid the filesystem lets connect. A peer whose uid
    /// is unavailable is refused when the list is not empty. The bearer
    /// token is still required afterwards.
    #[serde(default)]
    pub unix_socket_allow_uids: Vec<u32>,
    /// Named users granted `rw` on the socket file through its POSIX access
    /// ACL (ADR-0023), **in addition to** the owning group; the kernel checks
    /// it at `connect`, before this process sees the peer. Linux only (the
    /// entries live in `system.posix_acl_access`), and only with
    /// `unix_socket_mode = "0660"` plus `unix_socket_gid`, because the mode's
    /// group class is the ACL mask. Empty = no ACL is installed. At most 64
    /// entries.
    #[serde(default)]
    pub unix_socket_acl_uids: Vec<u32>,
    /// Bearer token required on every request. Prefer [`token_file`](Self::token_file):
    /// a token in the TOML travels wherever the file is copied.
    #[serde(default)]
    pub token: Option<String>,
    /// File holding the bearer token (one trailing newline trimmed).
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    /// Bearer token that may **write** (ADR-0018): `PUT` on the server-state
    /// route. Absent = the whole plane stays read-only. Must differ from
    /// [`token`](Self::token): one secret per privilege level.
    #[serde(default)]
    pub write_token: Option<String>,
    /// File holding the write token (one trailing newline trimmed).
    #[serde(default)]
    pub write_token_file: Option<PathBuf>,
    /// Allow binding a non-loopback TCP address (default false): the admin
    /// plane has no TLS in this slice, so a remote bind sends the bearer
    /// token in the clear. Meaningless with `unix_socket` (rejected).
    #[serde(default)]
    pub allow_remote: bool,
    /// Serve the web panel (`GET /panel`, ADR-0029) on this plane. Off by
    /// default; with it off every `/panel` path is a `404`. The panel is a
    /// client of the routes below: it opens a session with the read token
    /// (read-only panel) or the write token (full panel) and needs no other
    /// secret.
    #[serde(default)]
    pub panel: bool,
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
    /// Metrics options (D1/D5): per-server and per-route counters are
    /// opt-in and bounded by their own series budget (CE4).
    #[serde(default)]
    pub metrics: MetricsConfig,
    /// Administration plane (v0.8): read-only API and metrics. Absent = off.
    #[serde(default)]
    pub admin: Option<AdminConfig>,
    /// Structured access log (v0.8, ADR-0020). Absent = off.
    #[serde(default)]
    pub access_log: Option<AccessLogConfig>,
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
    /// Serve **HTTP/3 over QUIC** (B-H2) on the same address and port, over
    /// UDP. Requires `[listener.<name>.tls]` (QUIC is always TLS 1.3) and
    /// `mode = "http"`; the UDP endpoint offers ALPN `h3` with the same
    /// certificate, SNI entries and client CA as the TCP listener.
    #[serde(default)]
    pub quic: bool,
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
    /// Response compression (B-N6/H6): opt-in gzip/Brotli negotiated from the
    /// request's `Accept-Encoding`. `http` mode only.
    #[serde(default)]
    pub compression: CompressionConfig,
    /// Message limits and per-stream buffer sizing (B-N19/B-I17/B-E19).
    /// Absent = the documented defaults, which are the previous behaviour.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Ordered routing rules (v0.6, B-H3/B-H4): first match wins, the
    /// `backend` above is the fallback. `http` mode only.
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

/// Message limits and per-stream buffer sizing for one listener.
///
/// Every default is the constant the dataplane had before this section
/// existed, so an absent `[listener.<name>.limits]` changes nothing. The
/// head bound applies to the request head **and** to the response head the
/// backend sends; the body bound is a request bound (`413`), matching the
/// `client_max_body_size` class of limit rather than silently truncating a
/// response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Maximum message-head size in bytes (request and response head).
    /// Default 16384; 1024..=1048576.
    #[serde(default = "default_max_head_bytes")]
    pub max_head_bytes: usize,
    /// Maximum header fields per message. Default 100; 1..=1000.
    #[serde(default = "default_max_headers")]
    pub max_headers: usize,
    /// Maximum **request** body in bytes; `0` = unlimited (default).
    /// A declared `Content-Length` over the bound is refused before the
    /// backend is dialed; a chunked body is refused as soon as it crosses.
    #[serde(default)]
    pub max_body_bytes: u64,
    /// Buffer of each internal h2/h3/WebSocket stream pipe, in bytes.
    /// Absent = the protocol default (64 KiB; 16 KiB for h3), which is what
    /// the dataplane used before this knob existed. Present: 1024..=1048576.
    #[serde(default)]
    pub stream_buffer_bytes: Option<usize>,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_head_bytes: default_max_head_bytes(),
            max_headers: default_max_headers(),
            max_body_bytes: 0,
            stream_buffer_bytes: None,
        }
    }
}

fn default_max_head_bytes() -> usize {
    16 * 1024
}

fn default_max_headers() -> usize {
    100
}

/// Response compression (B-N6/H6): gzip and Brotli, opt-in per listener.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompressionConfig {
    /// Compress eligible responses with gzip when the client accepts it.
    #[serde(default)]
    pub gzip: bool,
    /// Compress eligible responses with Brotli when the client accepts `br`.
    #[serde(default)]
    pub brotli: bool,
    /// gzip level, 1 (fastest) to 9 (smallest); default 6.
    #[serde(default = "default_gzip_level")]
    pub level: u32,
    /// Brotli quality, 0 (fastest) to 11 (smallest); default 5. Values above
    /// 9 cost far more CPU per request than they save on the wire.
    #[serde(default = "default_brotli_quality")]
    pub brotli_quality: u32,
    /// Minimum declared body length worth compressing; responses without
    /// `Content-Length` (chunked or until-EOF) are not filtered by it.
    #[serde(default = "default_gzip_min_size")]
    pub min_size: u64,
    /// Eligible media types: `text/*`, `application/json`, `*/*`…
    #[serde(default = "default_gzip_types")]
    pub types: Vec<String>,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            gzip: false,
            brotli: false,
            level: default_gzip_level(),
            brotli_quality: default_brotli_quality(),
            min_size: default_gzip_min_size(),
            types: default_gzip_types(),
        }
    }
}

fn default_gzip_level() -> u32 {
    6
}

fn default_brotli_quality() -> u32 {
    5
}

fn default_gzip_min_size() -> u64 {
    1024
}

fn default_gzip_types() -> Vec<String> {
    [
        "text/*",
        "application/json",
        "application/javascript",
        "application/xml",
        "application/xhtml+xml",
        "application/rss+xml",
        "image/svg+xml",
    ]
    .iter()
    .map(|spec| (*spec).to_owned())
    .collect()
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
    /// Balance across **all** backups instead of one rung at a time
    /// (`option allbackups`, B8): when no primary server is eligible, every
    /// operational backup is a candidate and the configured algorithm
    /// spreads load across them by weight. `false` (the reference default)
    /// keeps one backup at a time, ordered by `priority`. The reference
    /// states that with this option there is no priority order among the
    /// backups, so combining it with `priority` is refused in
    /// [`crate::check`] instead of silently ignoring the ladder.
    #[serde(default)]
    pub all_backups: bool,
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
    pub fn server_entries(&self) -> Vec<ServerEntry<'_>> {
        match (&self.server, &self.servers) {
            (Some(addr), _) => vec![ServerEntry {
                addr: addr.as_str(),
                weight: 1,
                backup: false,
                priority: 0,
            }],
            (None, Some(servers)) => servers
                .iter()
                .map(|s| ServerEntry {
                    addr: s.addr.as_str(),
                    weight: s.weight,
                    backup: s.backup,
                    priority: s.priority,
                })
                .collect(),
            (None, None) => Vec::new(),
        }
    }
}
