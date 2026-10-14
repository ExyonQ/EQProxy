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
