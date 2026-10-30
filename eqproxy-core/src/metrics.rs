//! Dataplane counters.
//!
//! Bounded cardinality by design: no per-client, URL or token labels
//! (SPEC §7.3). The per-server and per-route breakdown (CE4) is **opt-in**
//! and lives in [`DetailMetrics`], under an explicit series budget: a label
//! combination that does not fit is refused and counted, never admitted
//! silently.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde::Serialize;

/// Series budget used when `[metrics] max_series` is absent (CE4).
/// The operator can raise or lower it, and the export reports the live one.
pub const DEFAULT_DETAIL_BUDGET: usize = 128;

/// Global counters of the traffic process.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Accepted connections (including ones that later fail to reach the backend).
    pub connections_accepted: AtomicU64,
    /// Connections refused for reaching `maxconn`.
    pub connections_rejected: AtomicU64,
    /// Proxied connections alive right now.
    pub connections_active: AtomicU64,
    /// Finished connections (any reason).
    pub connections_completed: AtomicU64,
    /// Backend connection failures (including connection timeout).
    pub connect_failures: AtomicU64,
    /// Directions closed by inactivity timeout.
    pub idle_timeouts: AtomicU64,
    /// Bytes transferred client → backend.
    pub bytes_client_to_backend: AtomicU64,
    /// Bytes transferred backend → client.
    pub bytes_backend_to_client: AtomicU64,
    /// Completed HTTP/1.1 exchanges (finished request + response).
    pub http_requests_proxied: AtomicU64,
    /// HTTP requests rejected by framing/validation (400/417/431/501/505).
    pub http_requests_rejected: AtomicU64,
    /// Access-log lines dropped because the bounded sink was full
    /// (ADR-0020): loss is counted, never hidden.
    pub access_log_dropped: AtomicU64,
    /// Requests rejected by a rule's rate limiter (B-N8/B-I7/B-E16).
    pub rate_limited: AtomicU64,
    /// Requests rejected by rule authentication (B-N9/B-I9): wrong or
    /// missing Basic credentials, or a 401/403 from the auth subrequest.
    pub auth_denied: AtomicU64,
    /// Auth subrequests that could not decide (service down, timeout,
    /// bad response): the request fails closed and this counts.
    pub auth_service_errors: AtomicU64,
    /// Message heads not received within their phase timeout.
    pub header_timeouts: AtomicU64,
    /// Failed TLS handshakes (client to listener, or proxy to backend).
    pub tls_handshake_failures: AtomicU64,
    /// Connections with no server available (all backends down/drained).
    pub no_available_server: AtomicU64,
    /// Backend connections reused from the keep-alive pool (A16).
    pub backend_connections_reused: AtomicU64,
    /// Freshly dialed backend connections (not reused).
    pub backend_connections_opened: AtomicU64,
    /// Backend connections dropped instead of pooled: bytes past the
    /// message end broke the A16 boundary contract. Operators can alert
    /// on this counter (no labels: bounded cardinality).
    pub backend_connections_discarded: AtomicU64,
    /// Successful hot config swaps (S-CFG-01).
    pub config_reloads: AtomicU64,
    /// Hot reloads rejected (gate failure or bind conflict); the running
    /// config keeps serving.
    pub config_reload_failures: AtomicU64,
    /// Duration of the last hot config swap in microseconds (PP-04/05:
    /// the swap latency is measured, never assumed).
    pub config_reload_duration_us: AtomicU64,
    /// Explicit rejections because the bounded backend queue was full (B-H7).
    pub queue_full: AtomicU64,
    /// Requests that expired in the bounded queue (B-H7).
    pub queue_timeout: AtomicU64,
    /// Connect-phase redials on dial failure (B-H7).
    pub retry_attempts: AtomicU64,
    /// Connections rejected: peer is not in the PROXY v1 allowlist (B-H9).
    pub proxy_protocol_denied: AtomicU64,
    /// Malformed or timed-out PROXY v1 headers (B-H9).
    pub proxy_protocol_invalid: AtomicU64,
    /// Custom local responses served (C9).
    pub local_responses_served: AtomicU64,
    /// Rule `redirect` responses served (v0.6 slice 2).
    pub redirects_served: AtomicU64,
    /// Rule `direct_response` responses served (v0.6 slice 2).
    pub direct_responses_served: AtomicU64,
    /// Successful DNS resolution rounds (B-H13/B-N18/B-E15).
    pub dns_resolutions_ok: AtomicU64,
    /// DNS rounds that failed, timed out or returned no address
    /// (the last-known address keeps serving).
    pub dns_resolution_failures: AtomicU64,
    /// Server address swaps applied by a re-resolution round (B-H13).
    pub dns_address_updates: AtomicU64,
    /// Hot data map swaps applied by the file watcher (C10/PP-02).
    pub map_reloads: AtomicU64,
    /// Map reloads that failed (unreadable or invalid file): the last
    /// good data keeps serving and this counts (C10).
    pub map_reload_failures: AtomicU64,
    /// Mirrored copies written to the mirror backend (B-H3).
    pub requests_mirrored: AtomicU64,
    /// Mirror attempts that failed (connect, write or timeout): the
    /// client response is unaffected (B-H3).
    pub mirror_failures: AtomicU64,
    /// Requests not mirrored because the body exceeded the mirror
    /// budget (B-H3): never a silent truncation.
    pub mirror_skipped: AtomicU64,
    /// Backend HTTP/2 sessions closed for being idle (no exchange for the
    /// listener's `idle_timeout`): the next exchange dials a fresh one.
    pub h2_sessions_idle_closed: AtomicU64,
    /// Backend HTTP/2 sessions the peer started closing with a `GOAWAY`:
    /// in-flight streams finish, new exchanges dial a fresh session.
    pub h2_goaway_received: AtomicU64,
    /// Streams the peer refused with `GOAWAY` (never processed) that were
    /// replayed on a fresh session: safe because the server said so.
    pub h2_refused_retried: AtomicU64,
    /// gRPC streams relayed end to end over HTTP/2 (B-I12/Q5).
    pub grpc_streams: AtomicU64,
    /// gRPC streams cut before a clean status (backend reset, deadline,
    /// failed request direction).
    pub grpc_stream_errors: AtomicU64,
    /// Responses served with `Content-Encoding: gzip` (B-N6/H6).
    pub compression_gzip_responses: AtomicU64,
    /// WebSocket tunnels opened through an HTTP/2 extended CONNECT
    /// (RFC 8441, B-I18).
    pub ws_tunnels: AtomicU64,
    /// Extended CONNECT streams whose handshake or tunnel failed (backend
    /// refused or reset, deadline, client gone).
    pub ws_failures: AtomicU64,
    /// Responses served with `Content-Encoding: br` (B-N6/H6).
    pub compression_brotli_responses: AtomicU64,
    /// Body bytes fed into the compressor (plaintext).
    pub compression_bytes_in: AtomicU64,
    /// Compressed bytes written to the client (gzip payload, no framing).
    pub compression_bytes_out: AtomicU64,
    /// HTTP/3 connections that ended with a normal close (`H3_NO_ERROR` or
    /// QUIC application code 0): not an error, not logged.
    pub h3_clean_closes: AtomicU64,
    /// HTTP/3 connections that ended with a real error (protocol error code,
    /// transport error, reset or timeout): counted and logged as `WARN`.
    pub h3_connection_errors: AtomicU64,
    /// WASM plugin invocations (B-I5/B-E4): every request that reached a
    /// configured filter, counted before the verdict.
    pub plugin_requests: AtomicU64,
    /// Requests a WASM plugin rejected explicitly (4xx/5xx from the guest).
    pub plugin_denied: AtomicU64,
    /// Plugin invocations that failed at runtime (trap, fuel, deadline,
    /// memory, host validation); `on_error` decided what the client saw.
    pub plugin_errors: AtomicU64,
    /// Cacheable requests served from a stored entry (B-N7/H1).
    pub cache_hits: AtomicU64,
    /// Origin fetches for cacheable requests (miss or expired entry).
    pub cache_misses: AtomicU64,
    /// Requests that bypassed the cache (session material, affinity,
    /// unstorable method or framing).
    pub cache_bypasses: AtomicU64,
    /// Stale entries refreshed by a `304` revalidation (B-N7/H1).
    pub cache_revalidations: AtomicU64,
    /// Entries written to the store (memory, plus disk when configured).
    pub cache_stores: AtomicU64,
    /// Stored entries evicted (expiry or memory pressure).
    pub cache_evictions: AtomicU64,
    /// Entries restored from disk at startup (B-N7/H1 persistence).
    pub cache_disk_loads: AtomicU64,
    /// Disk files skipped at startup (expired, corrupt or oversized).
    pub cache_disk_skipped: AtomicU64,
    /// Opt-in per-server/per-route series (CE4): disabled and empty until the
    /// configuration asks for it.
    pub detail: DetailMetrics,
}

/// Kind of an opt-in detail series (CE4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DetailKind {
    /// One backend server (the address that served the exchange).
    Server,
    /// One routing rule that matched.
    Route,
}

/// One live labelled series, as reported by `GET /api/v1/status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DetailRow {
    pub kind: DetailKind,
    /// `backend` for a server series, `listener` for a route series.
    pub scope: String,
    /// Dialed server address, or the name of the matched rule.
    pub key: String,
    /// Proxied exchanges attributed to this series.
    pub requests: u64,
    /// How many of them carried a 5xx answer from the server.
    pub errors: u64,
}

/// Coherent view of the detail registry: the budget, how many series it is
/// using, how many observations it refused, and the series themselves.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct DetailSnapshot {
    pub enabled: bool,
    pub budget: usize,
    pub series: usize,
    /// Observations refused because the series budget was full.
    pub dropped: u64,
    pub rows: Vec<DetailRow>,
}

impl DetailSnapshot {
    /// Prometheus exposition of the detail registry (CE4).
    ///
    /// Four label-free series always describe the budget itself, so a scrape
    /// can tell "no traffic" apart from "detail off" and from "the budget
    /// refused the series". The labelled families exist only while detail is
    /// on and only for the series that fit: the budget is the invariant, and
    /// the four accounting series are what makes it observable.
    #[must_use]
    pub fn prometheus(&self) -> String {
        let enabled = u8::from(self.enabled);
        let mut out = String::with_capacity(512 + self.rows.len() * 96);
        // Appending to a `String` cannot fail, so no `Result` is discarded
        // here (R10): the lines are pushed explicitly.
        out.push_str("# TYPE eqproxy_metrics_detail_enabled gauge\n");
        out.push_str(&format!("eqproxy_metrics_detail_enabled {enabled}\n"));
        out.push_str("# TYPE eqproxy_metrics_detail_series gauge\n");
        out.push_str(&format!("eqproxy_metrics_detail_series {}\n", self.series));
        out.push_str("# TYPE eqproxy_metrics_detail_budget gauge\n");
        out.push_str(&format!("eqproxy_metrics_detail_budget {}\n", self.budget));
        out.push_str("# TYPE eqproxy_metrics_detail_dropped_total counter\n");
        out.push_str(&format!(
            "eqproxy_metrics_detail_dropped_total {}\n",
            self.dropped
        ));
        // Server family: requests and 5xx, split by backend and dialed server.
        let servers: Vec<&DetailRow> = self
            .rows
            .iter()
            .filter(|row| row.kind == DetailKind::Server)
            .collect();
        if !servers.is_empty() {
            out.push_str("# TYPE eqproxy_server_requests_total counter\n");
            for row in &servers {
                out.push_str(&format!(
                    "eqproxy_server_requests_total{{backend=\"{}\",server=\"{}\"}} {}\n",
                    label_value(&row.scope),
                    label_value(&row.key),
                    row.requests
                ));
            }
            out.push_str("# TYPE eqproxy_server_errors_total counter\n");
            for row in &servers {
                out.push_str(&format!(
                    "eqproxy_server_errors_total{{backend=\"{}\",server=\"{}\"}} {}\n",
                    label_value(&row.scope),
                    label_value(&row.key),
                    row.errors
                ));
            }
        }
        // Route family: requests by listener and matched rule. An error split
        // by rule would duplicate the server one without an action to take.
        let routes: Vec<&DetailRow> = self
            .rows
            .iter()
            .filter(|row| row.kind == DetailKind::Route)
            .collect();
        if !routes.is_empty() {
            out.push_str("# TYPE eqproxy_route_requests_total counter\n");
            for row in &routes {
                out.push_str(&format!(
                    "eqproxy_route_requests_total{{listener=\"{}\",route=\"{}\"}} {}\n",
                    label_value(&row.scope),
                    label_value(&row.key),
                    row.requests
                ));
            }
        }
        out
    }
}

/// Escapes a Prometheus label value (the exposition format allows `\\`, `\"`
/// and a literal newline in the **escaped** form only).
fn label_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// One live series: atomics so recording takes the read lock and nothing
/// else, and two exchanges on the same series never serialize on the map.
#[derive(Debug, Default)]
struct Series {
    requests: AtomicU64,
    errors: AtomicU64,
}

#[derive(Debug, Default)]
struct DetailMaps {
    /// `backend` → dialed address → series.
    servers: BTreeMap<String, BTreeMap<String, Series>>,
    /// `listener` → rule name → series.
    routes: BTreeMap<String, BTreeMap<String, Series>>,
}

impl DetailMaps {
    fn get(&self, kind: DetailKind, scope: &str, key: &str) -> Option<&Series> {
        match kind {
            DetailKind::Server => self.servers.get(scope)?.get(key),
            DetailKind::Route => self.routes.get(scope)?.get(key),
        }
    }

    fn len(&self) -> usize {
        let servers: usize = self.servers.values().map(BTreeMap::len).sum();
        let routes: usize = self.routes.values().map(BTreeMap::len).sum();
        servers.saturating_add(routes)
    }

    fn insert(&mut self, kind: DetailKind, scope: &str, key: &str) -> &mut Series {
        let map = match kind {
            DetailKind::Server => self.servers.entry(scope.to_owned()).or_default(),
            DetailKind::Route => self.routes.entry(scope.to_owned()).or_default(),
        };
        map.entry(key.to_owned()).or_default()
    }

    fn clear(&mut self) {
        self.servers.clear();
        self.routes.clear();
    }

    fn snapshot(&self) -> Vec<DetailRow> {
        let mut rows = Vec::with_capacity(self.len());
        for (scope, servers) in &self.servers {
            for (key, series) in servers {
                rows.push(DetailRow {
                    kind: DetailKind::Server,
                    scope: scope.clone(),
                    key: key.clone(),
                    requests: series.requests.load(Ordering::Relaxed),
                    errors: series.errors.load(Ordering::Relaxed),
                });
            }
        }
        for (scope, routes) in &self.routes {
            for (key, series) in routes {
                rows.push(DetailRow {
                    kind: DetailKind::Route,
                    scope: scope.clone(),
                    key: key.clone(),
                    requests: series.requests.load(Ordering::Relaxed),
                    errors: series.errors.load(Ordering::Relaxed),
                });
            }
        }
        rows
    }
}

/// Opt-in detail registry (CE4): per-server and per-route series under an
/// **explicit budget**. Disabled by default; while disabled, recording is a
/// single relaxed load. A series that would exceed the budget is refused and
/// counted — the registry never grows past the number the operator set.
#[derive(Debug)]
pub struct DetailMetrics {
    enabled: AtomicBool,
    /// Fixed at startup: shrinking it under live series would need an eviction
    /// policy nobody asked for, so a reload reports it and asks for a restart.
    budget: usize,
    maps: RwLock<DetailMaps>,
    /// Observations refused for lack of budget (monotonic).
    dropped: AtomicU64,
}

impl Default for DetailMetrics {
    fn default() -> Self {
        Self::new(false, DEFAULT_DETAIL_BUDGET)
    }
}

impl DetailMetrics {
    #[must_use]
    pub fn new(enabled: bool, budget: usize) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            budget,
            maps: RwLock::new(DetailMaps::default()),
            dropped: AtomicU64::new(0),
        }
    }

    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn budget(&self) -> usize {
        self.budget
    }

    /// Enables or disables the registry in hot. Disabling **drops the series**:
    /// a disabled export must not show counts collected while it was on, or a
    /// later re-enable would publish a window that no longer means anything.
    /// The refusal counter is monotonic and survives, like every counter.
    pub fn set_enabled(&self, enabled: bool) {
        let was = self.enabled.swap(enabled, Ordering::AcqRel);
        if was && !enabled {
            self.maps
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear();
        }
    }

    /// Attributes one completed exchange to a backend server. `failed` marks
    /// a 5xx answer from that server.
    pub fn record_server(&self, backend: &str, server: &str, failed: bool) {
        self.record(DetailKind::Server, backend, server, failed);
    }

    /// Attributes one completed exchange to the routing rule that matched it.
    /// Traffic that fell through to the default backend has no rule and is
    /// therefore visible only in the server series (never under an invented
    /// label).
    pub fn record_route(&self, listener: &str, route: &str, failed: bool) {
        self.record(DetailKind::Route, listener, route, failed);
    }

    fn record(&self, kind: DetailKind, scope: &str, key: &str, failed: bool) {
        if !self.enabled() {
            return;
        }
        {
            let maps = self
                .maps
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(series) = maps.get(kind, scope, key) {
                series.requests.fetch_add(1, Ordering::Relaxed);
                if failed {
                    series.errors.fetch_add(1, Ordering::Relaxed);
                }
                return;
            }
        }
        let mut maps = self
            .maps
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Re-check under the write lock: another exchange may have registered
        // it between the read and this write.
        if let Some(series) = maps.get(kind, scope, key) {
            series.requests.fetch_add(1, Ordering::Relaxed);
            if failed {
                series.errors.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        if maps.len() >= self.budget {
            drop(maps);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let series = maps.insert(kind, scope, key);
        series.requests.fetch_add(1, Ordering::Relaxed);
        if failed {
            series.errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> DetailSnapshot {
        let maps = self
            .maps
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rows = maps.snapshot();
        DetailSnapshot {
            enabled: self.enabled(),
            budget: self.budget,
            series: rows.len(),
            dropped: self.dropped.load(Ordering::Relaxed),
            rows,
        }
    }
}

/// Immutable snapshot of the counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MetricsSnapshot {
    pub connections_accepted: u64,
    pub connections_rejected: u64,
    pub connections_active: u64,
    pub connections_completed: u64,
    pub connect_failures: u64,
    pub idle_timeouts: u64,
    pub bytes_client_to_backend: u64,
    pub bytes_backend_to_client: u64,
    pub http_requests_proxied: u64,
    pub http_requests_rejected: u64,
    /// Access-log lines dropped under backpressure (ADR-0020).
    pub access_log_dropped: u64,
    pub rate_limited: u64,
    pub auth_denied: u64,
    pub auth_service_errors: u64,
    pub header_timeouts: u64,
    pub tls_handshake_failures: u64,
    pub no_available_server: u64,
    pub backend_connections_reused: u64,
    pub backend_connections_opened: u64,
    pub backend_connections_discarded: u64,
    pub config_reloads: u64,
    pub config_reload_failures: u64,
    pub config_reload_duration_us: u64,
    pub queue_full: u64,
    pub queue_timeout: u64,
    pub retry_attempts: u64,
    pub proxy_protocol_denied: u64,
    pub proxy_protocol_invalid: u64,
    pub local_responses_served: u64,
    pub redirects_served: u64,
    pub direct_responses_served: u64,
    pub dns_resolutions_ok: u64,
    pub dns_resolution_failures: u64,
    pub dns_address_updates: u64,
    pub map_reloads: u64,
    pub map_reload_failures: u64,
    pub requests_mirrored: u64,
    pub mirror_failures: u64,
    pub mirror_skipped: u64,
    pub h2_sessions_idle_closed: u64,
    pub h2_goaway_received: u64,
    pub h2_refused_retried: u64,
    pub grpc_streams: u64,
    pub grpc_stream_errors: u64,
    pub ws_tunnels: u64,
    pub ws_failures: u64,
    pub compression_gzip_responses: u64,
    pub compression_brotli_responses: u64,
    pub compression_bytes_in: u64,
    pub compression_bytes_out: u64,
    pub h3_clean_closes: u64,
    pub h3_connection_errors: u64,
    pub plugin_requests: u64,
    pub plugin_denied: u64,
    pub plugin_errors: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_bypasses: u64,
    pub cache_revalidations: u64,
    pub cache_stores: u64,
    pub cache_evictions: u64,
    pub cache_disk_loads: u64,
    pub cache_disk_skipped: u64,
}

impl MetricsSnapshot {
    /// Prometheus text exposition (v0.8, D6): bounded cardinality — every
    /// series is a fixed name with no labels, so a scrape cannot grow the
    /// index (CE4). Counters carry the `_total` suffix Prometheus expects;
    /// `connections_active` and the last swap duration are gauges.
    #[must_use]
    pub fn prometheus(&self) -> String {
        use std::fmt::Write as _;

        let counters: &[(&str, u64)] = &[
            ("connections_accepted", self.connections_accepted),
            ("connections_rejected", self.connections_rejected),
            ("connections_completed", self.connections_completed),
            ("connect_failures", self.connect_failures),
            ("idle_timeouts", self.idle_timeouts),
            ("bytes_client_to_backend", self.bytes_client_to_backend),
            ("bytes_backend_to_client", self.bytes_backend_to_client),
            ("http_requests_proxied", self.http_requests_proxied),
            ("http_requests_rejected", self.http_requests_rejected),
            ("access_log_dropped", self.access_log_dropped),
            ("rate_limited", self.rate_limited),
            ("auth_denied", self.auth_denied),
            ("auth_service_errors", self.auth_service_errors),
            ("header_timeouts", self.header_timeouts),
            ("tls_handshake_failures", self.tls_handshake_failures),
            ("no_available_server", self.no_available_server),
            (
                "backend_connections_reused",
                self.backend_connections_reused,
            ),
            (
                "backend_connections_opened",
                self.backend_connections_opened,
            ),
            (
                "backend_connections_discarded",
                self.backend_connections_discarded,
            ),
            ("config_reloads", self.config_reloads),
            ("config_reload_failures", self.config_reload_failures),
            ("queue_full", self.queue_full),
            ("queue_timeout", self.queue_timeout),
            ("retry_attempts", self.retry_attempts),
            ("proxy_protocol_denied", self.proxy_protocol_denied),
            ("proxy_protocol_invalid", self.proxy_protocol_invalid),
            ("local_responses_served", self.local_responses_served),
            ("redirects_served", self.redirects_served),
            ("direct_responses_served", self.direct_responses_served),
            ("dns_resolutions", self.dns_resolutions_ok),
            ("dns_resolution_failures", self.dns_resolution_failures),
            ("dns_address_updates", self.dns_address_updates),
            ("map_reloads", self.map_reloads),
            ("map_reload_failures", self.map_reload_failures),
            ("requests_mirrored", self.requests_mirrored),
            ("mirror_failures", self.mirror_failures),
            ("mirror_skipped", self.mirror_skipped),
            ("h2_sessions_idle_closed", self.h2_sessions_idle_closed),
            ("h2_goaway_received", self.h2_goaway_received),
            ("h2_refused_retried", self.h2_refused_retried),
            ("grpc_streams", self.grpc_streams),
            ("grpc_stream_errors", self.grpc_stream_errors),
            ("ws_tunnels", self.ws_tunnels),
            ("ws_failures", self.ws_failures),
            (
                "compression_gzip_responses",
                self.compression_gzip_responses,
            ),
            (
                "compression_brotli_responses",
                self.compression_brotli_responses,
            ),
            ("compression_bytes_in", self.compression_bytes_in),
            ("compression_bytes_out", self.compression_bytes_out),
            ("h3_clean_closes", self.h3_clean_closes),
            ("h3_connection_errors", self.h3_connection_errors),
            ("plugin_requests", self.plugin_requests),
            ("plugin_denied", self.plugin_denied),
            ("plugin_errors", self.plugin_errors),
            ("cache_hits", self.cache_hits),
            ("cache_misses", self.cache_misses),
            ("cache_bypasses", self.cache_bypasses),
            ("cache_revalidations", self.cache_revalidations),
            ("cache_stores", self.cache_stores),
            ("cache_evictions", self.cache_evictions),
            ("cache_disk_loads", self.cache_disk_loads),
            ("cache_disk_skipped", self.cache_disk_skipped),
        ];
        let mut out = String::with_capacity(4096);
        for (name, value) in counters {
            let _ = writeln!(out, "# TYPE eqproxy_{name}_total counter");
            let _ = writeln!(out, "eqproxy_{name}_total {value}");
        }
        let _ = writeln!(out, "# TYPE eqproxy_connections_active gauge");
        let _ = writeln!(
            out,
            "eqproxy_connections_active {}",
            self.connections_active
        );
        let _ = writeln!(out, "# TYPE eqproxy_config_reload_last_swap_seconds gauge");
        let _ = writeln!(
            out,
            "eqproxy_config_reload_last_swap_seconds {:.6}",
            self.config_reload_duration_us as f64 / 1_000_000.0
        );
        let _ = writeln!(out, "# TYPE eqproxy_build_info gauge");
        let _ = writeln!(
            out,
            "eqproxy_build_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION")
        );
        out
    }
}

impl Metrics {
    /// Metrics with the CE4 detail registry in the state the configuration
    /// asked for at startup.
    #[must_use]
    pub fn with_detail(enabled: bool, budget: usize) -> Self {
        Self {
            detail: DetailMetrics::new(enabled, budget),
            ..Self::default()
        }
    }

    /// Coherent snapshot (per counter) for logging or tests.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            connections_accepted: self.connections_accepted.load(Ordering::Relaxed),
            connections_rejected: self.connections_rejected.load(Ordering::Relaxed),
            connections_active: self.connections_active.load(Ordering::Relaxed),
            connections_completed: self.connections_completed.load(Ordering::Relaxed),
            connect_failures: self.connect_failures.load(Ordering::Relaxed),
            idle_timeouts: self.idle_timeouts.load(Ordering::Relaxed),
            bytes_client_to_backend: self.bytes_client_to_backend.load(Ordering::Relaxed),
            bytes_backend_to_client: self.bytes_backend_to_client.load(Ordering::Relaxed),
            http_requests_proxied: self.http_requests_proxied.load(Ordering::Relaxed),
            http_requests_rejected: self.http_requests_rejected.load(Ordering::Relaxed),
            access_log_dropped: self.access_log_dropped.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            auth_denied: self.auth_denied.load(Ordering::Relaxed),
            auth_service_errors: self.auth_service_errors.load(Ordering::Relaxed),
            header_timeouts: self.header_timeouts.load(Ordering::Relaxed),
            tls_handshake_failures: self.tls_handshake_failures.load(Ordering::Relaxed),
            no_available_server: self.no_available_server.load(Ordering::Relaxed),
            backend_connections_reused: self.backend_connections_reused.load(Ordering::Relaxed),
            backend_connections_opened: self.backend_connections_opened.load(Ordering::Relaxed),
            backend_connections_discarded: self
                .backend_connections_discarded
                .load(Ordering::Relaxed),
            config_reloads: self.config_reloads.load(Ordering::Relaxed),
            config_reload_failures: self.config_reload_failures.load(Ordering::Relaxed),
            config_reload_duration_us: self.config_reload_duration_us.load(Ordering::Relaxed),
            queue_full: self.queue_full.load(Ordering::Relaxed),
            queue_timeout: self.queue_timeout.load(Ordering::Relaxed),
            retry_attempts: self.retry_attempts.load(Ordering::Relaxed),
            proxy_protocol_denied: self.proxy_protocol_denied.load(Ordering::Relaxed),
            proxy_protocol_invalid: self.proxy_protocol_invalid.load(Ordering::Relaxed),
            local_responses_served: self.local_responses_served.load(Ordering::Relaxed),
            redirects_served: self.redirects_served.load(Ordering::Relaxed),
            direct_responses_served: self.direct_responses_served.load(Ordering::Relaxed),
            dns_resolutions_ok: self.dns_resolutions_ok.load(Ordering::Relaxed),
            dns_resolution_failures: self.dns_resolution_failures.load(Ordering::Relaxed),
            dns_address_updates: self.dns_address_updates.load(Ordering::Relaxed),
            map_reloads: self.map_reloads.load(Ordering::Relaxed),
            map_reload_failures: self.map_reload_failures.load(Ordering::Relaxed),
            requests_mirrored: self.requests_mirrored.load(Ordering::Relaxed),
            mirror_failures: self.mirror_failures.load(Ordering::Relaxed),
            mirror_skipped: self.mirror_skipped.load(Ordering::Relaxed),
            h2_sessions_idle_closed: self.h2_sessions_idle_closed.load(Ordering::Relaxed),
            h2_goaway_received: self.h2_goaway_received.load(Ordering::Relaxed),
            h2_refused_retried: self.h2_refused_retried.load(Ordering::Relaxed),
            grpc_streams: self.grpc_streams.load(Ordering::Relaxed),
            grpc_stream_errors: self.grpc_stream_errors.load(Ordering::Relaxed),
            ws_tunnels: self.ws_tunnels.load(Ordering::Relaxed),
            ws_failures: self.ws_failures.load(Ordering::Relaxed),
            compression_gzip_responses: self.compression_gzip_responses.load(Ordering::Relaxed),
            compression_brotli_responses: self.compression_brotli_responses.load(Ordering::Relaxed),
            compression_bytes_in: self.compression_bytes_in.load(Ordering::Relaxed),
            compression_bytes_out: self.compression_bytes_out.load(Ordering::Relaxed),
            h3_clean_closes: self.h3_clean_closes.load(Ordering::Relaxed),
            h3_connection_errors: self.h3_connection_errors.load(Ordering::Relaxed),
            plugin_requests: self.plugin_requests.load(Ordering::Relaxed),
            plugin_denied: self.plugin_denied.load(Ordering::Relaxed),
            plugin_errors: self.plugin_errors.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            cache_bypasses: self.cache_bypasses.load(Ordering::Relaxed),
            cache_revalidations: self.cache_revalidations.load(Ordering::Relaxed),
            cache_stores: self.cache_stores.load(Ordering::Relaxed),
            cache_evictions: self.cache_evictions.load(Ordering::Relaxed),
            cache_disk_loads: self.cache_disk_loads.load(Ordering::Relaxed),
            cache_disk_skipped: self.cache_disk_skipped.load(Ordering::Relaxed),
        }
    }

    /// Reserves a connection slot. Returns `false` when `maxconn` is reached
    /// (the caller must refuse explicitly, never queue without a bound).
    pub fn try_acquire_connection(&self, maxconn: u32) -> bool {
        self.connections_active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                if active < u64::from(maxconn) {
                    Some(active + 1)
                } else {
                    None
                }
            })
            .is_ok()
    }

    /// Releases the connection slot and counts the connection as completed.
    pub fn release_connection(&self) {
        let _ = self
            .connections_active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                Some(v.saturating_sub(1))
            });
        self.connections_completed.fetch_add(1, Ordering::Relaxed);
    }
}

impl fmt::Display for MetricsSnapshot {
    /// Rendered by failure origin (Q4/H5/CE5: no black box): `client`,
    /// `proxy`, `network` and `backend` groups plus phases and bytes.
    /// Every group is a fixed set of counters (CE4: bounded cardinality).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "client[accepted={} active={} completed={} rejected_maxconn={} protocol_errors={} log_dropped={}]",
            self.connections_accepted,
            self.connections_active,
            self.connections_completed,
            self.connections_rejected,
            self.http_requests_rejected,
            self.access_log_dropped
        )?;
        write!(
            f,
            " proxy[no_server={} queue_full={} queue_timeout={} retries={} local_responses={} redirects={} direct={}]",
            self.no_available_server,
            self.queue_full,
            self.queue_timeout,
            self.retry_attempts,
            self.local_responses_served,
            self.redirects_served,
            self.direct_responses_served
        )?;
        write!(
            f,
            " network[idle_timeouts={} bytes_c2b={} bytes_b2c={}]",
            self.idle_timeouts, self.bytes_client_to_backend, self.bytes_backend_to_client
        )?;
        write!(
            f,
            " backend[connect_failures={} tls_failures={} discarded={} reused={} opened={} proxied={}]",
            self.connect_failures,
            self.tls_handshake_failures,
            self.backend_connections_discarded,
            self.backend_connections_reused,
            self.backend_connections_opened,
            self.http_requests_proxied
        )?;
        write!(
            f,
            " phases[header_timeouts={}] proxy_proto[denied={} invalid={}] cfg[reloads={} reload_failures={} last_swap_us={}]",
            self.header_timeouts,
            self.proxy_protocol_denied,
            self.proxy_protocol_invalid,
            self.config_reloads,
            self.config_reload_failures,
            self.config_reload_duration_us
        )?;
        write!(
            f,
            " auth[denied={} service_errors={}]",
            self.auth_denied, self.auth_service_errors
        )?;
        write!(
            f,
            " dns[ok={} failures={} updates={}]",
            self.dns_resolutions_ok, self.dns_resolution_failures, self.dns_address_updates
        )?;
        write!(
            f,
            " maps[reloads={} failures={}] mirror[sent={} failures={} skipped={}]",
            self.map_reloads,
            self.map_reload_failures,
            self.requests_mirrored,
            self.mirror_failures,
            self.mirror_skipped
        )?;
        write!(
            f,
            " h2[sessions_idle_closed={} goaway={} refused_retried={}]",
            self.h2_sessions_idle_closed, self.h2_goaway_received, self.h2_refused_retried
        )?;
        write!(
            f,
            " grpc[streams={} errors={}]",
            self.grpc_streams, self.grpc_stream_errors
        )?;
        write!(
            f,
            " h3[clean_closes={} connection_errors={}]",
            self.h3_clean_closes, self.h3_connection_errors
        )?;
        write!(
            f,
            " ws[tunnels={} failures={}]",
            self.ws_tunnels, self.ws_failures
        )?;
        write!(
            f,
            " compression[gzip={} brotli={} bytes_in={} bytes_out={}]",
            self.compression_gzip_responses,
            self.compression_brotli_responses,
            self.compression_bytes_in,
            self.compression_bytes_out
        )?;
        write!(
            f,
            " cache[hits={} misses={} bypasses={} revalidations={} stores={} evictions={} disk_loads={} disk_skipped={}]",
            self.cache_hits,
            self.cache_misses,
            self.cache_bypasses,
            self.cache_revalidations,
            self.cache_stores,
            self.cache_evictions,
            self.cache_disk_loads,
            self.cache_disk_skipped
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_respects_maxconn() {
        let metrics = Metrics::default();
        assert!(metrics.try_acquire_connection(2));
        assert!(metrics.try_acquire_connection(2));
        assert!(
            !metrics.try_acquire_connection(2),
            "maxconn=2 admits no third one"
        );
        metrics.release_connection();
        assert!(
            metrics.try_acquire_connection(2),
            "releasing the slot allows accepting again"
        );
    }

    #[test]
    fn snapshot_and_display_reflect_counters() {
        let metrics = Metrics::default();
        assert!(metrics.try_acquire_connection(1));
        metrics
            .bytes_client_to_backend
            .fetch_add(42, Ordering::Relaxed);
        metrics
            .backend_connections_discarded
            .fetch_add(1, Ordering::Relaxed);
        metrics.config_reloads.fetch_add(2, Ordering::Relaxed);
        metrics
            .config_reload_failures
            .fetch_add(1, Ordering::Relaxed);
        let snap = metrics.snapshot();
        assert_eq!(snap.connections_active, 1);
        assert_eq!(snap.bytes_client_to_backend, 42);
        assert_eq!(snap.backend_connections_discarded, 1);
        assert_eq!(snap.config_reloads, 2);
        assert_eq!(snap.config_reload_failures, 1);
        let shown = snap.to_string();
        assert!(shown.contains("active=1"), "display: {shown}");
        assert!(shown.contains("c2b=42"), "display: {shown}");
        assert!(shown.contains("discarded=1"), "display: {shown}");
        assert!(shown.contains("reloads=2"), "display: {shown}");
        assert!(shown.contains("reload_failures=1"), "display: {shown}");
    }

    #[test]
    fn release_never_underflows() {
        let metrics = Metrics::default();
        metrics.release_connection();
        assert_eq!(metrics.snapshot().connections_active, 0);
    }

    #[test]
    fn detail_is_opt_in_and_counts_nothing_while_disabled() {
        let detail = DetailMetrics::default();
        assert!(!detail.enabled());
        detail.record_server("api", "127.0.0.1:9000", false);
        detail.record_route("web", "alpha", false);
        let snap = detail.snapshot();
        assert!(snap.rows.is_empty(), "disabled registry records nothing");
        assert_eq!(snap.dropped, 0);
        let text = snap.prometheus();
        assert!(text.contains("eqproxy_metrics_detail_enabled 0"), "{text}");
        assert!(!text.contains("eqproxy_server_requests_total{"), "{text}");
    }

    #[test]
    fn detail_series_carry_their_counts() {
        let detail = DetailMetrics::new(true, 8);
        detail.record_server("api", "127.0.0.1:9000", false);
        detail.record_server("api", "127.0.0.1:9000", true);
        detail.record_server("api", "127.0.0.1:9001", false);
        detail.record_route("web", "alpha", false);
        let snap = detail.snapshot();
        assert_eq!(snap.series, 3);
        assert_eq!(snap.budget, 8);
        let server = snap
            .rows
            .iter()
            .find(|row| row.kind == DetailKind::Server && row.key == "127.0.0.1:9000")
            .expect("9000 series");
        assert_eq!(server.scope, "api");
        assert_eq!(server.requests, 2);
        assert_eq!(server.errors, 1);
        let route = snap
            .rows
            .iter()
            .find(|row| row.kind == DetailKind::Route)
            .expect("route series");
        assert_eq!((route.scope.as_str(), route.key.as_str()), ("web", "alpha"));
        let text = snap.prometheus();
        assert!(
            text.contains(
                "eqproxy_server_requests_total{backend=\"api\",server=\"127.0.0.1:9000\"} 2"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "eqproxy_server_errors_total{backend=\"api\",server=\"127.0.0.1:9000\"} 1"
            ),
            "{text}"
        );
        assert!(
            text.contains("eqproxy_route_requests_total{listener=\"web\",route=\"alpha\"} 1"),
            "{text}"
        );
        assert!(text.contains("eqproxy_metrics_detail_series 3"), "{text}");
    }

    #[test]
    fn detail_budget_refuses_and_counts_new_series() {
        let detail = DetailMetrics::new(true, 2);
        detail.record_server("api", "s1", false);
        detail.record_route("web", "r1", false);
        // At the budget: a third series is refused, and every observation it
        // would have carried is counted instead of admitted.
        detail.record_server("api", "s2", false);
        detail.record_server("api", "s2", false);
        detail.record_route("web", "r2", false);
        let snap = detail.snapshot();
        assert_eq!(snap.series, 2, "the registry never grows past the budget");
        assert_eq!(snap.dropped, 3);
        // A series that already exists keeps counting: the budget bounds the
        // index, not the traffic it can attribute.
        detail.record_server("api", "s1", true);
        let snap = detail.snapshot();
        assert_eq!(snap.series, 2);
        assert_eq!(snap.dropped, 3);
        assert_eq!(
            snap.rows
                .iter()
                .find(|row| row.key == "s1")
                .map(|row| (row.requests, row.errors)),
            Some((2, 1))
        );
        assert!(
            snap.prometheus()
                .contains("eqproxy_metrics_detail_dropped_total 3")
        );
    }

    #[test]
    fn detail_disable_drops_the_window() {
        let detail = DetailMetrics::new(true, 4);
        detail.record_server("api", "s1", false);
        assert_eq!(detail.snapshot().series, 1);
        detail.set_enabled(false);
        let snap = detail.snapshot();
        assert!(!snap.enabled);
        assert_eq!(snap.series, 0, "a disabled export shows no stale window");
        detail.record_server("api", "s1", false);
        assert_eq!(detail.snapshot().series, 0, "and records nothing");
        detail.set_enabled(true);
        assert_eq!(detail.snapshot().series, 0, "re-enabling starts empty");
        detail.record_server("api", "s1", false);
        assert_eq!(detail.snapshot().series, 1);
    }

    #[test]
    fn detail_labels_are_escaped() {
        let detail = DetailMetrics::new(true, 4);
        detail.record_route("web", "quo\"te\\back", false);
        let text = detail.snapshot().prometheus();
        assert!(
            text.contains("route=\"quo\\\"te\\\\back\""),
            "label value not escaped: {text}"
        );
        // Every sample line must keep a single closing quote before the space.
        for line in text
            .lines()
            .filter(|line| line.starts_with("eqproxy_route"))
        {
            assert!(line.contains("\"} "), "unparseable sample: {line}");
        }
    }
}
