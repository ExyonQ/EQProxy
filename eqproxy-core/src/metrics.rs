//! Dataplane counters.
//!
//! Bounded cardinality by design: no per-client, URL or token labels
//! (SPEC §7.3). Exportable metrics arrive in Phase 3; the real state the
//! dataplane increments lives here.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

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
}

/// Immutable snapshot of the counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

impl Metrics {
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
            "client[accepted={} active={} completed={} rejected_maxconn={} protocol_errors={}]",
            self.connections_accepted,
            self.connections_active,
            self.connections_completed,
            self.connections_rejected,
            self.http_requests_rejected
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
}
