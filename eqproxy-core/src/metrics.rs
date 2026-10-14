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
    pub header_timeouts: u64,
    pub tls_handshake_failures: u64,
    pub no_available_server: u64,
    pub backend_connections_reused: u64,
    pub backend_connections_opened: u64,
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
            header_timeouts: self.header_timeouts.load(Ordering::Relaxed),
            tls_handshake_failures: self.tls_handshake_failures.load(Ordering::Relaxed),
            no_available_server: self.no_available_server.load(Ordering::Relaxed),
            backend_connections_reused: self.backend_connections_reused.load(Ordering::Relaxed),
            backend_connections_opened: self.backend_connections_opened.load(Ordering::Relaxed),
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "conexiones[aceptadas={} activas={} completadas={} rechazadas={} fallos_conexion={} idle_timeouts={}] bytes[c2b={} b2c={}]",
            self.connections_accepted,
            self.connections_active,
            self.connections_completed,
            self.connections_rejected,
            self.connect_failures,
            self.idle_timeouts,
            self.bytes_client_to_backend,
            self.bytes_backend_to_client,
        )?;
        write!(
            f,
            " http[proxied={} rechazadas={} header_timeouts={}]",
            self.http_requests_proxied, self.http_requests_rejected, self.header_timeouts
        )?;
        write!(
            f,
            " tls[handshakes_fallidas={}] sin_servidor={}",
            self.tls_handshake_failures, self.no_available_server
        )?;
        write!(
            f,
            " pool[reutilizadas={} abiertas={}]",
            self.backend_connections_reused, self.backend_connections_opened
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
            "maxconn=2 no admite una tercera"
        );
        metrics.release_connection();
        assert!(
            metrics.try_acquire_connection(2),
            "liberar plaza permite aceptar de nuevo"
        );
    }

    #[test]
    fn snapshot_and_display_reflect_counters() {
        let metrics = Metrics::default();
        assert!(metrics.try_acquire_connection(1));
        metrics
            .bytes_client_to_backend
            .fetch_add(42, Ordering::Relaxed);
        let snap = metrics.snapshot();
        assert_eq!(snap.connections_active, 1);
        assert_eq!(snap.bytes_client_to_backend, 42);
        let shown = snap.to_string();
        assert!(shown.contains("activas=1"), "display: {shown}");
        assert!(shown.contains("c2b=42"), "display: {shown}");
    }

    #[test]
    fn release_never_underflows() {
        let metrics = Metrics::default();
        metrics.release_connection();
        assert_eq!(metrics.snapshot().connections_active, 0);
    }
}
