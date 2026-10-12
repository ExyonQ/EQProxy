//! Contadores del dataplane.
//!
//! Cardinalidad acotada por diseño: sin etiquetas por cliente, URL ni token
//! (SPEC §7.3). Las métricas exportables llegan en Fase 3; aquí vive el estado
//! real que el dataplane incrementa.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// Contadores globales del proceso de tráfico.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Conexiones aceptadas (incluye las que luego fallan al conectar al backend).
    pub connections_accepted: AtomicU64,
    /// Conexiones rechazadas por alcanzar `maxconn`.
    pub connections_rejected: AtomicU64,
    /// Conexiones proxyadas vivas ahora mismo.
    pub connections_active: AtomicU64,
    /// Conexiones terminadas (cualquier motivo).
    pub connections_completed: AtomicU64,
    /// Fallos de conexión al backend (incluido timeout de conexión).
    pub connect_failures: AtomicU64,
    /// Direcciones cerradas por timeout de inactividad.
    pub idle_timeouts: AtomicU64,
    /// Bytes transferidos cliente → backend.
    pub bytes_client_to_backend: AtomicU64,
    /// Bytes transferidos backend → cliente.
    pub bytes_backend_to_client: AtomicU64,
    /// Intercambios HTTP/1.1 completados (request + response terminados).
    pub http_requests_proxied: AtomicU64,
    /// Peticiones HTTP rechazadas por framing/validación (400/417/431/501/505).
    pub http_requests_rejected: AtomicU64,
    /// Cabeceras de mensaje no recibidas dentro de su timeout de fase.
    pub header_timeouts: AtomicU64,
}

/// Fotografía inmutable de los contadores.
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
}

impl Metrics {
    /// Fotografía coherente (por contador) para logging o tests.
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
        }
    }

    /// Reserva plaza de conexión. Devuelve `false` si se alcanzó `maxconn`
    /// (el llamador debe rechazar de forma explícita, nunca encolar sin límite).
    pub fn try_acquire_connection(&self, maxconn: u32) -> bool {
        self.connections_active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                if active < u64::from(maxconn) {
                    Some(active + 1)
                } else {
                    None
                }
            })
            .is_ok()
    }

    /// Libera la plaza de conexión y cuenta la conexión como completada.
    pub fn release_connection(&self) {
        let _ = self
            .connections_active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
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
