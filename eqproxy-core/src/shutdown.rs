//! Apagado gradual: una señal, múltiples oyentes (listeners y tareas de control).
//!
//! Implementado sobre `tokio::sync::watch`: sin dependencias adicionales y sin
//! bucles de sondeo.

use tokio::sync::watch;

/// Receptor de la señal de apagado (clonable, barato).
#[derive(Debug, Clone)]
pub struct Shutdown {
    rx: watch::Receiver<bool>,
}

/// Emisor de la señal de apagado.
#[derive(Debug, Clone)]
pub struct ShutdownHandle {
    tx: watch::Sender<bool>,
}

/// Crea el par (emisor, receptor) de apagado.
#[must_use]
pub fn channel() -> (ShutdownHandle, Shutdown) {
    let (tx, rx) = watch::channel(false);
    (ShutdownHandle { tx }, Shutdown { rx })
}

impl ShutdownHandle {
    /// Dispara el apagado. Idempotente.
    pub fn trigger(&self) {
        self.tx.send_replace(true);
    }

    /// ¿Está disparado el apagado?
    #[must_use]
    pub fn is_triggered(&self) -> bool {
        *self.tx.borrow()
    }
}

impl Shutdown {
    /// ¿Está disparado el apagado?
    #[must_use]
    pub fn is_triggered(&self) -> bool {
        *self.rx.borrow()
    }

    /// Espera hasta que se dispare el apagado (inmediato si ya está disparado).
    pub async fn wait(&mut self) {
        if self.is_triggered() {
            return;
        }
        let _ = self.rx.wait_for(|triggered| *triggered).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[cfg_attr(
        miri,
        ignore = "construye un runtime tokio (driver IO kqueue): miri no emula ese FFI"
    )]
    #[tokio::test]
    async fn trigger_releases_all_waiters() {
        let (handle, shutdown) = channel();
        let mut waiter = shutdown.clone();
        let waiting = tokio::spawn(async move { waiter.wait().await });
        assert!(!shutdown.is_triggered());
        handle.trigger();
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("wait() debe retornar tras trigger()")
            .expect("la tarea no debe fallar");
        assert!(shutdown.is_triggered());
        assert!(handle.is_triggered());
    }

    #[cfg_attr(
        miri,
        ignore = "construye un runtime tokio (driver IO kqueue): miri no emula ese FFI"
    )]
    #[tokio::test]
    async fn wait_returns_immediately_if_already_triggered() {
        let (handle, shutdown) = channel();
        handle.trigger();
        let mut waiter = shutdown;
        tokio::time::timeout(Duration::from_secs(1), waiter.wait())
            .await
            .expect("wait() sobre señal ya disparada debe ser inmediato");
    }
}
