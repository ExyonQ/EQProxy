//! Graceful shutdown: one signal, many listeners (listeners and control tasks).
//!
//! Built on `tokio::sync::watch`: no extra dependencies and no
//! polling loops.

use tokio::sync::watch;

/// Shutdown signal receiver (clonable, cheap).
#[derive(Debug, Clone)]
pub struct Shutdown {
    rx: watch::Receiver<bool>,
}

/// Shutdown signal sender.
#[derive(Debug, Clone)]
pub struct ShutdownHandle {
    tx: watch::Sender<bool>,
}

/// Creates the shutdown (sender, receiver) pair.
#[must_use]
pub fn channel() -> (ShutdownHandle, Shutdown) {
    let (tx, rx) = watch::channel(false);
    (ShutdownHandle { tx }, Shutdown { rx })
}

impl ShutdownHandle {
    /// Triggers shutdown. Idempotent.
    pub fn trigger(&self) {
        self.tx.send_replace(true);
    }

    /// Is the shutdown triggered?
    #[must_use]
    pub fn is_triggered(&self) -> bool {
        *self.tx.borrow()
    }
}

impl Shutdown {
    /// Is the shutdown triggered?
    #[must_use]
    pub fn is_triggered(&self) -> bool {
        *self.rx.borrow()
    }

    /// Waits until shutdown fires (immediate when already triggered).
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
    use std::future::Future;
    use std::time::Duration;

    /// Runs a future on a single-thread runtime **without IO driver**
    /// (mio/kqueue): tests only use timers and in-memory channels, so they
    /// also run under miri, which does not emulate that OS FFI.
    fn sin_driver_io<F: Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime tokio")
            .block_on(fut)
    }

    #[test]
    fn trigger_releases_all_waiters() {
        sin_driver_io(async {
            let (handle, shutdown) = channel();
            let mut waiter = shutdown.clone();
            let waiting = tokio::spawn(async move { waiter.wait().await });
            assert!(!shutdown.is_triggered());
            handle.trigger();
            tokio::time::timeout(Duration::from_secs(1), waiting)
                .await
                .expect("wait() must return after trigger()")
                .expect("the task must not fail");
            assert!(shutdown.is_triggered());
            assert!(handle.is_triggered());
        })
    }

    #[test]
    fn wait_returns_immediately_if_already_triggered() {
        sin_driver_io(async {
            let (handle, shutdown) = channel();
            handle.trigger();
            let mut waiter = shutdown;
            tokio::time::timeout(Duration::from_secs(1), waiter.wait())
                .await
                .expect("wait() on an already-triggered signal must be immediate");
        })
    }
}
