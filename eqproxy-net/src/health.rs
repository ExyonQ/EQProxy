//! Active TCP health checks (B11 TCP): one task per backend with configured
//! checks.
//!
//! Cycle: every `interval`, a TCP connection attempt to each server with
//! `timeout`; the result feeds the `fall`/`rise` machine of
//! [`Balancer`](crate::balancer::Balancer). HTTP checks with `expect`
//! arrive in Phase 3 (B11 HTTP).

use std::sync::Arc;
use std::time::Duration;

use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::task::JoinSet;

use eqproxy_core::Shutdown;

use crate::balancer::Balancer;

/// Parameters of a TCP health check (B11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthCheck {
    /// Interval between check cycles.
    pub interval: Duration,
    /// Timeout of each connection attempt.
    pub timeout: Duration,
}

/// Runs the health checks until the shutdown signal.
///
/// The first cycle runs after `interval` (servers start
/// operational; the first check round may drop them).
pub async fn run(balancer: Arc<Balancer>, check: HealthCheck, mut shutdown: Shutdown) {
    loop {
        tokio::select! {
            _ = shutdown.wait() => return,
            _ = tokio::time::sleep(check.interval) => {}
        }

        let mut attempts = JoinSet::new();
        for &addr in balancer.servers() {
            let balancer = Arc::clone(&balancer);
            attempts.spawn(async move { check_one(balancer, addr, check.timeout).await });
        }
        while attempts.join_next().await.is_some() {}
    }
}

async fn check_one(balancer: Arc<Balancer>, addr: SocketAddr, timeout: Duration) {
    let ok = matches!(
        tokio::time::timeout(timeout, TcpStream::connect(addr)).await,
        Ok(Ok(_))
    );
    if ok {
        balancer.report_ok(addr);
    } else {
        balancer.report_fail(addr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::balancer::ResolvedServer;

    #[cfg_attr(
        miri,
        ignore = "requiere sockets TCP: miri no soporta red (rust-lang/miri#3449)"
    )]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn check_task_marks_server_down_and_up_again() {
        // Server that accepts: we open and close it to toggle state.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let acceptor = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                drop(socket);
            }
        });

        let balancer = Arc::new(Balancer::new(
            vec![ResolvedServer { addr, weight: 1 }],
            1,
            1,
        ));
        let (handle, signal) = eqproxy_core::shutdown::channel();
        let task = tokio::spawn({
            let balancer = Arc::clone(&balancer);
            async move {
                run(
                    balancer,
                    HealthCheck {
                        interval: Duration::from_millis(20),
                        timeout: Duration::from_millis(200),
                    },
                    signal,
                )
                .await;
            }
        });

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            balancer.is_up(addr),
            "the live server must stay operational"
        );

        // Cerramos el listener: los checks fallan → down (fall=1).
        acceptor.abort();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!balancer.is_up(addr), "the dead server must drop");

        handle.trigger();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("the check task must finish on the signal")
            .expect("join");
    }
}
