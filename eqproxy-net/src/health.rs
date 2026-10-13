//! Health checks TCP activos (B11 TCP): un task por backend con checks
//! configurados.
//!
//! Ciclo: cada `interval`, intento de conexión TCP a cada servidor con
//! `timeout`; el resultado alimenta la máquina `fall`/`rise` del
//! [`Balancer`](crate::balancer::Balancer). Los checks de HTTP con `expect`
//! llegan en Fase 3 (B11 HTTP).

use std::sync::Arc;
use std::time::Duration;

use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::task::JoinSet;

use eqproxy_core::Shutdown;

use crate::balancer::Balancer;

/// Parámetros de un health check TCP (B11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthCheck {
    /// Intervalo entre ciclos de comprobación.
    pub interval: Duration,
    /// Timeout de cada intento de conexión.
    pub timeout: Duration,
}

/// Ejecuta los health checks hasta la señal de apagado.
///
/// El primer ciclo se ejecuta tras `interval` (los servidores arrancan
/// operativos; la primera ronda de checks puede derribarlos).
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
        // Servidor que acepta: lo abrimos y cerramos para alternar estado.
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
            "el servidor vivo debe seguir operativo"
        );

        // Cerramos el listener: los checks fallan → down (fall=1).
        acceptor.abort();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!balancer.is_up(addr), "el servidor muerto debe caer");

        handle.trigger();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("el task de checks debe terminar con la señal")
            .expect("join");
    }
}
