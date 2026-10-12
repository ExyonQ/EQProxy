//! Proxy TCP: aceptar, conectar al backend y bombear bytes con timeouts.
//!
//! Semántica (documentada y testeada):
//! - `maxconn` por listener: al llenarse, la conexión se **rechaza** (cierre
//!   inmediato + contador); nunca hay colas ilimitadas (SPEC §7.3).
//! - `connect_timeout`: máximo para establecer la conexión al backend.
//! - `idle_timeout`: por dirección; si no hay bytes en esa dirección durante la
//!   ventana, se cierra con EOF hacia su par y se cuenta `idle_timeouts`.
//! - Apagado gradual: se deja de aceptar, las conexiones vivas terminan dentro
//!   de `grace`; al expirar, el proceso termina y las restantes se cierran.
//! - `bind` es "o todo o nada": si un listener no puede abrirse, se cierran los
//!   demás y se devuelve error (preparación de recursos previa a la activación,
//!   SPEC §7.2).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

use eqproxy_core::{Metrics, Shutdown};

use crate::http1;

/// Buffer por dirección (SPEC §7.3: 16 KiB).
pub const READ_BUF: usize = 16 * 1024;

/// Modo de proxy de un listener (A1 `Tcp`, A2 `Http`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyMode {
    /// Túnel TCP sin interpretación.
    #[default]
    Tcp,
    /// Proxy HTTP/1.1 con framing estricto.
    Http,
}

/// Listener resuelto (config ya validada: direcciones parseadas, refs íntegras).
///
/// `#[non_exhaustive]`: añadir campos no es un cambio rupturante para los
/// consumidores (política semver de ADR-0004). Se construye con [`Self::new`].
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ResolvedListener {
    pub name: String,
    pub listen: SocketAddr,
    pub backend_name: String,
    pub server: SocketAddr,
    pub mode: ProxyMode,
    pub maxconn: u32,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    /// Fase cliente (solo `http`): cabecera de petición.
    pub client_header_timeout: Duration,
    /// Fase servidor (solo `http`): cabecera de respuesta.
    pub server_header_timeout: Duration,
}

impl ResolvedListener {
    /// Construye un listener resuelto con todos sus campos actuales.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        listen: SocketAddr,
        backend_name: impl Into<String>,
        server: SocketAddr,
        mode: ProxyMode,
        maxconn: u32,
        connect_timeout: Duration,
        idle_timeout: Duration,
        client_header_timeout: Duration,
        server_header_timeout: Duration,
    ) -> Self {
        Self {
            name: name.into(),
            listen,
            backend_name: backend_name.into(),
            server,
            mode,
            maxconn,
            connect_timeout,
            idle_timeout,
            client_header_timeout,
            server_header_timeout,
        }
    }
}

/// Error de arranque del dataplane.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("no se pudo escuchar en {addr} (listener «{name}»): {source}")]
    Bind {
        name: String,
        addr: SocketAddr,
        source: io::Error,
    },
}

#[derive(Debug)]
struct BoundListener {
    cfg: ResolvedListener,
    listener: TcpListener,
}

/// Dataplane con todos los sockets ya abiertos (activación pendiente).
#[derive(Debug)]
pub struct BoundProxy {
    listeners: Vec<BoundListener>,
    metrics: Arc<Metrics>,
}

/// Abre todos los listeners. Falla completo si alguno no puede abrirse.
pub async fn bind(
    listeners: Vec<ResolvedListener>,
    metrics: Arc<Metrics>,
) -> Result<BoundProxy, ProxyError> {
    let mut bound = Vec::with_capacity(listeners.len());
    for cfg in listeners {
        match TcpListener::bind(cfg.listen).await {
            Ok(listener) => bound.push(BoundListener { cfg, listener }),
            Err(source) => {
                return Err(ProxyError::Bind {
                    name: cfg.name,
                    addr: cfg.listen,
                    source,
                });
            }
        }
    }
    Ok(BoundProxy {
        listeners: bound,
        metrics,
    })
}

impl BoundProxy {
    /// Direcciones reales tras el bind (el puerto 0 resuelve uno efímero).
    #[must_use]
    pub fn local_addrs(&self) -> Vec<(String, SocketAddr)> {
        self.listeners
            .iter()
            .map(|b| {
                let addr = b.listener.local_addr().unwrap_or(b.cfg.listen);
                (b.cfg.name.clone(), addr)
            })
            .collect()
    }

    /// Sirve hasta la señal de apagado; después drena hasta `grace`.
    pub async fn serve(self, mut shutdown: Shutdown, grace: Duration) -> Result<(), ProxyError> {
        let mut acceptors = JoinSet::new();
        for bound in self.listeners {
            let metrics = Arc::clone(&self.metrics);
            let signal = shutdown.clone();
            acceptors.spawn(async move { accept_loop(bound, metrics, signal).await });
        }

        shutdown.wait().await;

        // Los bucles de accept retornan al instante con la señal disparada.
        let _ = tokio::time::timeout(grace, async {
            while acceptors.join_next().await.is_some() {}
        })
        .await;
        acceptors.abort_all();

        // Drenado: las conexiones vivas pueden terminar dentro de la ventana.
        let deadline = tokio::time::Instant::now() + grace;
        while self.metrics.connections_active.load(Ordering::Acquire) > 0 {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(())
    }
}

async fn accept_loop(bound: BoundListener, metrics: Arc<Metrics>, mut shutdown: Shutdown) {
    loop {
        tokio::select! {
            _ = shutdown.wait() => break,
            accepted = bound.listener.accept() => {
                let (socket, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        // Error transitorio (EMFILE, etc.): registrar y continuar,
                        // con pequeño respiro para no saturar la CPU.
                        eprintln!("ERROR [{}] accept falló: {err}", bound.cfg.name);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                if !metrics.try_acquire_connection(bound.cfg.maxconn) {
                    metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                    // Rechazo explícito: cierre inmediato, sin cola.
                    drop(socket);
                    continue;
                }
                metrics.connections_accepted.fetch_add(1, Ordering::Relaxed);
                let cfg = bound.cfg.clone();
                let task_metrics = Arc::clone(&metrics);
                tokio::spawn(async move {
                    handle_connection(socket, peer, cfg, task_metrics).await;
                });
            }
        }
    }
}

/// Guardia RAII: libera la plaza de conexión pase lo que pase.
struct ConnectionGuard {
    metrics: Arc<Metrics>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.metrics.release_connection();
    }
}

async fn handle_connection(
    client: TcpStream,
    peer: SocketAddr,
    cfg: ResolvedListener,
    metrics: Arc<Metrics>,
) {
    let _guard = ConnectionGuard {
        metrics: Arc::clone(&metrics),
    };
    let _ = client.set_nodelay(true);

    if cfg.mode == ProxyMode::Http {
        http1::serve_http(client, peer, &cfg, metrics).await;
        return;
    }

    match tokio::time::timeout(cfg.connect_timeout, TcpStream::connect(cfg.server)).await {
        Err(_elapsed) => {
            metrics.connect_failures.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "ERROR [{}] connect timeout hacia {} (par {peer}) tras {:?}",
                cfg.name, cfg.server, cfg.connect_timeout
            );
        }
        Ok(Err(err)) => {
            metrics.connect_failures.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "ERROR [{}] no se pudo conectar a {} (par {peer}): {err}",
                cfg.name, cfg.server
            );
        }
        Ok(Ok(server)) => {
            let _ = server.set_nodelay(true);
            pump(client, server, cfg.idle_timeout, &metrics).await;
        }
    }
}

/// Bomba bidireccional independiente por dirección.
async fn pump(client: TcpStream, server: TcpStream, idle: Duration, metrics: &Metrics) {
    let (client_read, client_write) = client.into_split();
    let (server_read, server_write) = server.into_split();

    let c2b = copy_dir(
        client_read,
        server_write,
        idle,
        &metrics.bytes_client_to_backend,
        &metrics.idle_timeouts,
    );
    let b2c = copy_dir(
        server_read,
        client_write,
        idle,
        &metrics.bytes_backend_to_client,
        &metrics.idle_timeouts,
    );
    // join!: cada dirección tiene su propio timeout, así el conjunto termina en
    // tiempo acotado aunque un par esté en silencio.
    let (c2b_result, b2c_result) = tokio::join!(c2b, b2c);
    for result in [c2b_result, b2c_result] {
        // El timeout de inactividad ya está contabilizado y cerrado en copy_dir;
        // los errores de I/O reales se registran para diagnóstico.
        if let Err(err) = result
            && err.kind() != io::ErrorKind::TimedOut
        {
            eprintln!("ERROR en el túnel TCP: {err}");
        }
    }
}

/// Copia `reader → writer` con timeout de inactividad por lectura.
///
/// Al llegar EOF (o timeout) se hace `shutdown()` del writer para propagar el
/// half-close hacia el par. Devuelve `TimedOut` si expiró el timeout.
async fn copy_dir<R, W>(
    mut reader: R,
    mut writer: W,
    idle: Duration,
    counter: &AtomicU64,
    idle_counter: &AtomicU64,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; READ_BUF];
    let mut total = 0u64;
    loop {
        let read = match tokio::time::timeout(idle, reader.read(&mut buf)).await {
            Err(_elapsed) => {
                idle_counter.fetch_add(1, Ordering::Relaxed);
                let _ = writer.shutdown().await;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timeout de inactividad en una dirección del túnel",
                ));
            }
            Ok(result) => result,
        };
        match read {
            Ok(0) => {
                let _ = writer.shutdown().await;
                return Ok(total);
            }
            Ok(n) => {
                writer.write_all(&buf[..n]).await?;
                total += n as u64;
                counter.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(err) => {
                let _ = writer.shutdown().await;
                return Err(err);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use tokio::io::AsyncWriteExt;

    /// Ejecuta un futuro en un runtime de un solo hilo **sin driver IO**
    /// (mio/kqueue): los tests solo usan timers y duplex en memoria, así que
    /// corren también bajo miri, que no emula ese FFI del SO.
    fn sin_driver_io<F: Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime tokio")
            .block_on(fut)
    }

    #[test]
    fn copy_dir_moves_bytes_and_propagates_eof() {
        sin_driver_io(async {
            let (mut client, server) = tokio::io::duplex(64);
            let bytes = Arc::new(AtomicU64::new(0));
            let idles = Arc::new(AtomicU64::new(0));
            let task_bytes = Arc::clone(&bytes);
            let task_idles = Arc::clone(&idles);

            let copier = tokio::spawn(async move {
                copy_dir(
                    server,
                    tokio::io::sink(),
                    Duration::from_secs(5),
                    &task_bytes,
                    &task_idles,
                )
                .await
            });
            client.write_all(b"hola").await.expect("write");
            drop(client); // EOF
            let copied = tokio::time::timeout(Duration::from_secs(2), copier)
                .await
                .expect("el copier debe terminar")
                .expect("join")
                .expect("sin error en EOF");
            assert_eq!(copied, 4);
            assert_eq!(bytes.load(Ordering::Relaxed), 4);
            assert_eq!(idles.load(Ordering::Relaxed), 0);
        })
    }

    #[test]
    fn copy_dir_times_out_when_reader_is_silent() {
        sin_driver_io(async {
            let (_client, server) = tokio::io::duplex(64);
            let bytes = AtomicU64::new(0);
            let idles = AtomicU64::new(0);
            let result = copy_dir(
                server,
                tokio::io::sink(),
                Duration::from_millis(50),
                &bytes,
                &idles,
            )
            .await;
            let err = result.expect_err("debe expirar por inactividad");
            assert_eq!(err.kind(), io::ErrorKind::TimedOut);
            assert_eq!(idles.load(Ordering::Relaxed), 1);
        })
    }
}
