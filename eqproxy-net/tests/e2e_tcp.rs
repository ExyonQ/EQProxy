//! Pruebas E2E del dataplane TCP con **sockets reales** (sin mocks de red).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use eqproxy_core::{Metrics, shutdown};
use eqproxy_net::{BoundProxy, ResolvedListener, bind};

const WAIT: Duration = Duration::from_secs(5);

/// Backend de eco real sobre sockets.
async fn start_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("addr echo");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if socket.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

fn listener_cfg(
    name: &str,
    listen: SocketAddr,
    server: SocketAddr,
    maxconn: u32,
    connect_timeout: Duration,
    idle_timeout: Duration,
) -> ResolvedListener {
    ResolvedListener::new(
        name,
        listen,
        "api",
        server,
        eqproxy_net::ProxyMode::Tcp,
        maxconn,
        connect_timeout,
        idle_timeout,
        Duration::from_secs(5),
        Duration::from_secs(30),
    )
}

/// Arranca el proxy y devuelve (dirección real, handle de apagado, tarea serve).
async fn start_proxy(
    cfg: ResolvedListener,
    metrics: Arc<Metrics>,
    grace: Duration,
) -> (SocketAddr, shutdown::ShutdownHandle, JoinHandle<()>) {
    let bound: BoundProxy = bind(vec![cfg], Arc::clone(&metrics))
        .await
        .expect("bind proxy");
    let addrs = bound.local_addrs();
    let addr = addrs[0].1;
    let (handle, signal) = shutdown::channel();
    let serve = tokio::spawn(async move {
        bound.serve(signal, grace).await.expect("serve");
    });
    (addr, handle, serve)
}

#[cfg_attr(
    miri,
    ignore = "requiere sockets TCP: miri no soporta red (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echo_roundtrip_through_proxy_updates_metrics() {
    let backend = start_echo().await;
    let metrics = Arc::new(Metrics::default());
    let cfg = listener_cfg(
        "web",
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        64,
        Duration::from_secs(2),
        Duration::from_secs(5),
    );
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics), WAIT).await;

    let mut client = tokio::time::timeout(WAIT, TcpStream::connect(proxy_addr))
        .await
        .expect("connect a tiempo")
        .expect("connect al proxy");
    let payload = vec![0xABu8; 4096];
    client.write_all(&payload).await.expect("write");
    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(WAIT, client.read_exact(&mut received))
        .await
        .expect("echo a tiempo")
        .expect("echo completo");
    assert_eq!(received, payload, "el eco debe ser byte a byte");

    drop(client);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let snap = metrics.snapshot();
    assert_eq!(snap.connections_accepted, 1);
    assert_eq!(snap.connections_rejected, 0);
    assert_eq!(snap.connect_failures, 0);
    assert_eq!(snap.bytes_client_to_backend, 4096);
    assert_eq!(snap.bytes_backend_to_client, 4096);

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve termina")
        .expect("tarea serve sin pánico");
}

#[cfg_attr(
    miri,
    ignore = "requiere sockets TCP: miri no soporta red (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn maxconn_rejects_excess_connections_explicitly() {
    let backend = start_echo().await;
    let metrics = Arc::new(Metrics::default());
    let cfg = listener_cfg(
        "web",
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        2,
        Duration::from_secs(2),
        Duration::from_secs(5),
    );
    // grace corto: las conexiones retenidas siguen vivas al apagar y el
    // drenado debe terminar al expirar la ventana (cierre forzado documentado).
    let (proxy_addr, handle, serve) =
        start_proxy(cfg, Arc::clone(&metrics), Duration::from_secs(1)).await;

    let _held_1 = TcpStream::connect(proxy_addr).await.expect("conn 1");
    let _held_2 = TcpStream::connect(proxy_addr).await.expect("conn 2");
    // La tercera supera maxconn=2: aceptada y cerrada de inmediato (rechazo).
    let mut third = TcpStream::connect(proxy_addr).await.expect("conn 3");
    let mut byte = [0u8; 1];
    let closed = tokio::time::timeout(WAIT, third.read(&mut byte))
        .await
        .expect("rechazo a tiempo")
        .expect("read");
    assert_eq!(closed, 0, "la conexión excedente debe cerrarse sin datos");
    assert_eq!(metrics.snapshot().connections_rejected, 1);

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve termina")
        .expect("tarea serve sin pánico");
}

#[cfg_attr(
    miri,
    ignore = "requiere sockets TCP: miri no soporta red (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_timeout_fails_fast_and_counts() {
    // 192.0.2.0/24 (TEST-NET-1) no enruta: la conexión al backend nunca completa.
    let blackhole: SocketAddr = "192.0.2.1:81".parse().expect("addr");
    let metrics = Arc::new(Metrics::default());
    let cfg = listener_cfg(
        "web",
        "127.0.0.1:0".parse().expect("addr"),
        blackhole,
        64,
        Duration::from_millis(200),
        Duration::from_secs(5),
    );
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics), WAIT).await;

    let started = std::time::Instant::now();
    let mut client = TcpStream::connect(proxy_addr)
        .await
        .expect("connect al proxy");
    let mut byte = [0u8; 1];
    let closed = tokio::time::timeout(WAIT, client.read(&mut byte))
        .await
        .expect("cierre a tiempo")
        .expect("read");
    assert_eq!(
        closed, 0,
        "el proxy debe cerrar la conexión al fallar el backend"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "el fallo debe ser rápido, no colgar: {:?}",
        started.elapsed()
    );
    assert_eq!(metrics.snapshot().connect_failures, 1);

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve termina")
        .expect("tarea serve sin pánico");
}

#[cfg_attr(
    miri,
    ignore = "requiere sockets TCP: miri no soporta red (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_timeout_closes_silent_connection() {
    let backend = start_echo().await;
    let metrics = Arc::new(Metrics::default());
    let cfg = listener_cfg(
        "web",
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        64,
        Duration::from_secs(2),
        Duration::from_millis(150),
    );
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics), WAIT).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
    let mut byte = [0u8; 1];
    let closed = tokio::time::timeout(WAIT, client.read(&mut byte))
        .await
        .expect("cierre por idle a tiempo")
        .expect("read");
    assert_eq!(closed, 0, "la conexión silenciosa debe cerrarse");
    assert!(
        metrics.snapshot().idle_timeouts >= 1,
        "debe contarse el timeout de inactividad: {}",
        metrics.snapshot()
    );

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve termina")
        .expect("tarea serve sin pánico");
}

#[cfg_attr(
    miri,
    ignore = "requiere sockets TCP: miri no soporta red (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn graceful_shutdown_finishes_inflight_and_stops_accepting() {
    let backend = start_echo().await;
    let metrics = Arc::new(Metrics::default());
    let cfg = listener_cfg(
        "web",
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        64,
        Duration::from_secs(2),
        Duration::from_secs(5),
    );
    let (proxy_addr, handle, serve) = start_proxy(cfg, metrics, Duration::from_secs(3)).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
    client.write_all(b"hola").await.expect("write");
    let mut buf = [0u8; 4];
    tokio::time::timeout(WAIT, client.read_exact(&mut buf))
        .await
        .expect("eco previo")
        .expect("read");
    assert_eq!(&buf, b"hola");

    // Apagado con la conexión viva: la conexión en curso debe poder seguir.
    handle.trigger();
    client
        .write_all(b"mundo!!")
        .await
        .expect("write tras shutdown");
    let mut buf2 = [0u8; 7];
    tokio::time::timeout(WAIT, client.read_exact(&mut buf2))
        .await
        .expect("la conexión en curso debe terminar su eco")
        .expect("read");
    assert_eq!(&buf2, b"mundo!!");

    // ...pero ya no se aceptan conexiones nuevas.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        TcpStream::connect(proxy_addr).await.is_err(),
        "tras el apagado no deben aceptarse conexiones nuevas"
    );

    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve termina")
        .expect("tarea serve sin pánico");
}

#[cfg_attr(
    miri,
    ignore = "requiere sockets TCP: miri no soporta red (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bind_is_all_or_nothing() {
    // Ocupa un puerto con un socket ajeno; el bind del proxy debe fallar entero.
    let taken = std::net::TcpListener::bind("127.0.0.1:0").expect("socket ajeno");
    let busy: SocketAddr = taken.local_addr().expect("addr");
    let backend = start_echo().await;

    let good = listener_cfg(
        "web",
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        64,
        Duration::from_secs(2),
        Duration::from_secs(5),
    );
    let bad = listener_cfg(
        "ocupado",
        busy,
        backend,
        64,
        Duration::from_secs(2),
        Duration::from_secs(5),
    );
    let metrics = Arc::new(Metrics::default());
    let err = bind(vec![good, bad], metrics)
        .await
        .expect_err("debe fallar");
    assert!(
        err.to_string().contains("ocupado"),
        "el error debe nombrar el listener: {err}"
    );
}
