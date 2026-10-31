//! TCP dataplane E2E tests with **real sockets** (no network mocks).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use eqproxy_core::{Metrics, shutdown};
use eqproxy_net::{
    BoundProxy, ResolvedBackend, ResolvedListener, ResolvedServer, ServerAddr, bind,
};

const WAIT: Duration = Duration::from_secs(5);

/// Real echo backend over sockets.
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

/// Starts the proxy and returns (real address, shutdown handle, serve task).
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
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
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
        .expect("connect in time")
        .expect("connect al proxy");
    let payload = vec![0xABu8; 4096];
    client.write_all(&payload).await.expect("write");
    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(WAIT, client.read_exact(&mut received))
        .await
        .expect("echo in time")
        .expect("full echo");
    assert_eq!(received, payload, "echo must be byte for byte");

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
        .expect("serve finishes")
        .expect("serve task without panic");
}

/// A TCP origin that announces its identity on accept: a tunnel has no HTTP
/// label to tell servers apart, so the banner is what a test reads.
async fn start_banner(label: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind banner");
    let addr = listener.local_addr().expect("addr banner");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = socket.write_all(format!("{label}\n").as_bytes()).await;
                let mut buf = [0u8; 64];
                let _ = socket.read(&mut buf).await;
            });
        }
    });
    addr
}

/// Opens one tunnel and reads the banner of the server behind it.
async fn banner(proxy: SocketAddr) -> String {
    let mut client = tokio::time::timeout(WAIT, TcpStream::connect(proxy))
        .await
        .expect("connect in time")
        .expect("connect to proxy");
    let mut label = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let got = tokio::time::timeout(WAIT, client.read(&mut byte))
            .await
            .expect("banner in time")
            .expect("banner");
        assert!(got > 0, "the server behind the tunnel must announce itself");
        if byte[0] == b'\n' {
            break;
        }
        label.push(byte[0]);
    }
    String::from_utf8(label).expect("utf8 banner")
}

/// B8 over TCP mode: a tunnel backend selects through the same function. The
/// primary owns the tier, the `backup = true` server receives the tunnel only
/// when every primary is down, and the recovered primary takes it back.
#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tcp_tunnel_fails_over_to_the_backup_server() {
    let primary = start_banner("primary").await;
    let backup = start_banner("backup").await;
    let metrics = Arc::new(Metrics::default());
    let backend = Arc::new(ResolvedBackend::new(
        "api",
        vec![
            ResolvedServer {
                addr: ServerAddr::Ip(primary),
                weight: 1,
                backup: false,
                priority: 0,
                maxconn: 0,
            },
            ResolvedServer {
                addr: ServerAddr::Ip(backup),
                weight: 1,
                backup: true,
                priority: 0,
                maxconn: 0,
            },
        ],
        1,
        1,
    ));
    let cfg = listener_cfg(
        "web",
        "127.0.0.1:0".parse().expect("addr"),
        primary,
        64,
        Duration::from_secs(2),
        Duration::from_secs(5),
    )
    .with_backend(Arc::clone(&backend));
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics), WAIT).await;

    assert_eq!(banner(proxy_addr).await, "primary");
    backend.balancer.report_fail(primary);
    assert_eq!(
        banner(proxy_addr).await,
        "backup",
        "the tunnel must reach the backup server"
    );
    backend.balancer.report_ok(primary);
    assert_eq!(banner(proxy_addr).await, "primary");

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve finishes")
        .expect("serve task without panic");
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
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
    // short grace: held connections stay alive at shutdown and the
    // drain must finish when the window expires (documented forced close).
    let (proxy_addr, handle, serve) =
        start_proxy(cfg, Arc::clone(&metrics), Duration::from_secs(1)).await;

    let _held_1 = TcpStream::connect(proxy_addr).await.expect("conn 1");
    let _held_2 = TcpStream::connect(proxy_addr).await.expect("conn 2");
    // The third exceeds maxconn=2: accepted and closed immediately (refusal).
    let mut third = TcpStream::connect(proxy_addr).await.expect("conn 3");
    let mut byte = [0u8; 1];
    let closed = tokio::time::timeout(WAIT, third.read(&mut byte))
        .await
        .expect("refusal in time")
        .expect("read");
    assert_eq!(closed, 0, "the excess connection must close without data");
    assert_eq!(metrics.snapshot().connections_rejected, 1);

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve finishes")
        .expect("serve task without panic");
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_timeout_fails_fast_and_counts() {
    // 192.0.2.0/24 (TEST-NET-1) does not route: the backend connection never completes.
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
        .expect("timely close")
        .expect("read");
    assert_eq!(
        closed, 0,
        "the proxy must close the connection when the backend fails"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the failure must be fast, not hang: {:?}",
        started.elapsed()
    );
    assert_eq!(metrics.snapshot().connect_failures, 1);

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve finishes")
        .expect("serve task without panic");
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
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
        .expect("timely idle close")
        .expect("read");
    assert_eq!(closed, 0, "the silent connection must close");
    assert!(
        metrics.snapshot().idle_timeouts >= 1,
        "the inactivity timeout must be counted: {}",
        metrics.snapshot()
    );

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve finishes")
        .expect("serve task without panic");
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
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
    client.write_all(b"hello").await.expect("write");
    let mut buf = [0u8; 5];
    tokio::time::timeout(WAIT, client.read_exact(&mut buf))
        .await
        .expect("previous echo")
        .expect("read");
    assert_eq!(&buf, b"hello");

    // Shutdown with a live connection: the in-flight connection must be able to continue.
    handle.trigger();
    client
        .write_all(b"world!!")
        .await
        .expect("write after shutdown");
    let mut buf2 = [0u8; 7];
    tokio::time::timeout(WAIT, client.read_exact(&mut buf2))
        .await
        .expect("the in-flight connection must finish its echo")
        .expect("read");
    assert_eq!(&buf2, b"world!!");

    // ...but no new connections are accepted anymore.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        TcpStream::connect(proxy_addr).await.is_err(),
        "after shutdown no new connections must be accepted"
    );

    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve finishes")
        .expect("serve task without panic");
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bind_is_all_or_nothing() {
    // Occupies a port with a foreign socket; the proxy bind must fail whole.
    let taken = std::net::TcpListener::bind("127.0.0.1:0").expect("foreign socket");
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
        "taken",
        busy,
        backend,
        64,
        Duration::from_secs(2),
        Duration::from_secs(5),
    );
    let metrics = Arc::new(Metrics::default());
    let err = bind(vec![good, bad], metrics).await.expect_err("must fail");
    assert!(
        err.to_string().contains("taken"),
        "the error must name the listener: {err}"
    );
}
