//! E2E hot config reload (S-CFG-01): real sockets, real accept loops and
//! real swaps against the running dataplane. The journeys mirror the
//! operator's: swap routing under traffic, reject a candidate fail-closed
//! (the running config keeps serving), add/remove/rebind listeners and
//! keep the counters monotonic (PP-03).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use eqproxy_core::Metrics;
use eqproxy_net::proxy::{self, ProxyMode, ResolvedListener, SwapSummary};

/// Echo backend that tags every echoed chunk with one byte (`A`, `B`, …),
/// so the client can observe **which** backend served it.
async fn tagged_echo(tag: u8) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let mut out = vec![tag];
                            out.extend_from_slice(&buf[..n]);
                            if socket.write_all(&out).await.is_err() {
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

/// A free port (probe bind then release).
async fn free_port() -> SocketAddr {
    let probe = TcpListener::bind("127.0.0.1:0").await.expect("probe");
    let addr = probe.local_addr().expect("probe addr");
    drop(probe);
    addr
}

fn tcp_listener(name: &str, listen: SocketAddr, server: SocketAddr) -> ResolvedListener {
    ResolvedListener::new(
        name,
        listen,
        "api",
        server,
        ProxyMode::Tcp,
        16,
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
}

/// One proxied round trip on a fresh connection: writes `x`, reads the
/// tag + echo and returns the tag (which backend served it).
async fn round_trip(addr: SocketAddr) -> u8 {
    let mut client = TcpStream::connect(addr).await.expect("connect proxy");
    client.write_all(b"x").await.expect("write");
    let mut buf = [0u8; 2];
    client.read_exact(&mut buf).await.expect("read echo");
    assert_eq!(&buf[1..], b"x", "the echo must come back");
    buf[0]
}

/// Polls `cond` until true or the deadline (async, 20 ms steps).
async fn wait_until(what: &str, cond: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timeout waiting for: {what}");
}

/// Polls until `addr` refuses connections (a stopped listener closes its
/// socket in the same instant, but a raced connect can slip in).
async fn wait_until_refused(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(addr).await.is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timeout waiting for {addr} to refuse connections");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hot_swap_changes_new_routing_and_drains_established_connections() {
    let a = tagged_echo(b'A').await;
    let b = tagged_echo(b'B').await;
    let metrics = Arc::new(Metrics::default());
    let listen = free_port().await;
    let mut proxy = proxy::bind(vec![tcp_listener("web", listen, a)], Arc::clone(&metrics))
        .await
        .expect("bind");

    // Connection established BEFORE the swap: it must drain with backend A.
    let mut old = TcpStream::connect(listen).await.expect("connect old");
    old.write_all(b"x").await.expect("write old");
    let mut buf = [0u8; 2];
    old.read_exact(&mut buf).await.expect("read old");
    assert_eq!(buf, [b'A', b'x'], "initial routing must reach backend A");

    // Hot swap: same listener name + address (socket kept), new backend.
    let summary = proxy
        .apply(vec![tcp_listener("web", listen, b)])
        .await
        .expect("apply must succeed");
    assert_eq!(
        summary,
        SwapSummary {
            kept: 1,
            added: 0,
            removed: 0
        }
    );

    // New connection → the new backend (observable behavior).
    assert_eq!(round_trip(listen).await, b'B', "new routing must reach B");

    // The established connection keeps the config it was accepted with.
    old.write_all(b"y").await.expect("write old 2");
    let mut buf = [0u8; 2];
    old.read_exact(&mut buf).await.expect("read old 2");
    assert_eq!(buf, [b'A', b'y'], "established connection drains with A");

    // Counters never reset (PP-03): three client connections so far.
    let snap = metrics.snapshot();
    assert_eq!(snap.connections_accepted, 2, "snap: {snap}");
    assert_eq!(
        snap.config_reloads, 0,
        "apply() is the primitive; the supervisor counts (snap: {snap})"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn supervisor_counts_reloads_and_rejects_fail_closed() {
    let a = tagged_echo(b'A').await;
    let b = tagged_echo(b'B').await;
    let metrics = Arc::new(Metrics::default());
    let listen = free_port().await;

    // Port P is held by this test: any listener on it can never bind.
    let held = TcpListener::bind("127.0.0.1:0").await.expect("held port");
    let held_addr = held.local_addr().expect("held addr");

    let proxy = proxy::bind(vec![tcp_listener("web", listen, a)], Arc::clone(&metrics))
        .await
        .expect("bind");
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let (stop, signal) = eqproxy_core::shutdown::channel();
    let server = tokio::spawn(proxy.serve_with_reloads(signal, Duration::from_secs(2), rx));

    // Bad candidate: a second listener on the held port → bind conflict.
    tx.send(vec![
        tcp_listener("web", listen, a),
        tcp_listener("extra", held_addr, b),
    ])
    .await
    .expect("send bad reload");
    wait_until("config_reload_failures == 1", || {
        metrics.snapshot().config_reload_failures == 1
    })
    .await;
    assert_eq!(
        metrics.snapshot().config_reloads,
        0,
        "a rejected swap never counts as applied"
    );

    // Fail-closed: the running config keeps serving unchanged.
    assert_eq!(
        round_trip(listen).await,
        b'A',
        "a rejected reload must not touch the running config"
    );

    // Good candidate: same listener, new backend.
    tx.send(vec![tcp_listener("web", listen, b)])
        .await
        .expect("send good reload");
    wait_until("config_reloads == 1", || {
        metrics.snapshot().config_reloads == 1
    })
    .await;
    assert_eq!(
        round_trip(listen).await,
        b'B',
        "new connections must follow the applied config"
    );

    stop.trigger();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("serve must finish after shutdown")
        .expect("serve join")
        .expect("serve result");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn apply_adds_removes_and_rebinds_listeners() {
    let a = tagged_echo(b'A').await;
    let metrics = Arc::new(Metrics::default());
    let l1 = free_port().await;
    let l2 = free_port().await;
    let l3 = free_port().await;
    let mut proxy = proxy::bind(vec![tcp_listener("web", l1, a)], Arc::clone(&metrics))
        .await
        .expect("bind");

    // Add a listener.
    let summary = proxy
        .apply(vec![
            tcp_listener("web", l1, a),
            tcp_listener("extra", l2, a),
        ])
        .await
        .expect("apply add");
    assert_eq!(
        summary,
        SwapSummary {
            kept: 1,
            added: 1,
            removed: 0
        }
    );
    assert_eq!(round_trip(l2).await, b'A', "the new listener must serve");

    // Remove it.
    let summary = proxy
        .apply(vec![tcp_listener("web", l1, a)])
        .await
        .expect("apply remove");
    assert_eq!(
        summary,
        SwapSummary {
            kept: 1,
            added: 0,
            removed: 1
        }
    );
    wait_until_refused(l2).await;

    // Rebind: same name, new address (removed + added).
    let summary = proxy
        .apply(vec![tcp_listener("web", l3, a)])
        .await
        .expect("apply rebind");
    assert_eq!(
        summary,
        SwapSummary {
            kept: 0,
            added: 1,
            removed: 1
        }
    );
    wait_until_refused(l1).await;
    assert_eq!(
        round_trip(l3).await,
        b'A',
        "the rebound listener must serve"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duplicate_addresses_are_rejected_without_touching_the_running_config() {
    let a = tagged_echo(b'A').await;
    let metrics = Arc::new(Metrics::default());
    let listen = free_port().await;
    let mut proxy = proxy::bind(vec![tcp_listener("web", listen, a)], Arc::clone(&metrics))
        .await
        .expect("bind");

    match proxy
        .apply(vec![
            tcp_listener("web", listen, a),
            tcp_listener("twin", listen, a),
        ])
        .await
    {
        Err(proxy::ProxyError::DuplicateListener { name, addr }) => {
            assert_eq!(name, "twin");
            assert_eq!(addr, listen);
        }
        other => panic!("the duplicate address must be rejected: {other:?}"),
    }
    assert_eq!(
        round_trip(listen).await,
        b'A',
        "the running config must be untouched"
    );
}
