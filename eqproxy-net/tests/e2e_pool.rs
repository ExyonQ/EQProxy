//! Phase 3 (A16) — Backend keep-alive pool over real sockets.
//!
//! Reuse contract under test: N sequential exchanges over one client
//! connection use ONE backend TCP connection; a framing error, a server
//! close, or any failed exchange never returns its connection to the pool.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use eqproxy_core::{Metrics, shutdown};
use eqproxy_net::{BoundProxy, ProxyMode, ResolvedListener, bind};

const WAIT: Duration = Duration::from_secs(5);
const N: usize = 5;

/// Origin behaviour per accepted connection batch.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OriginMode {
    /// Always `200 OK`, keep-alive.
    Clean,
    /// First response is garbage (framing error), then clean.
    GarbageOnce,
    /// Always `200 OK` with `Connection: close`.
    CloseAlways,
    /// Clean `200 OK` without a close header, but the socket closes shortly
    /// after — what a real backend does when the *request* carried
    /// `Connection: close` (forwarded verbatim by the proxy).
    CloseAfterFlush,
}

struct CountingOrigin {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
}

async fn start_origin(mode: OriginMode) -> CountingOrigin {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("addr origin");
    let accepts = Arc::new(AtomicUsize::new(0));
    let served = Arc::new(AtomicUsize::new(0));
    let accepts_task = Arc::clone(&accepts);
    let served_task = Arc::clone(&served);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            accepts_task.fetch_add(1, Ordering::SeqCst);
            let served = Arc::clone(&served_task);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let mut total = 0usize;
                    let head_end = loop {
                        match socket.read(&mut buf[total..]).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => total += n,
                        }
                        if let Some(pos) = buf[..total].windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                        if total == buf.len() {
                            return;
                        }
                    };
                    let n = served.fetch_add(1, Ordering::SeqCst);
                    let response: &[u8] = match mode {
                        OriginMode::Clean => b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
                        OriginMode::GarbageOnce if n == 0 => b"GARBAGE-NOT-HTTP\r\n\r\n",
                        OriginMode::GarbageOnce => b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
                        OriginMode::CloseAfterFlush => {
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                        }
                        OriginMode::CloseAlways => {
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        }
                    };
                    if socket.write_all(response).await.is_err() {
                        return;
                    }
                    if mode == OriginMode::CloseAlways {
                        return;
                    }
                    if mode == OriginMode::CloseAfterFlush {
                        // Delayed close: the proxy's post-exchange read sees
                        // no FIN yet, so only an explicit no-reuse decision
                        // keeps this connection out of the pool.
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        return;
                    }
                    let _ = head_end;
                }
            });
        }
    });
    CountingOrigin { addr, accepts }
}

fn listener_cfg(listen: SocketAddr, server: SocketAddr) -> ResolvedListener {
    ResolvedListener::new(
        "web",
        listen,
        "api",
        server,
        ProxyMode::Http,
        64,
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
}

async fn start_proxy(
    cfg: ResolvedListener,
    metrics: Arc<Metrics>,
) -> (SocketAddr, shutdown::ShutdownHandle, JoinHandle<()>) {
    let bound: BoundProxy = bind(vec![cfg], Arc::clone(&metrics))
        .await
        .expect("bind proxy");
    let addr = bound.local_addrs()[0].1;
    let (handle, signal) = shutdown::channel();
    let serve = tokio::spawn(async move {
        bound
            .serve(signal, Duration::from_secs(2))
            .await
            .expect("serve");
    });
    (addr, handle, serve)
}

async fn get_status(client: &mut TcpStream) -> String {
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
        .await
        .expect("write");
    let mut acc = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        let n = tokio::time::timeout(WAIT, client.read(&mut buf))
            .await
            .expect("response on time")
            .expect("read");
        assert!(n > 0, "EOF before a complete response: {acc:?}");
        acc.extend_from_slice(&buf[..n]);
        if acc.windows(4).any(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&acc).into_owned();
            return head.lines().next().unwrap_or("").to_owned();
        }
    }
}

async fn connect(addr: SocketAddr) -> TcpStream {
    tokio::time::timeout(WAIT, TcpStream::connect(addr))
        .await
        .expect("connect on time")
        .expect("connect")
}

/// Wait until the proxy has counted `want` proxied exchanges.
///
/// `http_requests_proxied` is incremented when the exchange finishes on the
/// proxy side (`http1.rs`), which can land **after** the client has read the
/// response head: the head is what `get_status` reads, and the bookkeeping
/// runs when the response body has been copied. Sampling the counter once
/// right after the last head therefore races the proxy — CI run 40616967835
/// read `4` where `5` was expected on a correct proxy. The assertions below
/// are unchanged: they observe the same final values, after the exchange has
/// been counted.
async fn wait_for_proxied(metrics: &Metrics, want: u64) {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        if metrics.snapshot().http_requests_proxied == want {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the proxy never counted {want} proxied requests"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[cfg_attr(
    miri,
    ignore = "requires TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keep_alive_reuses_a_single_backend_connection() {
    let origin = start_origin(OriginMode::Clean).await;
    let metrics = Arc::new(Metrics::default());
    let cfg = listener_cfg("127.0.0.1:0".parse().expect("addr"), origin.addr);
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let mut client = connect(proxy_addr).await;
    for _ in 0..N {
        let status = get_status(&mut client).await;
        assert!(status.contains("200"), "expected 200, got {status:?}");
    }
    drop(client);
    wait_for_proxied(&metrics, N as u64).await;

    assert_eq!(
        origin.accepts.load(Ordering::SeqCst),
        1,
        "N exchanges must reuse one backend connection"
    );
    let snap = metrics.snapshot();
    assert_eq!(snap.backend_connections_opened, 1);
    assert_eq!(snap.backend_connections_reused, (N - 1) as u64);
    assert_eq!(snap.http_requests_proxied, N as u64);

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("shutdown")
        .expect("serve");
}

#[cfg_attr(
    miri,
    ignore = "requires TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn framing_error_is_never_reused() {
    let origin = start_origin(OriginMode::GarbageOnce).await;
    let metrics = Arc::new(Metrics::default());
    let cfg = listener_cfg("127.0.0.1:0".parse().expect("addr"), origin.addr);
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let mut client = connect(proxy_addr).await;
    let first = get_status(&mut client).await;
    assert!(
        first.contains("502"),
        "garbage upstream must map to 502, got {first:?}"
    );
    drop(client);
    // The 502 closed the client connection too: reconnect. The poisoned
    // backend connection was dropped, so this exchange dials fresh.
    let mut client = connect(proxy_addr).await;
    let second = get_status(&mut client).await;
    assert!(
        second.contains("200"),
        "expected 200 after redial, got {second:?}"
    );
    drop(client);

    assert_eq!(origin.accepts.load(Ordering::SeqCst), 2);
    let snap = metrics.snapshot();
    assert_eq!(snap.backend_connections_opened, 2);
    assert_eq!(snap.backend_connections_reused, 0);

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("shutdown")
        .expect("serve");
}

#[cfg_attr(
    miri,
    ignore = "requires TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_close_is_not_reused() {
    let origin = start_origin(OriginMode::CloseAlways).await;
    let metrics = Arc::new(Metrics::default());
    let cfg = listener_cfg("127.0.0.1:0".parse().expect("addr"), origin.addr);
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    // The server closes every exchange, so the proxy closes the client too:
    // each request needs a fresh client connection and dials fresh.
    for _ in 0..2 {
        let mut client = connect(proxy_addr).await;
        let status = get_status(&mut client).await;
        assert!(status.contains("200"), "expected 200, got {status:?}");
    }

    assert_eq!(origin.accepts.load(Ordering::SeqCst), 2);
    let snap = metrics.snapshot();
    assert_eq!(snap.backend_connections_reused, 0);

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("shutdown")
        .expect("serve");
}

/// A request that carries `Connection: close` is forwarded to the backend
/// verbatim, so the backend closes even when its response says nothing
/// about it. Pooling that connection would hand the next exchange a dead
/// socket (observed as a spurious 502): reuse requires *both* sides to
/// keep-alive.
#[cfg_attr(
    miri,
    ignore = "requires TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn close_request_is_never_pooled() {
    let origin = start_origin(OriginMode::CloseAfterFlush).await;
    let metrics = Arc::new(Metrics::default());
    let cfg = listener_cfg("127.0.0.1:0".parse().expect("addr"), origin.addr);
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    // Two `Connection: close` requests, one exchange each. Both must be
    // answered in full; the second must dial fresh instead of reusing the
    // first's (dying) connection.
    for _ in 0..2 {
        let mut client = connect(proxy_addr).await;
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        let mut response = Vec::new();
        tokio::time::timeout(WAIT, client.read_to_end(&mut response))
            .await
            .expect("response on time")
            .expect("read");
        assert_eq!(
            String::from_utf8_lossy(&response),
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            "a close-request exchange must be answered, never 502"
        );
    }

    assert_eq!(origin.accepts.load(Ordering::SeqCst), 2);
    let snap = metrics.snapshot();
    assert_eq!(snap.backend_connections_opened, 2);
    assert_eq!(snap.backend_connections_reused, 0);

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("shutdown")
        .expect("serve");
}
