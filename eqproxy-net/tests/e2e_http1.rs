//! E2E tests of the HTTP/1.1 proxy with **real sockets** (no network mocks):
//! strict framing (T01–T03), per-phase timeouts (A17) and streaming with
//! cancellation (A19).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use eqproxy_core::{Metrics, shutdown};
use eqproxy_net::{BoundProxy, ProxyMode, ResolvedListener, bind};

const WAIT: Duration = Duration::from_secs(5);

/// Minimal real HTTP backend: answers 200 echoing the request body.
async fn start_http_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let addr = listener.local_addr().expect("addr backend");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    // Reads the full head (fixture: waits for the body per
                    // framing to echo it byte by byte).
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
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
                    let body_needed = if head.contains("transfer-encoding: chunked") {
                        // Up to the full terminal chunk: "0\r\n\r\n".
                        usize::MAX
                    } else if let Some(len) =
                        head.lines().find_map(|l| l.strip_prefix("content-length:"))
                    {
                        head_end + len.trim().parse::<usize>().unwrap_or(0)
                    } else {
                        head_end
                    };
                    while total < body_needed {
                        if body_needed == usize::MAX
                            && buf[..total].windows(5).any(|w| w == b"0\r\n\r\n")
                        {
                            break;
                        }
                        if body_needed != usize::MAX && total == buf.len() {
                            return;
                        }
                        match socket.read(&mut buf[total..]).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => total += n,
                        }
                    }
                    let body = &buf[head_end..total];
                    let response =
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                    if socket.write_all(response.as_bytes()).await.is_err()
                        || socket.write_all(body).await.is_err()
                    {
                        return;
                    }
                    if buf[..head_end].windows(7).any(|w| w == b"close\r\n") {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// Backend that answers each request with the next scripted raw response.
/// Reads every request in full (head + `Content-Length` body) to stay
/// message-aligned for keep-alive and pool reuse, and pops the script per
/// request across all connections (the tests are strictly sequential).
///
/// `chunked_writes` sends one chunk per message head with a pause in
/// between (stale bytes then arrive *after* a buggy proxy would pool the
/// connection); `false` writes each response atomically so over-sent bytes
/// land in the same read as the head.
async fn start_scripted_backend(script: Vec<Vec<u8>>, chunked_writes: bool) -> SocketAddr {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind scripted");
    let addr = listener.local_addr().expect("addr scripted");
    let script = Arc::new(Mutex::new(VecDeque::from(script)));
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let script = Arc::clone(&script);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
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
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
                    let body_needed = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    while total < head_end + body_needed {
                        match socket.read(&mut buf[total..]).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => total += n,
                        }
                    }
                    let response = {
                        let mut queue = script.lock().expect("script lock");
                        queue.pop_front().unwrap_or_default()
                    };
                    if chunked_writes {
                        // One chunk per message head (a pause between
                        // chunks keeps a stale final response un-read at
                        // the moment a buggy proxy would pool the
                        // connection: the desync then shows up as a
                        // cross-exchange mix-up).
                        for chunk in split_at_heads(&response) {
                            if socket.write_all(chunk).await.is_err() {
                                return;
                            }
                            tokio::time::sleep(Duration::from_millis(30)).await;
                        }
                    } else if socket.write_all(&response).await.is_err() {
                        return;
                    }
                    if head.contains("close") {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// Splits a scripted response into chunks at each `\r\n\r\n` head end.
fn split_at_heads(response: &[u8]) -> Vec<&[u8]> {
    let mut chunks = Vec::new();
    let mut start = 0;
    for (pos, window) in response.windows(4).enumerate() {
        if window == b"\r\n\r\n" {
            let end = pos + 4;
            chunks.push(&response[start..end]);
            start = end;
        }
    }
    if start < response.len() {
        chunks.push(&response[start..]);
    }
    chunks
}

/// Backend that accepts and never answers (for response-head timeout).
async fn start_silent_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind silent");
    let addr = listener.local_addr().expect("addr silent");
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    addr
}

fn http_listener_cfg(
    listen: SocketAddr,
    server: SocketAddr,
    client_header_timeout: Duration,
    server_header_timeout: Duration,
) -> ResolvedListener {
    ResolvedListener::new(
        "web",
        listen,
        "api",
        server,
        ProxyMode::Http,
        64,
        Duration::from_secs(2),
        Duration::from_secs(5),
        client_header_timeout,
        server_header_timeout,
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

/// Reads a full response (up to the end of head), tolerating short TCP
/// reads: a single `read()` does not guarantee a whole response. Fixture
/// responses to GET are `Content-Length: 0`, so end of head is also end
/// of message.
async fn read_one_response(client: &mut TcpStream) -> String {
    let mut acc = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        let n = tokio::time::timeout(WAIT, client.read(&mut buf))
            .await
            .expect("response in time")
            .expect("read");
        assert!(n > 0, "EOF before a full response: {acc:?}");
        acc.extend_from_slice(&buf[..n]);
        if acc.windows(4).any(|w| w == b"\r\n\r\n") {
            return String::from_utf8_lossy(&acc).into_owned();
        }
    }
}

/// Reads one complete message head (through `\r\n\r\n`), returning the
/// exact head bytes and anything read past the terminator.
async fn read_head_exact(client: &mut TcpStream) -> (String, Vec<u8>) {
    let mut acc = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        let n = tokio::time::timeout(WAIT, client.read(&mut buf))
            .await
            .expect("head in time")
            .expect("read head");
        assert!(n > 0, "EOF before a complete head: {acc:?}");
        acc.extend_from_slice(&buf[..n]);
        if let Some(pos) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&acc[..pos + 4]).into_owned();
            let rest = acc[pos + 4..].to_vec();
            return (head, rest);
        }
    }
}

/// Reads `len` body bytes, consuming `carry` first (short TCP reads).
/// Returns the body plus anything read past it: at a message boundary the
/// extra must be empty (a non-empty extra means bytes leaked downstream).
async fn read_body_bytes(
    client: &mut TcpStream,
    mut carry: Vec<u8>,
    len: usize,
) -> (String, Vec<u8>) {
    let mut buf = [0u8; 256];
    while carry.len() < len {
        let n = tokio::time::timeout(WAIT, client.read(&mut buf))
            .await
            .expect("body in time")
            .expect("read body");
        assert!(n > 0, "EOF before the response body was complete");
        carry.extend_from_slice(&buf[..n]);
    }
    let extra = carry.split_off(len);
    (String::from_utf8_lossy(&carry).into_owned(), extra)
}

async fn send_and_read(addr: SocketAddr, request: &[u8]) -> String {
    let mut client = tokio::time::timeout(WAIT, TcpStream::connect(addr))
        .await
        .expect("connect in time")
        .expect("connect al proxy");
    client.write_all(request).await.expect("write request");
    client.shutdown().await.expect("half-close");
    let mut response = Vec::new();
    tokio::time::timeout(WAIT, client.read_to_end(&mut response))
        .await
        .expect("response in time")
        .expect("read response");
    String::from_utf8_lossy(&response).into_owned()
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http1_get_roundtrip_and_keepalive() {
    let backend = start_http_backend().await;
    let metrics = Arc::new(Metrics::default());
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
    let get = b"GET /x HTTP/1.1\r\nHost: t\r\n\r\n";
    client.write_all(get).await.expect("write");
    let first = read_one_response(&mut client).await;
    assert!(first.starts_with("HTTP/1.1 200 OK"), "respuesta: {first:?}");

    // Keep-alive: second request over the SAME client connection.
    client.write_all(get).await.expect("write 2");
    let second = read_one_response(&mut client).await;
    assert!(
        second.starts_with("HTTP/1.1 200 OK"),
        "response 2: {second:?} metrics={:?}",
        metrics.snapshot()
    );

    drop(client);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(metrics.snapshot().http_requests_proxied, 2);
    assert_eq!(metrics.snapshot().http_requests_rejected, 0);

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
async fn http1_post_body_streams_end_to_end() {
    let backend = start_http_backend().await;
    let metrics = Arc::new(Metrics::default());
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let body = "test body with bytes";
    let request = format!(
        "POST /x HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let response = send_and_read(proxy_addr, request.as_bytes()).await;
    assert!(
        response.ends_with(body),
        "the body must forward byte for byte: {response}"
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    let snap = metrics.snapshot();
    assert_eq!(snap.http_requests_proxied, 1);
    assert!(snap.bytes_client_to_backend > 0);
    assert!(snap.bytes_backend_to_client > 0);

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
async fn http1_chunked_body_streams_end_to_end() {
    let backend = start_http_backend().await;
    let metrics = Arc::new(Metrics::default());
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let request = b"POST /x HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\nhello!\r\n0\r\n\r\n";
    let response = send_and_read(proxy_addr, request).await;
    assert!(response.contains("hello!"), "chunked echo: {response}");

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
async fn http1_smuggling_corpus_is_rejected_before_backend() {
    let backend = start_http_backend().await;
    let metrics = Arc::new(Metrics::default());
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    // T01–T02 corpus: each case must get 400/431/505 and never reach
    // the backend as a processable request.
    let corpus: &[&[u8]] = &[
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n",
        b"GET / HTTP/1.1\r\nFoo : x\r\nHost: y\r\n\r\n",
        b"GET / HTTP/1.1\r\n Host: x\r\n\r\n",
        b"GET http://evil/ HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET / HTTP/2.0\r\nHost: x\r\n\r\n",
    ];
    for request in corpus {
        let response = send_and_read(proxy_addr, request).await;
        assert!(
            response.starts_with("HTTP/1.1 4") || response.starts_with("HTTP/1.1 5"),
            "must be rejected, not served: {}",
            String::from_utf8_lossy(request)
        );
        assert!(
            !response.contains("200 OK"),
            "never200 for: {}",
            String::from_utf8_lossy(request)
        );
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        metrics.snapshot().http_requests_rejected as usize,
        corpus.len(),
        "every rejection counts"
    );
    assert_eq!(metrics.snapshot().http_requests_proxied, 0);

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve finishes")
        .expect("serve task without panic");
}

/// Backend that answers the handshake with `status_line` (e.g. "101
/// Switching Protocols" or "200 Connection established") and then
/// echoes every raw byte it receives (A7/A8 tunnel shape).
async fn start_switch_echo_backend(status_line: &'static str) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind switch backend");
    let addr = listener.local_addr().expect("addr switch backend");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                // Reads the request head (the tests never send bodies).
                let mut buf = vec![0u8; 8192];
                let mut total = 0usize;
                loop {
                    match socket.read(&mut buf[total..]).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => total += n,
                    }
                    if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    if total == buf.len() {
                        return;
                    }
                }
                let response = format!(
                    "HTTP/1.1 {status_line}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                );
                if socket.write_all(response.as_bytes()).await.is_err() {
                    return;
                }
                // Echo tunnel: every byte back.
                let mut buf = [0u8; 1024];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if socket.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// Reads from `socket` until the head terminator, returning the head and
/// any bytes read past it.
async fn read_head_until_blank(socket: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
    use tokio::io::AsyncReadExt;
    let mut collected: Vec<u8> = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        let n = tokio::time::timeout(WAIT, socket.read(&mut buf))
            .await
            .expect("head timeout")
            .expect("head read");
        assert!(n > 0, "EOF before the head terminator");
        collected.extend_from_slice(&buf[..n]);
        if let Some(end) = collected.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&collected[..end + 4]).into_owned();
            let rest = collected[end + 4..].to_vec();
            return (head, rest);
        }
    }
}

/// A7: an upgrade handshake (WebSocket shape) is forwarded and on `101`
/// the exchange becomes a raw bidirectional tunnel — bytes flow both
/// ways until close. The connection is consumed: never pooled.
#[tokio::test]
async fn upgrade_handshake_opens_a_bidirectional_tunnel() {
    let backend = start_switch_echo_backend("101 Switching Protocols").await;
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    let metrics = Arc::new(Metrics::default());
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let mut socket = tokio::time::timeout(WAIT, tokio::net::TcpStream::connect(proxy_addr))
        .await
        .expect("connect timeout")
        .expect("proxy up");
    {
        use tokio::io::AsyncWriteExt;
        socket
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            )
            .await
            .expect("handshake write");
    }
    let (head, rest) = read_head_until_blank(&mut socket).await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert!(head.to_lowercase().contains("upgrade: websocket"), "{head}");
    assert!(rest.is_empty(), "nothing tunneled yet: {rest:?}");

    // Tunnel: raw bytes to the backend and back.
    {
        use tokio::io::AsyncWriteExt;
        socket
            .write_all(b"ping-tunnel-bytes")
            .await
            .expect("tunnel write");
    }
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(WAIT, socket.read(&mut buf))
        .await
        .expect("echo timeout")
        .expect("echo read");
    assert_eq!(
        &buf[..n],
        b"ping-tunnel-bytes",
        "the tunnel echoes both ways"
    );

    drop(socket);
    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve finishes")
        .expect("serve task without panic");
}

/// A8: CONNECT routes on its authority host and on backend `2xx` becomes
/// the same raw bidirectional tunnel.
#[tokio::test]
async fn connect_opens_a_raw_tunnel_on_2xx() {
    let backend = start_switch_echo_backend("200 Connection established").await;
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    let metrics = Arc::new(Metrics::default());
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let mut socket = tokio::time::timeout(WAIT, tokio::net::TcpStream::connect(proxy_addr))
        .await
        .expect("connect timeout")
        .expect("proxy up");
    {
        use tokio::io::AsyncWriteExt;
        socket
            .write_all(b"CONNECT target:443 HTTP/1.1\r\nHost: target:443\r\n\r\n")
            .await
            .expect("connect write");
    }
    let (head, _) = read_head_until_blank(&mut socket).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    // Tunnel: a TLS-client-hello shape flows both ways.
    {
        use tokio::io::AsyncWriteExt;
        socket
            .write_all(b"tunneled-payload")
            .await
            .expect("tunnel write");
    }
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(WAIT, socket.read(&mut buf))
        .await
        .expect("echo timeout")
        .expect("echo read");
    assert_eq!(
        &buf[..n],
        b"tunneled-payload",
        "the tunnel echoes both ways"
    );

    drop(socket);
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
async fn http1_client_header_timeout_returns_408_and_counts() {
    let backend = start_http_backend().await;
    let metrics = Arc::new(Metrics::default());
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_millis(150),
        Duration::from_secs(5),
    );
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    // Incomplete request head: the phase timeout must fire.
    let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: t\r\n")
        .await
        .expect("write");
    let mut buf = vec![0u8; 128];
    let n = tokio::time::timeout(WAIT, client.read(&mut buf))
        .await
        .expect("408 in time")
        .expect("read");
    let response = String::from_utf8_lossy(&buf[..n]).into_owned();
    assert!(
        response.starts_with("HTTP/1.1 408"),
        "respuesta: {response}"
    );
    assert_eq!(metrics.snapshot().header_timeouts, 1);

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
async fn http1_server_header_timeout_returns_504() {
    let backend = start_silent_backend().await;
    let metrics = Arc::new(Metrics::default());
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_secs(5),
        Duration::from_millis(200),
    );
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let response = send_and_read(
        proxy_addr,
        b"GET /x HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        response.starts_with("HTTP/1.1 504"),
        "respuesta: {response}"
    );
    assert_eq!(metrics.snapshot().header_timeouts, 1);

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
async fn http1_max_stream_duration_cuts_the_exchange_with_504() {
    // B-H11/B-E12: the total exchange cap fires even while every
    // per-phase timeout would still wait (duration ≠ inactivity, Q5).
    let backend = start_silent_backend().await;
    let metrics = Arc::new(Metrics::default());
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_secs(5),
        Duration::from_secs(30),
    )
    .with_max_stream_duration(Duration::from_millis(200));
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let start = std::time::Instant::now();
    let response = send_and_read(
        proxy_addr,
        b"GET /x HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        response.starts_with("HTTP/1.1 504"),
        "respuesta: {response}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "the cap must fire before the phase timeouts: {:?}",
        start.elapsed()
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
async fn http1_client_abort_cancels_upstream_promptly() {
    // A19: the mid-body client abort must cancel the upstream
    // instantly (the backend sees the close), without waiting for the idle timeout (10s).
    let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let backend = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept backend");
        let mut buf = vec![0u8; 4096];
        // Reads the head and part of the body; the premature close is the cancel.
        let _ = socket.read(&mut buf).await;
        let _ = socket.read(&mut buf).await;
        let mut tx = Some(closed_tx);
        loop {
            match socket.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    if let Some(tx) = tx.take() {
                        let _ = tx.send(());
                    }
                    return;
                }
                Ok(_) => {}
            }
        }
    });

    let metrics = Arc::new(Metrics::default());
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    // high idle: the close cannot come from the timeout, it must be the abort.
    let mut cfg = cfg;
    cfg.idle_timeout = Duration::from_secs(10);
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
    let head = b"POST /x HTTP/1.1\r\nHost: t\r\nContent-Length: 100\r\n\r\n";
    client.write_all(head).await.expect("write head");
    client
        .write_all(&[0xAB; 10])
        .await
        .expect("partial body write");
    drop(client); // mid-body abort

    // The backend must observe the upstream connection close promptly.
    tokio::time::timeout(Duration::from_secs(2), closed_rx)
        .await
        .expect("the client abort must cancel the upstream immediately")
        .expect("backend close signal");

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        metrics.snapshot().connections_active,
        0,
        "no task leaks after the abort"
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
async fn http1_response_without_framing_is_eof_delimited() {
    // HTTP/1.0-style backend: response without Content-Length → body until EOF.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let backend = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nuntil-eof")
                .await;
        }
    });

    let metrics = Arc::new(Metrics::default());
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let response = send_and_read(proxy_addr, b"GET /x HTTP/1.1\r\nHost: t\r\n\r\n").await;
    assert!(response.contains("until-eof"), "response: {response}");

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
async fn expect_100_continue_releases_client_and_streams_body() {
    let backend = start_http_backend().await;
    let metrics = Arc::new(Metrics::default());
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
    let body = "hello";
    let head = format!(
        "POST /x HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\nExpect: 100-continue\r\n\r\n",
        body.len()
    );
    client.write_all(head.as_bytes()).await.expect("write head");

    // The real interim response releases the client: without it the client
    // waits forever and the body never flows (deadlock by timeout).
    let (interim, _) = read_head_exact(&mut client).await;
    assert_eq!(
        interim, "HTTP/1.1 100 Continue\r\n\r\n",
        "the client must receive the interim response before sending the body"
    );

    client.write_all(body.as_bytes()).await.expect("write body");
    let (final_head, carry) = read_head_exact(&mut client).await;
    assert!(
        final_head.starts_with("HTTP/1.1 200 OK"),
        "final response: {final_head:?}"
    );
    let (echoed, extra) = read_body_bytes(&mut client, carry, body.len()).await;
    assert_eq!(
        echoed, body,
        "the body must reach the backend byte for byte"
    );
    assert!(extra.is_empty(), "nothing past the body: {extra:?}");

    drop(client);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(metrics.snapshot().http_requests_proxied, 1);
    assert_eq!(metrics.snapshot().http_requests_rejected, 0);

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
async fn interim_1xx_is_forwarded_and_never_desyncs_keepalive() {
    let backend = start_scripted_backend(
        vec![
            // Interim then final: the interim must never be mistaken for
            // the final response, or the 200 stays queued for the next
            // exchange.
            b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                .to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nbye".to_vec(),
        ],
        true,
    )
    .await;
    let metrics = Arc::new(Metrics::default());
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
    let get = b"GET /x HTTP/1.1\r\nHost: t\r\n\r\n";

    // Exchange 1: interim forwarded first, then the real final response.
    client.write_all(get).await.expect("write 1");
    let (interim, _) = read_head_exact(&mut client).await;
    assert_eq!(
        interim,
        "HTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\n"
    );
    let (final_head, carry) = read_head_exact(&mut client).await;
    assert!(
        final_head.starts_with("HTTP/1.1 200 OK"),
        "final head: {final_head:?}"
    );
    let (body, extra) = read_body_bytes(&mut client, carry, 2).await;
    assert_eq!(body, "ok");
    assert!(extra.is_empty(), "nothing past the body: {extra:?}");

    // Exchange 2 on the SAME client connection: it must get its own
    // response — not the stale one left over from the interim handling.
    client.write_all(get).await.expect("write 2");
    let (second_head, carry) = read_head_exact(&mut client).await;
    assert!(
        second_head.starts_with("HTTP/1.1 200 OK"),
        "second head: {second_head:?}"
    );
    let (body, extra) = read_body_bytes(&mut client, carry, 3).await;
    assert_eq!(
        body, "bye",
        "the second exchange must never receive the first response (desync)"
    );
    assert!(extra.is_empty(), "nothing past the body: {extra:?}");

    drop(client);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(metrics.snapshot().http_requests_proxied, 2);

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
async fn backend_redundant_100_is_consumed_exactly_once() {
    // The backend answers with its own `100 Continue` before the final
    // response. Since the proxy already released the client with its own
    // interim, the backend's must be consumed, never duplicated downstream.
    let backend = start_scripted_backend(
        vec![
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nxyz"
                .to_vec(),
        ],
        true,
    )
    .await;
    let metrics = Arc::new(Metrics::default());
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
    let head = "POST /x HTTP/1.1\r\nHost: t\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n";
    client.write_all(head.as_bytes()).await.expect("write head");

    let (interim, _) = read_head_exact(&mut client).await;
    assert_eq!(interim, "HTTP/1.1 100 Continue\r\n\r\n");
    client.write_all(b"xyz").await.expect("write body");

    // Exactly one interim: the next head must be the final response.
    let (final_head, carry) = read_head_exact(&mut client).await;
    assert!(
        final_head.starts_with("HTTP/1.1 200 OK"),
        "the backend's redundant 100 must be consumed, not forwarded: {final_head:?}"
    );
    let (body, extra) = read_body_bytes(&mut client, carry, 3).await;
    assert_eq!(body, "xyz");
    assert!(extra.is_empty(), "nothing past the body: {extra:?}");

    drop(client);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(metrics.snapshot().http_requests_proxied, 1);

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
async fn unsupported_expectation_is_rejected_with_417() {
    let backend = start_http_backend().await;
    let metrics = Arc::new(Metrics::default());
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let response = send_and_read(
        proxy_addr,
        b"GET /x HTTP/1.1\r\nHost: t\r\nExpect: the-unexpected\r\n\r\n",
    )
    .await;
    assert!(
        response.starts_with("HTTP/1.1 417"),
        "unsupported expectations must be refused explicitly: {response}"
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(metrics.snapshot().http_requests_rejected, 1);

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
async fn oversent_backend_bytes_are_never_forwarded_or_pooled() {
    // The backend sends bytes past the end of the declared body ("XX"
    // after `Content-Length: 2`). They must never reach the client, and
    // the connection must be dropped instead of pooled (A16 contract: a
    // pooled connection is byte-aligned at a message boundary). If it were
    // pooled, the second exchange could consume the stale "XX" and desync.
    let backend = start_scripted_backend(
        vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokXX".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nbye".to_vec(),
        ],
        false,
    )
    .await;
    let metrics = Arc::new(Metrics::default());
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
    let get = b"GET /x HTTP/1.1\r\nHost: t\r\n\r\n";

    client.write_all(get).await.expect("write 1");
    let (head, carry) = read_head_exact(&mut client).await;
    assert!(head.starts_with("HTTP/1.1 200 OK"), "head: {head:?}");
    let (body, extra) = read_body_bytes(&mut client, carry, 2).await;
    assert_eq!(body, "ok");
    assert!(
        extra.is_empty(),
        "bytes past the body must never be forwarded to the client: {extra:?}"
    );

    // The second exchange must get a clean, freshly-dialed connection and
    // its own response byte for byte.
    client.write_all(get).await.expect("write 2");
    let (head2, carry2) = read_head_exact(&mut client).await;
    assert!(head2.starts_with("HTTP/1.1 200 OK"), "head 2: {head2:?}");
    let (body2, extra2) = read_body_bytes(&mut client, carry2, 3).await;
    assert_eq!(body2, "bye");
    assert!(extra2.is_empty(), "nothing past body 2: {extra2:?}");

    drop(client);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let snap = metrics.snapshot();
    assert_eq!(
        snap.backend_connections_opened, 2,
        "the polluted connection must be dropped and a new one dialed (never reused)"
    );
    assert_eq!(
        snap.backend_connections_reused, 0,
        "a connection holding bytes past the message must never return to the pool"
    );
    assert_eq!(
        snap.backend_connections_discarded, 1,
        "the drop must be counted exactly once so operators can alert on it (the clean second exchange must not count)"
    );

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve finishes")
        .expect("serve task without panic");
}
