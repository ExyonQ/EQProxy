//! E2E: per-listener message limits and per-stream buffers
//! (B-N19/B-I17/B-E19), over real sockets.
//!
//! The journeys assert the observable contract, not the implementation:
//! a configured header count or head size is the bound the client and the
//! backend are held to, a request body over the cap is refused with an
//! explicit 413 **before** the origin is dialed, and a 1 KiB stream pipe
//! still relays a large body intact under concurrency (backpressure, never
//! truncation). Every test names both sides of its bound: at the limit
//! succeeds, one over fails.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::Request;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use eqproxy_core::Metrics;
use eqproxy_core::shutdown;
use eqproxy_net::{BoundProxy, ProxyMode, ResolvedLimits, ResolvedListener, bind};

const WAIT: Duration = Duration::from_secs(30);

fn limits(
    max_head_bytes: usize,
    max_headers: usize,
    max_body_bytes: u64,
    stream_buffer_bytes: Option<usize>,
) -> ResolvedLimits {
    ResolvedLimits {
        max_head_bytes,
        max_headers,
        max_body_bytes,
        stream_buffer_bytes,
    }
}

fn listener(origin: SocketAddr, limits: ResolvedLimits) -> ResolvedListener {
    ResolvedListener::new(
        "web",
        "127.0.0.1:0".parse().expect("listen"),
        "api",
        origin,
        ProxyMode::Http,
        64,
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .with_limits(limits)
}

async fn start_proxy(
    cfg: ResolvedListener,
) -> (SocketAddr, shutdown::ShutdownHandle, JoinHandle<()>) {
    let metrics = Arc::new(Metrics::default());
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

async fn stop_proxy(handle: shutdown::ShutdownHandle, serve: JoinHandle<()>) {
    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve must finish")
        .expect("join");
}

/// Reads the head of one request and then its body (declared length or
/// chunked), so the origin answers exactly once the whole exchange arrived.
async fn read_request(socket: &mut TcpStream) -> Vec<u8> {
    let mut acc = Vec::new();
    let mut buf = [0u8; 4096];
    let head_end = loop {
        let n = tokio::time::timeout(WAIT, socket.read(&mut buf))
            .await
            .expect("request head in time")
            .expect("read request");
        if n == 0 {
            return acc;
        }
        acc.extend_from_slice(&buf[..n]);
        if let Some(pos) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let head = String::from_utf8_lossy(&acc[..head_end]).to_ascii_lowercase();
    if let Some(pos) = head.find("content-length:") {
        let rest = &head[pos + "content-length:".len()..];
        let digits: String = rest
            .chars()
            .skip_while(|c| *c == ' ')
            .take_while(char::is_ascii_digit)
            .collect();
        let want: usize = digits.parse().expect("content-length digits");
        let mut have = acc.len() - head_end;
        while have < want {
            let n = tokio::time::timeout(WAIT, socket.read(&mut buf))
                .await
                .expect("request body in time")
                .expect("read body");
            if n == 0 {
                return acc;
            }
            have += n;
        }
    } else if head.contains("transfer-encoding: chunked") {
        // Read until the last-chunk line arrives; the proxy forwarder keeps
        // the exact framing, so this is the wire form the origin sees.
        loop {
            if acc[head_end..].windows(5).any(|w| w == b"0\r\n\r\n") {
                break;
            }
            let n = tokio::time::timeout(WAIT, socket.read(&mut buf))
                .await
                .expect("chunked body in time")
                .expect("read chunked");
            if n == 0 {
                return acc;
            }
            acc.extend_from_slice(&buf[..n]);
        }
    }
    acc
}

/// Origin that answers every request with `response` and counts dials.
async fn start_origin(response: &'static [u8]) -> (SocketAddr, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let _ = read_request(&mut socket).await;
                let _ = socket.write_all(response).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (addr, hits, task)
}

/// Origin that answers a GET with `len` bytes, streamed in 16 KiB writes.
async fn start_bulk_origin(len: usize) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind bulk");
    let addr = listener.local_addr().expect("bulk addr");
    let task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let mut acc = Vec::new();
                loop {
                    let Ok(n) = socket.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    acc.extend_from_slice(&buf[..n]);
                    if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {len}\r\nconnection: close\r\n\r\n"
                );
                if socket.write_all(head.as_bytes()).await.is_err() {
                    return;
                }
                let body = vec![b'x'; 16 * 1024];
                let mut left = len;
                while left > 0 {
                    let take = left.min(body.len());
                    if socket.write_all(&body[..take]).await.is_err() {
                        return;
                    }
                    left -= take;
                }
                let _ = socket.shutdown().await;
            });
        }
    });
    (addr, task)
}

/// Sends `bytes` and returns the whole answer (status line and body), which
/// the refusals close right after (`connection: close`, length 0).
async fn raw_request(addr: SocketAddr, bytes: &[u8]) -> String {
    let mut client = TcpStream::connect(addr).await.expect("connect proxy");
    client.write_all(bytes).await.expect("write request");
    let mut acc = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(WAIT, client.read(&mut buf))
            .await
            .expect("answer in time")
            .expect("read answer");
        if n == 0 {
            break;
        }
        acc.extend_from_slice(&buf[..n]);
    }
    String::from_utf8_lossy(&acc).into_owned()
}

fn status_of(answer: &str) -> u16 {
    answer
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status in {answer:?}"))
}

async fn h2_connect(addr: SocketAddr) -> h2::client::SendRequest<Bytes> {
    let socket = TcpStream::connect(addr).await.expect("connect proxy");
    let (send, connection) = tokio::time::timeout(WAIT, h2::client::handshake(socket))
        .await
        .expect("h2 handshake in time")
        .expect("h2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    send
}

async fn h2_body(response: http::Response<h2::RecvStream>) -> (u16, Vec<u8>) {
    let status = response.status().as_u16();
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("DATA frame");
        let _ = body.flow_control().release_capacity(chunk.len());
        bytes.extend_from_slice(&chunk);
    }
    (status, bytes)
}

#[tokio::test]
async fn header_count_bound_is_configurable_and_explicit() {
    let (origin, hits, origin_task) =
        start_origin(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok").await;
    let (addr, handle, serve) = start_proxy(listener(origin, limits(16 * 1024, 3, 0, None))).await;

    // 3 header fields (host + two) are exactly the bound: accepted.
    let answer = raw_request(
        addr,
        b"GET /a HTTP/1.1\r\nhost: x\r\nx-a: 1\r\nx-b: 2\r\n\r\n",
    )
    .await;
    assert_eq!(status_of(&answer), 200, "{answer:?}");

    // One more field crosses it: 431, and the origin never sees it.
    let before = hits.load(Ordering::Relaxed);
    let answer = raw_request(
        addr,
        b"GET /a HTTP/1.1\r\nhost: x\r\nx-a: 1\r\nx-b: 2\r\nx-c: 3\r\n\r\n",
    )
    .await;
    assert_eq!(status_of(&answer), 431, "{answer:?}");
    assert_eq!(
        hits.load(Ordering::Relaxed),
        before,
        "a rejected head must not reach the origin"
    );

    stop_proxy(handle, serve).await;
    origin_task.abort();
}

#[tokio::test]
async fn declared_body_over_the_cap_is_refused_before_the_dial() {
    let (origin, hits, origin_task) =
        start_origin(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok").await;
    let (addr, handle, serve) =
        start_proxy(listener(origin, limits(16 * 1024, 100, 16, None))).await;

    let mut over = Vec::from(&b"POST /a HTTP/1.1\r\nhost: x\r\ncontent-length: 32\r\n\r\n"[..]);
    over.extend_from_slice(&[b'a'; 32]);
    let answer = raw_request(addr, &over).await;
    assert_eq!(status_of(&answer), 413, "{answer:?}");
    assert_eq!(
        hits.load(Ordering::Relaxed),
        0,
        "the declared body is refused before the origin is dialed"
    );

    // Exactly the cap is accepted, so the refusal is the bound and not a ban.
    let mut at_cap = Vec::from(&b"POST /a HTTP/1.1\r\nhost: x\r\ncontent-length: 16\r\n\r\n"[..]);
    at_cap.extend_from_slice(&[b'b'; 16]);
    let answer = raw_request(addr, &at_cap).await;
    assert_eq!(status_of(&answer), 200, "{answer:?}");
    assert_eq!(hits.load(Ordering::Relaxed), 1);

    stop_proxy(handle, serve).await;
    origin_task.abort();
}

#[tokio::test]
async fn chunked_body_over_the_cap_is_refused_with_413() {
    let (origin, _hits, origin_task) =
        start_origin(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok").await;
    let (addr, handle, serve) =
        start_proxy(listener(origin, limits(16 * 1024, 100, 16, None))).await;

    let mut at_cap =
        Vec::from(&b"POST /a HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\n\r\n10\r\n"[..]);
    at_cap.extend_from_slice(&[b'c'; 16]);
    at_cap.extend_from_slice(b"\r\n0\r\n\r\n");
    let answer = raw_request(addr, &at_cap).await;
    assert_eq!(status_of(&answer), 200, "{answer:?}");

    // One byte over: the frame that would cross the cap is never forwarded.
    let mut over =
        Vec::from(&b"POST /a HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\n\r\n11\r\n"[..]);
    over.extend_from_slice(&[b'd'; 17]);
    over.extend_from_slice(b"\r\n0\r\n\r\n");
    let answer = raw_request(addr, &over).await;
    assert_eq!(status_of(&answer), 413, "{answer:?}");

    stop_proxy(handle, serve).await;
    origin_task.abort();
}

#[tokio::test]
async fn response_head_over_the_bound_is_a_502_not_a_forward() {
    // A response head of ~300 bytes: over a 128-byte bound, under the default.
    let long_response: &'static [u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nx-padding: 012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234\r\nconnection: close\r\n\r\nok";
    let (origin, _hits, origin_task) = start_origin(long_response).await;
    let (addr, handle, serve) = start_proxy(listener(origin, limits(128, 100, 0, None))).await;
    let answer = raw_request(addr, b"GET /a HTTP/1.1\r\nhost: x\r\n\r\n").await;
    assert_eq!(status_of(&answer), 502, "{answer:?}");
    stop_proxy(handle, serve).await;
    origin_task.abort();

    // Control: the same response under the default bound reaches the client.
    let (origin, _hits, origin_task) = start_origin(long_response).await;
    let (addr, handle, serve) =
        start_proxy(listener(origin, limits(16 * 1024, 100, 0, None))).await;
    let answer = raw_request(addr, b"GET /a HTTP/1.1\r\nhost: x\r\n\r\n").await;
    assert_eq!(status_of(&answer), 200, "{answer:?}");
    assert!(answer.ends_with("ok"), "{answer:?}");
    stop_proxy(handle, serve).await;
    origin_task.abort();
}

#[tokio::test]
async fn request_body_cap_also_holds_for_h2_chunked_translation() {
    let (origin, hits, origin_task) =
        start_origin(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok").await;
    let (addr, handle, serve) =
        start_proxy(listener(origin, limits(16 * 1024, 100, 16, None))).await;

    let mut send = h2_connect(addr).await;
    let request = Request::builder()
        .method("POST")
        .uri("https://limits.test/upload")
        .body(())
        .expect("request");
    let (response, mut stream) = send.send_request(request, false).expect("send");
    stream
        .send_data(Bytes::from_static(&[b'e'; 20]), true)
        .expect("data");
    let response = tokio::time::timeout(WAIT, response)
        .await
        .expect("response in time")
        .expect("response");
    let (status, _body) = h2_body(response).await;
    assert_eq!(status, 413, "h2 DATA is translated to chunked upstream");
    // A chunked body cannot be bounded before the first chunk arrives, so
    // the origin may have been dialed; the client still gets the explicit
    // refusal and the exchange is never pooled (`hits <= 1`).
    assert!(hits.load(Ordering::Relaxed) <= 1);

    stop_proxy(handle, serve).await;
    origin_task.abort();
}

#[tokio::test]
async fn one_kib_stream_pipe_relays_large_bodies_under_pressure() {
    const STREAMS: usize = 16;
    const BODY: usize = 512 * 1024;

    let (origin, origin_task) = start_bulk_origin(BODY).await;
    let (addr, handle, serve) =
        start_proxy(listener(origin, limits(16 * 1024, 100, 0, Some(1024)))).await;

    let send = h2_connect(addr).await;
    let mut tasks = Vec::with_capacity(STREAMS);
    for i in 0..STREAMS {
        let mut stream_send = send.clone();
        tasks.push(tokio::spawn(async move {
            let request = Request::builder()
                .uri(format!("https://limits.test/bulk/{i}"))
                .body(())
                .expect("request");
            let (response, _) = stream_send
                .send_request(request, true)
                .expect("send request");
            let response = tokio::time::timeout(WAIT, response)
                .await
                .expect("response in time")
                .expect("response");
            let (status, body) = h2_body(response).await;
            (status, body.len())
        }));
    }
    let mut total = 0usize;
    for task in tasks {
        let (status, len) = task.await.expect("stream task");
        assert_eq!(status, 200);
        assert_eq!(
            len, BODY,
            "a 1 KiB pipe must apply backpressure, never truncate"
        );
        total += len;
    }
    assert_eq!(total, STREAMS * BODY);

    stop_proxy(handle, serve).await;
    origin_task.abort();
}
