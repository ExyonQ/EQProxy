//! Active health checks: TCP connect (B11) and HTTP with `expect`
//! matching (B-H6/B-N11/B-I19/B-E5). One task per backend with configured
//! checks.
//!
//! Cycle: every `interval`, one attempt per server bounded by `timeout`;
//! the result feeds the `fall`/`rise` machine of
//! [`Balancer`](crate::balancer::Balancer). Passive detection (B-N10)
//! feeds the same machine from live-traffic connect results
//! (`HealthCheck::passive`).
//!
//! HTTP semantics (documented, no surprises): the check sends
//! `METHOD path HTTP/1.1` with `Host`, reads **one** response message
//! (head + body, up to [`MAX_CHECK_RESPONSE_BYTES`]) and matches the
//! status against `expect_status` and the **raw** body against
//! `expect_rstring` (chunked bodies are matched as received; `HEAD`
//! bodies are empty). The read ends at the HTTP message boundary (RFC
//! 9112 §6: `Content-Length`, chunked framing, or no body for
//! `HEAD`/1xx/204/304) — never at the origin's discretion: a keep-alive
//! origin may hold the socket open forever, and waiting for its EOF
//! would time the check out and flap a healthy server to `down`. Only
//! close-delimited bodies (no framing header) are read to EOF.

use std::sync::Arc;
use std::time::Duration;

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;

use eqproxy_core::Shutdown;
use eqproxy_core::expectation::{RegexMatcher, StatusExpectation};

use crate::balancer::Balancer;

/// Maximum bytes read from a health-check response (head + body).
pub const MAX_CHECK_RESPONSE_BYTES: usize = 64 * 1024;

/// HTTP health-check request method (B-H6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpCheckMethod {
    #[default]
    Get,
    Head,
}

/// What the HTTP check sends and expects (B-H6).
#[derive(Debug, Clone)]
pub struct HttpCheck {
    /// Request method (GET or HEAD).
    pub method: HttpCheckMethod,
    /// Request path (origin form, starts with `/`).
    pub path: String,
    /// `Host` header (default: the server address).
    pub host: Option<String>,
    /// Expected status codes/ranges (`expect status`).
    pub expect_status: StatusExpectation,
    /// Regex that must match the raw body (`expect rstring`; optional).
    pub expect_rstring: Option<RegexMatcher>,
}

/// Check kind: TCP connect only (default) or HTTP with expectations.
#[derive(Debug, Clone)]
pub enum CheckKind {
    /// TCP connect (B11).
    Tcp,
    /// HTTP request + `expect` matching (B-H6).
    Http(HttpCheck),
}

/// Parameters of a health check (B11 + B-H6).
#[derive(Debug, Clone)]
pub struct HealthCheck {
    /// Interval between check cycles.
    pub interval: Duration,
    /// Timeout of each attempt (connect + request + response).
    pub timeout: Duration,
    /// What to do per attempt.
    pub kind: CheckKind,
    /// Passive detection (B-N10): live-traffic verdicts also feed the
    /// `fall`/`rise` machine — connect-phase failures and HTTP 5xx
    /// responses count as failures, other completed exchanges as success.
    pub passive: bool,
}

impl HealthCheck {
    /// TCP connect check (B11); passive detection off.
    #[must_use]
    pub fn tcp(interval: Duration, timeout: Duration) -> Self {
        Self {
            interval,
            timeout,
            kind: CheckKind::Tcp,
            passive: false,
        }
    }

    /// Enables the HTTP check with `expect` matching (B-H6).
    #[must_use]
    pub fn with_http(mut self, http: HttpCheck) -> Self {
        self.kind = CheckKind::Http(http);
        self
    }

    /// Passive detection from live traffic (B-N10).
    #[must_use]
    pub fn with_passive(mut self, passive: bool) -> Self {
        self.passive = passive;
        self
    }
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
        for addr in balancer.resolved_servers() {
            let balancer = Arc::clone(&balancer);
            let check = check.clone();
            attempts.spawn(async move { check_one(balancer, addr, check).await });
        }
        while attempts.join_next().await.is_some() {}
    }
}

async fn check_one(balancer: Arc<Balancer>, addr: SocketAddr, check: HealthCheck) {
    let ok = match &check.kind {
        CheckKind::Tcp => tcp_ok(addr, check.timeout).await,
        CheckKind::Http(http) => http_ok(addr, http, check.timeout).await,
    };
    if ok {
        balancer.report_ok(addr);
    } else {
        balancer.report_fail(addr);
    }
}

/// TCP connect attempt (B11).
async fn tcp_ok(addr: SocketAddr, timeout: Duration) -> bool {
    matches!(
        tokio::time::timeout(timeout, TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

/// HTTP attempt with `expect` matching (B-H6): one real exchange.
pub async fn http_ok(addr: SocketAddr, http: &HttpCheck, timeout: Duration) -> bool {
    tokio::time::timeout(timeout, http_exchange(addr, http))
        .await
        .unwrap_or_default()
}

async fn http_exchange(addr: SocketAddr, http: &HttpCheck) -> bool {
    let Ok(mut stream) = TcpStream::connect(addr).await else {
        return false;
    };
    let host = http.host.clone().unwrap_or_else(|| addr.to_string());
    let method = match http.method {
        HttpCheckMethod::Get => "GET",
        HttpCheckMethod::Head => "HEAD",
    };
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: eqproxy-health/0.5\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        path = http.path,
    );
    if stream.write_all(request.as_bytes()).await.is_err() {
        return false;
    }

    // Read exactly one response message. The head first (a check never
    // matches a partial head), then the body per its framing — the check
    // must complete at the message boundary (RFC 9112 §6) and never wait
    // for the origin to close the socket.
    let mut raw: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0_u8; 2048];
    let head_end = loop {
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if !read_more(&mut raw, &mut stream, &mut chunk).await {
            return false; // EOF or budget before a complete head
        }
    };
    let Some(framing) = body_framing(http.method, &raw[..head_end]) else {
        return false; // malformed status line or headers
    };
    match framing {
        // HEAD and 1xx/204/304 carry no body (RFC 9112 §6.3-6.4),
        // whatever `Content-Length` announces.
        BodyFraming::NoBody => {}
        BodyFraming::ContentLength(want) => {
            // Truncate at the budget: matching sees at most the first
            // MAX_CHECK_RESPONSE_BYTES of the response (as before).
            let end = head_end + want.min(MAX_CHECK_RESPONSE_BYTES.saturating_sub(raw.len()));
            while raw.len() < end && read_more(&mut raw, &mut stream, &mut chunk).await {}
        }
        BodyFraming::Chunked => {
            let mut pos = head_end;
            loop {
                // Chunk-size line: `hex[;ext] CRLF`.
                let line_end = loop {
                    if let Some(i) = raw[pos..].windows(2).position(|w| w == b"\r\n") {
                        break Some(pos + i);
                    }
                    if !read_more(&mut raw, &mut stream, &mut chunk).await {
                        break None;
                    }
                };
                let Some(line_end) = line_end else {
                    break; // EOF or budget mid-framing: match truncated
                };
                let size = String::from_utf8_lossy(&raw[pos..line_end]);
                let Ok(size) =
                    usize::from_str_radix(size.split(';').next().unwrap_or("").trim(), 16)
                else {
                    break; // malformed chunked framing: match truncated
                };
                pos = line_end + 2;
                if size == 0 {
                    break; // terminal chunk: the body ends here
                }
                // Chunk data + its trailing CRLF.
                pos = pos.saturating_add(size).saturating_add(2);
                while raw.len() < pos && read_more(&mut raw, &mut stream, &mut chunk).await {}
                if raw.len() < pos {
                    break; // EOF or budget mid-chunk: match truncated
                }
            }
        }
        // Close-delimited body (no framing header): EOF is the only
        // boundary the protocol offers.
        BodyFraming::UntilEof => while read_more(&mut raw, &mut stream, &mut chunk).await {},
    }
    matches_response(http, &raw)
}

/// How the response body is delimited (RFC 9112 §6).
enum BodyFraming {
    /// `HEAD` or 1xx/204/304: no body regardless of the headers.
    NoBody,
    /// `Content-Length: n` — exactly `n` bytes.
    ContentLength(usize),
    /// `Transfer-Encoding: chunked` — through the terminal chunk.
    Chunked,
    /// No framing header: close-delimited (read to EOF).
    UntilEof,
}

/// Body framing of a response head; `None` = malformed status/headers.
fn body_framing(method: HttpCheckMethod, head: &[u8]) -> Option<BodyFraming> {
    let head = String::from_utf8_lossy(head);
    let status = head
        .split("\r\n")
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse::<u16>()
        .ok()?;
    if matches!(method, HttpCheckMethod::Head)
        || (100..200).contains(&status)
        || status == 204
        || status == 304
    {
        return Some(BodyFraming::NoBody);
    }
    let mut content_length = None;
    let mut chunked = false;
    for line in head.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-length" => content_length = Some(value.parse::<usize>().ok()?),
            // Transfer-Encoding wins over Content-Length (RFC 9112 §6.1).
            "transfer-encoding" => {
                chunked |= value
                    .to_ascii_lowercase()
                    .split(',')
                    .any(|token| token.trim() == "chunked");
            }
            _ => {}
        }
    }
    Some(if chunked {
        BodyFraming::Chunked
    } else if let Some(n) = content_length {
        BodyFraming::ContentLength(n)
    } else {
        BodyFraming::UntilEof
    })
}

/// Reads one more socket chunk into `raw`, bounded by
/// [`MAX_CHECK_RESPONSE_BYTES`]. `false` = EOF, socket error or budget
/// exhausted (the response is then matched truncated).
async fn read_more(raw: &mut Vec<u8>, stream: &mut TcpStream, chunk: &mut [u8]) -> bool {
    if raw.len() >= MAX_CHECK_RESPONSE_BYTES {
        return false;
    }
    match stream.read(chunk).await {
        Ok(0) | Err(_) => false,
        Ok(n) => {
            let n = n.min(MAX_CHECK_RESPONSE_BYTES - raw.len());
            raw.extend_from_slice(&chunk[..n]);
            true
        }
    }
}

/// Matches a raw HTTP response against the expectations (pure).
fn matches_response(http: &HttpCheck, raw: &[u8]) -> bool {
    let text = String::from_utf8_lossy(raw);
    let status_line = text.split("\r\n").next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok());
    let Some(status) = status else {
        return false;
    };
    if !http.expect_status.matches(status) {
        return false;
    }
    if let Some(rstring) = &http.expect_rstring {
        let body = text.split_once("\r\n\r\n").map_or("", |(_, body)| body);
        return rstring.is_match(body);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http_check(status: &str, rstring: Option<&str>) -> HttpCheck {
        HttpCheck {
            method: HttpCheckMethod::Get,
            path: "/healthz".to_owned(),
            host: None,
            expect_status: StatusExpectation::parse(status).expect("status"),
            expect_rstring: rstring.map(|r| RegexMatcher::parse(r).expect("regex")),
        }
    }

    #[test]
    fn expectations_match_status_and_raw_body() {
        let ok = http_check("200-299", Some("^ok$"));
        assert!(matches_response(
            &ok,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        ));
        assert!(
            !matches_response(&ok, b"HTTP/1.1 200 OK\r\n\r\nokay"),
            "rstring ^ok$ must not match \"okay\""
        );
        assert!(
            !matches_response(&ok, b"HTTP/1.1 500 Internal Server Error\r\n\r\nok"),
            "status outside expect_status must fail"
        );
        assert!(
            !matches_response(&ok, b"garbage without status line"),
            "malformed response must fail"
        );

        let list = http_check("200-204,301", None);
        assert!(matches_response(&list, b"HTTP/1.1 301 Moved\r\n\r\n"));
        assert!(!matches_response(&list, b"HTTP/1.1 302 Found\r\n\r\n"));
    }

    #[cfg_attr(
        miri,
        ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
    )]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_check_over_real_sockets_follows_expectations() {
        // Real server whose response is controlled by an atomic flag:
        // 503 while "down", 200 + "ok" body while "up".
        use std::sync::atomic::{AtomicBool, Ordering};
        let up = Arc::new(AtomicBool::new(false));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn({
            let up = Arc::clone(&up);
            async move {
                while let Ok((mut socket, _)) = listener.accept().await {
                    let up = Arc::clone(&up);
                    tokio::spawn(async move {
                        let mut buf = [0_u8; 1024];
                        let _ = socket.read(&mut buf).await;
                        let response = if up.load(Ordering::Relaxed) {
                            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                        } else {
                            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"
                        };
                        let _ = socket.write_all(response.as_bytes()).await;
                    });
                }
            }
        });

        let check = http_check("200-299", Some("^ok$"));
        assert!(
            !http_ok(addr, &check, Duration::from_secs(2)).await,
            "a 503 backend must be reported DOWN"
        );

        up.store(true, Ordering::Relaxed);
        assert!(
            http_ok(addr, &check, Duration::from_secs(2)).await,
            "a 200 + \"ok\" backend must be reported UP"
        );

        let strict = http_check("200-299", Some("never-matches"));
        assert!(
            !http_ok(addr, &strict, Duration::from_secs(2)).await,
            "rstring mismatch must fail the check"
        );

        server.abort();
    }

    #[cfg_attr(
        miri,
        ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
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
            vec![crate::balancer::ResolvedServer {
                addr: addr.into(),
                weight: 1,
                backup: false,
                priority: 0,
                maxconn: 0,
            }],
            1,
            1,
        ));
        let (handle, signal) = eqproxy_core::shutdown::channel();
        let task = tokio::spawn({
            let balancer = Arc::clone(&balancer);
            async move {
                run(
                    balancer,
                    // The listener answers at once and the dead case is a
                    // refused connect: 1 s is headroom for the scheduler, not
                    // a wait for the origin, so one descheduled poll cannot
                    // drop the live server (the 200 ms budget could).
                    HealthCheck::tcp(Duration::from_millis(20), Duration::from_secs(1)),
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

        // We close the listener: checks fail → down (fall=1).
        acceptor.abort();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!balancer.is_up(addr), "the dead server must drop");

        handle.trigger();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("the check task must finish on the signal")
            .expect("join");
    }

    /// Origin that answers `response` to any request head. With
    /// `keep_alive` it **never** closes the socket (the interop hazard:
    /// a checker that reads to EOF hangs until its timeout).
    async fn origin_with(response: &'static [u8], keep_alive: bool) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0_u8; 1024];
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
                    if socket.write_all(response).await.is_err() {
                        return;
                    }
                    if keep_alive {
                        // Hold the socket open forever: no shutdown, no
                        // EOF for anyone reading.
                        std::future::pending::<()>().await;
                    }
                    let _ = socket.shutdown().await;
                });
            }
        });
        addr
    }

    #[cfg_attr(
        miri,
        ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
    )]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn content_length_closes_against_a_keep_alive_origin() {
        let addr = origin_with(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", true).await;
        let check = http_check("200-299", Some("^ok$"));
        let done = tokio::time::timeout(
            Duration::from_secs(1),
            http_ok(addr, &check, Duration::from_secs(30)),
        )
        .await
        .expect(
            "the check must complete at the Content-Length boundary, \
             never wait for a keep-alive origin to close",
        );
        assert!(done, "a 200 + \"ok\" keep-alive origin must be UP");
    }

    #[cfg_attr(
        miri,
        ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
    )]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn chunked_framing_closes_against_a_keep_alive_origin() {
        let addr = origin_with(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
            true,
        )
        .await;
        let check = http_check("200-299", Some("ok"));
        let done = tokio::time::timeout(
            Duration::from_secs(1),
            http_ok(addr, &check, Duration::from_secs(30)),
        )
        .await
        .expect("the check must complete at the terminal chunk");
        assert!(done, "a chunked keep-alive origin must be UP");
    }

    #[cfg_attr(
        miri,
        ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
    )]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn head_check_never_waits_for_the_declared_body() {
        // HEAD carries no body (RFC 9112 §6.3) even though the head
        // announces one — a keep-alive origin sends nothing more.
        let addr = origin_with(b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n", true).await;
        let mut check = http_check("200-299", None);
        check.method = HttpCheckMethod::Head;
        let done = tokio::time::timeout(
            Duration::from_secs(1),
            http_ok(addr, &check, Duration::from_secs(30)),
        )
        .await
        .expect("HEAD has no body: the check must complete at the head");
        assert!(done, "a 200 to HEAD must be UP");
    }

    #[cfg_attr(
        miri,
        ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
    )]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn close_delimited_body_is_still_read_to_eof() {
        // No framing header: EOF remains the message boundary (HTTP/1.0
        // style origins).
        let addr = origin_with(b"HTTP/1.1 200 OK\r\n\r\nok", false).await;
        let check = http_check("200-299", Some("^ok$"));
        assert!(
            http_ok(addr, &check, Duration::from_secs(2)).await,
            "a close-delimited origin must still be checked"
        );
    }

    #[cfg_attr(
        miri,
        ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
    )]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn oversized_body_is_matched_truncated_at_the_budget() {
        // Content-Length far beyond the 64 KiB budget: the read stops at
        // the budget (the origin keeps the body coming forever) and
        // matching sees the truncated body.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0_u8; 1024];
                    let mut total = 0usize;
                    loop {
                        match socket.read(&mut buf[total..]).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => total += n,
                        }
                        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let _ = socket
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 200000\r\n\r\nok")
                        .await;
                    let filler = [b'x'; 4096];
                    loop {
                        if socket.write_all(&filler).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        let check = http_check("200-299", Some("^ok"));
        let done = tokio::time::timeout(
            Duration::from_secs(2),
            http_ok(addr, &check, Duration::from_secs(30)),
        )
        .await
        .expect("the budget must bound the read even when the body is longer");
        assert!(done, "the truncated body still matches ^ok");
    }
}
