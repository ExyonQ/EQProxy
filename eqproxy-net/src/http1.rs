//! Strict-framing HTTP/1.1 proxy (A2) with ambiguity rejection (T01–T03).
//!
//! Security policy (THREAT_MODEL §2.1): **single shared parser between
//! analysis and forwarding** — every ambiguous message is rejected BEFORE
//! touching the backend, and what is forwarded is byte-for-byte what the
//! parser validated:
//! - `Content-Length` and `Transfer-Encoding` together → 400 (T01).
//! - duplicated `Content-Length` or `Transfer-Encoding` → 400 (T01).
//! - `Transfer-Encoding` other than exact `chunked` → 400 (T01).
//! - obs-fold, spaces in names, bare CR/LF, control characters → 400 (T02).
//! - Per-message limits: header count, header and line size → 431 (T03).
//! - `CONNECT` and `Upgrade` (A7/A8): the handshake is forwarded and on
//!   backend acceptance (101 / 2xx) the exchange becomes a raw
//!   bidirectional tunnel; an unsolicited `101` is refused with 502.
//! - `Expect` other than `100-continue` → 417; `Expect: 100-continue`
//!   releases the client with a real interim `100` (RFC 9112 §10.1.2).
//! - Interim (1xx) responses are never final: they are forwarded (RFC 9112
//!   §6.2) and the loop keeps reading until the final response, so a stale
//!   message is never left queued on a pooled connection.
//!
//! Connection semantics: one backend connection per exchange, reused
//! through the bounded pool when the exchange was clean (A16); client
//! keep-alive with `Connection`/version per RFC 9112.
//! A client abort closes the backend instantly (A19): the exchange
//! aborted never leaves live tasks.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{
    AsyncBufRead, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf,
};

use eqproxy_core::Metrics;

use crate::balancer::ServerMode;
use crate::cache;
use crate::compression;

use crate::mirror;
use crate::proxy::{
    AffinityMode, BoxRead, BoxWrite, ForwardedMode, OutboundError, READ_BUF, ResolvedBackend,
    ResolvedCors, ResolvedHeaders, ResolvedListener, ResolvedRewrite, RetryContext, RouteDecision,
    checkout_or_connect,
};

/// Maximum message-head size (final line included) (T03).
pub const MAX_HEAD_BYTES: usize = 16 * 1024;
/// Maximum headers per message (T03).
pub const MAX_HEADERS: usize = 100;
/// Maximum header-or-chunk line size (T03).
pub const MAX_LINE_BYTES: usize = 8 * 1024;
/// Pipe feeding the streaming compressor when the listener sets no
/// `limits.stream_buffer_bytes`.
const DEFAULT_COMPRESSION_PIPE: usize = 64 * 1024;

/// Head bounds for one message, resolved from
/// [`ResolvedListener::limits`](crate::proxy::ResolvedListener::limits)
/// (B-N19). [`Default`] is the historical constant pair, so a listener that
/// configures nothing parses exactly what it parsed before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadLimits {
    /// Maximum head size in bytes (terminator included in the budget).
    pub max_head_bytes: usize,
    /// Maximum header fields (the request/status line is not one).
    pub max_headers: usize,
}

impl Default for HeadLimits {
    fn default() -> Self {
        Self {
            max_head_bytes: MAX_HEAD_BYTES,
            max_headers: MAX_HEADERS,
        }
    }
}

const CRLF: &[u8] = b"\r\n";
const HEAD_END: &[u8] = b"\r\n\r\n";
/// Real interim response that releases an `Expect: 100-continue` client.
const CONTINUE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";
/// Interim responses accepted before the final one (bounded, never an
/// endless 1xx stream).
const MAX_INTERIM_RESPONSES: u32 = 8;

/// Writer wrapper that duplicates the bytes it forwards into a bounded
/// buffer (B-H3 request mirror): the copy keeps the **exact** wire framing
/// the primary backend received (chunk framing included), and the buffer is
/// dropped as soon as it would exceed its budget (the request is then not
/// mirrored — counted, never truncated into an invalid message).
struct MirrorTee<'a, W> {
    inner: &'a mut W,
    budget: usize,
    /// `None` once the budget was exceeded.
    buffer: Option<Vec<u8>>,
}

impl<'a, W> MirrorTee<'a, W> {
    fn new(inner: &'a mut W, budget: usize) -> Self {
        Self {
            inner,
            budget,
            buffer: Some(Vec::new()),
        }
    }

    /// The copied bytes, or `None` when they did not fit the budget.
    fn finish(self) -> Option<Vec<u8>> {
        self.buffer
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for MirrorTee<'_, W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let written = match Pin::new(&mut *this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => written,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        };
        if let Some(copy) = this.buffer.as_mut() {
            if copy.len() + written > this.budget {
                this.buffer = None;
            } else {
                copy.extend_from_slice(&buf[..written]);
            }
        }
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Headers forbidden in chunked trailers (T01).
pub(crate) const FORBIDDEN_TRAILERS: [&str; 6] = [
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "trailer",
    "upgrade",
];

/// Rejection of a message: HTTP status and short ASCII detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reject {
    pub status: u16,
    pub reason: &'static str,
}

/// Body framing per RFC 9112 §6 (the only source of limits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    /// No body.
    None,
    /// Exact `Content-Length: n`.
    ContentLength(u64),
    /// `Transfer-Encoding: chunked` (the only accepted TE).
    Chunked,
    /// Unframed response: body until backend EOF (responses only).
    UntilEof,
}

/// Parsed and validated request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    pub method: String,
    pub target: String,
    /// HTTP version: 10 (HTTP/1.0) or 11 (HTTP/1.1).
    pub version: u8,
    pub framing: BodyFraming,
    pub wants_close: bool,
    /// The client asked for a `100 Continue` before the body (HTTP/1.1
    /// only; ignored in HTTP/1.0 per RFC 9112 §10.1.2).
    pub expect_continue: bool,
    /// The client asked for a protocol upgrade (`Upgrade` +
    /// `Connection: upgrade`, A7); a backend `101` opens the tunnel.
    pub wants_upgrade: bool,
    /// Host header value as received (may carry `:port`; empty when
    /// absent). Kept for routing rules (B-H3).
    pub host: String,
    /// All request headers (names lowercased by [`parse_header_line`]).
    /// Kept for routing rules (B-H3).
    pub headers: Vec<(String, String)>,
}

/// Parsed and validated response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: u16,
    pub framing: BodyFraming,
    pub wants_close: bool,
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn trim_ows(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|b| *b != b' ' && *b != b'\t')
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|b| *b != b' ' && *b != b'\t')
        .map_or(start, |i| i + 1);
    &value[start..end]
}

/// Splits the head (without the `\r\n\r\n` terminator) into strict CRLF lines.
fn parse_lines(head: &[u8]) -> Result<Vec<&[u8]>, Reject> {
    let mut lines = Vec::new();
    let mut rest = head;
    while !rest.is_empty() {
        let Some(pos) = find_sub(rest, CRLF) else {
            // Last line: the head is delivered without the final terminator.
            if rest.contains(&b'\r') || rest.contains(&b'\n') {
                return Err(Reject {
                    status: 400,
                    reason: "bare CR or LF inside a line",
                });
            }
            lines.push(rest);
            break;
        };
        let line = &rest[..pos];
        if line.contains(&b'\r') || line.contains(&b'\n') {
            return Err(Reject {
                status: 400,
                reason: "bare CR or LF inside a line",
            });
        }
        lines.push(line);
        rest = &rest[pos + CRLF.len()..];
    }
    Ok(lines)
}

/// Validates a `name: value` line with strict rules (T02).
pub(crate) fn parse_header_line(line: &[u8]) -> Result<(String, String), Reject> {
    if line.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
        return Err(Reject {
            status: 400,
            reason: "obs-fold continuation is not allowed",
        });
    }
    let colon = line.iter().position(|&b| b == b':').ok_or(Reject {
        status: 400,
        reason: "header line without colon",
    })?;
    let name = &line[..colon];
    if name.is_empty() || !name.iter().all(|&b| is_tchar(b)) {
        return Err(Reject {
            status: 400,
            reason: "invalid header name",
        });
    }
    let value = trim_ows(&line[colon + 1..]);
    if value.iter().any(|b| {
        *b == b'\r' || *b == b'\n' || *b == b'\0' || (*b < 0x20 && *b != b'\t') || *b == 0x7f
    }) {
        return Err(Reject {
            status: 400,
            reason: "control character in header value",
        });
    }
    Ok((
        String::from_utf8_lossy(name).to_ascii_lowercase(),
        String::from_utf8_lossy(value).into_owned(),
    ))
}

/// Strict `Content-Length`: digits only, no leading zeros, no sign.
fn parse_content_length(value: &str) -> Result<u64, Reject> {
    let bad = Reject {
        status: 400,
        reason: "invalid content-length",
    };
    if value.is_empty()
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(bad);
    }
    value.parse().map_err(|_| bad)
}

/// Request body framing from the headers (T01).
fn request_framing(
    headers: &[(String, String)],
    version: u8,
) -> Result<(BodyFraming, bool, bool), Reject> {
    let mut content_length: Option<u64> = None;
    let mut te_chunked = false;
    let mut te_count = 0usize;
    let mut host_count = 0usize;
    let mut connection_close = false;
    let mut connection_keep_alive = false;
    let mut has_upgrade = false;

    for (name, value) in headers {
        match name.as_str() {
            "content-length" => {
                if content_length.is_some() {
                    return Err(Reject {
                        status: 400,
                        reason: "duplicated content-length",
                    });
                }
                content_length = Some(parse_content_length(value)?);
            }
            "transfer-encoding" => {
                te_count += 1;
                if te_count > 1 || !value.trim().eq_ignore_ascii_case("chunked") {
                    return Err(Reject {
                        status: 400,
                        reason: "only a single chunked transfer-encoding is accepted",
                    });
                }
                te_chunked = true;
            }
            "host" => host_count += 1,
            "connection" => {
                for token in value.split(',') {
                    match token.trim().to_ascii_lowercase().as_str() {
                        "close" => connection_close = true,
                        "keep-alive" => connection_keep_alive = true,
                        "upgrade" => has_upgrade = true,
                        _ => {}
                    }
                }
            }
            "upgrade" => has_upgrade = true,
            _ => {}
        }
    }

    if te_chunked && content_length.is_some() {
        return Err(Reject {
            status: 400,
            reason: "content-length together with transfer-encoding",
        });
    }
    if version >= 11 && host_count != 1 {
        return Err(Reject {
            status: 400,
            reason: "exactly one host header is required in HTTP/1.1",
        });
    }
    if host_count > 1 {
        return Err(Reject {
            status: 400,
            reason: "duplicated host header",
        });
    }

    let framing = if te_chunked {
        BodyFraming::Chunked
    } else if let Some(len) = content_length {
        BodyFraming::ContentLength(len)
    } else {
        BodyFraming::None
    };
    let wants_close = connection_close || (version == 10 && !connection_keep_alive);
    Ok((framing, wants_close, has_upgrade))
}

/// Parses the request head with strict rules (T01–T03).
pub fn parse_request_head(head: &[u8], limits: HeadLimits) -> Result<RequestHead, Reject> {
    let lines = parse_lines(head)?;
    let request_line = lines.first().ok_or(Reject {
        status: 400,
        reason: "empty request head",
    })?;

    // Exactly three space-separated parts: no allocation, no indexing.
    let mut parts = request_line.split(|&b| b == b' ');
    let (Some(method), Some(target), Some(raw_version)) =
        (parts.next(), parts.next(), parts.next())
    else {
        return Err(Reject {
            status: 400,
            reason: "malformed request line",
        });
    };
    if parts.next().is_some() {
        return Err(Reject {
            status: 400,
            reason: "malformed request line",
        });
    }
    if method.is_empty() || !method.iter().all(|&b| is_tchar(b)) {
        return Err(Reject {
            status: 400,
            reason: "invalid method",
        });
    }
    // CONNECT (A8) uses authority-form ("host:port"): the tunnel's
    // routing host. Everything else is origin-form (absolute-form is
    // rejected: this proxy is an origin, not a client).
    let is_connect = method == b"CONNECT";
    if target.is_empty()
        || target.iter().any(|b| *b <= 0x20 || *b == 0x7f)
        || (!is_connect && !target.starts_with(b"/") && target != b"*")
    {
        return Err(Reject {
            status: 400,
            reason: "invalid request target",
        });
    }
    let version = match raw_version {
        b"HTTP/1.1" => 11u8,
        b"HTTP/1.0" => 10u8,
        v if v.starts_with(b"HTTP/") => {
            return Err(Reject {
                status: 505,
                reason: "http version not supported",
            });
        }
        _ => {
            return Err(Reject {
                status: 400,
                reason: "malformed http version",
            });
        }
    };

    if lines.len() - 1 > limits.max_headers {
        return Err(Reject {
            status: 431,
            reason: "too many headers",
        });
    }
    let mut headers = Vec::with_capacity(lines.len() - 1);
    for line in &lines[1..] {
        headers.push(parse_header_line(line)?);
    }

    let (framing, wants_close, wants_upgrade) = request_framing(&headers, version)?;

    // `Expect` (RFC 9112 §10.1.2): only `100-continue` is understood and
    // only in HTTP/1.1 (HTTP/1.0 ignores it). Any other expectation is
    // refused explicitly (417), never silently dropped or faked.
    let mut expect_continue = false;
    for (name, value) in &headers {
        if name == "expect" {
            if value.trim().eq_ignore_ascii_case("100-continue") {
                expect_continue = true;
            } else {
                return Err(Reject {
                    status: 417,
                    reason: "expectation failed",
                });
            }
        }
    }
    let expect_continue = expect_continue && version >= 11;

    let host = headers
        .iter()
        .find(|(name, _)| name == "host")
        .map_or_else(String::new, |(_, value)| value.clone());
    // CONNECT (A8): with no Host header the authority-form target is the
    // routing host of the tunnel.
    let host = if is_connect && host.is_empty() {
        String::from_utf8_lossy(target).into_owned()
    } else {
        host
    };
    Ok(RequestHead {
        method: String::from_utf8_lossy(method).into_owned(),
        target: String::from_utf8_lossy(target).into_owned(),
        version,
        framing,
        wants_close,
        expect_continue,
        wants_upgrade,
        host,
        headers,
    })
}

/// Parses the response head with the same line rules (T02) and the
/// RFC 9112 §6 framing. An ambiguous backend answers 502 (never forwarded
/// a framing the client could interpret differently).
pub fn parse_response_head(
    head: &[u8],
    head_request: bool,
    limits: HeadLimits,
) -> Result<ResponseHead, Reject> {
    let bad_gateway = Reject {
        status: 502,
        reason: "malformed response from upstream",
    };
    let lines = parse_lines(head).map_err(|_| bad_gateway)?;
    let status_line = lines.first().ok_or(bad_gateway)?;

    let parts: Vec<&[u8]> = status_line.splitn(3, |&b| b == b' ').collect();
    if parts.len() < 2 {
        return Err(bad_gateway);
    }
    let version = match parts[0] {
        b"HTTP/1.1" => 11u8,
        b"HTTP/1.0" => 10u8,
        _ => return Err(bad_gateway),
    };
    let status_bytes = parts[1];
    if status_bytes.len() != 3 || !status_bytes.iter().all(|b| b.is_ascii_digit()) {
        return Err(bad_gateway);
    }
    let status: u16 = std::str::from_utf8(status_bytes)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(bad_gateway)?;
    if !(100..=599).contains(&status) {
        return Err(bad_gateway);
    }

    if lines.len() - 1 > limits.max_headers {
        return Err(bad_gateway);
    }
    let mut headers = Vec::with_capacity(lines.len() - 1);
    for line in &lines[1..] {
        headers.push(parse_header_line(line).map_err(|_| bad_gateway)?);
    }

    let mut content_length: Option<u64> = None;
    let mut te_chunked = false;
    let mut te_count = 0usize;
    let mut connection_close = false;
    let mut connection_keep_alive = false;
    for (name, value) in &headers {
        match name.as_str() {
            "content-length" => {
                if content_length.is_some() {
                    return Err(bad_gateway);
                }
                content_length = Some(parse_content_length(value).map_err(|_| bad_gateway)?);
            }
            "transfer-encoding" => {
                te_count += 1;
                if te_count > 1 || !value.trim().eq_ignore_ascii_case("chunked") {
                    return Err(bad_gateway);
                }
                te_chunked = true;
            }
            "connection" => {
                for token in value.split(',') {
                    match token.trim().to_ascii_lowercase().as_str() {
                        "close" => connection_close = true,
                        "keep-alive" => connection_keep_alive = true,
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    if te_chunked && content_length.is_some() {
        return Err(bad_gateway);
    }
    let bodyless = status < 200 || status == 204 || status == 304 || head_request;
    let framing = if bodyless {
        BodyFraming::None
    } else if te_chunked {
        BodyFraming::Chunked
    } else if let Some(len) = content_length {
        BodyFraming::ContentLength(len)
    } else {
        BodyFraming::UntilEof
    };
    let wants_close = connection_close
        || (version == 10 && !connection_keep_alive)
        || framing == BodyFraming::UntilEof;
    Ok(ResponseHead {
        status,
        framing,
        wants_close,
    })
}

// ---------------------------------------------------------------------------
// Serving one client connection
// ---------------------------------------------------------------------------

/// Body copy error: distinguishes framing, cut, inactivity and abort.
#[derive(Debug)]
pub(crate) enum CopyError {
    Framing(Reject),
    Truncated,
    Idle,
    Io,
    /// A request body crossed `limits.max_body_bytes` (B-N19): the frame
    /// that would cross is refused **before** its data is forwarded, and the
    /// exchange answers 413 instead of truncating silently.
    TooLarge,
}

fn idle_copy_error(idle_counter: &AtomicU64) -> CopyError {
    idle_counter.fetch_add(1, Ordering::Relaxed);
    CopyError::Idle
}

async fn write_with_timeout<W: AsyncWrite + Unpin>(
    writer: &mut W,
    buf: &[u8],
    idle: Duration,
) -> Result<(), CopyError> {
    match tokio::time::timeout(idle, writer.write_all(buf)).await {
        Err(_) => Err(CopyError::Idle),
        Ok(Err(_)) => Err(CopyError::Io),
        Ok(Ok(())) => Ok(()),
    }
}

/// Copies exactly `n` bytes with a per-operation inactivity timeout.
async fn copy_exact<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    mut remaining: u64,
    idle: Duration,
    counter: &AtomicU64,
    idle_counter: &AtomicU64,
) -> Result<(), CopyError> {
    let mut buf = vec![0u8; READ_BUF];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let got = match tokio::time::timeout(idle, reader.read(&mut buf[..want])).await {
            Err(_) => return Err(idle_copy_error(idle_counter)),
            Ok(Err(_)) => return Err(CopyError::Io),
            Ok(Ok(0)) => return Err(CopyError::Truncated),
            Ok(Ok(n)) => n,
        };
        write_with_timeout(writer, &buf[..got], idle).await?;
        counter.fetch_add(got as u64, Ordering::Relaxed);
        remaining -= got as u64;
    }
    Ok(())
}

/// Copies until reader EOF.
async fn copy_to_eof<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    idle: Duration,
    counter: &AtomicU64,
    idle_counter: &AtomicU64,
) -> Result<(), CopyError> {
    let mut buf = vec![0u8; READ_BUF];
    loop {
        let got = match tokio::time::timeout(idle, reader.read(&mut buf)).await {
            Err(_) => return Err(idle_copy_error(idle_counter)),
            Ok(Err(_)) => return Err(CopyError::Io),
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(n)) => n,
        };
        write_with_timeout(writer, &buf[..got], idle).await?;
        counter.fetch_add(got as u64, Ordering::Relaxed);
    }
}

/// Reads a CRLF-terminated line (terminator included), strict (T02).
/// `ponytail`: byte-by-byte reading via BufReader; optimize when Phase 9
/// benchmarks demand it.
pub(crate) async fn read_crlf_line<R: AsyncRead + Unpin>(
    reader: &mut R,
    idle: Duration,
    max: usize,
) -> Result<Vec<u8>, CopyError> {
    let mut line = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        let got = match tokio::time::timeout(idle, reader.read(&mut byte)).await {
            Err(_) => return Err(CopyError::Idle),
            Ok(Err(_)) => return Err(CopyError::Io),
            Ok(Ok(0)) => return Err(CopyError::Truncated),
            Ok(Ok(n)) => n,
        };
        debug_assert_eq!(got, 1);
        line.push(byte[0]);
        if line.ends_with(CRLF) {
            let inner = &line[..line.len() - CRLF.len()];
            if inner.contains(&b'\r') || inner.contains(&b'\n') {
                return Err(CopyError::Framing(Reject {
                    status: 400,
                    reason: "bare CR or LF in chunk framing",
                }));
            }
            return Ok(line);
        }
        if line.len() >= max {
            return Err(CopyError::Framing(Reject {
                status: 431,
                reason: "chunk line too long",
            }));
        }
    }
}

/// Strict `chunk-size [chunk-ext]`: pure hex (extension without controls).
pub(crate) fn parse_chunk_size(line: &[u8]) -> Result<u64, CopyError> {
    let bad = || {
        CopyError::Framing(Reject {
            status: 400,
            reason: "invalid chunk size",
        })
    };
    let without_crlf = &line[..line.len() - CRLF.len()];
    let (size_part, ext_part) = match without_crlf.iter().position(|&b| b == b';') {
        Some(pos) => (&without_crlf[..pos], Some(&without_crlf[pos + 1..])),
        None => (without_crlf, None),
    };
    if let Some(ext) = ext_part
        && ext
            .iter()
            .any(|b| *b == b'\r' || *b == b'\n' || *b == b'\0' || *b < 0x20)
    {
        return Err(bad());
    }
    if size_part.is_empty() || !size_part.iter().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad());
    }
    let text = std::str::from_utf8(size_part).map_err(|_| bad())?;
    // chunk-size es hexadecimal (RFC 9112 §7.1.1), no decimal.
    u64::from_str_radix(text, 16).map_err(|_| bad())
}

/// Copies a `chunked` body validating framing while forwarding (T01).
async fn copy_chunked<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    idle: Duration,
    counter: &AtomicU64,
    idle_counter: &AtomicU64,
) -> Result<(), CopyError> {
    copy_chunked_capped(reader, writer, idle, counter, idle_counter, None).await
}

/// [`copy_chunked`] with an optional payload cap (B-N19).
///
/// The cap is checked against the chunk **size line** before the frame is
/// written, so the backend never receives a chunk that would cross the
/// configured bound: the client gets an explicit 413 and the exchange is
/// abandoned (earlier chunks may already have reached the backend, so the
/// connection is never pooled).
async fn copy_chunked_capped<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    idle: Duration,
    counter: &AtomicU64,
    idle_counter: &AtomicU64,
    cap: Option<u64>,
) -> Result<(), CopyError> {
    let mut total = 0u64;
    loop {
        let line = read_crlf_line(reader, idle, MAX_LINE_BYTES).await?;
        let size = parse_chunk_size(&line)?;
        if let Some(cap) = cap
            && size > cap.saturating_sub(total)
        {
            return Err(CopyError::TooLarge);
        }
        total += size;
        write_with_timeout(writer, &line, idle).await?;
        if size == 0 {
            // Trailers: empty or validated as headers; never framing.
            loop {
                let trailer = read_crlf_line(reader, idle, MAX_LINE_BYTES).await?;
                if trailer == CRLF {
                    write_with_timeout(writer, CRLF, idle).await?;
                    return Ok(());
                }
                let (name, _) = parse_header_line(&trailer[..trailer.len() - CRLF.len()])
                    .map_err(CopyError::Framing)?;
                if FORBIDDEN_TRAILERS.contains(&name.as_str()) {
                    return Err(CopyError::Framing(Reject {
                        status: 400,
                        reason: "forbidden trailer header",
                    }));
                }
                write_with_timeout(writer, &trailer, idle).await?;
            }
        }
        copy_exact(reader, writer, size, idle, counter, idle_counter).await?;
        // CRLF after the chunk data.
        let mut crlf = [0u8; 2];
        match tokio::time::timeout(idle, reader.read_exact(&mut crlf)).await {
            Err(_) => return Err(idle_copy_error(idle_counter)),
            Ok(Err(_)) => return Err(CopyError::Io),
            Ok(Ok(_)) => {}
        }
        if crlf[..] != *CRLF {
            return Err(CopyError::Framing(Reject {
                status: 400,
                reason: "chunk data without CRLF terminator",
            }));
        }
        write_with_timeout(writer, CRLF, idle).await?;
    }
}

/// Writes one chunked frame (size line, payload, CRLF) and accounts for it.
async fn write_chunk<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
    idle: Duration,
    metrics: &Metrics,
) -> Result<(), CopyError> {
    let header = format!("{:x}\r\n", data.len());
    write_with_timeout(writer, header.as_bytes(), idle).await?;
    write_with_timeout(writer, data, idle).await?;
    write_with_timeout(writer, CRLF, idle).await?;
    metrics
        .compression_bytes_out
        .fetch_add(data.len() as u64, Ordering::Relaxed);
    metrics
        .bytes_backend_to_client
        .fetch_add(data.len() as u64, Ordering::Relaxed);
    Ok(())
}

/// Compresses a plaintext stream into chunked frames of the negotiated coding.
/// It stops after the last data chunk: the caller writes `0\r\n` and any
/// trailers, because the chunked terminator is not part of the compressed
/// stream.
async fn compress_to_chunks<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    encoding: compression::Encoding,
    settings: &compression::ResolvedCompression,
    idle: Duration,
    metrics: &Metrics,
) -> Result<(), CopyError> {
    let mut encoder = compression::Encoder::new(encoding, settings).map_err(|_| CopyError::Io)?;
    let mut buf = vec![0u8; READ_BUF];
    let mut out = Vec::with_capacity(READ_BUF);
    loop {
        let got = match tokio::time::timeout(idle, reader.read(&mut buf)).await {
            Err(_) => return Err(idle_copy_error(&metrics.idle_timeouts)),
            Ok(Err(_)) => return Err(CopyError::Io),
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
        };
        metrics
            .compression_bytes_in
            .fetch_add(got as u64, Ordering::Relaxed);
        encoder
            .push(&buf[..got], &mut out)
            .map_err(|_| CopyError::Io)?;
        if !out.is_empty() {
            write_chunk(writer, &out, idle, metrics).await?;
            out.clear();
        }
    }
    encoder.finish(&mut out).map_err(|_| CopyError::Io)?;
    if !out.is_empty() {
        write_chunk(writer, &out, idle, metrics).await?;
    }
    Ok(())
}

/// Reads a `chunked` body and writes only its payload (framing and trailers
/// are separate): the compressor sees the plaintext, and the validated
/// trailer lines are returned to be re-emitted after the gzip member.
async fn pump_chunked_plain<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    idle: Duration,
    idle_counter: &AtomicU64,
) -> Result<Vec<u8>, CopyError> {
    let scratch = AtomicU64::new(0);
    let mut trailers = Vec::new();
    loop {
        let line = read_crlf_line(reader, idle, MAX_LINE_BYTES).await?;
        let size = parse_chunk_size(&line)?;
        if size == 0 {
            loop {
                let trailer = read_crlf_line(reader, idle, MAX_LINE_BYTES).await?;
                if trailer == CRLF {
                    return Ok(trailers);
                }
                let (name, _) = parse_header_line(&trailer[..trailer.len() - CRLF.len()])
                    .map_err(CopyError::Framing)?;
                if FORBIDDEN_TRAILERS.contains(&name.as_str()) {
                    return Err(CopyError::Framing(Reject {
                        status: 400,
                        reason: "forbidden trailer header",
                    }));
                }
                trailers.extend_from_slice(&trailer);
            }
        }
        copy_exact(reader, writer, size, idle, &scratch, idle_counter).await?;
        let mut crlf = [0u8; 2];
        match tokio::time::timeout(idle, reader.read_exact(&mut crlf)).await {
            Err(_) => return Err(idle_copy_error(idle_counter)),
            Ok(Err(_)) => return Err(CopyError::Io),
            Ok(Ok(_)) => {}
        }
        if crlf[..] != *CRLF {
            return Err(CopyError::Framing(Reject {
                status: 400,
                reason: "chunk data without CRLF terminator",
            }));
        }
    }
}

/// How a response body is compressed, and how much memory its streaming
/// pipe may use (`limits.stream_buffer_bytes`, B-E19).
struct CompressPlan<'a> {
    framing: BodyFraming,
    encoding: compression::Encoding,
    settings: &'a compression::ResolvedCompression,
    pipe: usize,
}

/// Streams a response body to the client as a chunked compressed stream,
/// without buffering it whole. The decoder side closes the pipe on every path,
/// so the compressor always reaches EOF (a truncated body fails the exchange
/// instead of hanging).
async fn copy_compressed_body<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    plan: CompressPlan<'_>,
    idle: Duration,
    metrics: &Metrics,
) -> Result<(), CopyError> {
    let scratch = AtomicU64::new(0);
    let (mut plain_read, plain_write) = tokio::io::duplex(plan.pipe);
    let trailers = match plan.framing {
        BodyFraming::None => return Ok(()),
        BodyFraming::ContentLength(len) => {
            let (compressed, fed) = tokio::join!(
                compress_to_chunks(
                    &mut plain_read,
                    writer,
                    plan.encoding,
                    plan.settings,
                    idle,
                    metrics,
                ),
                async move {
                    let mut plain_write = plain_write;
                    let result = copy_exact(
                        reader,
                        &mut plain_write,
                        len,
                        idle,
                        &scratch,
                        &metrics.idle_timeouts,
                    )
                    .await;
                    drop(plain_write);
                    result
                },
            );
            compressed?;
            fed?;
            Vec::new()
        }
        BodyFraming::Chunked => {
            let (compressed, fed) = tokio::join!(
                compress_to_chunks(
                    &mut plain_read,
                    writer,
                    plan.encoding,
                    plan.settings,
                    idle,
                    metrics,
                ),
                async move {
                    let mut plain_write = plain_write;
                    let result =
                        pump_chunked_plain(reader, &mut plain_write, idle, &metrics.idle_timeouts)
                            .await;
                    drop(plain_write);
                    result
                },
            );
            compressed?;
            fed?
        }
        BodyFraming::UntilEof => {
            let (compressed, fed) = tokio::join!(
                compress_to_chunks(
                    &mut plain_read,
                    writer,
                    plan.encoding,
                    plan.settings,
                    idle,
                    metrics,
                ),
                async move {
                    let mut plain_write = plain_write;
                    let result = copy_to_eof(
                        reader,
                        &mut plain_write,
                        idle,
                        &scratch,
                        &metrics.idle_timeouts,
                    )
                    .await;
                    drop(plain_write);
                    result
                },
            );
            compressed?;
            fed?;
            Vec::new()
        }
    };
    // Chunked terminator: `0` line, the backend's validated trailers, and the
    // final CRLF. The gzip member already ended inside `gzip_to_chunks`.
    write_with_timeout(writer, b"0\r\n", idle).await?;
    if !trailers.is_empty() {
        write_with_timeout(writer, &trailers, idle).await?;
    }
    write_with_timeout(writer, CRLF, idle).await?;
    Ok(())
}

/// Reader that serves an already-read prefix first (head-read remainder).
pub(crate) struct Prefixed<R> {
    pub(crate) prefix: Vec<u8>,
    pub(crate) pos: usize,
    pub(crate) inner: R,
}

impl<R: AsyncRead + Unpin> AsyncRead for Prefixed<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let n = (this.prefix.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.prefix[this.pos..this.pos + n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

/// Reads a full head: returns (head without terminator, extra bytes read).
pub(crate) enum HeadError {
    Eof,
    Timeout,
    TooLarge,
    Io,
}

pub(crate) async fn read_head<R: AsyncRead + Unpin>(
    reader: &mut R,
    timeout: Duration,
    max_head_bytes: usize,
) -> Result<(Vec<u8>, Vec<u8>), HeadError> {
    tokio::time::timeout(timeout, async {
        let mut acc = Vec::with_capacity(1024);
        let mut buf = [0u8; 2048];
        loop {
            let got = reader.read(&mut buf).await.map_err(|_| HeadError::Io)?;
            if got == 0 {
                return Err(HeadError::Eof);
            }
            acc.extend_from_slice(&buf[..got]);
            if let Some(pos) = find_sub(&acc, HEAD_END) {
                // The bound is the head itself, not the read chunk: a single
                // 2 KiB read can deliver a whole oversized head, and the
                // terminator check must not bless it. (This was the gap the
                // configured-bound E2E found: `max_head_bytes = 128` still
                // forwarded a 300-byte head.)
                if pos > max_head_bytes {
                    return Err(HeadError::TooLarge);
                }
                let head = acc[..pos].to_vec();
                let rest = acc[pos + HEAD_END.len()..].to_vec();
                return Ok((head, rest));
            }
            if acc.len() > max_head_bytes {
                return Err(HeadError::TooLarge);
            }
        }
    })
    .await
    .map_err(|_| HeadError::Timeout)?
}

async fn write_error<W: AsyncWrite + Unpin>(writer: &mut W, status: u16, reason: &str) {
    let response =
        format!("HTTP/1.1 {status} {reason}\r\nconnection: close\r\ncontent-length: 0\r\n\r\n");
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        writer.write_all(response.as_bytes()),
    )
    .await;
    let _ = tokio::time::timeout(Duration::from_secs(5), writer.shutdown()).await;
}

/// Short reason phrase for a locally generated status (C9 + v0.6
/// rule actions).
pub(crate) fn phrase(status: u16) -> &'static str {
    match status {
        200 => "ok",
        201 => "created",
        202 => "accepted",
        204 => "no content",
        401 => "unauthorized",
        301 => "moved permanently",
        302 => "found",
        303 => "see other",
        304 => "not modified",
        307 => "temporary redirect",
        308 => "permanent redirect",
        400 => "bad request",
        403 => "forbidden",
        404 => "not found",
        429 => "too many requests",
        500 => "internal server error",
        502 => "bad gateway",
        503 => "service unavailable",
        504 => "gateway timeout",
        _ => "response",
    }
}

/// The "no server available" class (C9 minimal): optional custom response
/// with the configured body (counted in `local_responses_served`), else the
/// built-in minimal 503.
async fn write_no_server<W: AsyncWrite + Unpin>(
    writer: &mut W,
    cfg: &ResolvedListener,
    metrics: &Metrics,
    status: u16,
    reason: &str,
) {
    if let Some(local) = &cfg.local_response {
        metrics
            .local_responses_served
            .fetch_add(1, Ordering::Relaxed);
        let response = format!(
            "HTTP/1.1 {} {}\r\nconnection: close\r\ncontent-type: {}\r\ncontent-length: {}\r\n\r\n{}",
            local.status,
            phrase(local.status),
            local.content_type,
            local.body.len(),
            local.body
        );
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            writer.write_all(response.as_bytes()),
        )
        .await;
        let _ = tokio::time::timeout(Duration::from_secs(5), writer.shutdown()).await;
        return;
    }
    write_error(writer, status, reason).await;
}

/// Caps one exchange phase at `deadline` (B-H11/B-E12
/// `max_stream_duration`; Q5: duration ≠ inactivity). `None` = no cap;
/// `Err(())` = the cap fired and the exchange must end.
async fn until_deadline<T>(
    deadline: Option<tokio::time::Instant>,
    phase: impl std::future::Future<Output = T>,
) -> Result<T, ()> {
    match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, phase)
            .await
            .map_err(|_| ()),
        None => Ok(phase.await),
    }
}

/// Locally-served rule response (v0.6 slice 2: `redirect` and
/// `direct_response`). Keep-alive only when the exchange stayed aligned
/// (the request body was drained); otherwise `connection: close`.
async fn write_rule_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    status: u16,
    location: Option<&str>,
    content_type: Option<&str>,
    body: &str,
    extra_headers: &[String],
    close: bool,
) {
    let mut response = format!(
        "HTTP/1.1 {status} {}\r\nconnection: {}\r\n",
        phrase(status),
        if close { "close" } else { "keep-alive" }
    );
    if let Some(location) = location {
        response.push_str("location: ");
        response.push_str(location);
        response.push_str("\r\n");
    }
    for line in extra_headers {
        response.push_str(line);
        response.push_str("\r\n");
    }
    response.push_str("content-type: ");
    response.push_str(content_type.unwrap_or("text/plain"));
    response.push_str(&format!(
        "\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
    ));
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        writer.write_all(response.as_bytes()),
    )
    .await;
}

/// Auth rejection or auth-service error (B-N9/B-I9): the deny response
/// replaces the request and the connection closes (the request body was
/// never read, so the stream cannot stay aligned).
async fn write_deny<W: AsyncWrite + Unpin>(writer: &mut W, deny: &crate::auth::DenyResponse) {
    let mut response = format!(
        "HTTP/1.1 {} {}\r\nconnection: close\r\n",
        deny.status,
        phrase(deny.status)
    );
    for (name, value) in &deny.headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str(&format!(
        "content-length: {}\r\n\r\n{}",
        deny.body.len(),
        deny.body
    ));
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        writer.write_all(response.as_bytes()),
    )
    .await;
    let _ = tokio::time::timeout(Duration::from_secs(5), writer.shutdown()).await;
}

/// Reads and discards a request body so a locally-served exchange keeps
/// the connection aligned for the next one (v0.6 slice 2). `true` =
/// stream aligned (body fully consumed); a framing error leaves it
/// unaligned and the caller must close.
async fn drain_body<T: AsyncRead + Unpin>(
    reader: &mut T,
    framing: &BodyFraming,
    idle: Duration,
    metrics: &Metrics,
) -> bool {
    let discard = AtomicU64::new(0);
    match framing {
        BodyFraming::None => true,
        BodyFraming::ContentLength(len) => copy_exact(
            reader,
            &mut tokio::io::sink(),
            *len,
            idle,
            &discard,
            &metrics.idle_timeouts,
        )
        .await
        .is_ok(),
        BodyFraming::Chunked => copy_chunked(
            reader,
            &mut tokio::io::sink(),
            idle,
            &discard,
            &metrics.idle_timeouts,
        )
        .await
        .is_ok(),
        BodyFraming::UntilEof => false,
    }
}

/// New request target after a rule rewrite (v0.6 slice 2): the matched
/// prefix is replaced literally and the query string preserved.
fn rewrite_target(target: &str, rewrite: &ResolvedRewrite) -> String {
    match &rewrite.path_prefix_rewrite {
        Some(replacement) => {
            let (path, query) = match target.split_once('?') {
                Some((path, query)) => (path, Some(query)),
                None => (target, None),
            };
            let path =
                eqproxy_core::rules::rewrite_prefix(path, &rewrite.matched_prefix, replacement);
            match query {
                Some(query) => format!("{path}?{query}"),
                None => path,
            }
        }
        None => target.to_owned(),
    }
}

/// Rule rewrite applied to the forwarded copy of the head (v0.6 slice
/// 2): the request line's target is rewritten and/or the `Host` header
/// set to the configured value. The client's bytes are never mutated.
/// Same line contract as [`apply_forwarded`] (no trailing blank line).
pub(crate) fn apply_rewrite(head: &[u8], rewrite: &ResolvedRewrite, target: &str) -> Vec<u8> {
    let mut lines: Vec<&[u8]> = Vec::new();
    let mut rest = head;
    while let Some(pos) = rest.windows(2).position(|w| w == b"\r\n") {
        lines.push(&rest[..pos]);
        rest = &rest[pos + 2..];
    }
    lines.push(rest);

    let new_target = rewrite_target(target, rewrite);
    let mut out: Vec<Vec<u8>> = Vec::with_capacity(lines.len() + 1);
    let mut host_done = false;
    for (i, line) in lines.iter().enumerate() {
        if i == 0 {
            // Request line: METHOD SP target SP version.
            let mut parts = line.splitn(3, |&b| b == b' ');
            let method = parts.next().unwrap_or_default();
            let version = parts
                .next()
                .and_then(|_| parts.next())
                .unwrap_or(b"HTTP/1.1");
            let mut rebuilt = Vec::with_capacity(method.len() + new_target.len() + 16);
            rebuilt.extend_from_slice(method);
            rebuilt.push(b' ');
            rebuilt.extend_from_slice(new_target.as_bytes());
            rebuilt.push(b' ');
            rebuilt.extend_from_slice(version);
            out.push(rebuilt);
            continue;
        }
        let name_end = line.iter().position(|&b| b == b':').unwrap_or(line.len());
        if line[..name_end].eq_ignore_ascii_case(b"host")
            && let Some(host) = &rewrite.host_rewrite
        {
            out.push(format!("host: {host}").into_bytes());
            host_done = true;
            continue;
        }
        out.push(line.to_vec());
    }
    if let Some(host) = &rewrite.host_rewrite
        && !host_done
    {
        out.push(format!("host: {host}").into_bytes());
    }

    let mut joined = Vec::with_capacity(head.len() + new_target.len() + 32);
    for (i, line) in out.iter().enumerate() {
        if i > 0 {
            joined.extend_from_slice(CRLF);
        }
        joined.extend_from_slice(line);
    }
    joined
}

/// Has the peer already closed this connection? One non-blocking poll:
/// `Pending` (no data, no EOF) = alive; empty `Ready` = EOF; error or
/// pending bytes = unusable. Used before pooling (A16): a connection the
/// backend already closed must be dropped, never handed to the next
/// exchange (which would fail with 502 on its first write).
async fn peer_gone<R: AsyncBufRead + Unpin>(read: &mut R) -> bool {
    std::future::poll_fn(|cx| match Pin::new(&mut *read).poll_fill_buf(cx) {
        Poll::Ready(Ok(_)) => Poll::Ready(true),
        Poll::Ready(Err(_)) => Poll::Ready(true),
        Poll::Pending => Poll::Ready(false),
    })
    .await
}

/// Idempotent methods per RFC 9110 §9.2.2 (GET, HEAD, PUT, DELETE,
/// OPTIONS, TRACE): replay safety for B-H7 retries.
#[must_use]
pub fn method_is_idempotent(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "PUT" | "DELETE" | "OPTIONS" | "TRACE"
    )
}

/// Joins head lines with CRLF (no trailing terminator: the caller
/// writes [`HEAD_END`] separately).
fn join_head_lines(lines: &[Vec<u8>], capacity: usize) -> Vec<u8> {
    let mut joined = Vec::with_capacity(capacity);
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            joined.extend_from_slice(CRLF);
        }
        joined.extend_from_slice(line);
    }
    joined
}

/// Applies `X-Forwarded-For`/`X-Real-IP`/`X-Forwarded-Proto` per
/// listener policy (B-N4) to the forwarded copy of the head — the
/// client's bytes are never mutated.
///
/// - `Append`: `X-Forwarded-For` grows with the client address (header
///   created when absent); `X-Real-IP` only when absent.
/// - `Replace`: both headers reflect the real client address only.
/// - Both: `X-Forwarded-Proto` is the client-facing scheme (a
///   single-value header: the client's is replaced, never chained).
pub(crate) fn apply_forwarded(
    head: &[u8],
    peer: SocketAddr,
    mode: ForwardedMode,
    scheme: &str,
) -> Vec<u8> {
    if matches!(mode, ForwardedMode::Off) {
        return head.to_vec();
    }
    let client_ip = peer.ip().to_string();

    // Split into CRLF lines (the only accepted line end).
    let mut lines: Vec<&[u8]> = Vec::new();
    let mut rest = head;
    while let Some(pos) = rest.windows(2).position(|w| w == b"\r\n") {
        lines.push(&rest[..pos]);
        rest = &rest[pos + 2..];
    }
    lines.push(rest);

    let mut out: Vec<Vec<u8>> = Vec::with_capacity(lines.len() + 2);
    let mut xff_done = false;
    for line in lines {
        let name_end = line.iter().position(|&b| b == b':').unwrap_or(line.len());
        let name = line[..name_end].to_ascii_lowercase();
        match name.as_slice() {
            b"x-forwarded-for" => match mode {
                ForwardedMode::Replace => {} // dropped; rewritten below
                ForwardedMode::Append => {
                    if !xff_done {
                        xff_done = true;
                        let value = trim_ows(&line[name_end + 1..]);
                        let mut merged = b"x-forwarded-for: ".to_vec();
                        if value.is_empty() {
                            merged.extend_from_slice(client_ip.as_bytes());
                        } else {
                            merged.extend_from_slice(value);
                            merged.extend_from_slice(b", ");
                            merged.extend_from_slice(client_ip.as_bytes());
                        }
                        out.push(merged);
                    }
                }
                ForwardedMode::Off => {}
            },
            b"x-real-ip" if matches!(mode, ForwardedMode::Replace) => {} // dropped
            b"x-forwarded-proto" => {}                                   // dropped; rewritten below
            _ => out.push(line.to_vec()),
        }
    }
    if !xff_done {
        out.push(format!("x-forwarded-for: {client_ip}").into_bytes());
    }
    if matches!(mode, ForwardedMode::Replace) {
        out.push(format!("x-real-ip: {client_ip}").into_bytes());
    }
    out.push(format!("x-forwarded-proto: {scheme}").into_bytes());
    join_head_lines(&out, head.len() + 64)
}

/// Renders a rule's header action values for one request (B-E17).
/// The CORS response headers of a policy (B-I10). `preflight` adds the
/// allow-methods/allow-headers/max-age trio the preflight needs.
fn cors_response_lines(cors: &ResolvedCors, preflight: bool) -> Vec<String> {
    let mut lines = vec![format!(
        "access-control-allow-origin: {}",
        cors.allow_origin
    )];
    if cors.allow_credentials {
        lines.push("access-control-allow-credentials: true".to_owned());
    }
    if preflight {
        lines.push(format!(
            "access-control-allow-methods: {}",
            cors.allow_methods
        ));
        if let Some(headers) = &cors.allow_headers {
            lines.push(format!("access-control-allow-headers: {headers}"));
        }
        if !cors.max_age.is_zero() {
            lines.push(format!(
                "access-control-max-age: {}",
                cors.max_age.as_secs()
            ));
        }
    } else if let Some(expose) = &cors.expose_headers {
        lines.push(format!("access-control-expose-headers: {expose}"));
    }
    lines.push("vary: origin".to_owned());
    lines
}

/// A CORS preflight (B-I10): `OPTIONS` carrying both `Origin` and
/// `Access-Control-Request-Method`.
fn is_cors_preflight(request: &RequestHead) -> bool {
    request.method == "OPTIONS"
        && request.headers.iter().any(|(name, _)| name == "origin")
        && request
            .headers
            .iter()
            .any(|(name, _)| name == "access-control-request-method")
}

/// Pumps both directions of an upgrade tunnel (A7/A8) until either side
/// closes or goes idle. The connection is consumed by the tunnel.
async fn run_tunnel<CR, CW, BR, BW>(
    from_client: &mut Prefixed<CR>,
    client_write: &mut CW,
    from_backend: &mut Prefixed<BR>,
    backend_write: &mut BW,
    idle: Duration,
) where
    CR: tokio::io::AsyncRead + Unpin,
    CW: tokio::io::AsyncWrite + Unpin,
    BR: tokio::io::AsyncRead + Unpin,
    BW: tokio::io::AsyncWrite + Unpin,
{
    let _ = tokio::join!(
        tunnel_pump(from_client, backend_write, idle),
        tunnel_pump(from_backend, client_write, idle),
    );
}

/// One direction of an upgrade tunnel (A7/A8): raw bytes until EOF, an
/// error, or inactivity — `idle_timeout` is the tunnel's inactivity cap.
async fn tunnel_pump<R, W>(from: &mut R, to: &mut W, idle: Duration)
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; READ_BUF];
    loop {
        let n = match tokio::time::timeout(idle, from.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => break,
        };
        match tokio::time::timeout(idle, to.write_all(&buf[..n])).await {
            Ok(Ok(())) => {}
            _ => break,
        }
    }
    let _ = to.shutdown().await;
}

/// The value of cookie `name` in the request's `Cookie` headers (B-H8).
pub(crate) fn cookie_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .filter(|(header, _)| header == "cookie")
        .flat_map(|(_, value)| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| key.trim() == name)
        .map(|(_, value)| value.trim().to_owned())
}

fn render_header_lines(
    ops: &[(String, String)],
    peer: SocketAddr,
    host: &str,
    scheme: &str,
) -> Vec<String> {
    let remote_addr = peer.ip().to_string();
    ops.iter()
        .filter_map(|(name, value)| {
            eqproxy_core::rules::render_header_value(value, &remote_addr, host, scheme)
                .ok()
                .map(|value| format!("{name}: {value}"))
        })
        .collect()
}

/// Applies a matched rule's request header actions (B-N4/B-I4/B-E17) to
/// the forwarded copy of the head: `del` drops every line with the name,
/// `set` drops the client's and appends the new value, `add` keeps the
/// client's and appends another line. Runs before the forwarded-headers
/// policy, which a rule can never override.
pub(crate) fn apply_header_actions(
    head: &[u8],
    actions: &ResolvedHeaders,
    peer: SocketAddr,
    host: &str,
    scheme: &str,
) -> Vec<u8> {
    let mut lines: Vec<&[u8]> = Vec::new();
    let mut rest = head;
    while let Some(pos) = rest.windows(2).position(|w| w == b"\r\n") {
        lines.push(&rest[..pos]);
        rest = &rest[pos + 2..];
    }
    lines.push(rest);

    let mut out: Vec<Vec<u8>> =
        Vec::with_capacity(lines.len() + actions.set.len() + actions.add.len());
    for line in lines {
        let name_end = line.iter().position(|&b| b == b':').unwrap_or(line.len());
        let name = &line[..name_end];
        let replaced = actions
            .del
            .iter()
            .chain(actions.set.iter().map(|(name, _)| name))
            .any(|candidate| candidate.as_bytes().eq_ignore_ascii_case(name));
        if !replaced {
            out.push(line.to_vec());
        }
    }
    for line in render_header_lines(&actions.set, peer, host, scheme)
        .into_iter()
        .chain(render_header_lines(&actions.add, peer, host, scheme))
    {
        out.push(line.into_bytes());
    }
    join_head_lines(&out, head.len() + 64)
}

/// Applies a plugin's header operations to the forwarded copy (B-I5/B-E4,
/// ADR-0031). The plugin runs last, so its `set` replaces any value earlier
/// stages wrote; `remove` drops every line with that name. Names and values
/// were validated and framed out (no CR/LF, reserved headers refused) by the
/// plugin host before reaching this function.
pub(crate) fn apply_plugin_headers(
    head: &[u8],
    set: &[(String, String)],
    remove: &[String],
) -> Vec<u8> {
    let mut lines: Vec<&[u8]> = Vec::new();
    let mut rest = head;
    while let Some(pos) = rest.windows(2).position(|w| w == b"\r\n") {
        lines.push(&rest[..pos]);
        rest = &rest[pos + 2..];
    }
    lines.push(rest);

    let mut out: Vec<Vec<u8>> = Vec::with_capacity(lines.len() + set.len());
    for line in lines {
        let name_end = line.iter().position(|&b| b == b':').unwrap_or(line.len());
        let name = &line[..name_end];
        let dropped = remove
            .iter()
            .chain(set.iter().map(|(name, _)| name))
            .any(|candidate| candidate.as_bytes().eq_ignore_ascii_case(name));
        if !dropped {
            out.push(line.to_vec());
        }
    }
    for (name, value) in set {
        out.push(format!("{name}: {value}").into_bytes());
    }
    let capacity = head.len()
        + set
            .iter()
            .map(|(name, value)| name.len() + value.len() + 4)
            .sum::<usize>();
    join_head_lines(&out, capacity)
}

/// Appends the rendered `response` header actions to the response head
/// the client sees (B-N4/B-I4/B-E17).
fn append_response_headers(head: &[u8], lines: &[String]) -> Vec<u8> {
    let mut split: Vec<Vec<u8>> = Vec::new();
    let mut rest = head;
    while let Some(pos) = rest.windows(2).position(|w| w == b"\r\n") {
        split.push(rest[..pos].to_vec());
        rest = &rest[pos + 2..];
    }
    split.push(rest.to_vec());
    for line in lines {
        split.push(line.as_bytes().to_vec());
    }
    join_head_lines(&split, head.len() + lines.len() * 32)
}

/// First value of a lower-cased request header, for the access log only.
fn access_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header, _)| header == name)
        .map(|(_, value)| value.as_str())
}

/// Request target without its query string (ADR-0020: tokens in a query are
/// never copied to a log that leaves the host).
fn access_path(target: &str) -> &str {
    target.split('?').next().unwrap_or(target)
}

/// Logs a request that never parsed (408/431/4xx): method and path are `-`.
fn log_unparsed(
    cfg: &ResolvedListener,
    peer: SocketAddr,
    protocol: crate::access::ClientProtocol,
    status: u16,
) {
    let Some(log) = cfg.access.as_ref() else {
        return;
    };
    let mut record = crate::access::AccessRecord::new(
        Arc::clone(log),
        &cfg.name,
        peer,
        protocol,
        "-",
        "-",
        "-",
        None,
        None,
    );
    record.status(status);
}

/// Response-cache state for one exchange (B-N7/H1, ADR-0034). The lookup
/// runs after routing and the plugin, before any backend byte: a hit
/// answers without dialing, a miss or stale entry registers the fetch
/// under the cache lock, and anything else streams exactly as before.
enum CacheAction {
    /// Cache disabled, tunnel/upgrade, or bypassed: the origin path.
    Off,
    /// Serve the stored entry without dialing.
    Serve(Arc<cache::StoredEntry>),
    /// Fetch from origin, then store (or refresh when `stale` is set).
    Origin(CacheFetch),
    /// A lock waiter whose owner is gone or stuck: fetch without
    /// registering, so waiters never pile up behind a dead fetch.
    Direct(CacheFetch),
    /// Another task owns the fetch: resolved (wait, then hit or fetch)
    /// before the dial.
    Wait(CacheFetch, Arc<cache::SharedFetch>),
}

/// What an origin fetch remembers to complete the cache bookkeeping.
struct CacheFetch {
    key: cache::CacheKey,
    /// Forwarded headers (rules, rewrites and plugin mutations applied):
    /// the backend-visible values the `Vary` key and the conditional
    /// headers come from.
    headers: Vec<(String, String)>,
    /// The client sent `Cache-Control: no-cache`.
    force_revalidate: bool,
    /// Stale entry being revalidated (`None` = cold miss).
    stale: Option<Arc<cache::StoredEntry>>,
}

/// A storable origin response, fully assembled in memory (B-N7/H1): only
/// `Content-Length` bodies under the entry bound assemble; chunked and
/// close-delimited responses stream through uncached, never re-framed.
struct StorePlan {
    key: cache::CacheKey,
    /// A lock waiter's fallback fetch stores without touching the
    /// in-flight table (the owner already published).
    direct: bool,
    vary: Vec<String>,
    vary_values: Vec<String>,
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    etag: Option<String>,
    last_modified: Option<String>,
    ttl: Duration,
    len: u64,
}

/// Decides the cache action for one parsed request. Pure except for the
/// lookup registration and the bypass counter.
fn plan_cache(
    cache: &cache::Cache,
    backend_affinity_cookie: bool,
    request: &RequestHead,
    forwarded_head: &[u8],
    head_limits: HeadLimits,
    scheme: &str,
    metrics: &Metrics,
) -> CacheAction {
    let bypass = || {
        metrics.cache_bypasses.fetch_add(1, Ordering::Relaxed);
        CacheAction::Off
    };
    // Tunnels never cache: an `Upgrade` handshake becomes a raw byte
    // pipe, not a storable exchange.
    if request.wants_upgrade {
        return bypass();
    }
    // The key uses the forwarded head (rules, rewrites and plugin
    // mutations applied): two requests that reach the backend differently
    // never share an entry. A rule-injected session header bypasses here,
    // exactly like a client-sent one.
    let forwarded = match parse_request_head(forwarded_head, head_limits) {
        Ok(forwarded) => forwarded,
        Err(_) => return bypass(),
    };
    let framing_none = matches!(request.framing, BodyFraming::None);
    let decision = match cache::decide(
        &request.method,
        framing_none,
        &forwarded.headers,
        backend_affinity_cookie,
    ) {
        Ok(decision) => decision,
        Err(_) => return bypass(),
    };
    let fetch = CacheFetch {
        key: cache::base_key(&request.method, scheme, &forwarded.host, &forwarded.target),
        headers: forwarded.headers,
        force_revalidate: decision.force_revalidate,
        stale: None,
    };
    match cache.lookup(&fetch.key, &fetch.headers, fetch.force_revalidate) {
        cache::Lookup::Hit(entry) => CacheAction::Serve(entry),
        cache::Lookup::Fetch => {
            metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
            CacheAction::Origin(fetch)
        }
        cache::Lookup::Revalidate(stale) => {
            metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
            CacheAction::Origin(CacheFetch {
                stale: Some(stale),
                ..fetch
            })
        }
        cache::Lookup::Wait(shared) => CacheAction::Wait(fetch, shared),
    }
}

/// Resolves a lock wait before the dial: a published fetch becomes a hit
/// (or the new owner), a failed or timed-out one a direct fetch.
async fn resolve_cache_wait(
    cache: &cache::Cache,
    fetch: CacheFetch,
    shared: &cache::SharedFetch,
    metrics: &Metrics,
) -> CacheAction {
    match cache.wait(shared).await {
        Some(cache::FetchResult::Ready) => {
            match cache.lookup(&fetch.key, &fetch.headers, fetch.force_revalidate) {
                cache::Lookup::Hit(entry) => CacheAction::Serve(entry),
                cache::Lookup::Fetch => {
                    metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
                    CacheAction::Origin(fetch)
                }
                cache::Lookup::Revalidate(stale) => {
                    metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
                    CacheAction::Origin(CacheFetch {
                        stale: Some(stale),
                        ..fetch
                    })
                }
                // Another fetch started while this waiter woke: fetch
                // alone rather than queue behind it.
                cache::Lookup::Wait(_) => {
                    metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
                    CacheAction::Direct(fetch)
                }
            }
        }
        // Failed, unstorable or stuck fetch: fetch directly (exactly one
        // extra origin load, never a wrong byte).
        Some(cache::FetchResult::Gone) | None => {
            metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
            CacheAction::Direct(fetch)
        }
    }
}

/// Guard arming the owner's fetch: any error return after the plan
/// publishes `Gone` (waiters fetch directly) and drops a stale entry,
/// unless the success path disarmed it first. Spawned, never awaited:
/// the error path must not wait on disk I/O.
struct CacheGuard {
    cache: Option<Arc<cache::Cache>>,
    key: Option<cache::CacheKey>,
}

impl CacheGuard {
    fn armed(cache: &Arc<cache::Cache>, key: &cache::CacheKey) -> Self {
        Self {
            cache: Some(Arc::clone(cache)),
            key: Some(key.clone()),
        }
    }

    fn disarm(&mut self) {
        self.key = None;
        self.cache = None;
    }
}

impl Drop for CacheGuard {
    fn drop(&mut self) {
        if let (Some(cache), Some(key)) = (self.cache.take(), self.key.take()) {
            tokio::spawn(async move {
                cache.complete(key, cache::FetchOutcome::Gone).await;
            });
        }
    }
}

/// Whether the parsed origin response may assemble into a store entry.
/// `None` streams through untouched (chunked and close-delimited bodies
/// are never re-framed; oversized and unstorable responses never store).
fn store_plan(
    cache: &cache::Cache,
    fetch: &CacheFetch,
    direct: bool,
    method: &str,
    framing: BodyFraming,
    response_head: &[u8],
) -> Option<StorePlan> {
    // `HEAD` populates nothing (served from `GET` entries); only
    // `Content-Length` bodies under the entry bound assemble.
    if method != "GET" {
        return None;
    }
    let BodyFraming::ContentLength(len) = framing else {
        return None;
    };
    if len > cache.max_entry_bytes() as u64 {
        return None;
    }
    let facts = cache::parse_origin_head(response_head)?;
    let vary = cache::storable_vary(&facts)?;
    let ttl = cache::effective_ttl(cache.default_ttl(), &facts.cache_control);
    if ttl.is_zero() && facts.etag.is_none() && facts.last_modified.is_none() {
        return None;
    }
    Some(StorePlan {
        key: fetch.key.clone(),
        direct,
        vary_values: cache::vary_values(&fetch.headers, &vary),
        vary,
        status: facts.status,
        reason: facts.reason,
        headers: cache::end_to_end(&facts.headers),
        etag: facts.etag,
        last_modified: facts.last_modified,
        ttl,
        len,
    })
}

/// Serves a stored entry without dialing (B-N7/H1): rule response headers
/// and CORS re-apply per request, compression re-negotiates from the
/// client's `Accept-Encoding`, and the answer carries `X-Cache` plus its
/// age. A matching client `If-None-Match` earns a `304` with no body.
#[allow(clippy::too_many_arguments)]
async fn serve_cached<CW: AsyncWrite + Unpin>(
    client_write: &mut CW,
    cfg: &ResolvedListener,
    rule_headers: Option<&ResolvedHeaders>,
    peer: SocketAddr,
    host: &str,
    scheme: &str,
    request: &RequestHead,
    entry: &cache::StoredEntry,
    access: &mut Option<crate::access::AccessRecord>,
    metrics: &Metrics,
    revalidated: bool,
) {
    let client_304 = request
        .headers
        .iter()
        .find(|(name, _)| name == "if-none-match")
        .is_some_and(|(_, value)| cache::client_fresh(value, entry.etag.as_deref()));
    let status = if client_304 { 304 } else { entry.status };
    let mut head = if client_304 {
        let mut head = format!("HTTP/1.1 304 {}", phrase(304)).into_bytes();
        for (name, value) in &entry.headers {
            if name == "content-encoding" || name == "content-range" {
                continue;
            }
            head.extend_from_slice(b"\r\n");
            head.extend_from_slice(name.as_bytes());
            head.extend_from_slice(b": ");
            head.extend_from_slice(value.as_bytes());
        }
        head
    } else {
        cache::render_head(entry)
    };
    let mut extra = rule_headers
        .map(|actions| render_header_lines(&actions.response, peer, host, scheme))
        .unwrap_or_default();
    if let Some(cors) = rule_headers.and_then(|actions| actions.cors.as_ref()) {
        extra.extend(cors_response_lines(cors, false));
    }
    if !extra.is_empty() {
        head = append_response_headers(&head, &extra);
    }
    head.extend_from_slice(if revalidated {
        b"\r\nx-cache: REVALIDATED"
    } else {
        b"\r\nx-cache: HIT"
    });
    if !client_304 {
        head.extend_from_slice(format!("\r\nage: {}", entry.age_secs()).as_bytes());
    }
    let accept_encoding = request
        .headers
        .iter()
        .find(|(name, _)| name == "accept-encoding")
        .map(|(_, value)| value.as_str());
    let settings = cfg.compression.as_ref();
    let encoding = if client_304 {
        None
    } else {
        settings.and_then(|settings| {
            compression::eligible(
                &request.method,
                request.version,
                accept_encoding,
                &compression::ResponseFacts {
                    status: entry.status,
                    no_body: entry.framing_none(),
                    declared_len: entry.declared_len(),
                    head: &head,
                },
                settings,
            )
        })
    };
    if let Some(encoding) = encoding {
        head = compression::rewrite_head(&head, encoding);
        match encoding {
            compression::Encoding::Gzip => metrics
                .compression_gzip_responses
                .fetch_add(1, Ordering::Relaxed),
            compression::Encoding::Brotli => metrics
                .compression_brotli_responses
                .fetch_add(1, Ordering::Relaxed),
        };
    }
    if let Some(record) = access.as_mut() {
        record.status(status);
        let bytes = if client_304 || request.method == "HEAD" {
            Some(0)
        } else if encoding.is_some() {
            None
        } else {
            Some(entry.body_len() as u64)
        };
        if let Some(bytes) = bytes {
            record.bytes(bytes);
        }
    }
    metrics
        .http_requests_proxied
        .fetch_add(1, Ordering::Relaxed);
    if write_with_timeout(client_write, &head, cfg.idle_timeout)
        .await
        .is_err()
        || write_with_timeout(client_write, HEAD_END, cfg.idle_timeout)
            .await
            .is_err()
    {
        return;
    }
    if client_304 || request.method == "HEAD" {
        return;
    }
    let body: &[u8] = &entry.body;
    match encoding {
        Some(encoding) => {
            let Some(settings) = settings else { return };
            let mut reader = body;
            let _ = copy_compressed_body(
                &mut reader,
                client_write,
                CompressPlan {
                    framing: BodyFraming::ContentLength(body.len() as u64),
                    encoding,
                    settings,
                    pipe: cfg
                        .limits
                        .stream_buffer_bytes
                        .unwrap_or(DEFAULT_COMPRESSION_PIPE),
                },
                cfg.idle_timeout,
                metrics,
            )
            .await;
        }
        None => {
            let _ = write_with_timeout(client_write, body, cfg.idle_timeout).await;
        }
    }
}

/// Closes one origin exchange: counts it, attributes it to the serving
/// server (CE4) and the passive health machine (B-N10), then pools the
/// backend connection under the A16 reuse contract or drops it.
/// Returns `true` when the client connection closes with it.
#[allow(clippy::too_many_arguments)]
fn finish_exchange(
    metrics: &Metrics,
    listener: &str,
    backend: &ResolvedBackend,
    served_addr: SocketAddr,
    route_name: Option<&str>,
    maintenance: bool,
    status: u16,
    poolable: bool,
    req_close: bool,
    resp_close: bool,
    clean_boundary: bool,
    backend_alive: bool,
    conn_addr: SocketAddr,
    backend_read: BufReader<BoxRead>,
    backend_write: BoxWrite,
) -> bool {
    metrics
        .http_requests_proxied
        .fetch_add(1, Ordering::Relaxed);
    // Opt-in detail (CE4): the exchange is attributed to the server that
    // served it and to the rule that matched (if any). Disabled, this is
    // one relaxed load and no allocation.
    if metrics.detail.enabled() {
        let failed = status >= 500;
        metrics
            .detail
            .record_server(&backend.name, &served_addr.to_string(), failed);
        if let Some(route) = route_name {
            metrics.detail.record_route(listener, route, failed);
        }
    }
    // Passive detection (B-N10): with `passive = true`, real-traffic
    // verdicts feed the fall/rise machine — 5xx = failure (the
    // "500 → DOWN" acceptance criterion), anything else = success.
    if backend.health_check.as_ref().is_some_and(|h| h.passive) {
        if status >= 500 {
            backend.balancer.report_fail(conn_addr);
        } else {
            backend.balancer.report_ok(conn_addr);
        }
    }
    // Reuse-safety contract (A16): a pooled connection must end the
    // exchange byte-aligned at a message boundary.
    if poolable && !req_close && !resp_close && clean_boundary && backend_alive && !maintenance {
        backend
            .pool
            .checkin(conn_addr, backend_read, backend_write, Instant::now());
        return false;
    }
    if !clean_boundary {
        // Counted, not logged: the counter is what operators alert on
        // (bounded cardinality, no labels).
        metrics
            .backend_connections_discarded
            .fetch_add(1, Ordering::Relaxed);
    }
    drop((backend_read, backend_write));
    // `false` falls through to the keep-alive loop with no backend
    // connection held, exactly like the pre-cache path.
    req_close || resp_close
}

/// Serves a full HTTP/1.1 client connection (keep-alive included).
///
/// Takes the client stream halves (plain TCP or already-accepted TLS) and the
/// peer addresses for PROXY protocol (A9). With no servers available the
/// exchange gets 503 (customizable via `local_response`, C9); when the chosen
/// server fails, 502 (SPEC §7.4). Connect-phase failures retry per the
/// backend retry policy (B-H7: idempotent unless explicit opt-in).
pub async fn serve_http<CR, CW>(
    client_read: CR,
    client_write: CW,
    peer: SocketAddr,
    local: SocketAddr,
    cfg: &ResolvedListener,
    metrics: Arc<Metrics>,
    protocol: crate::access::ClientProtocol,
) where
    CR: AsyncRead + Unpin,
    CW: AsyncWrite + Unpin,
{
    let limits = cfg.limits;
    let head_limits = HeadLimits {
        max_head_bytes: limits.max_head_bytes,
        max_headers: limits.max_headers,
    };
    let body_cap = (limits.max_body_bytes > 0).then_some(limits.max_body_bytes);
    let mut client_read = BufReader::new(client_read);
    let mut client_write = client_write;
    let mut first_exchange = true;
    // Bytes the client already sent beyond the current exchange (HTTP/1.1
    // pipelining): carried across loop iterations instead of dropped with
    // the exchange scope, so a queued request is never lost.
    let mut client_carry: Vec<u8> = Vec::new();

    loop {
        // --- Client phase: request head ---
        // Prefixed serves the previous exchange's leftover before the
        // socket (the same shape the server phase uses for the carry).
        let mut source = Prefixed {
            prefix: std::mem::take(&mut client_carry),
            pos: 0,
            inner: &mut client_read,
        };
        // The bound of the wait is the phase it belongs to: the first request
        // of a connection is the client-header phase (`client_header_timeout`,
        // answered with 408), while a request on an already-served keep-alive
        // connection is connection inactivity (`idle_timeout`): the proxy
        // promises to hold the connection open for that window, and dropping
        // it at the header-phase bound would break the documented behaviour
        // (a client idle for 5 s loses a connection it may keep for 60 s).
        let head_timeout = if first_exchange {
            cfg.client_header_timeout
        } else {
            cfg.idle_timeout
        };
        let (head_bytes, rest) =
            match read_head(&mut source, head_timeout, limits.max_head_bytes).await {
                Ok(pair) => pair,
                Err(HeadError::Eof) => return,
                Err(HeadError::Timeout) => {
                    if first_exchange {
                        metrics.header_timeouts.fetch_add(1, Ordering::Relaxed);
                        log_unparsed(cfg, peer, protocol, 408);
                        write_error(&mut client_write, 408, "request timeout").await;
                    } else {
                        // An idle keep-alive close is normal traffic: counted as
                        // inactivity, never as a client protocol failure.
                        metrics.idle_timeouts.fetch_add(1, Ordering::Relaxed);
                    }
                    return;
                }
                Err(HeadError::TooLarge) => {
                    metrics
                        .http_requests_rejected
                        .fetch_add(1, Ordering::Relaxed);
                    log_unparsed(cfg, peer, protocol, 431);
                    write_error(&mut client_write, 431, "request header fields too large").await;
                    return;
                }
                Err(HeadError::Io) => return,
            };
        first_exchange = false;
        // Exact stream remainder after the head, in order: bytes read past
        // the terminator plus any prefix bytes read_head never consumed.
        let unread_prefix = source.prefix.split_off(source.pos);
        let mut carry = rest;
        carry.extend(unread_prefix);

        let request = match parse_request_head(&head_bytes, head_limits) {
            Ok(request) => request,
            Err(reject) => {
                metrics
                    .http_requests_rejected
                    .fetch_add(1, Ordering::Relaxed);
                log_unparsed(cfg, peer, protocol, reject.status);
                write_error(&mut client_write, reject.status, reject.reason).await;
                return;
            }
        };

        // Access log (ADR-0020): one record per parsed request. Every terminal
        // path below sets what it knows; dropping the record stamps the
        // duration and sends the entry, so `return` and `continue` both log.
        let mut access = cfg.access.as_ref().map(|log| {
            crate::access::AccessRecord::new(
                Arc::clone(log),
                &cfg.name,
                peer,
                protocol,
                &request.method,
                access_path(&request.target),
                &request.host,
                access_header(&request.headers, "referer"),
                access_header(&request.headers, "user-agent"),
            )
        });

        // --- Route the request (B-H3/B-H4): first matching rule wins,
        // the listener's default backend is the fallback. Selection runs
        // per exchange: a keep-alive connection may route each request to
        // a different backend.
        let facts = eqproxy_core::rules::RequestFacts {
            method: &request.method,
            host: &request.host,
            // CONNECT (A8) routes on host only: there is no path in an
            // authority-form target.
            path: if request.method == "CONNECT" {
                "/"
            } else {
                eqproxy_core::rules::path_of(&request.target)
            },
            headers: &request.headers,
            peer: peer.ip(),
            maps: cfg.maps.as_ref(),
        };
        // The rule name is kept so the exchange can be attributed to it when
        // the opt-in detail registry is on (CE4).
        let (decision, route_name) = cfg.decide_routed(&facts);
        // Rate limit (B-N8/B-I7/B-E16): a token bucket per client IP and
        // rule, in-memory (no network in the hot path, Q6). Over the
        // limit the request is rejected explicitly (429 + counter) and
        // the connection closes — never silently dropped or queued.
        if let Some(limiter) = decision.rate_limiter()
            && !limiter.try_acquire(peer.ip())
        {
            metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
            if let Some(record) = access.as_mut() {
                record.status(429);
            }
            write_error(&mut client_write, 429, "too many requests").await;
            return;
        }
        // Authentication (B-N9/B-I9): Basic first (local), then the
        // external auth subrequest — before any action runs, preflight
        // included (nginx parity). Fail closed: an auth service that
        // cannot decide rejects the request explicitly (502/500), never
        // forwards it.
        if let Some(auth) = decision.auth() {
            match crate::auth::check(
                auth,
                &request,
                cfg.connect_timeout,
                cfg.server_header_timeout,
            )
            .await
            {
                crate::auth::AuthOutcome::Allow => {}
                crate::auth::AuthOutcome::Deny(deny) => {
                    metrics.auth_denied.fetch_add(1, Ordering::Relaxed);
                    if let Some(record) = access.as_mut() {
                        record.status(deny.status);
                        record.bytes(u64::try_from(deny.body.len()).unwrap_or(u64::MAX));
                    }
                    write_deny(&mut client_write, &deny).await;
                    return;
                }
                crate::auth::AuthOutcome::Error(deny) => {
                    metrics.auth_service_errors.fetch_add(1, Ordering::Relaxed);
                    if let Some(record) = access.as_mut() {
                        record.status(deny.status);
                        record.bytes(u64::try_from(deny.body.len()).unwrap_or(u64::MAX));
                    }
                    write_deny(&mut client_write, &deny).await;
                    return;
                }
            }
        }
        let mut from_client = Prefixed {
            prefix: carry,
            pos: 0,
            inner: &mut client_read,
        };
        let scheme: &str = if cfg.server_tls.is_some() {
            "https"
        } else {
            "http"
        };
        let (backend, rewrite, rule_headers) = match decision {
            RouteDecision::Proxy {
                backend,
                rewrite,
                headers,
            } => (backend, rewrite, headers),
            RouteDecision::Redirect {
                status,
                location,
                headers,
            } => {
                // Templates are validated at the config gate; a failure
                // here means a corrupted config (fail closed).
                let location =
                    eqproxy_core::rules::render_location(location, &request.host, &request.target)
                        .unwrap_or_else(|_| "about:blank".to_owned());
                metrics.redirects_served.fetch_add(1, Ordering::Relaxed);
                // A local answer is final: with `Expect: 100-continue`
                // the body was never sent (and must not be awaited) and
                // `UntilEof` bodies have no boundary — both close after
                // the response. Otherwise the body is drained so the
                // connection stays aligned for the next exchange.
                let aligned = !request.expect_continue
                    && !matches!(request.framing, BodyFraming::UntilEof)
                    && drain_body(
                        &mut from_client,
                        &request.framing,
                        cfg.idle_timeout,
                        &metrics,
                    )
                    .await;
                let close = !aligned || request.wants_close;
                let mut extra_headers = headers
                    .map(|actions| {
                        render_header_lines(&actions.response, peer, &request.host, scheme)
                    })
                    .unwrap_or_default();
                if let Some(cors) = headers.and_then(|actions| actions.cors.as_ref()) {
                    extra_headers.extend(cors_response_lines(cors, false));
                }
                if let Some(record) = access.as_mut() {
                    record.status(status);
                    record.bytes(0);
                }
                write_rule_response(
                    &mut client_write,
                    status,
                    Some(&location),
                    None,
                    "",
                    &extra_headers,
                    close,
                )
                .await;
                if close {
                    let _ =
                        tokio::time::timeout(Duration::from_secs(5), client_write.shutdown()).await;
                    return;
                }
                client_carry = from_client.prefix.split_off(from_client.pos);
                continue;
            }
            RouteDecision::Direct {
                status,
                content_type,
                body,
                headers,
            } => {
                metrics
                    .direct_responses_served
                    .fetch_add(1, Ordering::Relaxed);
                let aligned = !request.expect_continue
                    && !matches!(request.framing, BodyFraming::UntilEof)
                    && drain_body(
                        &mut from_client,
                        &request.framing,
                        cfg.idle_timeout,
                        &metrics,
                    )
                    .await;
                let close = !aligned || request.wants_close;
                let mut extra_headers = headers
                    .map(|actions| {
                        render_header_lines(&actions.response, peer, &request.host, scheme)
                    })
                    .unwrap_or_default();
                if let Some(cors) = headers.and_then(|actions| actions.cors.as_ref()) {
                    extra_headers.extend(cors_response_lines(cors, false));
                }
                if let Some(record) = access.as_mut() {
                    record.status(status);
                    record.bytes(u64::try_from(body.len()).unwrap_or(u64::MAX));
                }
                write_rule_response(
                    &mut client_write,
                    status,
                    None,
                    Some(content_type),
                    body,
                    &extra_headers,
                    close,
                )
                .await;
                if close {
                    let _ =
                        tokio::time::timeout(Duration::from_secs(5), client_write.shutdown()).await;
                    return;
                }
                client_carry = from_client.prefix.split_off(from_client.pos);
                continue;
            }
        };

        // WASM request filter (B-I5/B-E4, ADR-0031): proxied requests only,
        // after authentication and before any backend byte is dialed. It
        // receives the client's head; its mutations are applied last to the
        // forwarded copy, below.
        let plugin_policy = cfg.plugin.as_ref().map(|plugin| plugin.policy());
        let mut plugin_set: Vec<(String, String)> = Vec::new();
        let mut plugin_remove: Vec<String> = Vec::new();
        if let Some(plugin) = cfg.plugin.as_ref() {
            metrics.plugin_requests.fetch_add(1, Ordering::Relaxed);
            match plugin.run(&head_bytes) {
                crate::plugin::PluginOutcome::Allow { set, remove } => {
                    plugin_set = set;
                    plugin_remove = remove;
                }
                crate::plugin::PluginOutcome::Deny(status) => {
                    metrics.plugin_denied.fetch_add(1, Ordering::Relaxed);
                    if let Some(record) = access.as_mut() {
                        record.status(status);
                    }
                    write_error(&mut client_write, status, "denied by plugin").await;
                    return;
                }
                crate::plugin::PluginOutcome::Failed { .. } => {
                    metrics.plugin_errors.fetch_add(1, Ordering::Relaxed);
                    if plugin_policy == Some(crate::plugin::FailurePolicy::Closed) {
                        if let Some(record) = access.as_mut() {
                            record.status(503);
                        }
                        write_error(&mut client_write, 503, "plugin failure").await;
                        return;
                    }
                    // `open`: forward the request unchanged, never a partial
                    // set of mutations from a failed invocation.
                }
            }
        }

        // Forwarded headers (B-N4) and rule rewrites (v0.6 slice 2):
        // applied to the forwarded copy only, never to the client's bytes.
        // Rule header actions run first; the forwarded-headers policy is
        // applied last, so `replace` cannot be undone by a rule. The plugin
        // runs after both, per ADR-0031.
        let acted = rule_headers
            .map(|actions| apply_header_actions(&head_bytes, actions, peer, &request.host, scheme));
        let base: &[u8] = acted.as_deref().unwrap_or(&head_bytes);
        let forwarded_base = apply_forwarded(base, peer, cfg.forwarded_headers, scheme);
        let forwarded_base = match rewrite {
            Some(rewrite) => apply_rewrite(&forwarded_base, rewrite, &request.target),
            None => forwarded_base,
        };
        let mut forwarded_head = if plugin_set.is_empty() && plugin_remove.is_empty() {
            forwarded_base
        } else {
            let mutated = apply_plugin_headers(&forwarded_base, &plugin_set, &plugin_remove);
            // A plugin can only grow the head through validated header lines,
            // but the listener's own bound still applies: over it is a plugin
            // failure, handled by the same `on_error` policy (open forwards
            // the unmutated head, never a truncated one).
            if mutated.len() > limits.max_head_bytes {
                metrics.plugin_errors.fetch_add(1, Ordering::Relaxed);
                if plugin_policy == Some(crate::plugin::FailurePolicy::Closed) {
                    if let Some(record) = access.as_mut() {
                        record.status(503);
                    }
                    write_error(&mut client_write, 503, "plugin failure").await;
                    return;
                }
                forwarded_base
            } else {
                mutated
            }
        };

        // Request mirror (B-H3): resolved per matching request — the rule's
        // policy decides by its own percentage, and only a sampled request
        // costs anything. Placement matters: a mirror never runs for a
        // request answered locally below (preflight) or rejected by the
        // forwarding phase.
        let mirror = rule_headers
            .and_then(|actions| actions.mirror.as_ref())
            .filter(|policy| policy.sample())
            .cloned();

        // CORS preflight (B-I10): a matched rule with a CORS policy
        // answers OPTIONS locally — the backend never sees the preflight.
        if is_cors_preflight(&request)
            && let Some(cors) = rule_headers.and_then(|actions| actions.cors.as_ref())
        {
            let aligned = !request.expect_continue
                && !matches!(request.framing, BodyFraming::UntilEof)
                && drain_body(
                    &mut from_client,
                    &request.framing,
                    cfg.idle_timeout,
                    &metrics,
                )
                .await;
            let close = !aligned || request.wants_close;
            let mut extra_headers = cors_response_lines(cors, true);
            extra_headers.extend(
                rule_headers
                    .map(|actions| {
                        render_header_lines(&actions.response, peer, &request.host, scheme)
                    })
                    .unwrap_or_default(),
            );
            if let Some(record) = access.as_mut() {
                record.status(204);
                record.bytes(0);
            }
            write_rule_response(
                &mut client_write,
                204,
                None,
                None,
                "",
                &extra_headers,
                close,
            )
            .await;
            if close {
                let _ = tokio::time::timeout(Duration::from_secs(5), client_write.shutdown()).await;
                return;
            }
            client_carry = from_client.prefix.split_off(from_client.pos);
            continue;
        }

        // Request-body cap (B-N19): a declared length over the bound is
        // refused before the backend is dialed, so not one byte of an
        // unacceptable body is forwarded. `0` = unlimited (the default, and
        // the behaviour before this limit existed).
        if let BodyFraming::ContentLength(len) = request.framing
            && limits.max_body_bytes > 0
            && len > limits.max_body_bytes
        {
            metrics
                .http_requests_rejected
                .fetch_add(1, Ordering::Relaxed);
            if let Some(record) = access.as_mut() {
                record.status(413);
                record.bytes(0);
            }
            write_error(&mut client_write, 413, "request body too large").await;
            return;
        }

        // Response cache lookup (B-N7/H1, ADR-0034): after routing, auth
        // and the plugin, before any backend byte. A hit answers here
        // without dialing; anything else falls through to the origin path.
        // The guard publishes `Gone` on any error return past this point,
        // so waiters never hang on a fetch that died mid-exchange.
        let mut cache_guard: Option<CacheGuard> = None;
        let mut cache_action = match cfg.cache.as_ref() {
            Some(cache) => {
                let affinity_cookie = backend
                    .affinity
                    .as_ref()
                    .is_some_and(|affinity| affinity.mode == AffinityMode::Cookie);
                plan_cache(
                    cache,
                    affinity_cookie,
                    &request,
                    &forwarded_head,
                    head_limits,
                    scheme,
                    &metrics,
                )
            }
            None => CacheAction::Off,
        };
        if let CacheAction::Wait(fetch, shared) = cache_action {
            // Planned from `Some`, so the cache is there; `None` degrades
            // to the uncached path instead of panicking the exchange.
            cache_action = match cfg.cache.as_ref() {
                Some(cache) => resolve_cache_wait(cache, fetch, &shared, &metrics).await,
                None => CacheAction::Off,
            };
        }
        if let CacheAction::Serve(entry) = &cache_action {
            metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            entry.hits.fetch_add(1, Ordering::Relaxed);
            serve_cached(
                &mut client_write,
                cfg,
                rule_headers,
                peer,
                &request.host,
                scheme,
                &request,
                entry,
                &mut access,
                &metrics,
                false,
            )
            .await;
            client_carry = from_client.prefix.split_off(from_client.pos);
            if request.wants_close {
                let _ = tokio::time::timeout(Duration::from_secs(5), client_write.shutdown()).await;
                return;
            }
            continue;
        }
        // A stale entry earns conditional headers; the `304` below
        // refreshes it without touching the body.
        if let CacheAction::Origin(fetch) = &cache_action {
            if let Some(cache) = cfg.cache.as_ref() {
                cache_guard = Some(CacheGuard::armed(cache, &fetch.key));
            }
            if let Some(stale) = &fetch.stale {
                // The head carries no trailing terminator (`HEAD_END` goes
                // on the wire separately), so conditional lines join with
                // a leading CRLF — a trailing one would glue them onto
                // the last header line and the origin would never see
                // the validator.
                if let Some(etag) = &stale.etag {
                    forwarded_head
                        .extend_from_slice(format!("\r\nif-none-match: {etag}").as_bytes());
                }
                if let Some(last_modified) = &stale.last_modified {
                    forwarded_head.extend_from_slice(
                        format!("\r\nif-modified-since: {last_modified}").as_bytes(),
                    );
                }
            }
        }

        // B-H11/B-E12 (`max_stream_duration`, Q5): one total cap for the
        // forwarded exchange — request body, response head and response
        // body — on top of the per-phase timeouts. `ZERO` disables it.
        let stream_deadline = (cfg.max_stream_duration > Duration::ZERO)
            .then(|| tokio::time::Instant::now() + cfg.max_stream_duration);

        // --- Backend: reuse from the pool (A16) or dial again ---
        // Retry safety (B-H7): only idempotent requests are replayed
        // unless the backend opts in explicitly.
        let ctx = if method_is_idempotent(&request.method) {
            RetryContext::idempotent()
        } else {
            RetryContext::non_idempotent()
        };
        // Affinity (B-H8/B-N13/B-I8): pin from the request's sticky
        // cookie (cookie mode); source mode hashes the IP in the balancer.
        let affinity_cookie = backend.affinity.as_ref().and_then(|affinity| {
            (affinity.mode == AffinityMode::Cookie)
                .then(|| cookie_value(&request.headers, &affinity.cookie))
                .flatten()
        });
        // `active` (B-H5 leastconn) holds the in-flight slot from the pick
        // to the end of this exchange (released on drop). Its mode tells the
        // completion path whether the slot may still pool a connection
        // (ADR-0028: after a `maintenance` declaration the pool must hold
        // nothing for the server).
        let (conn, active) = match checkout_or_connect(
            cfg,
            backend,
            peer,
            local,
            &metrics,
            ctx,
            affinity_cookie.as_deref(),
        )
        .await
        {
            Ok(picked) => picked,
            Err(OutboundError::NoServer) => {
                // All servers down/drained (B11): explicit 503 (C9 custom).
                if let Some(record) = access.as_mut() {
                    record.status(
                        cfg.local_response
                            .as_ref()
                            .map_or(503, |local| local.status),
                    );
                }
                write_no_server(&mut client_write, cfg, &metrics, 503, "service unavailable").await;
                return;
            }
            Err(OutboundError::QueueFull) | Err(OutboundError::QueueTimeout) => {
                // B-H7: bounded queue rejected explicitly (never silent).
                if let Some(record) = access.as_mut() {
                    record.status(
                        cfg.local_response
                            .as_ref()
                            .map_or(503, |local| local.status),
                    );
                }
                write_no_server(&mut client_write, cfg, &metrics, 503, "service unavailable").await;
                return;
            }
            Err(OutboundError::Connect) => {
                if let Some(record) = access.as_mut() {
                    record.status(502);
                }
                write_error(&mut client_write, 502, "bad gateway").await;
                return;
            }
        };
        let served_addr = conn.addr;
        if let Some(record) = access.as_mut() {
            record.backend(&backend.name, served_addr);
        }
        // An HTTP/2 exchange owns one stream: its pipe is single-use and is
        // dropped here, never checked back in (the h2 session is shared
        // underneath instead).
        let poolable = conn.poolable;
        let mut backend_read = conn.read;
        let mut backend_write = conn.write;

        // --- Head + request body forwarding ---
        // `forwarded_head` was built before the dial (rules, forwarded
        // headers, rewrite and plugin, in that order): a plugin rejection or
        // failure never opens a backend connection.
        if write_with_timeout(&mut backend_write, &forwarded_head, cfg.idle_timeout)
            .await
            .is_err()
            || write_with_timeout(&mut backend_write, HEAD_END, cfg.idle_timeout)
                .await
                .is_err()
        {
            if let Some(record) = access.as_mut() {
                record.status(502);
            }
            write_error(&mut client_write, 502, "bad gateway").await;
            return;
        }

        // `Expect: 100-continue` (RFC 9112 §10.1.2): the client waits for an
        // interim response before sending the body. Now that the request
        // head reached the backend, release it with a real `100 Continue`
        // (never simulated: the client sees the actual interim message).
        // Only when a body is actually expected: a request without one is
        // not waiting for anything.
        let sent_continue =
            request.expect_continue && !matches!(request.framing, BodyFraming::None);
        if sent_continue
            && write_with_timeout(&mut client_write, CONTINUE, cfg.idle_timeout)
                .await
                .is_err()
        {
            return;
        }

        // Request body forwarding, teeing the bytes for the mirror copy when
        // the matched rule has one (B-H3). `None` after the copy = the body
        // exceeded the mirror budget (counted, never truncated).
        let mut mirror_body: Option<Vec<u8>> = mirror.as_ref().map(|_| Vec::new());
        let request_body = match until_deadline(stream_deadline, async {
            match request.framing {
                BodyFraming::None => Ok(()),
                BodyFraming::ContentLength(len) => match mirror.is_some() {
                    true => {
                        let mut tee = MirrorTee::new(&mut backend_write, mirror::BODY_BUDGET);
                        let copied = copy_exact(
                            &mut from_client,
                            &mut tee,
                            len,
                            cfg.idle_timeout,
                            &metrics.bytes_client_to_backend,
                            &metrics.idle_timeouts,
                        )
                        .await;
                        mirror_body = tee.finish();
                        copied
                    }
                    false => {
                        copy_exact(
                            &mut from_client,
                            &mut backend_write,
                            len,
                            cfg.idle_timeout,
                            &metrics.bytes_client_to_backend,
                            &metrics.idle_timeouts,
                        )
                        .await
                    }
                },
                BodyFraming::Chunked => match mirror.is_some() {
                    true => {
                        let mut tee = MirrorTee::new(&mut backend_write, mirror::BODY_BUDGET);
                        let copied = copy_chunked_capped(
                            &mut from_client,
                            &mut tee,
                            cfg.idle_timeout,
                            &metrics.bytes_client_to_backend,
                            &metrics.idle_timeouts,
                            body_cap,
                        )
                        .await;
                        mirror_body = tee.finish();
                        copied
                    }
                    false => {
                        copy_chunked_capped(
                            &mut from_client,
                            &mut backend_write,
                            cfg.idle_timeout,
                            &metrics.bytes_client_to_backend,
                            &metrics.idle_timeouts,
                            body_cap,
                        )
                        .await
                    }
                },
                BodyFraming::UntilEof => Ok(()),
            }
        })
        .await
        {
            Ok(body) => body,
            // max_stream_duration fired mid-request: the forwarded
            // exchange is over (504 + close, never a silent hang).
            Err(()) => {
                if let Some(record) = access.as_mut() {
                    record.status(504);
                }
                write_error(&mut client_write, 504, "gateway timeout").await;
                return;
            }
        };
        match request_body {
            Ok(()) => {}
            Err(CopyError::Framing(reject)) => {
                metrics
                    .http_requests_rejected
                    .fetch_add(1, Ordering::Relaxed);
                if let Some(record) = access.as_mut() {
                    record.status(reject.status);
                }
                write_error(&mut client_write, reject.status, reject.reason).await;
                return;
            }
            Err(CopyError::Truncated) => {
                metrics
                    .http_requests_rejected
                    .fetch_add(1, Ordering::Relaxed);
                if let Some(record) = access.as_mut() {
                    record.status(400);
                }
                write_error(&mut client_write, 400, "truncated request body").await;
                return;
            }
            Err(CopyError::TooLarge) => {
                // The exchange is abandoned: earlier chunks already reached
                // the backend, so the connection is not pooled (dropped on
                // return) and the client gets the explicit refusal.
                metrics
                    .http_requests_rejected
                    .fetch_add(1, Ordering::Relaxed);
                if let Some(record) = access.as_mut() {
                    record.status(413);
                }
                write_error(&mut client_write, 413, "request body too large").await;
                return;
            }
            Err(CopyError::Idle) => return,
            // A19: client abort → the backend is dropped on exit.
            Err(CopyError::Io) => return,
        }
        // Bytes past the request body belong to the next pipelined
        // exchange on this client connection.
        client_carry = from_client.prefix.split_off(from_client.pos);

        // Request mirror (B-H3): the copy goes out on a detached task now
        // that the client's body is complete, so it adds no latency to the
        // exchange and its outcome (success or failure) never reaches the
        // client — only the counters and the log see it.
        match (mirror, mirror_body) {
            (Some(policy), Some(body)) => mirror::spawn(mirror::MirrorCopy {
                name: cfg.name.clone(),
                connect_timeout: cfg.connect_timeout,
                idle_timeout: cfg.idle_timeout,
                policy,
                peer,
                local,
                head: forwarded_head.clone(),
                body,
                metrics: Arc::clone(&metrics),
            }),
            (Some(_policy), None) => {
                metrics.mirror_skipped.fetch_add(1, Ordering::Relaxed);
            }
            (None, _) => {}
        }

        // --- Server phase: response head ---
        // Interim (1xx) responses are never final (RFC 9112 §6.2): forward
        // them and keep reading until the final message, so a stale head is
        // never left queued on the connection (which would desync the next
        // exchange that reuses it from the pool).
        let mut carry: Vec<u8> = Vec::new();
        let mut interim_count = 0u32;
        // Set when a `304` refreshed the stored entry: the tail below is
        // skipped and the entry serves instead.
        let mut refreshed: Option<(bool, Arc<cache::StoredEntry>)> = None;
        let (response_head_bytes, response) = loop {
            let mut source = Prefixed {
                prefix: std::mem::take(&mut carry),
                pos: 0,
                inner: &mut backend_read,
            };
            let (head_bytes, rest) = match until_deadline(
                stream_deadline,
                read_head(
                    &mut source,
                    cfg.server_header_timeout,
                    limits.max_head_bytes,
                ),
            )
            .await
            .map_err(|_| HeadError::Timeout)
            .and_then(|result| result)
            {
                Ok(pair) => pair,
                Err(HeadError::Timeout) => {
                    metrics.header_timeouts.fetch_add(1, Ordering::Relaxed);
                    if let Some(record) = access.as_mut() {
                        record.status(504);
                    }
                    write_error(&mut client_write, 504, "gateway timeout").await;
                    return;
                }
                Err(_) => {
                    if let Some(record) = access.as_mut() {
                        record.status(502);
                    }
                    write_error(&mut client_write, 502, "bad gateway").await;
                    return;
                }
            };
            // Bytes read past the head terminator, plus any prefix bytes
            // read_head never consumed: the exact stream remainder, in order.
            let unread_prefix = source.prefix.split_off(source.pos);
            carry = rest;
            carry.extend(unread_prefix);

            let response = match parse_response_head(
                &head_bytes,
                request.method == "HEAD",
                head_limits,
            ) {
                Ok(response) => response,
                Err(reject) => {
                    eprintln!(
                        "WARN [{}] invalid response head from {} (peer {peer}): {} — refusing with {}",
                        cfg.name, conn.addr, reject.reason, reject.status
                    );
                    if let Some(record) = access.as_mut() {
                        record.status(reject.status);
                    }
                    write_error(&mut client_write, reject.status, reject.reason).await;
                    return;
                }
            };
            // A7: a `101` answering the client's upgrade request is final
            // for us — the tunnel opens after the loop. A CONNECT `2xx`
            // breaks out the same way (A8).
            if response.status >= 200 || (response.status == 101 && request.wants_upgrade) {
                // Revalidation answer (B-N7/H1): a `304` to our conditional
                // refreshes the stored headers without touching the body.
                // The waiters were already published by `refresh`; the
                // connection returns to the pool under the same contract
                // as a clean origin exchange.
                if let CacheAction::Origin(fetch) = &cache_action
                    && fetch.stale.is_some()
                    && response.status == 304
                    && let Some(stale) = &fetch.stale
                    && let Some(facts_304) = cache::parse_origin_head(&head_bytes)
                {
                    if let Some(guard) = cache_guard.as_mut() {
                        guard.disarm();
                    }
                    // Planned from `Some`; `None` serves the stale bytes
                    // without a refresh instead of panicking.
                    let entry = match cfg.cache.as_ref() {
                        Some(cache) => {
                            let ttl =
                                cache::effective_ttl(cache.default_ttl(), &facts_304.cache_control);
                            cache
                                .refresh(fetch.key.clone(), stale, &facts_304.headers, ttl)
                                .await;
                            // No backend stream is moved here: the check-in
                            // (or drop) happens in the `refreshed` block
                            // below, whose `continue`/`return` keeps the tail
                            // from touching the moved connection.
                            match cache.lookup(&fetch.key, &fetch.headers, false) {
                                cache::Lookup::Hit(entry) => entry,
                                // Evicted between lookup and refresh: the
                                // stale bytes are still correct, only the
                                // headers aged.
                                _ => Arc::clone(stale),
                            }
                        }
                        None => Arc::clone(stale),
                    };
                    refreshed = Some((carry.is_empty(), entry));
                    break (head_bytes, response);
                }
                break (head_bytes, response);
            }
            // Interim: an unsolicited `101` (the client never asked for a
            // switch) is refused explicitly (A7): never half-forwarded.
            if response.status == 101 {
                eprintln!(
                    "WARN [{}] backend {} offered a protocol switch (101); refused (peer {peer})",
                    cfg.name, conn.addr
                );
                if let Some(record) = access.as_mut() {
                    record.status(502);
                }
                write_error(&mut client_write, 502, "bad gateway").await;
                return;
            }
            interim_count += 1;
            if interim_count > MAX_INTERIM_RESPONSES {
                eprintln!(
                    "WARN [{}] backend {} sent more than {MAX_INTERIM_RESPONSES} interim responses; refused (peer {peer})",
                    cfg.name, conn.addr
                );
                if let Some(record) = access.as_mut() {
                    record.status(502);
                }
                write_error(&mut client_write, 502, "bad gateway").await;
                return;
            }
            if sent_continue && response.status == 100 {
                // The client already got our own `100 Continue`: the
                // backend's redundant one is consumed, never forwarded.
                continue;
            }
            if write_with_timeout(&mut client_write, &head_bytes, cfg.idle_timeout)
                .await
                .is_err()
                || write_with_timeout(&mut client_write, HEAD_END, cfg.idle_timeout)
                    .await
                    .is_err()
            {
                return;
            }
        };

        // A revalidated entry serves from the store: the 304 connection
        // returns to the pool under the same contract as a clean origin
        // exchange. This block diverges (`continue`/`return`), so the
        // tail below never touches the moved connection.
        if let Some((clean, entry)) = refreshed.take() {
            let backend_alive = !peer_gone(&mut backend_read).await;
            if poolable
                && !request.wants_close
                && !response.wants_close
                && clean
                && backend_alive
                && active.mode() != ServerMode::Maintenance
            {
                backend
                    .pool
                    .checkin(conn.addr, backend_read, backend_write, Instant::now());
            } else {
                drop((backend_read, backend_write));
            }
            metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            entry.hits.fetch_add(1, Ordering::Relaxed);
            serve_cached(
                &mut client_write,
                cfg,
                rule_headers,
                peer,
                &request.host,
                scheme,
                &request,
                &entry,
                &mut access,
                &metrics,
                true,
            )
            .await;
            client_carry = from_client.prefix.split_off(from_client.pos);
            if request.wants_close {
                let _ = tokio::time::timeout(Duration::from_secs(5), client_write.shutdown()).await;
                return;
            }
            continue;
        }

        if let Some(record) = access.as_mut() {
            record.status(response.status);
        }

        // A7/A8 upgrade tunnel: the client asked (Upgrade or CONNECT) and
        // the backend accepted (101 / 2xx). The switch head is forwarded
        // verbatim (no proxy additions on a protocol switch) and the
        // exchange becomes a raw bidirectional tunnel until either side
        // closes or goes idle (`idle_timeout` is the inactivity cap). The
        // connection is consumed: it never returns to the pool.
        if (response.status == 101 && request.wants_upgrade)
            || (request.method == "CONNECT" && (200..300).contains(&response.status))
        {
            if write_with_timeout(&mut client_write, &response_head_bytes, cfg.idle_timeout)
                .await
                .is_err()
                || write_with_timeout(&mut client_write, HEAD_END, cfg.idle_timeout)
                    .await
                    .is_err()
            {
                return;
            }
            let mut from_backend = Prefixed {
                prefix: carry,
                pos: 0,
                inner: &mut backend_read,
            };
            run_tunnel(
                &mut from_client,
                &mut client_write,
                &mut from_backend,
                &mut backend_write,
                cfg.idle_timeout,
            )
            .await;
            return;
        }

        // Response header actions (B-N4/B-I4/B-E17) on the proxied
        // response the client sees.
        let mut response_lines = rule_headers
            .map(|actions| render_header_lines(&actions.response, peer, &request.host, scheme))
            .unwrap_or_default();
        // Sticky cookie (B-H8): re-issued only when the request had none
        // or it did not pin to the server that served.
        if let Some(affinity) = backend.affinity.as_ref()
            && affinity.mode == AffinityMode::Cookie
            && let Some(token) = backend
                .balancer
                // Stable slot index (B-H13): a re-resolution must not
                // change the cookie's meaning.
                .slot_of(served_addr)
                .map(|idx| idx.to_string())
            && Some(&token) != affinity_cookie.as_ref()
        {
            response_lines.push(format!(
                "set-cookie: {}={token}; Path=/; HttpOnly",
                affinity.cookie
            ));
        }
        if let Some(cors) = rule_headers.and_then(|actions| actions.cors.as_ref()) {
            response_lines.extend(cors_response_lines(cors, false));
        }
        let mut response_head_bytes = if response_lines.is_empty() {
            response_head_bytes
        } else {
            append_response_headers(&response_head_bytes, &response_lines)
        };
        // Response compression (B-N6/H6): the decision happens once, before a
        // byte of the head is sent, so nothing has to be unwound later. The
        // backend framing is untouched; only the client's view is rewritten.
        let accept_encoding = request
            .headers
            .iter()
            .find(|(name, _)| name == "accept-encoding")
            .map(|(_, value)| value.as_str());
        let compression_settings = cfg.compression.as_ref();
        let encoding = compression_settings.and_then(|settings| {
            compression::eligible(
                &request.method,
                request.version,
                accept_encoding,
                &compression::ResponseFacts {
                    status: response.status,
                    no_body: response.framing == BodyFraming::None,
                    declared_len: match response.framing {
                        BodyFraming::ContentLength(len) => Some(len),
                        _ => None,
                    },
                    head: &response_head_bytes,
                },
                settings,
            )
        });
        if let Some(encoding) = encoding {
            response_head_bytes = compression::rewrite_head(&response_head_bytes, encoding);
            match encoding {
                compression::Encoding::Gzip => metrics
                    .compression_gzip_responses
                    .fetch_add(1, Ordering::Relaxed),
                compression::Encoding::Brotli => metrics
                    .compression_brotli_responses
                    .fetch_add(1, Ordering::Relaxed),
            };
        }
        if let Some(record) = access.as_mut() {
            // Only an uncompressed, declared length is the client's byte
            // count; chunked, until-EOF and compressed bodies are unknown and
            // stay absent rather than lying.
            let bytes = match (encoding, response.framing) {
                (None, BodyFraming::None) => Some(0),
                (None, BodyFraming::ContentLength(len)) => Some(len),
                _ => None,
            };
            if let Some(bytes) = bytes {
                record.bytes(bytes);
            }
        }
        // B-N7/H1: a cacheable miss is marked like a hit (visibility for
        // operators and tests), on both the assembled and the streamed
        // path. Never stored: `end_to_end` strips it.
        if matches!(
            cache_action,
            CacheAction::Origin(_) | CacheAction::Direct(_)
        ) {
            response_head_bytes.extend_from_slice(b"\r\nx-cache: MISS");
        }
        // Storable responses (B-N7/H1) assemble fully in memory — bounded
        // by the entry bound — then forward from the slice and store.
        // Chunked and close-delimited bodies never assemble (no
        // re-framing): they stream through uncached below. The guard
        // stays armed until the store completes, so any failure here
        // publishes `Gone` for the waiters.
        // Planned from `Some`; `None` skips the store instead of
        // panicking the exchange.
        let store_plan = match &cache_action {
            CacheAction::Origin(fetch) | CacheAction::Direct(fetch) => {
                let direct = matches!(cache_action, CacheAction::Direct(_));
                cfg.cache.as_ref().and_then(|cache| {
                    store_plan(
                        cache,
                        fetch,
                        direct,
                        &request.method,
                        response.framing,
                        &response_head_bytes,
                    )
                })
            }
            CacheAction::Off | CacheAction::Serve(_) | CacheAction::Wait(_, _) => None,
        };
        if let Some(plan) = store_plan {
            let mut from_backend = Prefixed {
                prefix: carry,
                pos: 0,
                inner: &mut backend_read,
            };
            // Exact-length read with per-chunk idle timeout: the same
            // contract as `copy_exact` (a slow trickle trips idle, a
            // short close truncates), with the same counters.
            let mut body = vec![0u8; plan.len as usize];
            let mut read = 0usize;
            let mut clean_read = true;
            while read < body.len() {
                match tokio::time::timeout(cfg.idle_timeout, from_backend.read(&mut body[read..]))
                    .await
                {
                    Ok(Ok(0)) => {
                        clean_read = false;
                        break;
                    }
                    Ok(Ok(n)) => {
                        read += n;
                        metrics
                            .bytes_backend_to_client
                            .fetch_add(n as u64, Ordering::Relaxed);
                    }
                    Ok(Err(_)) => {
                        clean_read = false;
                        break;
                    }
                    Err(_) => {
                        metrics.idle_timeouts.fetch_add(1, Ordering::Relaxed);
                        clean_read = false;
                        break;
                    }
                }
            }
            if !clean_read {
                // Truncated, I/O or idle: exactly like the copy path, the
                // exchange ends here with no store and no pool return.
                return;
            }
            let mut head_forwarded = false;
            let send = until_deadline(stream_deadline, async {
                write_with_timeout(&mut client_write, &response_head_bytes, cfg.idle_timeout)
                    .await?;
                write_with_timeout(&mut client_write, HEAD_END, cfg.idle_timeout).await?;
                head_forwarded = true;
                match encoding {
                    Some(encoding) => {
                        let settings = compression_settings.ok_or(CopyError::Io)?;
                        let mut slice = &body[..];
                        copy_compressed_body(
                            &mut slice,
                            &mut client_write,
                            CompressPlan {
                                framing: BodyFraming::ContentLength(plan.len),
                                encoding,
                                settings,
                                pipe: limits
                                    .stream_buffer_bytes
                                    .unwrap_or(DEFAULT_COMPRESSION_PIPE),
                            },
                            cfg.idle_timeout,
                            &metrics,
                        )
                        .await
                    }
                    None => {
                        let mut slice = &body[..];
                        copy_exact(
                            &mut slice,
                            &mut client_write,
                            plan.len,
                            cfg.idle_timeout,
                            &metrics.bytes_backend_to_client,
                            &metrics.idle_timeouts,
                        )
                        .await
                    }
                }
            })
            .await;
            match send {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return,
                Err(()) => {
                    if !head_forwarded {
                        if let Some(record) = access.as_mut() {
                            record.status(504);
                        }
                        write_error(&mut client_write, 504, "gateway timeout").await;
                    }
                    return;
                }
            }
            // Success: disarm first (a spawned `Gone` would drop the fresh
            // entry), then publish. Waiters wake with `Ready`.
            if let Some(guard) = cache_guard.as_mut() {
                guard.disarm();
            }
            // Planned from `Some`; `None` skips the publish (the guard
            // was never armed, so no waiter hangs on it) instead of
            // panicking the exchange.
            if let Some(cache) = cfg.cache.as_ref() {
                let parts = cache::StoredParts {
                    status: plan.status,
                    reason: plan.reason,
                    headers: plan.headers,
                    body,
                    etag: plan.etag,
                    last_modified: plan.last_modified,
                    vary: plan.vary,
                    vary_values: plan.vary_values,
                    framing_none: false,
                    has_declared_len: true,
                    ttl: plan.ttl,
                    stored_at_unix: cache::unix_now(),
                };
                if plan.direct {
                    cache.store_direct(plan.key, parts).await;
                } else {
                    cache
                        .complete(plan.key, cache::FetchOutcome::Stored(parts))
                        .await;
                }
            }
            let clean_boundary = from_backend.pos == from_backend.prefix.len();
            let backend_alive = !peer_gone(&mut backend_read).await;
            if finish_exchange(
                &metrics,
                &cfg.name,
                backend,
                served_addr,
                route_name,
                active.mode() == ServerMode::Maintenance,
                response.status,
                poolable,
                request.wants_close,
                response.wants_close,
                clean_boundary,
                backend_alive,
                conn.addr,
                backend_read,
                backend_write,
            ) {
                let _ = client_write.shutdown().await;
                return;
            }
            continue;
        }
        let mut from_backend = Prefixed {
            prefix: carry,
            pos: 0,
            inner: &mut backend_read,
        };
        let mut head_forwarded = false;
        let response_body = until_deadline(stream_deadline, async {
            write_with_timeout(&mut client_write, &response_head_bytes, cfg.idle_timeout).await?;
            write_with_timeout(&mut client_write, HEAD_END, cfg.idle_timeout).await?;
            head_forwarded = true;
            match encoding {
                Some(encoding) => {
                    // `encoding` is only produced from `compression_settings`.
                    let settings = compression_settings.ok_or(CopyError::Io)?;
                    copy_compressed_body(
                        &mut from_backend,
                        &mut client_write,
                        CompressPlan {
                            framing: response.framing,
                            encoding,
                            settings,
                            pipe: limits
                                .stream_buffer_bytes
                                .unwrap_or(DEFAULT_COMPRESSION_PIPE),
                        },
                        cfg.idle_timeout,
                        &metrics,
                    )
                    .await
                }
                None => match response.framing {
                    BodyFraming::None => Ok(()),
                    BodyFraming::ContentLength(len) => {
                        copy_exact(
                            &mut from_backend,
                            &mut client_write,
                            len,
                            cfg.idle_timeout,
                            &metrics.bytes_backend_to_client,
                            &metrics.idle_timeouts,
                        )
                        .await
                    }
                    BodyFraming::Chunked => {
                        copy_chunked(
                            &mut from_backend,
                            &mut client_write,
                            cfg.idle_timeout,
                            &metrics.bytes_backend_to_client,
                            &metrics.idle_timeouts,
                        )
                        .await
                    }
                    BodyFraming::UntilEof => {
                        copy_to_eof(
                            &mut from_backend,
                            &mut client_write,
                            cfg.idle_timeout,
                            &metrics.bytes_backend_to_client,
                            &metrics.idle_timeouts,
                        )
                        .await
                    }
                },
            }
        })
        .await;
        let response_body = match response_body {
            Ok(body) => body,
            // max_stream_duration fired mid-response: the stream is cut
            // (504 before the head; a truncated stream after it).
            Err(()) => {
                if !head_forwarded {
                    if let Some(record) = access.as_mut() {
                        record.status(504);
                    }
                    write_error(&mut client_write, 504, "gateway timeout").await;
                }
                return;
            }
        };
        match response_body {
            Ok(()) => {}
            // Before the response head a clean 502/500 still fits.
            Err(CopyError::Framing(reject)) if !head_forwarded => {
                if let Some(record) = access.as_mut() {
                    record.status(reject.status);
                }
                write_error(&mut client_write, reject.status, reject.reason).await;
                return;
            }
            Err(_) => return,
        }

        // A16 reuse contract, extended: never pool a connection whose
        // forwarded request carried `Connection: close` (or lacked
        // keep-alive in HTTP/1.0), nor one to a server taken out for a
        // patch window (ADR-0028). See `finish_exchange`.
        let clean_boundary = from_backend.pos == from_backend.prefix.len();
        let backend_alive = !peer_gone(&mut backend_read).await;
        if finish_exchange(
            &metrics,
            &cfg.name,
            backend,
            served_addr,
            route_name,
            active.mode() == ServerMode::Maintenance,
            response.status,
            poolable,
            request.wants_close,
            response.wants_close,
            clean_boundary,
            backend_alive,
            conn.addr,
            backend_read,
            backend_write,
        ) {
            let _ = client_write.shutdown().await;
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(head: &str) -> Result<RequestHead, Reject> {
        parse_request_head(head.as_bytes(), HeadLimits::default())
    }

    #[test]
    fn valid_get_parses_with_no_body() {
        let parsed = req("GET /a HTTP/1.1\r\nHost: x\r\n").expect("must parse");
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.framing, BodyFraming::None);
        assert!(!parsed.wants_close);
    }

    #[test]
    fn content_length_and_chunked_bodies_parse() {
        let parsed = req("POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n").expect("cl");
        assert_eq!(parsed.framing, BodyFraming::ContentLength(3));
        let parsed =
            req("POST /a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n").expect("te");
        assert_eq!(parsed.framing, BodyFraming::Chunked);
    }

    #[test]
    fn smuggling_corpus_is_rejected() {
        // (head, expected status) — T01–T03 corpus.
        let corpus: &[(&str, u16)] = &[
            (
                "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n",
                400,
            ),
            (
                "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 4\r\n",
                400,
            ),
            (
                "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
                400,
            ),
            (
                "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n",
                400,
            ),
            (
                "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: identity\r\n",
                400,
            ),
            ("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +3\r\n", 400),
            ("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 03\r\n", 400),
            ("GET / HTTP/1.1\r\nHost: x\r\nHost: y\r\n", 400),
            ("GET / HTTP/1.1\r\n", 400),
            ("GET / HTTP/1.1\r\n Host: x\r\n", 400),
            ("GET / HTTP/1.1\r\nFoo : x\r\nHost: y\r\n", 400),
            ("GET / HTTP/1.1\r\nFoo: a\nb\r\nHost: y\r\n", 400),
            ("GET / HTTP/1.1\r\nFo o: x\r\nHost: y\r\n", 400),
            ("GET http://evil/ HTTP/1.1\r\nHost: x\r\n", 400),
            ("GET / HTTP/2.0\r\nHost: x\r\n", 505),
            // A7/A8 (v0.6): CONNECT and Upgrade are valid requests now —
            // routed and tunneled on backend acceptance (see
            // `framing_fuzz_corpus` and the e2e tunnel tests).
            ("GET /x HTTP/1.1\r\n", 400),
        ];
        for (head, expected) in corpus {
            let err = req(head).expect_err(head);
            assert_eq!(err.status, *expected, "case: {head:?}");
        }
    }

    #[test]
    fn request_without_trailing_crlf_parses() {
        // read_head delivers the head without the final terminator.
        let parsed = req("GET /a HTTP/1.1\r\nHost: x").expect("must parse");
        assert_eq!(parsed.target, "/a");
    }

    #[test]
    fn too_many_headers_is_431() {
        let mut head = String::from("GET / HTTP/1.1\r\nHost: x\r\n");
        for i in 0..MAX_HEADERS {
            head.push_str(&format!("X-H{i}: v\r\n"));
        }
        let err = req(&head).expect_err("too many headers");
        assert_eq!(err.status, 431);
    }

    #[test]
    fn configured_header_count_is_the_bound_in_both_directions() {
        let limits = HeadLimits {
            max_head_bytes: 1024,
            max_headers: 2,
        };
        let at_limit = "GET / HTTP/1.1\r\nHost: x\r\nA: 1\r\n";
        assert!(parse_request_head(at_limit.as_bytes(), limits).is_ok());
        let over = "GET / HTTP/1.1\r\nHost: x\r\nA: 1\r\nB: 2\r\n";
        assert_eq!(
            parse_request_head(over.as_bytes(), limits)
                .expect_err("over the configured count")
                .status,
            431
        );
        // The same bound applies to the backend's answer, which is a 502.
        let at_limit = "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nA: 1\r\n";
        assert!(parse_response_head(at_limit.as_bytes(), false, limits).is_ok());
        let over = "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nA: 1\r\nB: 2\r\n";
        assert_eq!(
            parse_response_head(over.as_bytes(), false, limits)
                .expect_err("over the configured count")
                .status,
            502
        );
    }

    #[tokio::test]
    async fn chunked_cap_refuses_a_max_size_chunk_without_overflowing() {
        let (mut sender, mut reader) = tokio::io::duplex(64);
        sender
            .write_all(b"ffffffffffffffff\r\n")
            .await
            .expect("write size line");
        let mut out = Vec::new();
        let countered = AtomicU64::new(0);
        let idle = AtomicU64::new(0);
        let result = copy_chunked_capped(
            &mut reader,
            &mut out,
            Duration::from_secs(1),
            &countered,
            &idle,
            Some(16),
        )
        .await;
        assert!(
            matches!(result, Err(CopyError::TooLarge)),
            "a chunk of u64::MAX bytes must be refused by the cap, not added to the total"
        );
        assert!(out.is_empty(), "nothing of that frame may be forwarded");
    }

    #[tokio::test]
    async fn read_head_enforces_the_configured_byte_budget() {
        let unterminated = vec![b'x'; 200];
        let mut source = Prefixed {
            prefix: unterminated,
            pos: 0,
            inner: &mut &b""[..],
        };
        assert!(
            matches!(
                read_head(&mut source, Duration::from_secs(1), 100).await,
                Err(HeadError::TooLarge)
            ),
            "a head over the configured budget must be refused, not read whole"
        );
        let mut source = Prefixed {
            prefix: b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
            pos: 0,
            inner: &mut &b""[..],
        };
        assert!(
            read_head(&mut source, Duration::from_secs(1), 1024)
                .await
                .is_ok(),
            "the configured budget must still accept a head that fits"
        );
    }

    #[test]
    fn response_framing_follows_rfc_9112() {
        let parsed = parse_response_head(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n",
            false,
            HeadLimits::default(),
        )
        .expect("respuesta");
        assert_eq!(parsed.framing, BodyFraming::ContentLength(2));
        assert!(!parsed.wants_close);

        let parsed = parse_response_head(
            b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n",
            false,
            HeadLimits::default(),
        )
        .expect("1.0");
        assert!(parsed.wants_close);

        let parsed =
            parse_response_head(b"HTTP/1.1 204 No Content\r\n", false, HeadLimits::default())
                .expect("204");
        assert_eq!(parsed.framing, BodyFraming::None);

        let parsed =
            parse_response_head(b"HTTP/1.1 200 OK\r\n", false, HeadLimits::default()).expect("eof");
        assert_eq!(parsed.framing, BodyFraming::UntilEof);

        let parsed = parse_response_head(
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n",
            true,
            HeadLimits::default(),
        )
        .expect("HEAD");
        assert_eq!(parsed.framing, BodyFraming::None);
    }

    #[test]
    fn ambiguous_response_framing_is_rejected() {
        let err = parse_response_head(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n",
            false,
            HeadLimits::default(),
        )
        .expect_err("CL+TE en respuesta");
        assert_eq!(err.status, 502);
    }

    #[test]
    fn expect_100_continue_is_flagged_and_ignored_in_http10() {
        let parsed =
            req("POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nExpect: 100-continue\r\n")
                .expect("expect");
        assert!(parsed.expect_continue);
        // HTTP/1.0 ignores the expectation (RFC 9112 §10.1.2).
        let parsed =
            req("POST /a HTTP/1.0\r\nContent-Length: 3\r\nExpect: 100-continue\r\n").expect("1.0");
        assert!(!parsed.expect_continue);
    }

    #[test]
    fn unsupported_expectation_is_rejected_with_417() {
        let err = req("GET / HTTP/1.1\r\nHost: x\r\nExpect: the-unexpected\r\n").expect_err("417");
        assert_eq!(err.status, 417);
    }

    #[test]
    fn response_status_out_of_range_is_rejected_as_502() {
        for head in ["HTTP/1.1 999 X\r\n", "HTTP/1.1 016 X\r\n"] {
            let err =
                parse_response_head(head.as_bytes(), false, HeadLimits::default()).expect_err(head);
            assert_eq!(err.status, 502, "case: {head}");
        }
    }

    #[test]
    fn chunk_size_parsing_is_strict() {
        assert_eq!(parse_chunk_size(b"1a\r\n").expect("hex"), 26);
        assert!(parse_chunk_size(b"\r\n").is_err());
        assert!(parse_chunk_size(b"z\r\n").is_err());
        assert!(parse_chunk_size(b"0x1\r\n").is_err());
        assert!(parse_chunk_size(b"1 ;\r\n").is_err());
    }
}
