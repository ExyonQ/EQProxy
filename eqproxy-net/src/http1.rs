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
//! - `CONNECT` and `Upgrade` (A7/A8, Phase 4) → explicit 501, never faked.
//! - `Expect` other than `100-continue` → 417; `Expect: 100-continue`
//!   releases the client with a real interim `100` (RFC 9112 §10.1.2).
//! - Interim (1xx) responses are never final: they are forwarded (RFC 9112
//!   §6.2) and the loop keeps reading until the final response, so a stale
//!   message is never left queued on a pooled connection. `101` → 502
//!   (upgrade tunneling unsupported).
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

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};

use eqproxy_core::Metrics;

use crate::proxy::{OutboundError, READ_BUF, ResolvedListener, checkout_or_connect};

/// Maximum message-head size (final line included) (T03).
pub const MAX_HEAD_BYTES: usize = 16 * 1024;
/// Maximum headers per message (T03).
pub const MAX_HEADERS: usize = 100;
/// Maximum header-or-chunk line size (T03).
pub const MAX_LINE_BYTES: usize = 8 * 1024;

const CRLF: &[u8] = b"\r\n";
const HEAD_END: &[u8] = b"\r\n\r\n";
/// Real interim response that releases an `Expect: 100-continue` client.
const CONTINUE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";
/// Interim responses accepted before the final one (bounded, never an
/// endless 1xx stream).
const MAX_INTERIM_RESPONSES: u32 = 8;

/// Headers forbidden in chunked trailers (T01).
const FORBIDDEN_TRAILERS: [&str; 6] = [
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
fn parse_header_line(line: &[u8]) -> Result<(String, String), Reject> {
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
pub fn parse_request_head(head: &[u8]) -> Result<RequestHead, Reject> {
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
    if method == b"CONNECT" {
        // A8 (Phase 4): never faked; explicit rejection.
        return Err(Reject {
            status: 501,
            reason: "connect is not implemented (planned for phase 4)",
        });
    }
    if target.is_empty()
        || target.iter().any(|b| *b <= 0x20 || *b == 0x7f)
        || (!target.starts_with(b"/") && target != b"*")
    {
        // Rejects absolute-form ("http://…"): this proxy is an origin, not a client.
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

    if lines.len() - 1 > MAX_HEADERS {
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
    if wants_upgrade {
        // A7 (Phase 4): never faked; explicit rejection.
        return Err(Reject {
            status: 501,
            reason: "upgrade is not implemented (planned for phase 4)",
        });
    }

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

    Ok(RequestHead {
        method: String::from_utf8_lossy(method).into_owned(),
        target: String::from_utf8_lossy(target).into_owned(),
        version,
        framing,
        wants_close,
        expect_continue,
    })
}

/// Parses the response head with the same line rules (T02) and the
/// RFC 9112 §6 framing. An ambiguous backend answers 502 (never forwarded
/// a framing the client could interpret differently).
pub fn parse_response_head(head: &[u8], head_request: bool) -> Result<ResponseHead, Reject> {
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

    if lines.len() - 1 > MAX_HEADERS {
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
enum CopyError {
    Framing(Reject),
    Truncated,
    Idle,
    Io,
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
async fn read_crlf_line<R: AsyncRead + Unpin>(
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
fn parse_chunk_size(line: &[u8]) -> Result<u64, CopyError> {
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
    loop {
        let line = read_crlf_line(reader, idle, MAX_LINE_BYTES).await?;
        let size = parse_chunk_size(&line)?;
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

/// Reader that serves an already-read prefix first (head-read remainder).
struct Prefixed<R> {
    prefix: Vec<u8>,
    pos: usize,
    inner: R,
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
enum HeadError {
    Eof,
    Timeout,
    TooLarge,
    Io,
}

async fn read_head<R: AsyncRead + Unpin>(
    reader: &mut R,
    timeout: Duration,
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
                let head = acc[..pos].to_vec();
                let rest = acc[pos + HEAD_END.len()..].to_vec();
                return Ok((head, rest));
            }
            if acc.len() > MAX_HEAD_BYTES {
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

/// Serves a full HTTP/1.1 client connection (keep-alive included).
///
/// Takes the client stream halves (plain TCP or already-accepted TLS) and the
/// peer addresses for PROXY protocol (A9). With no servers available the
/// exchange gets 503; when the chosen server fails, 502 (SPEC §7.4).
pub async fn serve_http<CR, CW>(
    client_read: CR,
    client_write: CW,
    peer: SocketAddr,
    local: SocketAddr,
    cfg: &ResolvedListener,
    metrics: Arc<Metrics>,
) where
    CR: AsyncRead + Unpin,
    CW: AsyncWrite + Unpin,
{
    let mut client_read = BufReader::new(client_read);
    let mut client_write = client_write;
    let mut first_exchange = true;

    loop {
        // --- Client phase: request head ---
        let (head_bytes, carry) = match read_head(&mut client_read, cfg.client_header_timeout).await
        {
            Ok(pair) => pair,
            Err(HeadError::Eof) => return,
            Err(HeadError::Timeout) => {
                metrics.header_timeouts.fetch_add(1, Ordering::Relaxed);
                if first_exchange {
                    write_error(&mut client_write, 408, "request timeout").await;
                }
                return;
            }
            Err(HeadError::TooLarge) => {
                metrics
                    .http_requests_rejected
                    .fetch_add(1, Ordering::Relaxed);
                write_error(&mut client_write, 431, "request header fields too large").await;
                return;
            }
            Err(HeadError::Io) => return,
        };
        first_exchange = false;

        let request = match parse_request_head(&head_bytes) {
            Ok(request) => request,
            Err(reject) => {
                metrics
                    .http_requests_rejected
                    .fetch_add(1, Ordering::Relaxed);
                write_error(&mut client_write, reject.status, reject.reason).await;
                return;
            }
        };

        // --- Backend: reuse from the pool (A16) or dial again ---
        let conn = match checkout_or_connect(cfg, peer, local, &metrics).await {
            Ok(conn) => conn,
            Err(OutboundError::NoServer) => {
                // All servers down/drained (B11): explicit 503.
                write_error(&mut client_write, 503, "service unavailable").await;
                return;
            }
            Err(OutboundError::Connect) => {
                write_error(&mut client_write, 502, "bad gateway").await;
                return;
            }
        };
        let mut backend_read = conn.read;
        let mut backend_write = conn.write;
        let mut from_client = Prefixed {
            prefix: carry,
            pos: 0,
            inner: &mut client_read,
        };

        // --- Head + request body forwarding ---
        if write_with_timeout(&mut backend_write, &head_bytes, cfg.idle_timeout)
            .await
            .is_err()
            || write_with_timeout(&mut backend_write, HEAD_END, cfg.idle_timeout)
                .await
                .is_err()
        {
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

        let request_body = match request.framing {
            BodyFraming::None => Ok(()),
            BodyFraming::ContentLength(len) => {
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
            BodyFraming::Chunked => {
                copy_chunked(
                    &mut from_client,
                    &mut backend_write,
                    cfg.idle_timeout,
                    &metrics.bytes_client_to_backend,
                    &metrics.idle_timeouts,
                )
                .await
            }
            BodyFraming::UntilEof => Ok(()),
        };
        match request_body {
            Ok(()) => {}
            Err(CopyError::Framing(reject)) => {
                metrics
                    .http_requests_rejected
                    .fetch_add(1, Ordering::Relaxed);
                write_error(&mut client_write, reject.status, reject.reason).await;
                return;
            }
            Err(CopyError::Truncated) => {
                metrics
                    .http_requests_rejected
                    .fetch_add(1, Ordering::Relaxed);
                write_error(&mut client_write, 400, "truncated request body").await;
                return;
            }
            Err(CopyError::Idle) => return,
            // A19: client abort → the backend is dropped on exit.
            Err(CopyError::Io) => return,
        }

        // --- Server phase: response head ---
        // Interim (1xx) responses are never final (RFC 9112 §6.2): forward
        // them and keep reading until the final message, so a stale head is
        // never left queued on the connection (which would desync the next
        // exchange that reuses it from the pool).
        let mut carry: Vec<u8> = Vec::new();
        let mut interim_count = 0u32;
        let (response_head_bytes, response) = loop {
            let mut source = Prefixed {
                prefix: std::mem::take(&mut carry),
                pos: 0,
                inner: &mut backend_read,
            };
            let (head_bytes, rest) = match read_head(&mut source, cfg.server_header_timeout).await {
                Ok(pair) => pair,
                Err(HeadError::Timeout) => {
                    metrics.header_timeouts.fetch_add(1, Ordering::Relaxed);
                    write_error(&mut client_write, 504, "gateway timeout").await;
                    return;
                }
                Err(_) => {
                    write_error(&mut client_write, 502, "bad gateway").await;
                    return;
                }
            };
            // Bytes read past the head terminator, plus any prefix bytes
            // read_head never consumed: the exact stream remainder, in order.
            let unread_prefix = source.prefix.split_off(source.pos);
            carry = rest;
            carry.extend(unread_prefix);

            let response = match parse_response_head(&head_bytes, request.method == "HEAD") {
                Ok(response) => response,
                Err(reject) => {
                    eprintln!(
                        "WARN [{}] invalid response head from {} (peer {peer}): {} — refusing with {}",
                        cfg.name, conn.addr, reject.reason, reject.status
                    );
                    write_error(&mut client_write, reject.status, reject.reason).await;
                    return;
                }
            };
            if response.status >= 200 {
                break (head_bytes, response);
            }
            // Interim: `101` would open an upgrade tunnel (unsupported,
            // A7/A8): explicit 502, never half-forwarded.
            if response.status == 101 {
                eprintln!(
                    "WARN [{}] backend {} offered a protocol switch (101); refused (peer {peer})",
                    cfg.name, conn.addr
                );
                write_error(&mut client_write, 502, "bad gateway").await;
                return;
            }
            interim_count += 1;
            if interim_count > MAX_INTERIM_RESPONSES {
                eprintln!(
                    "WARN [{}] backend {} sent more than {MAX_INTERIM_RESPONSES} interim responses; refused (peer {peer})",
                    cfg.name, conn.addr
                );
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

        let mut from_backend = Prefixed {
            prefix: carry,
            pos: 0,
            inner: &mut backend_read,
        };
        let mut head_forwarded = false;
        let response_body = async {
            write_with_timeout(&mut client_write, &response_head_bytes, cfg.idle_timeout).await?;
            write_with_timeout(&mut client_write, HEAD_END, cfg.idle_timeout).await?;
            head_forwarded = true;
            match response.framing {
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
            }
        }
        .await;
        match response_body {
            Ok(()) => {}
            // Before the response head a clean 502/500 still fits.
            Err(CopyError::Framing(reject)) if !head_forwarded => {
                write_error(&mut client_write, reject.status, reject.reason).await;
                return;
            }
            Err(_) => return,
        }

        metrics
            .http_requests_proxied
            .fetch_add(1, Ordering::Relaxed);
        // Reuse-safety contract (A16): a pooled connection must end the
        // exchange byte-aligned at a message boundary. Bytes the backend
        // sent past the body land in the carry; silently discarding them
        // and pooling would hand the next exchange a connection whose
        // stream disagrees with ours (and hide the over-send).
        let clean_boundary = from_backend.pos == from_backend.prefix.len();
        if !response.wants_close && clean_boundary {
            // Clean exchange and server on keep-alive: the connection returns
            // to the pool message-aligned (A16). Every error path
            // returns early without it: after a framing failure, cut,
            // server timeout or close it is never reused.
            cfg.backend
                .pool
                .checkin(conn.addr, backend_read, backend_write, Instant::now());
            // The backend connection is no longer ours: the rest of the loop only
            // touches the client.
            if request.wants_close {
                let _ = client_write.shutdown().await;
                return;
            }
            continue;
        }
        if !clean_boundary {
            // Counted, not logged: the counter is what operators alert on
            // (bounded cardinality, no labels).
            metrics
                .backend_connections_discarded
                .fetch_add(1, Ordering::Relaxed);
        }
        // The server closed or broke framing (UntilEof): the backend
        // connection dies here and never returns to the pool.
        drop((backend_read, backend_write));
        if request.wants_close || response.wants_close {
            let _ = client_write.shutdown().await;
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(head: &str) -> Result<RequestHead, Reject> {
        parse_request_head(head.as_bytes())
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
            ("CONNECT host:443 HTTP/1.1\r\nHost: x\r\n", 501),
            ("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: h2c\r\n", 501),
            ("GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\n", 501),
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
    fn response_framing_follows_rfc_9112() {
        let parsed = parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n", false)
            .expect("respuesta");
        assert_eq!(parsed.framing, BodyFraming::ContentLength(2));
        assert!(!parsed.wants_close);

        let parsed =
            parse_response_head(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n", false).expect("1.0");
        assert!(parsed.wants_close);

        let parsed = parse_response_head(b"HTTP/1.1 204 No Content\r\n", false).expect("204");
        assert_eq!(parsed.framing, BodyFraming::None);

        let parsed = parse_response_head(b"HTTP/1.1 200 OK\r\n", false).expect("eof");
        assert_eq!(parsed.framing, BodyFraming::UntilEof);

        let parsed =
            parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n", true).expect("HEAD");
        assert_eq!(parsed.framing, BodyFraming::None);
    }

    #[test]
    fn ambiguous_response_framing_is_rejected() {
        let err = parse_response_head(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n",
            false,
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
            let err = parse_response_head(head.as_bytes(), false).expect_err(head);
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
