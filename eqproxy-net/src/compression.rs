//! Response compression (B-N6, H6): gzip and Brotli negotiated from
//! `Accept-Encoding`.
//!
//! Both encoders stream (nothing is buffered whole) and are opt-in per
//! listener; the roadmap asks for measurements before any performance claim
//! (H6). The negotiation grammar (`MediaType`, `choose_encoding`, the default
//! type list) lives in `eqproxy_core::compression`, so the configuration gate
//! validates exactly what the dataplane applies.

pub use eqproxy_core::compression::{
    DEFAULT_TYPES, EnabledCodings, Encoding, MediaType, choose_encoding,
};

use std::io::{self, Write};

use flate2::{Compress, Compression, Crc, FlushCompress, Status};

/// Default gzip level: the middle of the 1–9 range (nginx defaults to 1,
/// HAProxy to 3; this slice measures 1, 6 and 9 before claiming anything).
pub const DEFAULT_LEVEL: u32 = 6;

/// Default Brotli quality: the middle of the 0–11 range. Levels at or above 9
/// are for precompressed assets, not per-request work.
pub const DEFAULT_BROTLI_QUALITY: u32 = 5;

/// Default minimum body for compression when the response declares its
/// length: below this, the gzip trailer costs more than it saves.
pub const DEFAULT_MIN_SIZE: u64 = 1024;

/// Parsed compression settings of one listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCompression {
    /// gzip enabled.
    pub gzip: bool,
    /// Brotli enabled.
    pub brotli: bool,
    /// gzip level, 1–9.
    pub level: u32,
    /// Brotli quality, 0–11.
    pub brotli_quality: u32,
    /// Minimum declared body length worth compressing.
    pub min_size: u64,
    /// Allowed media types.
    pub types: Vec<MediaType>,
}

impl Default for ResolvedCompression {
    /// Inert settings (no coding enabled); the gate builds the real ones with
    /// [`ResolvedCompression::new`].
    fn default() -> Self {
        Self {
            gzip: false,
            brotli: false,
            level: DEFAULT_LEVEL,
            brotli_quality: DEFAULT_BROTLI_QUALITY,
            min_size: DEFAULT_MIN_SIZE,
            types: DEFAULT_TYPES
                .iter()
                .filter_map(|spec| MediaType::parse(spec).ok())
                .collect(),
        }
    }
}

impl ResolvedCompression {
    /// Parses and validates the configured codings and media types (the config
    /// gate calls this, so an invalid entry is rejected with field and fix).
    pub fn new(
        gzip: bool,
        brotli: bool,
        level: u32,
        brotli_quality: u32,
        min_size: u64,
        types: &[String],
    ) -> Result<Self, String> {
        if !(1..=9).contains(&level) {
            return Err(format!(
                "compression level {level} is outside 1–9: use 1 (fastest) to 9 (smallest)"
            ));
        }
        if brotli_quality > 11 {
            return Err(format!(
                "brotli quality {brotli_quality} is outside 0–11: use 5 (default) or 1 for streaming"
            ));
        }
        let parsed = types
            .iter()
            .map(|spec| MediaType::parse(spec))
            .collect::<Result<Vec<_>, _>>()?;
        if (gzip || brotli) && parsed.is_empty() {
            return Err(
                "the compression type list is empty: add e.g. \"text/*\" or disable compression"
                    .to_owned(),
            );
        }
        Ok(Self {
            gzip,
            brotli,
            level,
            brotli_quality,
            min_size,
            types: parsed,
        })
    }

    /// Is this response content type eligible?
    #[must_use]
    pub fn allows_type(&self, content_type: &str) -> bool {
        self.types.iter().any(|entry| entry.matches(content_type))
    }

    /// The codings this listener could produce.
    #[must_use]
    pub fn enabled(&self) -> EnabledCodings {
        EnabledCodings {
            gzip: self.gzip,
            brotli: self.brotli,
        }
    }
}

/// One `name: value` header of a raw head (names matched case-insensitively).
fn header_values<'a>(head: &'a [u8], name: &str) -> impl Iterator<Item = &'a str> + 'a {
    let name = name.to_ascii_lowercase();
    head.split(|b| *b == b'\n').skip(1).filter_map(move |line| {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let colon = line.iter().position(|b| *b == b':')?;
        let header_name = std::str::from_utf8(&line[..colon]).ok()?.trim();
        if !header_name.eq_ignore_ascii_case(name.as_str()) {
            return None;
        }
        std::str::from_utf8(line[colon + 1..].trim_ascii()).ok()
    })
}

/// Whether a raw response head carries `name`, case-insensitively.
fn has_header(head: &[u8], name: &str) -> bool {
    header_values(head, name).next().is_some()
}

/// Facts the eligibility check needs, already parsed by the h1 engine.
pub struct ResponseFacts<'a> {
    /// Final status code.
    pub status: u16,
    /// `BodyFraming::None`.
    pub no_body: bool,
    /// `Content-Length` when the response declared one.
    pub declared_len: Option<u64>,
    /// Raw response head (status line + headers, rule additions included).
    pub head: &'a [u8],
}

/// Decides which coding (if any) this response gets. Every `None` has a named
/// reason in the comments: a silent skip is a behaviour change nobody can
/// debug.
#[must_use]
pub fn eligible(
    method: &str,
    request_version: u8,
    accept_encoding: Option<&str>,
    response: &ResponseFacts<'_>,
    settings: &ResolvedCompression,
) -> Option<Encoding> {
    // HEAD has no body to compress; HTTP/1.0 clients cannot read chunked.
    if method == "HEAD" || request_version < 11 {
        return None;
    }
    // Statuses without a body, partial replies (byte ranges are already
    // selected) and protocol switches.
    if response.no_body
        || response.status < 200
        || response.status == 204
        || response.status == 206
        || response.status == 304
        || response.status == 101
    {
        return None;
    }
    // An already-encoded or transformed body is never re-encoded.
    if has_header(response.head, "content-encoding")
        || has_header(response.head, "content-range")
        || header_values(response.head, "cache-control").any(|value| {
            value
                .split(',')
                .any(|directive| directive.trim().eq_ignore_ascii_case("no-transform"))
        })
    {
        return None;
    }
    let content_type = header_values(response.head, "content-type").next()?;
    if !settings.allows_type(content_type) {
        return None;
    }
    if let Some(len) = response.declared_len
        && len < settings.min_size
    {
        return None;
    }
    choose_encoding(accept_encoding, settings.enabled())
}

/// Rewrites a raw response head for a compressed body: drops `Content-Length`,
/// the old `Transfer-Encoding` and any `Content-Encoding`, adds
/// `Content-Encoding: <token>`, `Vary: Accept-Encoding` (unless already
/// present) and `Transfer-Encoding: chunked`.
#[must_use]
pub fn rewrite_head(head: &[u8], encoding: Encoding) -> Vec<u8> {
    // Same shape the h1 engine writes elsewhere: lines joined by CRLF, no
    // trailing terminator (the caller writes `HEAD_END`).
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut lines = head.split(|b| *b == b'\n').peekable();
    if let Some(status) = lines.next() {
        let status = status.strip_suffix(b"\r").unwrap_or(status);
        // Chunked framing requires HTTP/1.1: a backend that answered 1.0 is
        // presented as 1.1 to a client that asked for 1.1 (the only case in
        // which compression is eligible at all).
        let mut parts = status.splitn(3, |b| *b == b' ');
        match (parts.next(), parts.next(), parts.next()) {
            (Some(version), Some(code), Some(reason)) if version.starts_with(b"HTTP/") => {
                let mut line = b"HTTP/1.1 ".to_vec();
                line.extend_from_slice(code);
                line.push(b' ');
                line.extend_from_slice(reason);
                out.push(line);
            }
            _ => out.push(status.to_vec()),
        }
    }
    let mut vary_says_accept_encoding = false;
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            continue;
        };
        let name = &line[..colon];
        if name.eq_ignore_ascii_case(b"content-length")
            || name.eq_ignore_ascii_case(b"transfer-encoding")
            || name.eq_ignore_ascii_case(b"content-encoding")
        {
            continue;
        }
        if name.eq_ignore_ascii_case(b"vary")
            && line[colon + 1..]
                .split(|b| *b == b',')
                .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"accept-encoding"))
        {
            vary_says_accept_encoding = true;
        }
        out.push(line.to_vec());
    }
    out.push(format!("content-encoding: {}", encoding.token()).into_bytes());
    if !vary_says_accept_encoding {
        out.push(b"vary: Accept-Encoding".to_vec());
    }
    out.push(b"transfer-encoding: chunked".to_vec());
    let mut joined = Vec::with_capacity(head.len() + 96);
    for (index, line) in out.iter().enumerate() {
        if index > 0 {
            joined.extend_from_slice(b"\r\n");
        }
        joined.extend_from_slice(line);
    }
    joined
}

/// Fixed gzip member header (RFC 1952 §2.3): deflate, no FNAME/FCOMMENT,
/// mtime 0 (reproducible output), OS 255 (unspecified).
const GZIP_HEADER: [u8; 10] = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];

/// Streaming gzip encoder: no body is buffered whole, and the caller decides
/// where the produced bytes go (the h1 chunk writer). The member header is
/// emitted with the first `push` and the CRC/ISIZE trailer with `finish`.
pub struct GzipEncoder {
    compress: Compress,
    crc: Crc,
    /// Total uncompressed bytes; ISIZE is this modulo 2^32 (RFC 1952 §2.3).
    input_len: u64,
    started: bool,
}

impl GzipEncoder {
    /// A gzip member with the given level (validated by the config gate).
    pub fn new(level: u32) -> io::Result<Self> {
        // Raw deflate: the gzip wrapper is written here, byte for byte.
        let compress = Compress::new(Compression::new(level.clamp(1, 9)), false);
        Ok(Self {
            compress,
            crc: Crc::new(),
            input_len: 0,
            started: false,
        })
    }

    /// Compresses `input` into `out` (appended). No flush.
    pub fn push(&mut self, input: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        if !self.started {
            out.extend_from_slice(&GZIP_HEADER);
            self.started = true;
        }
        self.crc.update(input);
        self.input_len += input.len() as u64;
        self.pump(input, FlushCompress::None, out, false)
    }

    /// Ends the member (writes the trailer) into `out` (appended).
    pub fn finish(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        if !self.started {
            out.extend_from_slice(&GZIP_HEADER);
            self.started = true;
        }
        self.pump(&[], FlushCompress::Finish, out, true)?;
        out.extend_from_slice(&self.crc.sum().to_le_bytes());
        out.extend_from_slice(&(self.input_len as u32).to_le_bytes());
        Ok(())
    }

    /// One compression round-trip loop: feeds all of `input`, then keeps
    /// draining until the output buffer is not full (or the member ends).
    fn pump(
        &mut self,
        input: &[u8],
        flush: FlushCompress,
        out: &mut Vec<u8>,
        finishing: bool,
    ) -> io::Result<()> {
        const CHUNK: usize = 16 * 1024;
        const MAX_ROUNDS: usize = 4096;
        let mut fed = 0usize;
        for _ in 0..MAX_ROUNDS {
            let start = out.len();
            out.resize(start + CHUNK, 0);
            let before_in = self.compress.total_in();
            let before_out = self.compress.total_out();
            let status = self
                .compress
                .compress(&input[fed..], &mut out[start..], flush)
                .map_err(|err| io::Error::other(err.to_string()))?;
            fed += (self.compress.total_in() - before_in) as usize;
            out.truncate(start + (self.compress.total_out() - before_out) as usize);
            if status == Status::StreamEnd {
                return Ok(());
            }
            let produced = out.len() - start;
            if fed >= input.len() && produced < CHUNK && !finishing {
                return Ok(());
            }
            if produced == 0 && fed >= input.len() {
                return if finishing {
                    Err(io::Error::other("gzip stream did not finish"))
                } else {
                    Ok(())
                };
            }
        }
        Err(io::Error::other("gzip stream did not converge"))
    }
}

/// Streaming Brotli encoder (RFC 7932) over the pure-Rust `brotli` crate.
///
/// `CompressorWriter` is fed the plaintext bytes and flushes after every push:
/// the h1 relay must forward what it has read without waiting for a full
/// internal buffer (a stalled streaming response would otherwise sit in the
/// encoder). The produced bytes are drained from the writer's inner `Vec`.
pub struct BrotliEncoder {
    writer: Option<brotli::CompressorWriter<Vec<u8>>>,
}

impl BrotliEncoder {
    /// A Brotli stream with the given quality (validated by the config gate).
    pub fn new(quality: u32) -> io::Result<Self> {
        if quality > 11 {
            return Err(io::Error::other(format!(
                "brotli quality {quality} is outside 0–11"
            )));
        }
        // 16 KiB internal buffer, window 2^22 (the format's usual maximum for
        // streams served to browsers).
        Ok(Self {
            writer: Some(brotli::CompressorWriter::new(
                Vec::new(),
                16 * 1024,
                quality,
                22,
            )),
        })
    }

    /// Compresses `input` into `out` (appended) and flushes a decodable
    /// prefix, so the relay never holds the response back.
    pub fn push(&mut self, input: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| io::Error::other("brotli stream already finished"))?;
        writer.write_all(input)?;
        writer.flush()?;
        out.append(writer.get_mut());
        Ok(())
    }

    /// Ends the stream (writes the final block) into `out` (appended).
    pub fn finish(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        let writer = self
            .writer
            .take()
            .ok_or_else(|| io::Error::other("brotli stream already finished"))?;
        // `into_inner` runs BROTLI_OPERATION_FINISH; a `Vec` sink cannot fail.
        out.append(&mut writer.into_inner());
        Ok(())
    }
}

/// The streaming encoder selected for one response.
pub enum Encoder {
    /// gzip member writer.
    Gzip(Box<GzipEncoder>),
    /// Brotli stream writer.
    Brotli(Box<BrotliEncoder>),
}

impl Encoder {
    /// Builds the encoder for `encoding` from the listener settings. The
    /// encoder is boxed because the two states differ by an order of
    /// magnitude; one allocation per compressed response buys a small enum.
    pub fn new(encoding: Encoding, settings: &ResolvedCompression) -> io::Result<Self> {
        Ok(match encoding {
            Encoding::Gzip => Self::Gzip(Box::new(GzipEncoder::new(settings.level)?)),
            Encoding::Brotli => {
                Self::Brotli(Box::new(BrotliEncoder::new(settings.brotli_quality)?))
            }
        })
    }

    /// Compresses `input` into `out` (appended).
    pub fn push(&mut self, input: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        match self {
            Self::Gzip(encoder) => encoder.push(input, out),
            Self::Brotli(encoder) => encoder.push(input, out),
        }
    }

    /// Ends the compressed stream into `out` (appended).
    pub fn finish(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        match self {
            Self::Gzip(encoder) => encoder.finish(out),
            Self::Brotli(encoder) => encoder.finish(out),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn settings(gzip: bool, brotli: bool) -> ResolvedCompression {
        let types = DEFAULT_TYPES.map(str::to_owned);
        ResolvedCompression::new(gzip, brotli, 6, 5, 1024, &types).unwrap()
    }

    fn head(lines: &[&str]) -> Vec<u8> {
        let mut head = String::from("HTTP/1.1 200 OK\r\n");
        for line in lines {
            head.push_str(line);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        head.into_bytes()
    }

    fn facts<'a>(head: &'a [u8], len: Option<u64>) -> ResponseFacts<'a> {
        ResponseFacts {
            status: 200,
            no_body: false,
            declared_len: len,
            head,
        }
    }

    #[test]
    fn eligibility_names_every_refusal() {
        let plain = head(&["content-type: text/plain"]);
        let set = settings(true, false);
        assert_eq!(
            eligible("GET", 11, Some("gzip"), &facts(&plain, Some(4096)), &set),
            Some(Encoding::Gzip)
        );
        // Unknown length (chunked / until-EOF) cannot be compared to the
        // minimum: it is eligible, as the origin chose to stream it.
        assert_eq!(
            eligible("GET", 11, Some("gzip"), &facts(&plain, None), &set),
            Some(Encoding::Gzip)
        );
        assert!(eligible("HEAD", 11, Some("gzip"), &facts(&plain, Some(4096)), &set).is_none());
        assert!(eligible("GET", 10, Some("gzip"), &facts(&plain, Some(4096)), &set).is_none());
        assert!(eligible("GET", 11, None, &facts(&plain, Some(4096)), &set).is_none());
        assert!(eligible("GET", 11, Some("gzip"), &facts(&plain, Some(512)), &set).is_none());
        let mut no_body = facts(&plain, None);
        no_body.no_body = true;
        assert!(eligible("GET", 11, Some("gzip"), &no_body, &set).is_none());
        let mut not_modified = facts(&plain, Some(4096));
        not_modified.status = 304;
        assert!(eligible("GET", 11, Some("gzip"), &not_modified, &set).is_none());
        let mut partial = facts(&plain, Some(4096));
        partial.status = 206;
        assert!(eligible("GET", 11, Some("gzip"), &partial, &set).is_none());
        assert!(
            eligible(
                "GET",
                11,
                Some("gzip"),
                &facts(
                    &head(&["content-type: text/plain", "content-encoding: br"]),
                    None
                ),
                &set
            )
            .is_none()
        );
        assert!(
            eligible(
                "GET",
                11,
                Some("gzip"),
                &facts(
                    &head(&["content-type: text/plain", "content-range: bytes 0-9/10"]),
                    None
                ),
                &set
            )
            .is_none()
        );
        assert!(
            eligible(
                "GET",
                11,
                Some("gzip"),
                &facts(
                    &head(&[
                        "content-type: text/plain",
                        "cache-control: public, no-transform"
                    ]),
                    None
                ),
                &set
            )
            .is_none()
        );
        assert!(
            eligible(
                "GET",
                11,
                Some("gzip"),
                &facts(&head(&["content-type: image/png"]), None),
                &set
            )
            .is_none()
        );
        assert!(eligible("GET", 11, Some("gzip"), &facts(&head(&[]), None), &set).is_none());
    }

    #[test]
    fn brotli_is_selected_only_when_enabled_and_accepted() {
        let plain = head(&["content-type: text/plain"]);
        let both = settings(true, true);
        let only_brotli = settings(false, true);
        assert_eq!(
            eligible(
                "GET",
                11,
                Some("gzip, br"),
                &facts(&plain, Some(4096)),
                &both
            ),
            Some(Encoding::Brotli)
        );
        assert_eq!(
            eligible(
                "GET",
                11,
                Some("br;q=0.4, gzip"),
                &facts(&plain, Some(4096)),
                &both
            ),
            Some(Encoding::Gzip)
        );
        assert_eq!(
            eligible(
                "GET",
                11,
                Some("br"),
                &facts(&plain, Some(4096)),
                &only_brotli
            ),
            Some(Encoding::Brotli)
        );
        assert!(
            eligible(
                "GET",
                11,
                Some("gzip"),
                &facts(&plain, Some(4096)),
                &only_brotli
            )
            .is_none()
        );
        // A coding the listener did not enable is never fabricated.
        assert!(
            eligible(
                "GET",
                11,
                Some("br"),
                &facts(&plain, Some(4096)),
                &settings(true, false)
            )
            .is_none()
        );
    }

    #[test]
    fn the_rewritten_head_says_what_the_body_is() {
        let raw = head(&[
            "content-type: text/html",
            "content-length: 4096",
            "vary: accept-encoding",
            "server: origin",
        ]);
        let rewritten = String::from_utf8(rewrite_head(&raw, Encoding::Gzip)).unwrap();
        // The caller writes the head terminator: it must not be duplicated.
        assert!(!rewritten.ends_with("\r\n"), "{rewritten:?}");
        assert!(rewritten.starts_with("HTTP/1.1 200 OK\r\n"), "{rewritten}");
        assert!(
            !rewritten.to_lowercase().contains("content-length"),
            "{rewritten}"
        );
        assert_eq!(rewritten.matches("vary:").count(), 1, "{rewritten}");
        assert!(
            rewritten.contains("content-encoding: gzip\r\n"),
            "{rewritten}"
        );
        assert!(
            rewritten.contains("transfer-encoding: chunked"),
            "{rewritten}"
        );
        assert!(
            rewritten.ends_with("transfer-encoding: chunked"),
            "{rewritten}"
        );
        assert!(rewritten.contains("server: origin\r\n"), "{rewritten}");
        // The token follows the negotiated coding, not a hardcoded name.
        let rewritten = String::from_utf8(rewrite_head(&raw, Encoding::Brotli)).unwrap();
        assert!(
            rewritten.contains("content-encoding: br\r\n"),
            "{rewritten}"
        );
        assert!(
            !rewritten.to_lowercase().contains("content-encoding: gzip"),
            "{rewritten}"
        );
        // A backend that answered HTTP/1.0 is presented as HTTP/1.1 to the
        // 1.1 client that can read chunked framing.
        let old = b"HTTP/1.0 200 OK\r\ncontent-type: text/plain";
        let rewritten = String::from_utf8(rewrite_head(old, Encoding::Gzip)).unwrap();
        assert!(rewritten.starts_with("HTTP/1.1 200 OK\r\n"), "{rewritten}");
        // Without an existing Vary, it is added once.
        let raw = head(&["content-type: text/plain", "content-length: 9"]);
        let rewritten = String::from_utf8(rewrite_head(&raw, Encoding::Gzip)).unwrap();
        assert_eq!(
            rewritten.matches("vary: Accept-Encoding").count(),
            1,
            "{rewritten}"
        );
    }

    #[test]
    fn the_encoder_roundtrips_and_sets_the_gzip_magic() {
        let body = "hello compression ".repeat(4096);
        let mut out = Vec::new();
        let mut encoder = GzipEncoder::new(6).unwrap();
        for block in body.as_bytes().chunks(1000) {
            encoder.push(block, &mut out).unwrap();
        }
        encoder.finish(&mut out).unwrap();
        assert_eq!(&out[..2], &[0x1f, 0x8b], "gzip magic missing");
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(&out[..])
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, body.as_bytes());
    }

    #[test]
    fn the_encoder_bounds_expand_incompressible_input() {
        // A member never grows the payload by more than the gzip framing plus
        // deflate's worst case for stored blocks (5 bytes per 65 535).
        let body: Vec<u8> = (0..200_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        let mut out = Vec::new();
        let mut encoder = GzipEncoder::new(1).unwrap();
        encoder.push(&body, &mut out).unwrap();
        encoder.finish(&mut out).unwrap();
        assert!(
            out.len() < body.len() + body.len() / 10_000 + 64,
            "unexpected expansion: {} for {}",
            out.len(),
            body.len()
        );
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(&out[..])
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn the_brotli_encoder_streams_a_decodable_body() {
        let body = "hello brotli compression ".repeat(4096);
        let mut out = Vec::new();
        let mut encoder = BrotliEncoder::new(5).unwrap();
        for block in body.as_bytes().chunks(1000) {
            encoder.push(block, &mut out).unwrap();
            // Each push flushes: the relay can write what it already has.
            assert!(!out.is_empty(), "a flushed chunk must produce bytes");
        }
        encoder.finish(&mut out).unwrap();
        let mut decoded = Vec::new();
        brotli::Decompressor::new(&out[..], 4096)
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, body.as_bytes());
        assert!(
            out.len() < body.len() / 2,
            "repetitive text should compress: {} vs {}",
            out.len(),
            body.len()
        );
        assert!(BrotliEncoder::new(12).is_err(), "quality 12 is invalid");
    }

    #[test]
    fn the_brotli_encoder_bounds_expand_incompressible_input() {
        let body: Vec<u8> = (0..200_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        let mut out = Vec::new();
        let mut encoder = BrotliEncoder::new(1).unwrap();
        encoder.push(&body, &mut out).unwrap();
        encoder.finish(&mut out).unwrap();
        assert!(
            out.len() < body.len() + body.len() / 100 + 1024,
            "unexpected expansion: {} for {}",
            out.len(),
            body.len()
        );
        let mut decoded = Vec::new();
        brotli::Decompressor::new(&out[..], 4096)
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn the_encoder_selects_the_negotiated_coding() {
        let body = "selected coding ".repeat(2000);
        for (encoding, magic) in [
            (Encoding::Gzip, Some([0x1f, 0x8b])),
            (Encoding::Brotli, None),
        ] {
            let set = settings(encoding == Encoding::Gzip, encoding == Encoding::Brotli);
            let mut out = Vec::new();
            let mut encoder = Encoder::new(encoding, &set).unwrap();
            encoder.push(body.as_bytes(), &mut out).unwrap();
            encoder.finish(&mut out).unwrap();
            if let Some(magic) = magic {
                assert_eq!(&out[..2], &magic);
            }
            assert!(!out.is_empty());
        }
    }
}
