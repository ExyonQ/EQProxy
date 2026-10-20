//! PROXY protocol v1 (A9) and v2 (A10): header generation towards the
//! backend and reception from trusted origins (B-H9/B-E10).
//!
//! THREAT_MODEL: never trust PROXY from unauthorized sources — reception
//! is strict: only allowlisted origins, only a valid header. Formats per
//! the PROXY protocol spec: v1 line (max 107 bytes) or v2 binary (the
//! signature auto-detects the version; TLVs past the address block are
//! accepted and ignored, everything malformed is rejected explicitly).

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use eqproxy_core::expectation::IpAllowlist;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum PROXY v1 line length, CRLF included (spec).
pub const MAX_V1_LINE: usize = 107;

/// PROXY v2 signature (`\r\n\r\n\0\r\nQUIT\n`, spec §2.2).
const V2_SIG: &[u8] = b"\x0D\x0A\x0D\x0A\x00\x0D\x0AQUIT\x0A";

/// Bounded v2 address block (12/36 bytes used; the rest are TLVs).
const MAX_V2_BLOCK: usize = 512;

/// PROXY protocol send mode (A9/A10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyProtocolMode {
    /// No PROXY header (default).
    #[default]
    None,
    /// PROXY protocol v1 header (`PROXY TCP4/TCP6 …`).
    V1,
    /// PROXY protocol v2 binary header.
    V2,
}

/// Encodes the PROXY v1 header for the pair (client, proxy local address).
/// Mixed families or non-TCP → `PROXY UNKNOWN\r\n` (HAProxy semantics).
#[must_use]
pub fn encode_v1(peer: SocketAddr, local: SocketAddr) -> Vec<u8> {
    match (peer, local) {
        (SocketAddr::V4(p), SocketAddr::V4(l)) => format!(
            "PROXY TCP4 {} {} {} {}\r\n",
            p.ip(),
            l.ip(),
            p.port(),
            l.port()
        )
        .into_bytes(),
        (SocketAddr::V6(p), SocketAddr::V6(l)) => format!(
            "PROXY TCP6 {} {} {} {}\r\n",
            p.ip(),
            l.ip(),
            p.port(),
            l.port()
        )
        .into_bytes(),
        _ => b"PROXY UNKNOWN\r\n".to_vec(),
    }
}

/// Encodes the PROXY v2 header for the pair (client, proxy local address).
/// Mixed families or non-TCP → LOCAL command with empty block (HAProxy
/// semantics, the v2 form of `PROXY UNKNOWN`).
#[must_use]
pub fn encode_v2(peer: SocketAddr, local: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 36);
    out.extend_from_slice(V2_SIG);
    match (peer, local) {
        (SocketAddr::V4(p), SocketAddr::V4(l)) => {
            out.extend_from_slice(&[0x21, 0x11]); // version 2, PROXY; AF_INET, STREAM
            out.extend_from_slice(&12u16.to_be_bytes());
            out.extend_from_slice(&p.ip().octets());
            out.extend_from_slice(&l.ip().octets());
            out.extend_from_slice(&p.port().to_be_bytes());
            out.extend_from_slice(&l.port().to_be_bytes());
        }
        (SocketAddr::V6(p), SocketAddr::V6(l)) => {
            out.extend_from_slice(&[0x21, 0x21]); // version 2, PROXY; AF_INET6, STREAM
            out.extend_from_slice(&36u16.to_be_bytes());
            out.extend_from_slice(&p.ip().octets());
            out.extend_from_slice(&l.ip().octets());
            out.extend_from_slice(&p.port().to_be_bytes());
            out.extend_from_slice(&l.port().to_be_bytes());
        }
        _ => {
            out.extend_from_slice(&[0x20, 0x00]); // version 2, LOCAL; unspecified
            out.extend_from_slice(&0u16.to_be_bytes());
        }
    }
    out
}

/// Writes the PROXY v2 header to the stream (single write, flush
/// included) before pumping the payload.
pub async fn write_v2<W: AsyncWrite + Unpin>(
    writer: &mut W,
    peer: SocketAddr,
    local: SocketAddr,
) -> std::io::Result<()> {
    let header = encode_v2(peer, local);
    writer.write_all(&header).await?;
    writer.flush().await
}

/// Writes the PROXY v1 header to the stream (single write, flush
/// included) before pumping the payload.
pub async fn write_v1<W: AsyncWrite + Unpin>(
    writer: &mut W,
    peer: SocketAddr,
    local: SocketAddr,
) -> std::io::Result<()> {
    let header = encode_v1(peer, local);
    writer.write_all(&header).await?;
    writer.flush().await
}

/// Reception error of a PROXY v1 header (B-H9/B-E10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyReceiveError {
    /// The peer is not in the origin allowlist (strict front door).
    Denied,
    /// Malformed or oversized header.
    Invalid,
    /// The header never arrived within the window.
    Timeout,
}

/// Reads and validates a PROXY header (v1 line or v2 binary, detected by
/// signature) from a trusted origin (B-H9/B-E10). Same strict front door
/// as [`read_v1`]: allowlisted origins only, valid headers only, nothing
/// past the header consumed.
pub async fn read_proxy_header<R: AsyncRead + Unpin>(
    reader: &mut R,
    peer: SocketAddr,
    allowlist: &IpAllowlist,
    timeout: Duration,
) -> Result<SocketAddr, ProxyReceiveError> {
    if !allowlist.contains(peer.ip()) {
        return Err(ProxyReceiveError::Denied);
    }
    match tokio::time::timeout(timeout, read_any_header(reader)).await {
        Err(_elapsed) => Err(ProxyReceiveError::Timeout),
        Ok(Err(_io)) => Err(ProxyReceiveError::Invalid),
        Ok(Ok(bytes)) => {
            if bytes.len() >= V2_SIG.len() && bytes[..V2_SIG.len()] == *V2_SIG {
                parse_v2(&bytes, peer)
            } else {
                parse_v1(&String::from_utf8_lossy(&bytes), peer)
            }
        }
    }
}

/// Reads one PROXY header of either version, byte by byte so no payload
/// byte past it is ever consumed. v1 ends at `\r\n` (107 bytes max); v2
/// is fixed-size from its length field ([`MAX_V2_BLOCK`] bound).
async fn read_any_header<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(MAX_V1_LINE);
    let mut byte = [0_u8; 1];
    loop {
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF before the PROXY header ended",
            ));
        }
        buf.push(byte[0]);
        // The two signatures diverge byte by byte; anything else is not
        // a PROXY header at all.
        let is_v2 = if buf.len() >= V2_SIG.len() {
            buf[..V2_SIG.len()] == *V2_SIG
        } else {
            V2_SIG.starts_with(&buf)
        };
        let is_v1 = buf.starts_with(b"PROXY ") || b"PROXY ".starts_with(&buf);
        if !is_v2 && !is_v1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "not a PROXY header",
            ));
        }
        if is_v2 {
            if buf.len() < 16 {
                continue;
            }
            if buf.len() == 16 {
                let block = usize::from(u16::from_be_bytes([buf[14], buf[15]]));
                if block > MAX_V2_BLOCK {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "PROXY v2 block exceeds the bound",
                    ));
                }
                while buf.len() < 16 + block {
                    let n = reader.read(&mut byte).await?;
                    if n == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "EOF before the PROXY v2 block ended",
                        ));
                    }
                    buf.push(byte[0]);
                }
                return Ok(buf);
            }
            continue;
        }
        if buf.ends_with(b"\r\n") {
            return Ok(buf);
        }
        if buf.len() >= MAX_V1_LINE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "PROXY v1 line exceeds 107 bytes",
            ));
        }
    }
}

/// Parses a complete PROXY v2 header. `LOCAL` keeps the real peer (the
/// v2 form of `PROXY UNKNOWN`); `PROXY` claims the source address. TLVs
/// past the address block are ignored (spec §2.2).
fn parse_v2(header: &[u8], peer: SocketAddr) -> Result<SocketAddr, ProxyReceiveError> {
    if header.len() < 16 || header[..V2_SIG.len()] != *V2_SIG {
        return Err(ProxyReceiveError::Invalid);
    }
    let version_cmd = header[12];
    let family = header[13];
    let block = usize::from(u16::from_be_bytes([header[14], header[15]]));
    if version_cmd >> 4 != 2 || header.len() != 16 + block {
        return Err(ProxyReceiveError::Invalid);
    }
    match version_cmd & 0x0f {
        0x0 => Ok(peer), // LOCAL
        0x1 => match family {
            0x11 => {
                // AF_INET, STREAM: src(4) dst(4) srcport(2) dstport(2).
                if block < 12 {
                    return Err(ProxyReceiveError::Invalid);
                }
                let src = IpAddr::V4(std::net::Ipv4Addr::new(
                    header[16], header[17], header[18], header[19],
                ));
                let src_port = u16::from_be_bytes([header[24], header[25]]);
                let dst_port = u16::from_be_bytes([header[26], header[27]]);
                if src_port == 0 || dst_port == 0 {
                    return Err(ProxyReceiveError::Invalid);
                }
                Ok(SocketAddr::new(src, src_port))
            }
            0x21 => {
                // AF_INET6, STREAM: src(16) dst(16) srcport(2) dstport(2).
                if block < 36 {
                    return Err(ProxyReceiveError::Invalid);
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&header[16..32]);
                let src = IpAddr::V6(std::net::Ipv6Addr::from(octets));
                let src_port = u16::from_be_bytes([header[48], header[49]]);
                let dst_port = u16::from_be_bytes([header[50], header[51]]);
                if src_port == 0 || dst_port == 0 {
                    return Err(ProxyReceiveError::Invalid);
                }
                Ok(SocketAddr::new(src, src_port))
            }
            // UNIX/UNSPEC and non-stream: unsupported, explicit rejection.
            _ => Err(ProxyReceiveError::Invalid),
        },
        _ => Err(ProxyReceiveError::Invalid),
    }
}

/// Reads and validates a PROXY v1 header from a trusted origin (B-H9).
///
/// Strict front-door semantics (documented): when reception is enabled,
/// **every** connection must come from an allowlisted origin and start
/// with a valid PROXY v1 line; anything else is rejected explicitly
/// (never silently treated as payload). The claimed client address
/// replaces `peer` downstream (XFF, logs, PROXY send); `PROXY UNKNOWN`
/// keeps the real peer. The line is read byte by byte, so no payload
/// byte past `\r\n` is consumed.
pub async fn read_v1<R: AsyncRead + Unpin>(
    reader: &mut R,
    peer: SocketAddr,
    allowlist: &IpAllowlist,
    timeout: Duration,
) -> Result<SocketAddr, ProxyReceiveError> {
    if !allowlist.contains(peer.ip()) {
        return Err(ProxyReceiveError::Denied);
    }
    match tokio::time::timeout(timeout, read_v1_line(reader)).await {
        Err(_elapsed) => Err(ProxyReceiveError::Timeout),
        Ok(Err(_io)) => Err(ProxyReceiveError::Invalid),
        Ok(Ok(line)) => parse_v1(&line, peer),
    }
}

/// Reads one PROXY v1 line (`\r\n`-terminated, [`MAX_V1_LINE`] max).
async fn read_v1_line<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<String> {
    let mut line: Vec<u8> = Vec::with_capacity(MAX_V1_LINE);
    let mut byte = [0_u8; 1];
    loop {
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF before the PROXY v1 line ended",
            ));
        }
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            return String::from_utf8(line).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "non-UTF-8 PROXY line")
            });
        }
        if line.len() >= MAX_V1_LINE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "PROXY v1 line exceeds 107 bytes",
            ));
        }
    }
}

/// Parses a complete PROXY v1 line (with its `\r\n`). Pure.
fn parse_v1(line: &str, peer: SocketAddr) -> Result<SocketAddr, ProxyReceiveError> {
    let body = line
        .strip_suffix("\r\n")
        .ok_or(ProxyReceiveError::Invalid)?;
    let rest = body
        .strip_prefix("PROXY ")
        .ok_or(ProxyReceiveError::Invalid)?;
    if rest == "UNKNOWN" {
        return Ok(peer);
    }
    let mut parts = rest.split(' ');
    let proto = parts.next().ok_or(ProxyReceiveError::Invalid)?;
    let src_ip = parts.next().ok_or(ProxyReceiveError::Invalid)?;
    let dst_ip = parts.next().ok_or(ProxyReceiveError::Invalid)?;
    let src_port = parts.next().ok_or(ProxyReceiveError::Invalid)?;
    let dst_port = parts.next().ok_or(ProxyReceiveError::Invalid)?;
    if parts.next().is_some() {
        return Err(ProxyReceiveError::Invalid);
    }
    let src_ip: IpAddr = src_ip.parse().map_err(|_| ProxyReceiveError::Invalid)?;
    let dst_ip: IpAddr = dst_ip.parse().map_err(|_| ProxyReceiveError::Invalid)?;
    let src_port: u16 = src_port.parse().map_err(|_| ProxyReceiveError::Invalid)?;
    let dst_port: u16 = dst_port.parse().map_err(|_| ProxyReceiveError::Invalid)?;
    let family_ok = match proto {
        "TCP4" => src_ip.is_ipv4() && dst_ip.is_ipv4(),
        "TCP6" => src_ip.is_ipv6() && dst_ip.is_ipv6(),
        _ => false,
    };
    if !family_ok || src_port == 0 || dst_port == 0 {
        return Err(ProxyReceiveError::Invalid);
    }
    Ok(SocketAddr::new(src_ip, src_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_v1_formats_tcp4() {
        let peer: SocketAddr = "192.0.2.1:51234".parse().expect("peer");
        let local: SocketAddr = "198.51.100.7:443".parse().expect("local");
        assert_eq!(
            encode_v1(peer, local),
            b"PROXY TCP4 192.0.2.1 198.51.100.7 51234 443\r\n"
        );
    }

    #[test]
    fn encode_v1_formats_tcp6() {
        let peer: SocketAddr = "[2001:db8::1]:51234".parse().expect("peer");
        let local: SocketAddr = "[2001:db8::2]:443".parse().expect("local");
        let header = encode_v1(peer, local);
        assert_eq!(
            header,
            b"PROXY TCP6 2001:db8::1 2001:db8::2 51234 443\r\n".to_vec()
        );
        assert!(header.len() <= 107, "the v1 header is 107 bytes max");
    }

    #[test]
    fn encode_v1_mixed_families_produce_unknown() {
        let peer: SocketAddr = "192.0.2.1:1".parse().expect("peer");
        let local: SocketAddr = "[::1]:2".parse().expect("local");
        assert_eq!(encode_v1(peer, local), b"PROXY UNKNOWN\r\n");

        let peer6: SocketAddr = "[::1]:1".parse().expect("peer");
        let local4: SocketAddr = "127.0.0.1:2".parse().expect("local");
        assert_eq!(encode_v1(peer6, local4), b"PROXY UNKNOWN\r\n");
    }

    fn allowlist(entries: &[&str]) -> IpAllowlist {
        IpAllowlist::parse(&entries.iter().map(|e| (*e).to_owned()).collect::<Vec<_>>())
            .expect("allowlist")
    }

    #[test]
    fn parse_v1_claims_the_source_address() {
        let peer: SocketAddr = "10.0.0.1:1000".parse().expect("peer");
        assert_eq!(
            parse_v1("PROXY TCP4 192.0.2.1 198.51.100.7 51234 443\r\n", peer),
            Ok("192.0.2.1:51234".parse().expect("addr"))
        );
        assert_eq!(
            parse_v1("PROXY TCP6 2001:db8::1 2001:db8::2 1 2\r\n", peer),
            Ok("[2001:db8::1]:1".parse().expect("addr"))
        );
        assert_eq!(
            parse_v1("PROXY UNKNOWN\r\n", peer),
            Ok(peer),
            "UNKNOWN keeps the real peer"
        );
    }

    #[test]
    fn parse_v1_rejects_malformed_lines() {
        let peer: SocketAddr = "10.0.0.1:1000".parse().expect("peer");
        for line in [
            "PROXY TCP4 192.0.2.1 198.51.100.7 51234\r\n", // missing field
            "PROXY TCP4 192.0.2.1 198.51.100.7 51234 443 extra\r\n", // extra field
            "PROXY TCP4 192.0.2.1 198.51.100.7 0 443\r\n", // port 0
            "PROXY TCP4 2001:db8::1 198.51.100.7 1 2\r\n", // family mismatch
            "PROXY TCP4 not-an-ip 198.51.100.7 1 2\r\n",   // bad ip
            "PROXY TCP4 192.0.2.1 198.51.100.7 x 2\r\n",   // bad port
            "hello TCP4 192.0.2.1 198.51.100.7 1 2\r\n",   // no prefix
            "PROXY TCP4 192.0.2.1 198.51.100.7 1 2\n",     // no CRLF pair
        ] {
            assert_eq!(
                parse_v1(line, peer),
                Err(ProxyReceiveError::Invalid),
                "{line:?} must be rejected"
            );
        }
    }

    #[test]
    fn read_v1_is_strict_about_origins_and_format() {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime tokio")
            .block_on(async {
                let allowed = allowlist(&["10.0.0.0/8"]);
                let peer: SocketAddr = "10.0.0.1:1000".parse().expect("peer");

                // Not in the allowlist: denied before reading anything.
                let outsider: SocketAddr = "203.0.113.9:2000".parse().expect("peer");
                let mut bytes: &[u8] = b"PROXY TCP4 192.0.2.1 198.51.100.7 51234 443\r\n";
                assert_eq!(
                    read_v1(&mut bytes, outsider, &allowed, Duration::from_secs(1)).await,
                    Err(ProxyReceiveError::Denied)
                );

                // Allowlisted + valid: the claimed address replaces the peer.
                let mut bytes: &[u8] = b"PROXY TCP4 192.0.2.1 198.51.100.7 51234 443\r\nGET /\r\n";
                let claimed = read_v1(&mut bytes, peer, &allowed, Duration::from_secs(1))
                    .await
                    .expect("valid header");
                assert_eq!(claimed, "192.0.2.1:51234".parse().expect("addr"));
                assert_eq!(bytes, b"GET /\r\n", "no payload byte is consumed");

                // Allowlisted + malformed: rejected explicitly.
                let mut bytes: &[u8] = b"GET / HTTP/1.1\r\n";
                assert_eq!(
                    read_v1(&mut bytes, peer, &allowed, Duration::from_secs(1)).await,
                    Err(ProxyReceiveError::Invalid)
                );
            });
    }

    #[test]
    fn encode_v2_formats_tcp4_tcp6_and_local() {
        let peer: SocketAddr = "192.0.2.1:51234".parse().expect("peer");
        let local: SocketAddr = "198.51.100.7:443".parse().expect("local");
        let header = encode_v2(peer, local);
        assert_eq!(&header[..12], V2_SIG);
        assert_eq!(&header[12..16], &[0x21, 0x11, 0x00, 0x0c]);
        assert_eq!(&header[16..20], &[192, 0, 2, 1]);
        assert_eq!(&header[20..24], &[198, 51, 100, 7]);
        assert_eq!(&header[24..26], &51234u16.to_be_bytes());
        assert_eq!(&header[26..28], &443u16.to_be_bytes());
        assert_eq!(header.len(), 28);

        let peer6: SocketAddr = "[2001:db8::1]:1".parse().expect("peer");
        let local6: SocketAddr = "[2001:db8::2]:2".parse().expect("local");
        let header = encode_v2(peer6, local6);
        assert_eq!(&header[12..16], &[0x21, 0x21, 0x00, 0x24]);
        assert_eq!(header.len(), 52);

        // Mixed families → LOCAL (the v2 form of `PROXY UNKNOWN`).
        let header = encode_v2(peer, local6);
        assert_eq!(&header[12..16], &[0x20, 0x00, 0x00, 0x00]);
        assert_eq!(header.len(), 16);
    }

    #[test]
    fn parse_v2_claims_the_source_and_ignores_tlv_padding() {
        let peer: SocketAddr = "10.0.0.1:1000".parse().expect("peer");
        let claimed: SocketAddr = "192.0.2.1:51234".parse().expect("claimed");
        let local: SocketAddr = "198.51.100.7:443".parse().expect("local");
        let header = encode_v2(claimed, local);
        assert_eq!(parse_v2(&header, peer), Ok(claimed));

        // TLVs past the address block are ignored (spec §2.2).
        let mut padded = header.clone();
        padded[14..16].copy_from_slice(&16u16.to_be_bytes());
        padded.extend_from_slice(&[0xEA, 0x04, 0x00, 0x00]);
        assert_eq!(parse_v2(&padded, peer), Ok(claimed));

        // LOCAL keeps the real peer.
        let local_only = encode_v2(claimed, "[2001:db8::2]:2".parse().expect("local6"));
        assert_eq!(parse_v2(&local_only, peer), Ok(peer));

        // Malformed: wrong version, unsupported family, port 0, truncated.
        let mut bad = header.clone();
        bad[12] = 0x31; // version 3
        assert_eq!(parse_v2(&bad, peer), Err(ProxyReceiveError::Invalid));
        let mut bad = header.clone();
        bad[13] = 0x31; // AF_UNIX: unsupported
        assert_eq!(parse_v2(&bad, peer), Err(ProxyReceiveError::Invalid));
        let mut bad = header.clone();
        bad[24..26].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(parse_v2(&bad, peer), Err(ProxyReceiveError::Invalid));
        let mut bad = header;
        bad.truncate(20);
        assert_eq!(parse_v2(&bad, peer), Err(ProxyReceiveError::Invalid));
    }

    #[test]
    fn read_proxy_header_detects_both_versions_without_consuming_payload() {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime tokio")
            .block_on(async {
                let allowed = allowlist(&["10.0.0.0/8"]);
                let peer: SocketAddr = "10.0.0.1:1000".parse().expect("peer");
                let claimed: SocketAddr = "192.0.2.1:51234".parse().expect("claimed");
                let local: SocketAddr = "198.51.100.7:443".parse().expect("local");

                // v2 binary header + payload untouched.
                let mut bytes_owned = encode_v2(claimed, local);
                bytes_owned.extend_from_slice(b"GET /\r\n");
                let mut bytes: &[u8] = &bytes_owned;
                let got = read_proxy_header(&mut bytes, peer, &allowed, Duration::from_secs(1))
                    .await
                    .expect("v2 header");
                assert_eq!(got, claimed);
                assert_eq!(bytes, b"GET /\r\n", "no payload byte is consumed");

                // v1 line auto-detected as well.
                let mut bytes: &[u8] = b"PROXY TCP4 192.0.2.1 198.51.100.7 51234 443\r\nGET /";
                let got = read_proxy_header(&mut bytes, peer, &allowed, Duration::from_secs(1))
                    .await
                    .expect("v1 header");
                assert_eq!(got, claimed);
                assert_eq!(bytes, b"GET /");

                // Denied before reading; neither-version garbage rejected.
                let outsider: SocketAddr = "203.0.113.9:2000".parse().expect("peer");
                let mut bytes: &[u8] = b"PROXY UNKNOWN\r\n";
                assert_eq!(
                    read_proxy_header(&mut bytes, outsider, &allowed, Duration::from_secs(1)).await,
                    Err(ProxyReceiveError::Denied)
                );
                let mut bytes: &[u8] = b"HELLO WORLD!!";
                assert_eq!(
                    read_proxy_header(&mut bytes, peer, &allowed, Duration::from_secs(1)).await,
                    Err(ProxyReceiveError::Invalid)
                );
            });
    }

    #[test]
    fn write_v1_writes_exact_header() {
        // Runtime without IO driver (mio/kqueue): the test only writes to memory.
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime tokio")
            .block_on(async {
                let mut sink = Vec::new();
                let peer: SocketAddr = "127.0.0.1:1234".parse().expect("peer");
                let local: SocketAddr = "127.0.0.1:8080".parse().expect("local");
                write_v1(&mut sink, peer, local).await.expect("write");
                assert_eq!(sink, b"PROXY TCP4 127.0.0.1 127.0.0.1 1234 8080\r\n");
            });
    }
}
