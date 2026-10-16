//! PROXY protocol v1 (A9): header generation towards the backend and
//! reception from trusted origins (B-H9/B-E10).
//!
//! THREAT_MODEL: never trust PROXY from unauthorized sources — reception
//! is strict: only allowlisted origins, only a valid v1 line. Format per
//! the PROXY protocol v1 spec (max 107 bytes).

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use eqproxy_core::expectation::IpAllowlist;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum PROXY v1 line length, CRLF included (spec).
pub const MAX_V1_LINE: usize = 107;

/// PROXY protocol send mode (A9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyProtocolMode {
    /// No PROXY header (default).
    #[default]
    None,
    /// PROXY protocol v1 header (`PROXY TCP4/TCP6 …`).
    V1,
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
