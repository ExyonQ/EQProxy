//! PROXY protocol v1 (A9): generación de la cabecera hacia el backend.
//!
//! Solo **envío** (Fase 2b); la recepción llega en Fase 3 con su política de
//! confianza (THREAT_MODEL: nunca confiar en PROXY de fuentes no autorizadas).
//! Formato según la especificación PROXY protocol v1 (máx. 107 bytes).

use std::net::SocketAddr;

use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Modo de envío de PROXY protocol (A9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyProtocolMode {
    /// Sin cabecera PROXY (por defecto).
    #[default]
    None,
    /// Cabecera PROXY protocol v1 (`PROXY TCP4/TCP6 …`).
    V1,
}

/// Codifica la cabecera PROXY v1 para el par (cliente, dirección local del
/// proxy). Familias mixtas o no TCP → `PROXY UNKNOWN\r\n` (semántica HAProxy).
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

/// Escribe la cabecera PROXY v1 en el stream (una sola escritura, flush
/// incluido) antes de bombear el payload.
pub async fn write_v1<W: AsyncWrite + Unpin>(
    writer: &mut W,
    peer: SocketAddr,
    local: SocketAddr,
) -> std::io::Result<()> {
    let header = encode_v1(peer, local);
    writer.write_all(&header).await?;
    writer.flush().await
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
        assert!(header.len() <= 107, "la cabecera v1 máx. son 107 bytes");
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

    #[test]
    fn write_v1_writes_exact_header() {
        // Runtime sin driver IO (mio/kqueue): el test solo escribe en memoria.
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
