//! TLS (A11/A12) con rustls: termination en el listener y cliente a backends.
//!
//! - **Servidor (A11)**: cadena de certificados + clave privada PEM, ALPN
//!   explícito (A14) y versión mínima TLS 1.2 (TLS 1.0/1.1 nunca se aceptan).
//! - **Cliente (A12)**: verificación de certificado **y de nombre** activada
//!   por defecto (SNI derivado de la dirección o `server_name`); `verify =
//!   false` es un opt-out consciente y peligroso (THREAT_MODEL), y `ca_file`
//!   añade CAs privadas a las raíces de Mozilla.
//! - CryptoProvider: aws-lc-rs (ADR-0004). Código 100 % safe Rust.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, IpAddr, PrivateKeyDer, ServerName};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Versión mínima de TLS aceptada (1.0/1.1 no existen en rustls moderno).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsVersion {
    /// TLS 1.2 como mínimo (por defecto).
    #[default]
    V1_2,
    /// Solo TLS 1.3.
    V1_3,
}

/// Error de configuración TLS accionable.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("certificado PEM inválido: {0}")]
    Cert(String),
    #[error("clave privada PEM inválida: {0}")]
    Key(String),
    #[error("CA PEM inválido: {0}")]
    Ca(String),
    #[error("server_name «{0}» no es un nombre DNS ni una IP válida")]
    ServerName(String),
    #[error("configuración TLS inválida: {0}")]
    Config(String),
}

/// Cliente TLS hacia backends (A12), listo para conectar.
#[derive(Clone)]
pub struct ClientTls {
    pub connector: TlsConnector,
    /// SNI/verificación fijados en config; si es `None` se deriva de la
    /// dirección del servidor elegido (IP literal, sin SNI DNS).
    pub server_name: Option<ServerName<'static>>,
}

/// Aceptor TLS del listener (A11), con acceso a lo negociado (ALPN).
#[derive(Clone)]
pub struct ServerTls {
    pub acceptor: TlsAcceptor,
    config: Arc<rustls::ServerConfig>,
}

impl ServerTls {
    /// Protocolos ALPN configurados en el listener (A14).
    #[must_use]
    pub fn alpn(&self) -> &[Vec<u8>] {
        &self.config.alpn_protocols
    }
}

impl std::fmt::Debug for ServerTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerTls")
            .field("alpn", &self.config.alpn_protocols)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ClientTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientTls")
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

fn protocol_versions(min: TlsVersion) -> &'static [&'static rustls::SupportedProtocolVersion] {
    const V12: &[&rustls::SupportedProtocolVersion] =
        &[&rustls::version::TLS13, &rustls::version::TLS12];
    const V13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
    match min {
        TlsVersion::V1_2 => V12,
        TlsVersion::V1_3 => V13,
    }
}

/// Parsea una cadena de certificados PEM (hoja primero).
///
/// Usa el parser de `rustls-pki-types` (`PemObject`); `rustls-pemfile` está
/// deprecated (RUSTSEC-2025-0134).
pub fn parse_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<_, _>>()
        .map_err(|e| TlsError::Cert(e.to_string()))?;
    if certs.is_empty() {
        return Err(TlsError::Cert("sin certificados en el PEM".to_owned()));
    }
    Ok(certs)
}

/// Parsea una clave privada PEM (PKCS#8, PKCS#1 o SEC1).
pub fn parse_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, TlsError> {
    PrivateKeyDer::pem_slice_iter(pem)
        .next()
        .transpose()
        .map_err(|e| TlsError::Key(e.to_string()))?
        .ok_or_else(|| TlsError::Key("sin clave privada en el PEM".to_owned()))
}

/// Construye el acceptor TLS del listener (A11).
///
/// `cert_chain_pem`: cadena completa (hoja primero); `key_pem`: clave privada.
/// `alpn`: protocolos ofrecidos (vacío = sin ALPN). Error accionable si el PEM
/// no parsea o la clave no corresponde a la hoja.
pub fn server_config(
    cert_chain_pem: &[u8],
    key_pem: &[u8],
    alpn: &[String],
    min: TlsVersion,
) -> Result<ServerTls, TlsError> {
    let certs = parse_certs(cert_chain_pem)?;
    let key = parse_key(key_pem)?;
    let mut config = rustls::ServerConfig::builder_with_protocol_versions(protocol_versions(min))
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| TlsError::Config(format!("clave y certificado no compatibles: {e}")))?;
    config.alpn_protocols = alpn.iter().map(|proto| proto.as_bytes().to_vec()).collect();
    let config = Arc::new(config);
    Ok(ServerTls {
        acceptor: TlsAcceptor::from(Arc::clone(&config)),
        config,
    })
}

/// Construye el cliente TLS hacia backends (A12).
///
/// Verificación activada por defecto; raíces de Mozilla + `ca_pem` opcional.
/// `verify = false` desactiva la verificación por completo (opt-out consciente).
pub fn client_config(
    ca_pem: Option<&[u8]>,
    verify: bool,
    server_name: Option<&str>,
    alpn: &[String],
    min: TlsVersion,
) -> Result<ClientTls, TlsError> {
    let versions = protocol_versions(min);
    let builder = rustls::ClientConfig::builder_with_protocol_versions(versions);
    let mut config = if verify {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(ca) = ca_pem {
            for cert in parse_certs(ca).map_err(|e| TlsError::Ca(e.to_string()))? {
                roots
                    .add(cert)
                    .map_err(|e| TlsError::Ca(format!("raíz inválida: {e}")))?;
            }
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier(
                rustls::crypto::aws_lc_rs::default_provider(),
            )))
            .with_no_client_auth()
    };
    config.alpn_protocols = alpn.iter().map(|proto| proto.as_bytes().to_vec()).collect();
    let server_name = server_name
        .map(|name| {
            ServerName::try_from(name.to_owned()).map_err(|_| TlsError::ServerName(name.to_owned()))
        })
        .transpose()?;
    Ok(ClientTls {
        connector: TlsConnector::from(Arc::new(config)),
        server_name,
    })
}

/// Nombre a verificar/SNI para una conexión concreta: el `server_name` de la
/// config si existe; si no, la IP del servidor (SNI literal sin DNS).
#[must_use]
pub fn server_name_for(client: &ClientTls, addr: SocketAddr) -> ServerName<'static> {
    client
        .server_name
        .clone()
        .unwrap_or_else(|| ServerName::IpAddress(IpAddr::from(addr.ip())))
}

/// Verificador sin verificación (`verify = false`): acepta cualquier certificado
/// pero sigue validando las firmas del handshake.
#[derive(Debug)]
struct NoVerifier(rustls::crypto::CryptoProvider);

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERT: &[u8] = include_bytes!("../tests/fixtures/cert.pem");
    const KEY: &[u8] = include_bytes!("../tests/fixtures/key.pem");

    #[cfg_attr(miri, ignore = "usa rustls/aws-lc-rs (FFI no emulable por miri)")]
    #[test]
    fn server_config_accepts_valid_pem_and_alpn() {
        let server = server_config(CERT, KEY, &["http/1.1".to_owned()], TlsVersion::V1_2)
            .expect("cert/key de test válidos");
        assert_eq!(server.alpn(), vec![b"http/1.1".to_vec()]);
    }

    #[cfg_attr(miri, ignore = "usa rustls/aws-lc-rs (FFI no emulable por miri)")]
    #[test]
    fn server_config_rejects_garbage_with_actionable_error() {
        let err = server_config(b"no es PEM", KEY, &[], TlsVersion::V1_2)
            .expect_err("debe rechazar basura");
        assert!(matches!(err, TlsError::Cert(_)), "error: {err}");

        let err = server_config(CERT, b"no es PEM", &[], TlsVersion::V1_2)
            .expect_err("debe rechazar clave basura");
        assert!(matches!(err, TlsError::Key(_)), "error: {err}");
    }

    #[cfg_attr(miri, ignore = "usa rustls/aws-lc-rs (FFI no emulable por miri)")]
    #[test]
    fn client_config_rejects_invalid_server_name() {
        let err = client_config(
            None,
            true,
            Some("no es un nombre .."),
            &[],
            TlsVersion::V1_2,
        )
        .expect_err("debe rechazar el nombre");
        assert!(matches!(err, TlsError::ServerName(_)), "error: {err}");
    }

    #[cfg_attr(miri, ignore = "usa rustls/aws-lc-rs (FFI no emulable por miri)")]
    #[test]
    fn server_name_defaults_to_server_ip() {
        let client = client_config(None, false, None, &[], TlsVersion::V1_2).expect("cliente");
        let addr: SocketAddr = "127.0.0.1:9000".parse().expect("addr");
        assert!(matches!(
            server_name_for(&client, addr),
            ServerName::IpAddress(_)
        ));
    }
}
