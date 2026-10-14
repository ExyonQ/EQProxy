//! TLS (A11/A12) with rustls: termination at the listener and client to backends.
//!
//! - **Server (A11)**: certificate chain + PEM private key, explicit ALPN
//!   (A14) and minimum TLS 1.2 (TLS 1.0/1.1 are never accepted).
//! - **Client (A12)**: certificate **and name** verification on
//!   by default (SNI derived from the address or `server_name`); `verify =
//!   false` is a conscious, dangerous opt-out (THREAT_MODEL), and `ca_file`
//!   adds private CAs to the Mozilla roots.
//! - CryptoProvider: aws-lc-rs (ADR-0004). 100 % safe Rust code.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, IpAddr, PrivateKeyDer, ServerName};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Minimum accepted TLS version (1.0/1.1 do not exist in modern rustls).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsVersion {
    /// TLS 1.2 at minimum (default).
    #[default]
    V1_2,
    /// TLS 1.3 only.
    V1_3,
}

/// Actionable TLS configuration error.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("invalid PEM certificate: {0}")]
    Cert(String),
    #[error("invalid PEM private key: {0}")]
    Key(String),
    #[error("invalid PEM CA: {0}")]
    Ca(String),
    #[error("server_name \"{0}\" is not a valid DNS name or IP")]
    ServerName(String),
    #[error("invalid TLS configuration: {0}")]
    Config(String),
}

/// TLS client to backends (A12), ready to connect.
#[derive(Clone)]
pub struct ClientTls {
    pub connector: TlsConnector,
    /// Config-pinned SNI/verification; when `None` it is derived from the
    /// chosen server address (literal IP, no DNS SNI).
    pub server_name: Option<ServerName<'static>>,
}

/// TLS acceptor of the listener (A11), with access to the negotiated (ALPN).
#[derive(Clone)]
pub struct ServerTls {
    pub acceptor: TlsAcceptor,
    config: Arc<rustls::ServerConfig>,
}

impl ServerTls {
    /// ALPN protocols configured on the listener (A14).
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

/// Parses a PEM certificate chain (leaf first).
///
/// Uses the `rustls-pki-types` parser (`PemObject`); `rustls-pemfile` is
/// deprecated (RUSTSEC-2025-0134).
pub fn parse_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<_, _>>()
        .map_err(|e| TlsError::Cert(e.to_string()))?;
    if certs.is_empty() {
        return Err(TlsError::Cert("no certificates in the PEM".to_owned()));
    }
    Ok(certs)
}

/// Parses a PEM private key (PKCS#8, PKCS#1 or SEC1).
pub fn parse_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, TlsError> {
    PrivateKeyDer::pem_slice_iter(pem)
        .next()
        .transpose()
        .map_err(|e| TlsError::Key(e.to_string()))?
        .ok_or_else(|| TlsError::Key("no private key in the PEM".to_owned()))
}

/// Builds the listener TLS acceptor (A11).
///
/// `cert_chain_pem`: full chain (leaf first); `key_pem`: private key.
/// `alpn`: offered protocols (empty = no ALPN). Actionable error when the PEM
/// does not parse or the key does not match the leaf.
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
        .map_err(|e| TlsError::Config(format!("key and certificate do not match: {e}")))?;
    config.alpn_protocols = alpn.iter().map(|proto| proto.as_bytes().to_vec()).collect();
    let config = Arc::new(config);
    Ok(ServerTls {
        acceptor: TlsAcceptor::from(Arc::clone(&config)),
        config,
    })
}

/// Builds the TLS client to backends (A12).
///
/// Verification on by default; Mozilla roots + optional `ca_pem`.
/// `verify = false` disables verification entirely (conscious opt-out).
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
                    .map_err(|e| TlsError::Ca(format!("invalid root: {e}")))?;
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

/// Name to verify/SNI for a given connection: the config `server_name`
/// when present; otherwise the server IP (literal SNI, no DNS).
#[must_use]
pub fn server_name_for(client: &ClientTls, addr: SocketAddr) -> ServerName<'static> {
    client
        .server_name
        .clone()
        .unwrap_or_else(|| ServerName::IpAddress(IpAddr::from(addr.ip())))
}

/// Non-verifying verifier (`verify = false`): accepts any certificate
/// but still validates the handshake signatures.
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

    #[cfg_attr(miri, ignore = "uses rustls/aws-lc-rs (FFI not emulatable by miri)")]
    #[test]
    fn server_config_accepts_valid_pem_and_alpn() {
        let server = server_config(CERT, KEY, &["http/1.1".to_owned()], TlsVersion::V1_2)
            .expect("valid test cert/key");
        assert_eq!(server.alpn(), vec![b"http/1.1".to_vec()]);
    }

    #[cfg_attr(miri, ignore = "uses rustls/aws-lc-rs (FFI not emulatable by miri)")]
    #[test]
    fn server_config_rejects_garbage_with_actionable_error() {
        let err = server_config(b"no es PEM", KEY, &[], TlsVersion::V1_2)
            .expect_err("must reject garbage");
        assert!(matches!(err, TlsError::Cert(_)), "error: {err}");

        let err = server_config(CERT, b"no es PEM", &[], TlsVersion::V1_2)
            .expect_err("must reject garbage key");
        assert!(matches!(err, TlsError::Key(_)), "error: {err}");
    }

    #[cfg_attr(miri, ignore = "uses rustls/aws-lc-rs (FFI not emulatable by miri)")]
    #[test]
    fn client_config_rejects_invalid_server_name() {
        let err = client_config(None, true, Some("not a name .."), &[], TlsVersion::V1_2)
            .expect_err("must reject the name");
        assert!(matches!(err, TlsError::ServerName(_)), "error: {err}");
    }

    #[cfg_attr(miri, ignore = "uses rustls/aws-lc-rs (FFI not emulatable by miri)")]
    #[test]
    fn server_name_defaults_to_server_ip() {
        let client = client_config(None, false, None, &[], TlsVersion::V1_2).expect("client");
        let addr: SocketAddr = "127.0.0.1:9000".parse().expect("addr");
        assert!(matches!(
            server_name_for(&client, addr),
            ServerName::IpAddress(_)
        ));
    }
}
