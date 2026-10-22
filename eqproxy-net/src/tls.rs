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
    /// ALPN protocols offered in the handshake, as configured. Listing `h2`
    /// is what opts a backend into HTTP/2 (B-H1).
    pub alpn: Vec<Vec<u8>>,
}

/// TLS acceptor of the listener (A11), with access to the negotiated (ALPN).
#[derive(Clone)]
pub struct ServerTls {
    pub acceptor: TlsAcceptor,
    config: Arc<rustls::ServerConfig>,
    /// SNI names of the additional certificates, in declaration order
    /// (empty when the listener serves a single certificate).
    sni_names: Vec<Vec<String>>,
}

impl ServerTls {
    /// ALPN protocols configured on the listener (A14).
    #[must_use]
    pub fn alpn(&self) -> &[Vec<u8>] {
        &self.config.alpn_protocols
    }

    /// SNI names of the additional certificates (B-I2/B-H10/B-E9).
    #[must_use]
    pub fn sni_names(&self) -> &[Vec<String>] {
        &self.sni_names
    }
}

impl std::fmt::Debug for ServerTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerTls")
            .field("alpn", &self.config.alpn_protocols)
            .field("sni_names", &self.sni_names)
            .finish_non_exhaustive()
    }
}

/// One additional certificate selected by SNI (B-I2/B-H10/B-E9).
#[derive(Debug, Clone)]
pub struct SniCertPem {
    /// Names this certificate answers (exact or `*.domain`).
    pub names: Vec<String>,
    /// Full PEM chain, leaf first.
    pub cert_chain_pem: Vec<u8>,
    /// PEM private key of the leaf.
    pub key_pem: Vec<u8>,
}

/// Parsed SNI name pattern (`*.` prefix = wildcard for one extra label).
#[derive(Debug, Clone, PartialEq, Eq)]
enum NamePattern {
    Exact(String),
    Wildcard(String),
}

impl NamePattern {
    fn parse(raw: &str) -> Result<Self, TlsError> {
        let name = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if let Some(suffix) = name.strip_prefix("*.") {
            if suffix.is_empty() || suffix.contains('*') || suffix.starts_with('.') {
                return Err(TlsError::Config(format!(
                    "invalid SNI name \"{raw}\": the wildcard must be the leftmost label (*.example.com)"
                )));
            }
            return Ok(NamePattern::Wildcard(suffix.to_owned()));
        }
        if name.is_empty() || name.contains('*') {
            return Err(TlsError::Config(format!(
                "invalid SNI name \"{raw}\": a literal name or *.domain is required"
            )));
        }
        Ok(NamePattern::Exact(name))
    }

    fn matches(&self, name: &str) -> bool {
        match self {
            NamePattern::Exact(want) => want == name,
            // `*.example.com` needs exactly one extra label: `a.example.com`
            // matches, `example.com` and `a.b.example.com` do not.
            NamePattern::Wildcard(suffix) => name
                .strip_suffix(suffix.as_str())
                .and_then(|head| head.strip_suffix('.'))
                .is_some_and(|head| !head.is_empty() && !head.contains('.')),
        }
    }
}

/// Certificate resolver by SNI: exact name, then the longest matching
/// wildcard, then the listener's default certificate.
///
/// A name no entry claims (or a client without SNI) is **not** an error:
/// the default certificate answers, like nginx's default server. The
/// handshake only fails if no default exists, which the builder rejects.
#[derive(Debug)]
struct SniResolver {
    entries: Vec<(Vec<NamePattern>, Arc<rustls::sign::CertifiedKey>)>,
    default: Arc<rustls::sign::CertifiedKey>,
}

impl SniResolver {
    /// Picks the certificate for a (lowercased, port-free) SNI name.
    fn pick(&self, name: Option<&str>) -> Arc<rustls::sign::CertifiedKey> {
        let Some(name) = name.map(|n| n.trim_end_matches('.').to_ascii_lowercase()) else {
            return Arc::clone(&self.default);
        };
        let mut wildcard: Option<(usize, &Arc<rustls::sign::CertifiedKey>)> = None;
        for (patterns, key) in &self.entries {
            for pattern in patterns {
                if !pattern.matches(&name) {
                    continue;
                }
                match pattern {
                    NamePattern::Exact(_) => return Arc::clone(key),
                    NamePattern::Wildcard(suffix) => {
                        let len = suffix.len();
                        if wildcard.as_ref().is_none_or(|(best, _)| len > *best) {
                            wildcard = Some((len, key));
                        }
                    }
                }
            }
        }
        match wildcard {
            Some((_, key)) => Arc::clone(key),
            None => Arc::clone(&self.default),
        }
    }
}

impl rustls::server::ResolvesServerCert for SniResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.pick(client_hello.server_name()))
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
    client_ca_pem: Option<&[u8]>,
    alpn: &[String],
    min: TlsVersion,
) -> Result<ServerTls, TlsError> {
    server_config_with_sni(cert_chain_pem, key_pem, &[], client_ca_pem, alpn, min)
}

/// Builds the listener TLS acceptor with certificates selected by SNI
/// (B-I2/B-H10/B-E9; Envoy `filter_chains`, nginx multiple
/// `ssl_certificate`).
///
/// The `cert_chain_pem`/`key_pem` pair is the default certificate: it
/// answers clients without SNI and names no [`SniCertPem`] claims. Each
/// entry answers the names it declares (exact first, then the longest
/// wildcard), and the handshake never fails for an unknown name — it
/// gets the default certificate, like nginx's default server.
#[allow(clippy::too_many_arguments)]
pub fn server_config_with_sni(
    cert_chain_pem: &[u8],
    key_pem: &[u8],
    sni: &[SniCertPem],
    client_ca_pem: Option<&[u8]>,
    alpn: &[String],
    min: TlsVersion,
) -> Result<ServerTls, TlsError> {
    let default = certified_key(cert_chain_pem, key_pem)?;
    let mut entries = Vec::with_capacity(sni.len());
    let mut sni_names = Vec::with_capacity(sni.len());
    let mut claimed: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for entry in sni {
        if entry.names.is_empty() {
            return Err(TlsError::Config(
                "an SNI certificate needs at least one name".to_owned(),
            ));
        }
        let mut patterns = Vec::with_capacity(entry.names.len());
        for raw in &entry.names {
            let pattern = NamePattern::parse(raw)?;
            let key = raw.trim().trim_end_matches('.').to_ascii_lowercase();
            if !claimed.insert(key.clone()) {
                return Err(TlsError::Config(format!(
                    "SNI name \"{key}\" is claimed by more than one certificate"
                )));
            }
            patterns.push(pattern);
        }
        sni_names.push(entry.names.clone());
        entries.push((
            patterns,
            certified_key(&entry.cert_chain_pem, &entry.key_pem)?,
        ));
    }
    let resolver = Arc::new(SniResolver {
        entries,
        default: Arc::clone(&default),
    }) as Arc<dyn rustls::server::ResolvesServerCert>;
    let builder = rustls::ServerConfig::builder_with_protocol_versions(protocol_versions(min));
    let mut config = if let Some(client_ca_pem) = client_ca_pem {
        // mTLS (A15): clients must present a certificate issued by this CA.
        let ca_certs = parse_certs(client_ca_pem)?;
        let mut roots = RootCertStore::empty();
        for cert in ca_certs {
            roots
                .add(cert)
                .map_err(|e| TlsError::Ca(format!("client CA certificate: {e}")))?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| TlsError::Ca(format!("client CA verifier: {e}")))?;
        builder
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::clone(&resolver))
    } else {
        builder.with_no_client_auth().with_cert_resolver(resolver)
    };
    config.alpn_protocols = alpn.iter().map(|proto| proto.as_bytes().to_vec()).collect();
    let config = Arc::new(config);
    Ok(ServerTls {
        acceptor: TlsAcceptor::from(Arc::clone(&config)),
        config,
        sni_names,
    })
}

/// Parses one certificate chain + key into the signer rustls needs.
fn certified_key(
    cert_chain_pem: &[u8],
    key_pem: &[u8],
) -> Result<Arc<rustls::sign::CertifiedKey>, TlsError> {
    let certs = parse_certs(cert_chain_pem)?;
    let key = parse_key(key_pem)?;
    let signing = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
        .map_err(|e| TlsError::Key(format!("unsupported private key: {e}")))?;
    Ok(Arc::new(rustls::sign::CertifiedKey::new(certs, signing)))
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
        alpn: alpn.iter().map(|proto| proto.as_bytes().to_vec()).collect(),
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
    const ALPHA: &[u8] = include_bytes!("../tests/fixtures/alpha.pem");
    const ALPHA_KEY: &[u8] = include_bytes!("../tests/fixtures/alpha.key");
    const BETA: &[u8] = include_bytes!("../tests/fixtures/beta.pem");
    const BETA_KEY: &[u8] = include_bytes!("../tests/fixtures/beta.key");

    /// Leaf DER of a PEM chain (what the handshake serves).
    fn leaf(pem: &[u8]) -> Vec<u8> {
        parse_certs(pem).expect("fixture parses")[0]
            .as_ref()
            .to_vec()
    }

    #[test]
    fn sni_name_patterns_follow_rfc6125_single_label_wildcards() {
        let exact = NamePattern::parse("Shop.Example.TEST.").expect("exact");
        assert_eq!(exact, NamePattern::Exact("shop.example.test".to_owned()));
        assert!(exact.matches("shop.example.test"), "exact name matches");
        assert!(
            !exact.matches("api.example.test"),
            "an exact name is not a prefix"
        );

        let wildcard = NamePattern::parse("*.example.test").expect("wildcard");
        assert!(
            wildcard.matches("a.example.test"),
            "a wildcard matches one extra label"
        );
        assert!(!wildcard.matches("a.b.example.test"), "one label only");
        assert!(!wildcard.matches("example.test"), "no bare domain");
        assert!(
            NamePattern::parse("*.*.example.test").is_err(),
            "a wildcard is only the leftmost label"
        );
        assert!(
            NamePattern::parse("a*b.example.test").is_err(),
            "a wildcard inside a label is rejected"
        );
        assert!(NamePattern::parse("").is_err(), "an empty name is rejected");
    }

    #[cfg_attr(miri, ignore = "uses rustls/aws-lc-rs (FFI not emulatable by miri)")]
    #[test]
    fn sni_resolver_prefers_exact_then_longest_wildcard_then_default() {
        let resolver = SniResolver {
            entries: vec![
                (
                    vec![NamePattern::parse("alpha.example.test").expect("alpha")],
                    certified_key(ALPHA, ALPHA_KEY).expect("alpha key"),
                ),
                (
                    vec![NamePattern::parse("*.example.test").expect("wild")],
                    certified_key(BETA, BETA_KEY).expect("beta key"),
                ),
            ],
            default: certified_key(CERT, KEY).expect("default key"),
        };
        let alpha = leaf(ALPHA);
        let beta = leaf(BETA);
        let default = leaf(CERT);

        assert_eq!(
            resolver.pick(Some("alpha.example.test")).cert[0].as_ref(),
            alpha
        );
        assert_eq!(
            resolver.pick(Some("ALPHA.example.test.")).cert[0].as_ref(),
            alpha,
            "names are case-insensitive and tolerate a trailing dot"
        );
        assert_eq!(
            resolver.pick(Some("other.example.test")).cert[0].as_ref(),
            beta
        );
        assert_eq!(
            resolver.pick(Some("localhost")).cert[0].as_ref(),
            default,
            "an unclaimed name gets the default certificate"
        );
        assert_eq!(
            resolver.pick(None).cert[0].as_ref(),
            default,
            "a client without SNI gets the default certificate"
        );
        assert_eq!(
            resolver.pick(Some("deep.other.example.test")).cert[0].as_ref(),
            default,
            "a wildcard is one label only"
        );
    }

    #[cfg_attr(miri, ignore = "uses rustls/aws-lc-rs (FFI not emulatable by miri)")]
    #[test]
    fn sni_configuration_rejects_duplicate_names_and_empty_entries() {
        let dupes = vec![
            SniCertPem {
                names: vec!["a.example.test".to_owned()],
                cert_chain_pem: ALPHA.to_vec(),
                key_pem: ALPHA_KEY.to_vec(),
            },
            SniCertPem {
                names: vec!["A.example.test".to_owned()],
                cert_chain_pem: BETA.to_vec(),
                key_pem: BETA_KEY.to_vec(),
            },
        ];
        let err = server_config_with_sni(CERT, KEY, &dupes, None, &[], TlsVersion::V1_2)
            .expect_err("duplicate SNI names must be rejected");
        assert!(
            err.to_string().contains("more than one certificate"),
            "{err}"
        );

        let empty = vec![SniCertPem {
            names: Vec::new(),
            cert_chain_pem: ALPHA.to_vec(),
            key_pem: ALPHA_KEY.to_vec(),
        }];
        let err = server_config_with_sni(CERT, KEY, &empty, None, &[], TlsVersion::V1_2)
            .expect_err("an SNI entry without names must be rejected");
        assert!(err.to_string().contains("at least one name"), "{err}");
    }

    #[cfg_attr(miri, ignore = "uses rustls/aws-lc-rs (FFI not emulatable by miri)")]
    #[test]
    fn sni_configuration_keeps_the_default_when_no_entries() {
        let server = server_config_with_sni(CERT, KEY, &[], None, &[], TlsVersion::V1_2)
            .expect("default only");
        assert!(server.sni_names().is_empty());
    }

    #[cfg_attr(miri, ignore = "uses rustls/aws-lc-rs (FFI not emulatable by miri)")]
    #[test]
    fn server_config_accepts_valid_pem_and_alpn() {
        let server = server_config(CERT, KEY, None, &["http/1.1".to_owned()], TlsVersion::V1_2)
            .expect("valid test cert/key");
        assert_eq!(server.alpn(), vec![b"http/1.1".to_vec()]);
    }

    #[cfg_attr(miri, ignore = "uses rustls/aws-lc-rs (FFI not emulatable by miri)")]
    #[test]
    fn server_config_rejects_garbage_with_actionable_error() {
        let err = server_config(b"no es PEM", KEY, None, &[], TlsVersion::V1_2)
            .expect_err("must reject garbage");
        assert!(matches!(err, TlsError::Cert(_)), "error: {err}");

        let err = server_config(CERT, b"no es PEM", None, &[], TlsVersion::V1_2)
            .expect_err("must reject garbage key");
        assert!(matches!(err, TlsError::Key(_)), "error: {err}");

        // mTLS (A15): a garbage client CA must be rejected with an
        // actionable error, never silently ignored.
        let err = server_config(CERT, KEY, Some(b"no es PEM"), &[], TlsVersion::V1_2)
            .expect_err("must reject garbage client CA");
        assert!(matches!(err, TlsError::Cert(_)), "error: {err}");
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
