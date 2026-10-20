//! SNI E2E with **real TLS handshakes** (B-I2/B-H10/B-E9): the listener
//! serves the certificate of the requested name (exact, then wildcard) and
//! keeps the default certificate for names no entry claims and for
//! clients without SNI — nginx's default-server behaviour.
//!
//! The client verifier records the presented leaf, so the assertion is on
//! the actual handshake (what the peer sent), not on configuration state.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use eqproxy_core::{Metrics, shutdown};
use eqproxy_net::tls::{self, SniCertPem, TlsVersion};
use eqproxy_net::{BoundProxy, ProxyMode, ResolvedBackend, ResolvedListener, bind};

const WAIT: Duration = Duration::from_secs(5);
const CERT: &[u8] = include_bytes!("fixtures/cert.pem");
const KEY: &[u8] = include_bytes!("fixtures/key.pem");
const ALPHA: &[u8] = include_bytes!("fixtures/alpha.pem");
const ALPHA_KEY: &[u8] = include_bytes!("fixtures/alpha.key");
const BETA: &[u8] = include_bytes!("fixtures/beta.pem");
const BETA_KEY: &[u8] = include_bytes!("fixtures/beta.key");

/// Leaf DER of a PEM chain (what a handshake serves).
fn leaf(pem: &[u8]) -> Vec<u8> {
    tls::parse_certs(pem).expect("fixture parses")[0]
        .as_ref()
        .to_vec()
}

async fn start_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("addr echo");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if socket.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

fn base_listener(backend: Arc<ResolvedBackend>) -> ResolvedListener {
    ResolvedListener::new(
        "web",
        "127.0.0.1:0".parse().expect("addr"),
        backend.name.clone(),
        backend.servers[0].addr.clone(),
        ProxyMode::Tcp,
        64,
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(30),
    )
    .with_backend(backend)
}

async fn start_proxy(
    cfg: ResolvedListener,
) -> (SocketAddr, shutdown::ShutdownHandle, JoinHandle<()>) {
    let bound: BoundProxy = bind(vec![cfg], Arc::new(Metrics::default()))
        .await
        .expect("bind proxy");
    let addr = bound.local_addrs()[0].1;
    let (handle, signal) = shutdown::channel();
    let serve = tokio::spawn(async move {
        bound.serve(signal, WAIT).await.expect("serve");
    });
    (addr, handle, serve)
}

/// Verifier that records the leaf the server presents and accepts any
/// chain (the fixtures are self-signed on purpose).
#[derive(Debug)]
struct Recorder {
    seen: Mutex<Option<Vec<u8>>>,
    provider: rustls::crypto::CryptoProvider,
}

impl Recorder {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            seen: Mutex::new(None),
            provider: rustls::crypto::aws_lc_rs::default_provider(),
        })
    }

    fn take(&self) -> Vec<u8> {
        self.seen
            .lock()
            .expect("recorder lock")
            .take()
            .expect("the handshake must present a certificate")
    }
}

impl rustls::client::danger::ServerCertVerifier for Recorder {
    fn verify_server_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        *self.seen.lock().expect("recorder lock") = Some(end_entity.as_ref().to_vec());
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Handshakes with the given SNI (or none) and returns (presented leaf, stream).
async fn connect(
    addr: SocketAddr,
    sni: Option<&str>,
) -> (Vec<u8>, tokio_rustls::client::TlsStream<TcpStream>) {
    let recorder = Recorder::new();
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::clone(&recorder) as Arc<_>)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = match sni {
        // No SNI is expressed by connecting to the IP literal: rustls then
        // sends no server_name extension (RFC 6066).
        None => rustls_pki_types::ServerName::IpAddress(addr.ip().into()),
        Some(name) => rustls_pki_types::ServerName::try_from(name.to_owned()).expect("sni name"),
    };
    let stream = tokio::time::timeout(
        WAIT,
        connector.connect(name, TcpStream::connect(addr).await.expect("connect")),
    )
    .await
    .expect("handshake in time")
    .expect("handshake");
    (recorder.take(), stream)
}

#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sni_selects_the_certificate_and_keeps_the_default_for_unknown_names() {
    let backend = start_echo().await;
    let server = tls::server_config_with_sni(
        CERT,
        KEY,
        &[
            SniCertPem {
                names: vec!["alpha.example.test".to_owned()],
                cert_chain_pem: ALPHA.to_vec(),
                key_pem: ALPHA_KEY.to_vec(),
            },
            SniCertPem {
                names: vec!["*.wild.example.test".to_owned()],
                cert_chain_pem: BETA.to_vec(),
                key_pem: BETA_KEY.to_vec(),
            },
        ],
        None,
        &[],
        TlsVersion::V1_2,
    )
    .expect("SNI listener");
    assert_eq!(
        server.sni_names(),
        &[
            vec!["alpha.example.test".to_owned()],
            vec!["*.wild.example.test".to_owned()]
        ]
    );
    let cfg =
        base_listener(Arc::new(ResolvedBackend::single("api", backend))).with_server_tls(server);
    let (addr, handle, serve) = start_proxy(cfg).await;

    let alpha = leaf(ALPHA);
    let beta = leaf(BETA);
    let default = leaf(CERT);

    // Exact name → alpha certificate, and the tunnel still carries bytes.
    let (presented, mut stream) = connect(addr, Some("alpha.example.test")).await;
    assert_eq!(
        presented, alpha,
        "exact SNI name must serve its certificate"
    );
    stream.write_all(b"ping-sni").await.expect("write");
    let mut echoed = vec![0u8; b"ping-sni".len()];
    tokio::time::timeout(WAIT, stream.read_exact(&mut echoed))
        .await
        .expect("echo in time")
        .expect("full echo");
    assert_eq!(echoed, b"ping-sni");
    drop(stream);

    // Wildcard → beta certificate (one extra label).
    let (presented, stream) = connect(addr, Some("x.wild.example.test")).await;
    assert_eq!(presented, beta, "a wildcard name serves its certificate");
    drop(stream);

    // Two labels under the wildcard → no match, default certificate.
    let (presented, stream) = connect(addr, Some("a.b.wild.example.test")).await;
    assert_eq!(
        presented, default,
        "a wildcard covers one label only; the default answers"
    );
    drop(stream);

    // Unclaimed name → default certificate (never a failed handshake).
    let (presented, stream) = connect(addr, Some("other.example.test")).await;
    assert_eq!(presented, default, "unclaimed names get the default");
    drop(stream);

    // No SNI at all → default certificate.
    let (presented, stream) = connect(addr, None).await;
    assert_eq!(presented, default, "clients without SNI get the default");
    drop(stream);

    // Names are case-insensitive.
    let (presented, stream) = connect(addr, Some("ALPHA.Example.TEST")).await;
    assert_eq!(presented, alpha, "SNI names are case-insensitive");
    drop(stream);

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve must finish")
        .expect("join");
}

/// The hot certificate reload rebuilds the resolver too: the SNI set (and
/// which certificate each name gets) swaps without dropping the listener.
#[cfg_attr(
    miri,
    ignore = "needs TCP sockets: miri does not support networking (rust-lang/miri#3449)"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sni_set_swaps_in_hot_with_the_certificate_reload() {
    fn listener_with(
        backend: SocketAddr,
        names: &[&str],
        cert: &[u8],
        key: &[u8],
    ) -> ResolvedListener {
        let server = tls::server_config_with_sni(
            CERT,
            KEY,
            &[SniCertPem {
                names: names.iter().map(|n| (*n).to_owned()).collect(),
                cert_chain_pem: cert.to_vec(),
                key_pem: key.to_vec(),
            }],
            None,
            &[],
            TlsVersion::V1_2,
        )
        .expect("SNI listener");
        base_listener(Arc::new(ResolvedBackend::single("api", backend))).with_server_tls(server)
    }

    let backend = start_echo().await;
    let metrics = Arc::new(Metrics::default());
    let first = listener_with(backend, &["alpha.example.test"], ALPHA, ALPHA_KEY);
    let bound: BoundProxy = bind(vec![first], Arc::clone(&metrics)).await.expect("bind");
    let addr = bound.local_addrs()[0].1;
    let (handle, signal) = shutdown::channel();
    let (reload_tx, reload_rx) = tokio::sync::mpsc::channel(4);
    let serve = tokio::spawn(async move {
        bound
            .serve_with_reloads(signal, WAIT, reload_rx)
            .await
            .expect("serve");
    });

    // Before the reload: alpha is served by the alpha certificate.
    let (presented, stream) = connect(addr, Some("alpha.example.test")).await;
    assert_eq!(presented, leaf(ALPHA), "initial SNI certificate");
    drop(stream);

    // Reload: the same name now answers with the beta certificate.
    let second = listener_with(backend, &["alpha.example.test"], BETA, BETA_KEY);
    reload_tx.send(vec![second]).await.expect("send reload");
    let deadline = tokio::time::Instant::now() + WAIT;
    while metrics.snapshot().config_reloads == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the reload must be applied"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let (presented, stream) = connect(addr, Some("alpha.example.test")).await;
    assert_eq!(
        presented,
        leaf(BETA),
        "the reloaded SNI set must be live on the same listener"
    );
    drop(stream);

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve must finish")
        .expect("join");
}
