//! Pruebas E2E del proxy HTTP/1.1 con **sockets reales** (sin mocks de red):
//! framing estricto (T01–T03), timeouts por fase (A17) y streaming con
//! cancelación (A19).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use eqproxy_core::{Metrics, shutdown};
use eqproxy_net::{BoundProxy, ProxyMode, ResolvedListener, bind};

const WAIT: Duration = Duration::from_secs(5);

/// Backend HTTP mínimo real: responde 200 con eco del cuerpo de petición.
async fn start_http_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let addr = listener.local_addr().expect("addr backend");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    // Lee la cabecera completa (fixture: espera el cuerpo según
                    // el framing para poder ecoarlo byte a byte).
                    let mut total = 0usize;
                    let head_end = loop {
                        match socket.read(&mut buf[total..]).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => total += n,
                        }
                        if let Some(pos) = buf[..total].windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                        if total == buf.len() {
                            return;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
                    let body_needed = if head.contains("transfer-encoding: chunked") {
                        // Hasta el chunk terminal completo: "0\r\n\r\n".
                        usize::MAX
                    } else if let Some(len) =
                        head.lines().find_map(|l| l.strip_prefix("content-length:"))
                    {
                        head_end + len.trim().parse::<usize>().unwrap_or(0)
                    } else {
                        head_end
                    };
                    while total < body_needed {
                        if body_needed == usize::MAX
                            && buf[..total].windows(5).any(|w| w == b"0\r\n\r\n")
                        {
                            break;
                        }
                        if body_needed != usize::MAX && total == buf.len() {
                            return;
                        }
                        match socket.read(&mut buf[total..]).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => total += n,
                        }
                    }
                    let body = &buf[head_end..total];
                    let response =
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                    if socket.write_all(response.as_bytes()).await.is_err()
                        || socket.write_all(body).await.is_err()
                    {
                        return;
                    }
                    if buf[..head_end].windows(7).any(|w| w == b"close\r\n") {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// Backend que acepta y nunca responde (para timeout de cabecera de respuesta).
async fn start_silent_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind silent");
    let addr = listener.local_addr().expect("addr silent");
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    addr
}

fn http_listener_cfg(
    listen: SocketAddr,
    server: SocketAddr,
    client_header_timeout: Duration,
    server_header_timeout: Duration,
) -> ResolvedListener {
    ResolvedListener {
        name: "web".to_owned(),
        listen,
        backend_name: "api".to_owned(),
        server,
        mode: ProxyMode::Http,
        maxconn: 64,
        connect_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(5),
        client_header_timeout,
        server_header_timeout,
    }
}

async fn start_proxy(
    cfg: ResolvedListener,
    metrics: Arc<Metrics>,
) -> (SocketAddr, shutdown::ShutdownHandle, JoinHandle<()>) {
    let bound: BoundProxy = bind(vec![cfg], Arc::clone(&metrics))
        .await
        .expect("bind proxy");
    let addr = bound.local_addrs()[0].1;
    let (handle, signal) = shutdown::channel();
    let serve = tokio::spawn(async move {
        bound
            .serve(signal, Duration::from_secs(2))
            .await
            .expect("serve");
    });
    (addr, handle, serve)
}

async fn send_and_read(addr: SocketAddr, request: &[u8]) -> String {
    let mut client = tokio::time::timeout(WAIT, TcpStream::connect(addr))
        .await
        .expect("connect a tiempo")
        .expect("connect al proxy");
    client.write_all(request).await.expect("write request");
    client.shutdown().await.expect("half-close");
    let mut response = Vec::new();
    tokio::time::timeout(WAIT, client.read_to_end(&mut response))
        .await
        .expect("respuesta a tiempo")
        .expect("read response");
    String::from_utf8_lossy(&response).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http1_get_roundtrip_and_keepalive() {
    let backend = start_http_backend().await;
    let metrics = Arc::new(Metrics::default());
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
    let get = b"GET /x HTTP/1.1\r\nHost: t\r\n\r\n";
    client.write_all(get).await.expect("write");
    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(WAIT, client.read(&mut buf))
        .await
        .expect("respuesta a tiempo")
        .expect("read");
    let first = String::from_utf8_lossy(&buf[..n]).into_owned();
    assert!(first.starts_with("HTTP/1.1 200 OK"), "respuesta: {first}");

    // Keep-alive: segunda petición sobre la MISMA conexión cliente.
    client.write_all(get).await.expect("write 2");
    let n = tokio::time::timeout(WAIT, client.read(&mut buf))
        .await
        .expect("respuesta 2 a tiempo")
        .expect("read 2");
    let second = String::from_utf8_lossy(&buf[..n]).into_owned();
    assert!(
        second.starts_with("HTTP/1.1 200 OK"),
        "respuesta 2: {second}"
    );

    drop(client);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(metrics.snapshot().http_requests_proxied, 2);
    assert_eq!(metrics.snapshot().http_requests_rejected, 0);

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve termina")
        .expect("tarea serve sin pánico");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http1_post_body_streams_end_to_end() {
    let backend = start_http_backend().await;
    let metrics = Arc::new(Metrics::default());
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let body = "cuerpo de prueba con bytes";
    let request = format!(
        "POST /x HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let response = send_and_read(proxy_addr, request.as_bytes()).await;
    assert!(
        response.ends_with(body),
        "el cuerpo debe reenviarse byte a byte: {response}"
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    let snap = metrics.snapshot();
    assert_eq!(snap.http_requests_proxied, 1);
    assert!(snap.bytes_client_to_backend > 0);
    assert!(snap.bytes_backend_to_client > 0);

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve termina")
        .expect("tarea serve sin pánico");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http1_chunked_body_streams_end_to_end() {
    let backend = start_http_backend().await;
    let metrics = Arc::new(Metrics::default());
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let request = b"POST /x HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhola!\r\n0\r\n\r\n";
    let response = send_and_read(proxy_addr, request).await;
    assert!(response.contains("hola!"), "eco chunked: {response}");

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve termina")
        .expect("tarea serve sin pánico");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http1_smuggling_corpus_is_rejected_before_backend() {
    let backend = start_http_backend().await;
    let metrics = Arc::new(Metrics::default());
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    // Corpus T01–T02: cada caso debe recibir 400/431/501/505 y jamás llegar
    // al backend como petición procesable.
    let corpus: &[&[u8]] = &[
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n",
        b"GET / HTTP/1.1\r\nFoo : x\r\nHost: y\r\n\r\n",
        b"GET / HTTP/1.1\r\n Host: x\r\n\r\n",
        b"GET http://evil/ HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET / HTTP/2.0\r\nHost: x\r\n\r\n",
        b"CONNECT host:443 HTTP/1.1\r\nHost: x\r\n\r\n",
    ];
    for request in corpus {
        let response = send_and_read(proxy_addr, request).await;
        assert!(
            response.starts_with("HTTP/1.1 4") || response.starts_with("HTTP/1.1 5"),
            "debe rechazarse, no servirse: {}",
            String::from_utf8_lossy(request)
        );
        assert!(
            !response.contains("200 OK"),
            "nunca200 para: {}",
            String::from_utf8_lossy(request)
        );
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        metrics.snapshot().http_requests_rejected as usize,
        corpus.len(),
        "cada rechazo cuenta"
    );
    assert_eq!(metrics.snapshot().http_requests_proxied, 0);

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve termina")
        .expect("tarea serve sin pánico");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http1_client_header_timeout_returns_408_and_counts() {
    let backend = start_http_backend().await;
    let metrics = Arc::new(Metrics::default());
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_millis(150),
        Duration::from_secs(5),
    );
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    // Cabecera de petición incompleta: el timeout de fase debe dispararse.
    let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: t\r\n")
        .await
        .expect("write");
    let mut buf = vec![0u8; 128];
    let n = tokio::time::timeout(WAIT, client.read(&mut buf))
        .await
        .expect("408 a tiempo")
        .expect("read");
    let response = String::from_utf8_lossy(&buf[..n]).into_owned();
    assert!(
        response.starts_with("HTTP/1.1 408"),
        "respuesta: {response}"
    );
    assert_eq!(metrics.snapshot().header_timeouts, 1);

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve termina")
        .expect("tarea serve sin pánico");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http1_server_header_timeout_returns_504() {
    let backend = start_silent_backend().await;
    let metrics = Arc::new(Metrics::default());
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_secs(5),
        Duration::from_millis(200),
    );
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let response = send_and_read(
        proxy_addr,
        b"GET /x HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        response.starts_with("HTTP/1.1 504"),
        "respuesta: {response}"
    );
    assert_eq!(metrics.snapshot().header_timeouts, 1);

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve termina")
        .expect("tarea serve sin pánico");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http1_client_abort_cancels_upstream_promptly() {
    // A19: el abort del cliente a mitad de cuerpo debe cancelar el upstream
    // al instante (el backend ve el cierre), sin esperar al idle timeout (10s).
    let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let backend = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept backend");
        let mut buf = vec![0u8; 4096];
        // Lee la cabecera y parte del cuerpo; el cierre prematuro es el cancel.
        let _ = socket.read(&mut buf).await;
        let _ = socket.read(&mut buf).await;
        let mut tx = Some(closed_tx);
        loop {
            match socket.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    if let Some(tx) = tx.take() {
                        let _ = tx.send(());
                    }
                    return;
                }
                Ok(_) => {}
            }
        }
    });

    let metrics = Arc::new(Metrics::default());
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    // idle alto: el cierre no puede venir del timeout, debe ser el abort.
    let mut cfg = cfg;
    cfg.idle_timeout = Duration::from_secs(10);
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
    let head = b"POST /x HTTP/1.1\r\nHost: t\r\nContent-Length: 100\r\n\r\n";
    client.write_all(head).await.expect("write head");
    client
        .write_all(&[0xAB; 10])
        .await
        .expect("write body parcial");
    drop(client); // abort a mitad de cuerpo

    // El backend debe observar el cierre de la conexión upstream enseguida.
    tokio::time::timeout(Duration::from_secs(2), closed_rx)
        .await
        .expect("el abort del cliente debe cancelar el upstream de inmediato")
        .expect("señal de cierre del backend");

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        metrics.snapshot().connections_active,
        0,
        "sin fugas de tareas tras el abort"
    );

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve termina")
        .expect("tarea serve sin pánico");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http1_response_without_framing_is_eof_delimited() {
    // Backend HTTP/1.0-style: respuesta sin Content-Length → cuerpo hasta EOF.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let backend = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhasta-eof")
                .await;
        }
    });

    let metrics = Arc::new(Metrics::default());
    let cfg = http_listener_cfg(
        "127.0.0.1:0".parse().expect("addr"),
        backend,
        Duration::from_secs(5),
        Duration::from_secs(5),
    );
    let (proxy_addr, handle, serve) = start_proxy(cfg, Arc::clone(&metrics)).await;

    let response = send_and_read(proxy_addr, b"GET /x HTTP/1.1\r\nHost: t\r\n\r\n").await;
    assert!(response.contains("hasta-eof"), "respuesta: {response}");

    handle.trigger();
    tokio::time::timeout(WAIT, serve)
        .await
        .expect("serve termina")
        .expect("tarea serve sin pánico");
}
