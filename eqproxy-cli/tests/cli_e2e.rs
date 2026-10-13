//! Pruebas E2E a través del **binario real** `eqproxy` (la interfaz que usará
//! el operador), con sockets reales y señales de proceso reales.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_eqproxy"))
}

fn temp_config(name: &str, contents: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "eqproxy-cli-e2e-{}-{name}.toml",
        std::process::id()
    ));
    std::fs::write(&path, contents).expect("escribir config de test");
    path
}

fn remove_temp(path: &PathBuf) {
    let _ = std::fs::remove_file(path);
}

/// Backend de eco real en un hilo síncrono.
fn start_echo_backend() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
    let addr = listener.local_addr().expect("addr echo");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    use std::io::Read;
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).is_err() {
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

#[cfg_attr(
    miri,
    ignore = "requiere procesos y sockets TCP: miri no los soporta (rust-lang/miri#3449)"
)]
#[test]
fn validate_accepts_a_good_config() {
    let backend = start_echo_backend();
    let config = temp_config(
        "ok",
        &format!(
            "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\n[backend.api]\nserver = \"{backend}\"\n"
        ),
    );
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&config)
        .output()
        .expect("ejecutar eqproxy config validate");
    remove_temp(&config);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("config OK"), "stdout: {stdout}");
    assert!(
        stdout.contains("1 listener(es), 1 backend(s)"),
        "stdout: {stdout}"
    );
}

#[cfg_attr(
    miri,
    ignore = "requiere procesos y sockets TCP: miri no los soporta (rust-lang/miri#3449)"
)]
#[test]
fn validate_reports_file_line_field_cause_example() {
    // [listener.web] está en la línea 3; el backend referenciado no existe.
    let config = temp_config(
        "bad-ref",
        "schema_version = 1\n\n[listener.web]\nlisten = \"127.0.0.1:8080\"\nbackend = \"fantasma\"\n",
    );
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&config)
        .output()
        .expect("ejecutar eqproxy config validate");
    remove_temp(&config);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "debe fallar con código 1; stderr: {stderr}"
    );
    for expected in [
        &*format!("{}", config.display()),
        ":3",
        "campo `listener.web.backend`",
        "fantasma",
        "ejemplo:",
        "[backend.fantasma]",
    ] {
        assert!(
            stderr.contains(expected),
            "falta {expected:?} en stderr:\n{stderr}"
        );
    }
}

#[cfg_attr(
    miri,
    ignore = "requiere procesos y sockets TCP: miri no los soporta (rust-lang/miri#3449)"
)]
#[test]
fn validate_reports_syntax_errors_with_line() {
    let config = temp_config("syntax", "schema_version = 1\n[listener.web\n");
    let output = bin()
        .args(["config", "validate", "--config"])
        .arg(&config)
        .output()
        .expect("ejecutar eqproxy config validate");
    remove_temp(&config);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr.contains("error de configuración en"),
        "stderr:\n{stderr}"
    );
    assert!(stderr.contains(":2"), "debe ubicar la línea 2:\n{stderr}");
    assert!(stderr.contains("ejemplo:"), "stderr:\n{stderr}");
}

#[cfg_attr(
    miri,
    ignore = "requiere procesos y sockets TCP: miri no los soporta (rust-lang/miri#3449)"
)]
#[test]
fn unimplemented_commands_fail_explicitly_with_exit_2() {
    let cases: &[(&[&str], &str)] = &[
        (
            &["config", "explain", "--config", "x.toml"],
            "config explain",
        ),
        (&["config", "plan", "--config", "x.toml"], "config plan"),
        (&["config", "apply", "--config", "x.toml"], "config apply"),
        (&["config", "rollback"], "config rollback"),
        (
            &["config", "import", "--input", "a.cfg", "--output", "b.toml"],
            "config import",
        ),
        (&["doctor"], "eqproxy doctor"),
    ];
    for (args, name) in cases {
        let output = bin().args(*args).output().expect("ejecutar eqproxy");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{name} debe salir con código 2; stderr: {stderr}"
        );
        assert!(
            stderr.contains("no está implementado"),
            "{name} debe fallar explícitamente; stderr: {stderr}"
        );
    }
}

#[cfg_attr(
    miri,
    ignore = "requiere procesos y sockets TCP: miri no los soporta (rust-lang/miri#3449)"
)]
#[test]
fn run_http_mode_proxies_requests_and_rejects_smuggling() {
    // Backend HTTP real mínimo: responde 200 con eco del cuerpo.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend http");
    let backend = listener.local_addr().expect("addr backend");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let mut total = 0usize;
                loop {
                    use std::io::Read;
                    match stream.read(&mut buf[total..]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => total += n,
                    }
                    if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let response =
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = stream.write_all(response);
            });
        }
    });

    let config = temp_config(
        "http",
        &format!(
            "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\nmode = \"http\"\n[backend.api]\nserver = \"{backend}\"\n"
        ),
    );

    let mut child = bin()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run (http)");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));

    let mut proxy_addr = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        let read = stderr.read_line(&mut line).expect("leer stderr");
        assert!(read > 0, "eqproxy cerró stderr sin anunciar bind");
        if let Some(addr) = line.split("escuchando en ").nth(1) {
            proxy_addr = addr.trim().to_owned();
            break;
        }
    }
    assert!(!proxy_addr.is_empty(), "no se anunció la dirección");

    // Recorrido real: GET proxificado con respuesta observada.
    let mut client = TcpStream::connect(proxy_addr.as_str()).expect("connect al proxy");
    client
        .write_all(b"GET /x HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        .expect("write GET");
    let mut response = Vec::new();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let _ = client.read_to_end(&mut response);
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 200 OK"), "respuesta: {text}");
    assert!(text.ends_with("ok"), "cuerpo ecoado: {text}");

    // Caso de error: smuggling CL+TE rechazado con 400 por el binario real.
    let mut evil = TcpStream::connect(proxy_addr.as_str()).expect("connect 2");
    evil.write_all(
        b"POST /x HTTP/1.1\r\nHost: t\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
    )
    .expect("write smuggle");
    let mut rejected = Vec::new();
    evil.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let _ = evil.read_to_end(&mut rejected);
    let rejected = String::from_utf8_lossy(&rejected);
    assert!(
        rejected.starts_with("HTTP/1.1 400"),
        "smuggling debe rechazarse: {rejected}"
    );

    // SIGINT real → apagado limpio con código 0.
    let pid = child.id();
    let kill = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .expect("ejecutar kill");
    assert!(kill.success(), "kill -INT debe aceptarse");
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("eqproxy no terminó tras SIGINT");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    remove_temp(&config);
    assert_eq!(status.code(), Some(0), "apagado limpio debe salir con 0");
}

#[cfg_attr(
    miri,
    ignore = "requiere procesos y sockets TCP: miri no los soporta (rust-lang/miri#3449)"
)]
#[test]
fn run_proxies_traffic_and_shuts_down_gracefully_on_sigint() {
    let backend = start_echo_backend();
    let config = temp_config(
        "run",
        &format!(
            "schema_version = 1\nshutdown_grace = \"5s\"\n[listener.web]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\nconnect_timeout = \"2s\"\nidle_timeout = \"30s\"\n[backend.api]\nserver = \"{backend}\"\n"
        ),
    );

    let mut child = bin()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--metrics-interval", "1h"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn eqproxy run");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr piped"));

    // Espera la línea de bind para conocer el puerto efímero real.
    let mut proxy_addr = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        let read = stderr.read_line(&mut line).expect("leer stderr");
        assert!(read > 0, "eqproxy cerró stderr sin anunciar bind");
        if let Some(addr) = line.split("escuchando en ").nth(1) {
            proxy_addr = addr.trim().to_owned();
            break;
        }
    }
    assert!(
        !proxy_addr.is_empty(),
        "no se anunció la dirección de escucha"
    );

    // Tráfico real a través del proxy.
    let mut client = TcpStream::connect(proxy_addr.as_str()).expect("connect al proxy");
    client.write_all(b"ping").expect("write");
    let mut buf = [0u8; 4];
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    client.read_exact(&mut buf).expect("read eco");
    assert_eq!(&buf, b"ping", "el eco debe ser byte a byte");

    // SIGINT real → apagado gradual.
    let pid = child.id();
    let kill = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .expect("ejecutar kill");
    assert!(kill.success(), "kill -INT debe aceptarse");

    // La conexión en curso debe poder terminar tras la señal.
    client.write_all(b"fin").expect("write tras SIGINT");
    let mut tail = [0u8; 3];
    client.read_exact(&mut tail).expect("eco tras SIGINT");
    assert_eq!(&tail, b"fin");
    drop(client);

    // El proceso debe terminar solo, con código 0.
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("eqproxy no terminó tras SIGINT");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    remove_temp(&config);

    assert_eq!(status.code(), Some(0), "el apagado limpio debe salir con 0");
    let mut rest = String::new();
    let _ = stderr.read_line(&mut rest);
    let mut remainder = String::new();
    for line in stderr.lines().map_while(Result::ok) {
        remainder.push_str(&line);
        remainder.push('\n');
    }
    let all = format!("{rest}{remainder}");
    assert!(all.contains("apagado completado"), "stderr final:\n{all}");
    assert!(all.contains("METRICAS"), "debe reportar métricas:\n{all}");
}
