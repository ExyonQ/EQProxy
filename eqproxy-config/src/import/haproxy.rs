//! HAProxy → EQProxy.
//!
//! Reads the section grammar (`global`, `defaults`, `frontend`, `backend`,
//! `listen`, …), the `server`/`default-server` parameter list and the timeout
//! set, and maps what the v1 schema expresses today: backends with weights and
//! backup servers, TCP **and HTTP** health checks, retries, bounded queue,
//! cookie/source affinity, slow start, `option forwardfor`, TLS to the backend
//! and to clients (with SNI-less single certificates), `http-request`
//! set-header/deny and conditional `use_backend` over the conditions
//! `[[listener.*.rules]]` can evaluate. Everything else is classified.

use std::collections::BTreeMap;

use super::{
    Conv, HeaderOp, ImportError, Listener, ListenerTls, Rule, convert_duration, normalize_addr,
};

/// Directives EQProxy covers in a field the converter does not fill in.
fn supported_manually(name: &str) -> Option<&'static str> {
    Some(match name {
        "stats" => "[admin].unix_socket + token_file (plano de administración con bearer token)",
        "log" => "[access_log].path con format = \"json\" | \"combined\"",
        "log-format" | "log-format-sd" => "[access_log].format (campos estables, no plantillas)",
        "errorfile" | "errorloc" | "errorloc302" | "errorloc303" => {
            "[[listener.*.rules]].direct_response / local_response"
        }
        "monitor-uri" => "una regla con path + direct_response 200 en [[listener.*.rules]]",
        "resolvers" => "[backend.*].resolve_interval (re-resolución en caliente)",
        "server-template" => {
            "servidores HOSTNAME:PORT en [backend.*].servers (resolución en caliente)"
        }
        "peers" => "sin sincronía de estado entre instancias (cada una mantiene su vista)",
        "stick-table" | "stick" => {
            "[backend.*.affinity] (cookie o source), sin rate-limit por tabla"
        }
        "compression" => "[listener.*.compression] (gzip/brotli negociados por Accept-Encoding)",
        "http-reuse" => "política de pool fija: 64 conexiones idle por servidor, 60 s",
        "maxqueue" => "[backend.*].maxqueue + timeout_queue",
        "retries" => "[backend.*].retries",
        "retry-on" => "[backend.*].retries + retry_non_idempotent",
        "backlog" => "lo fija el sistema (somaxconn)",
        "nbthread" => "runtime multi-hilo de tokio (no configurable)",
        "daemon" => "ejecute bajo systemd/supervisord",
        "chroot" => "aislamiento del sistema (contenedor, usuario sin privilegios)",
        "ulimit-n" => "`eqproxy doctor` comprueba el presupuesto de descriptores",
        "tune" | "tune.bufsize" | "tune.maxrewrite" => "sin mandos de runtime expuestos",
        "h1-case-adjust" | "h1-case-adjust-bogus-client" | "h1-case-adjust-bogus-server" => {
            "EQProxy normaliza el framing de HTTP/1.1 y rechaza lo dudoso"
        }
        "option httpclose" | "option http-server-close" | "option http-keep-alive" => {
            "keep-alive HTTP/1.1 con pool de backend propio"
        }
        "option forwardfor" => "[listener.*].forwarded_headers = \"append\"",
        "http-response" => "[[listener.*.rules]].response_headers",
        "acl" => "condiciones de [[listener.*.rules]] (host, path, ip, method, header, cookie)",
        _ => return None,
    })
}

/// Directives with no equivalent at all.
fn unsupported(name: &str) -> Option<&'static str> {
    Some(match name {
        "lua-load" | "lua-load-per-thread" | "lua-prepend-path" => {
            "Lua no se admite: la extensión es un plugin WASM en un sandbox (ADR-0031)"
        }
        "filter" => "filtros (compresión, SPOE): use compression o un plugin WASM",
        "program" | "mailers" | "userlist" => "sin equivalente",
        "stick-table" => "stick-tables como almacén compartido: solo hay afinidad por cookie/IP",
        "tcp-request" | "tcp-response" => "reglas L4 por conexión: sin motor de ACLs L4",
        "transparent" => "TPROXY: sin soporte",
        "source" => "source bind / usesrc: sin soporte",
        "dispatch" => "dispatch a otro proceso: sin soporte",
        "redir" => "redirección del servidor (ahora obsoleto en HAProxy): use una regla redirect",
        "force-persist" | "ignore-persist" => "persistencia forzada: sin soporte",
        "load-server-state-from-file" => "persistencia de estado entre reinicios: sin soporte",
        "dynamic-cookie-key" => "clave del cookie dinámico: la afinidad usa un cookie propio",
        "external-check" | "agent-check" => "checks externos/agente: solo TCP y HTTP",
        "setenv" => "variables de entorno del proceso: sin equivalente en el TOML",
        "ssl-engine" => "motor criptográfico externo: sin soporte",
        "strict-limits" => "límites estrictos: sin mando",
        "capture" => "captura de cabeceras: use el access log estructurado",
        "disable-h2-upgrade" => "h2 no se negocia por upgrade, sino por ALPN",
        "option httplog" | "option dontlognull" | "option redispatch" | "option tcplog" => {
            "opción sin mapeo automático: revísela en [access_log] y [backend.*].retries"
        }
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Line grammar
// ---------------------------------------------------------------------------

/// Splits one line into arguments, honouring single and double quotes.
fn split_args(line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut has_current = false;
    for ch in line.chars() {
        match quote {
            Some(q) => {
                if ch == q {
                    quote = None;
                } else {
                    current.push(ch);
                }
            }
            None => {
                if ch == '"' || ch == '\'' {
                    quote = Some(ch);
                    has_current = true;
                } else if ch.is_whitespace() {
                    if has_current {
                        args.push(std::mem::take(&mut current));
                        has_current = false;
                    }
                } else {
                    current.push(ch);
                    has_current = true;
                }
            }
        }
    }
    if has_current {
        args.push(current);
    }
    args
}

/// Removes the trailing comment of a line, honouring quotes.
fn strip_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    for (index, ch) in line.char_indices() {
        match quote {
            Some(q) if ch == q => quote = None,
            Some(_) => {}
            None => match ch {
                '"' | '\'' => quote = Some(ch),
                '#' => return &line[..index],
                _ => {}
            },
        }
    }
    line
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Global,
    Defaults,
    Frontend,
    Backend,
    Listen,
    Other,
}

#[derive(Debug)]
struct Section {
    kind: Kind,
    name: String,
    lines: Vec<Vec<String>>,
}

fn sections(text: &str) -> Vec<Section> {
    let mut out: Vec<Section> = vec![Section {
        kind: Kind::Global,
        name: String::new(),
        lines: Vec::new(),
    }];
    for raw in text.lines() {
        let args = split_args(strip_comment(raw));
        if args.is_empty() {
            continue;
        }
        let keyword = args[0].to_ascii_lowercase();
        let (kind, starts) = match keyword.as_str() {
            "global" | "defaults" if args.len() == 1 => (
                if keyword == "global" {
                    Kind::Global
                } else {
                    Kind::Defaults
                },
                true,
            ),
            "frontend" => (Kind::Frontend, true),
            "backend" => (Kind::Backend, true),
            "listen" => (Kind::Listen, true),
            "peers" | "resolvers" | "userlist" | "mailers" | "program" | "cache" | "ring"
            | "log-forward" | "fcgi-app" | "traces" => (Kind::Other, true),
            _ => (Kind::Other, false),
        };
        if starts {
            out.push(Section {
                kind,
                name: args.get(1).cloned().unwrap_or_default(),
                lines: Vec::new(),
            });
        } else if let Some(last) = out.last_mut() {
            last.lines.push(args);
        }
    }
    // An empty leading `global` (nothing before the first keyword) or a
    // `defaults` with no lines carries nothing to classify.
    out.retain(|section| {
        !section.lines.is_empty()
            || matches!(section.kind, Kind::Frontend | Kind::Backend | Kind::Listen)
    });
    out
}

/// Server-line parameters: `key value`, `key=value` and bare flags.
fn server_params(args: &[String], into: &mut BTreeMap<String, String>) {
    const WITH_VALUE: &[&str] = &[
        "weight",
        "inter",
        "fastinter",
        "downinter",
        "fall",
        "rise",
        "maxconn",
        "maxqueue",
        "slowstart",
        "port",
        "sni",
        "check-sni",
        "verify",
        "ca-file",
        "crt",
        "alpn",
        "proto",
        "minconn",
        "observe",
        "on-error",
        "on-marked-down",
        "on-marked-up",
        "error-limit",
        "agent-inter",
        "agent-port",
        "source",
        "interface",
        "namespace",
        "pool",
        "pool-maxconn",
        "pool-purge-delay",
        "resolve-prefer",
        "log-bufsize",
    ];
    let mut index = 0;
    while index < args.len() {
        let token = &args[index];
        let lower = token.to_ascii_lowercase();
        if let Some((key, value)) = lower.split_once('=')
            && (WITH_VALUE.contains(&key) || !value.is_empty())
        {
            into.insert(key.to_owned(), value.to_owned());
            index += 1;
            continue;
        }
        if lower == "no-check" {
            into.insert("check".to_owned(), "no".to_owned());
            index += 1;
            continue;
        }
        if WITH_VALUE.contains(&lower.as_str()) {
            let value = args.get(index + 1).cloned().unwrap_or_default();
            into.insert(lower, value);
            index += 2;
            continue;
        }
        into.insert(lower, "yes".to_owned());
        index += 1;
    }
}

#[derive(Default)]
struct Defaults {
    mode: Option<String>,
    balance: Option<String>,
    timeouts: BTreeMap<String, String>,
    forwardfor: bool,
    maxconn: Option<u32>,
}

pub(super) fn convert(conv: &mut Conv, text: &str) -> Result<(), ImportError> {
    let sections = sections(text);
    let mut defaults = Defaults::default();

    for section in &sections {
        if section.kind != Kind::Global {
            continue;
        }
        let context = "global";
        for args in &section.lines {
            let before = conv.notes.len();
            let text = args.join(" ");
            match args[0].to_ascii_lowercase().as_str() {
                "maxconn" => match args.get(1).map(|v| v.parse::<u32>()) {
                    Some(Ok(value)) => {
                        defaults.maxconn = Some(value);
                        conv.done(1, &text, context, format!("listener.maxconn = {value}"));
                    }
                    _ => conv.review(1, &text, context, "maxconn no numérico: se usa 1024"),
                },
                keyword => match supported_manually(keyword) {
                    Some(place) => conv.review(
                        1,
                        &text,
                        context,
                        format!("EQProxy sí lo cubre en {place}: transcríbalo a mano"),
                    ),
                    None => match unsupported(keyword) {
                        Some(reason) => conv.gap(1, &text, context, reason),
                        None => conv.info(
                            1,
                            text.clone(),
                            context,
                            "directiva global sin traducción (no afecta a eqproxy.toml)",
                        ),
                    },
                },
            }
            conv.touch(&text, context, before)?;
        }
    }

    for section in sections.iter().filter(|s| s.kind == Kind::Defaults) {
        let context = "defaults";
        for args in &section.lines {
            let before = conv.notes.len();
            let text = args.join(" ");
            let keyword = args[0].to_ascii_lowercase();
            match keyword.as_str() {
                "mode" => {
                    let mode = args.get(1).cloned().unwrap_or_else(|| "http".to_owned());
                    defaults.mode = Some(mode.clone());
                    conv.review(
                        1,
                        &text,
                        context,
                        format!("modo por defecto «{mode}»: el modo real lo fija cada listener"),
                    );
                }
                "balance" => {
                    let algorithm = args
                        .get(1)
                        .cloned()
                        .unwrap_or_else(|| "roundrobin".to_owned());
                    defaults.balance = Some(algorithm.clone());
                    if algorithm == "roundrobin" || algorithm == "leastconn" {
                        conv.done(
                            1,
                            &text,
                            context,
                            format!("balance por defecto «{algorithm}» en los backends generados"),
                        );
                    } else {
                        conv.gap(
                            1,
                            &text,
                            context,
                            format!(
                                "balance «{algorithm}» sin soporte: EQProxy usa roundrobin o leastconn ponderados"
                            ),
                        );
                    }
                }
                "timeout" => {
                    let name = args
                        .get(1)
                        .cloned()
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    let value = args.get(2).cloned().unwrap_or_default();
                    if matches!(name.as_str(), "queue" | "tunnel") {
                        conv.gap(
                            1,
                            text.clone(),
                            context,
                            format!("«timeout {name}» sin equivalente: idle_timeout es el único plazo de inactividad"),
                        );
                    } else {
                        defaults.timeouts.insert(name.clone(), value.clone());
                        if convert_duration(conv, &value, "ms", &text, context).is_some() {
                            conv.done(1, &text, context, format!("timeout por defecto «{name}»"));
                        }
                    }
                }
                "option" => {
                    let option = args.get(1).map(String::as_str).unwrap_or_default();
                    if option == "forwardfor" {
                        defaults.forwardfor = true;
                        conv.done(
                            1,
                            &text,
                            context,
                            "[listener.*].forwarded_headers = \"append\" en cada listener",
                        );
                    } else {
                        let key = format!("option {option}");
                        match supported_manually(&key) {
                            Some(place) => conv.review(
                                1,
                                &text,
                                context,
                                format!("EQProxy sí lo cubre en {place}"),
                            ),
                            None => conv.gap(1, &text, context, "opción sin equivalente conocido"),
                        }
                    }
                }
                keyword => match supported_manually(keyword) {
                    Some(place) => conv.review(
                        1,
                        &text,
                        context,
                        format!("EQProxy sí lo cubre en {place}: transcríbalo a mano"),
                    ),
                    None => conv.review(
                        1,
                        text.clone(),
                        context,
                        "directiva de defaults sin traducción automática: revísela a mano",
                    ),
                },
            }
            conv.touch(&text, context, before)?;
        }
    }

    // Backends first: listeners reference them by name.
    for section in sections.iter().filter(|s| s.kind == Kind::Backend) {
        backend(conv, section, &defaults)?;
    }
    for section in sections.iter().filter(|s| s.kind == Kind::Listen) {
        backend_named(conv, section, &defaults)?;
    }
    for section in sections.iter().filter(|s| s.kind == Kind::Frontend) {
        frontend(conv, section, &defaults, None)?;
    }
    for section in sections.iter().filter(|s| s.kind == Kind::Listen) {
        frontend(conv, section, &defaults, Some(&section.name))?;
    }
    for section in sections.iter().filter(|s| s.kind == Kind::Other) {
        let context = format!("{} {}", kind_name(section.kind), section.name);
        let before = conv.notes.len();
        conv.gap(
            1,
            section.name.clone(),
            &context,
            format!(
                "sección «{}» sin soporte en EQProxy: revísela a mano",
                kind_name(section.kind)
            ),
        );
        conv.touch(&section.name, &context, before)?;
    }
    Ok(())
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Global => "global",
        Kind::Defaults => "defaults",
        Kind::Frontend => "frontend",
        Kind::Backend => "backend",
        Kind::Listen => "listen",
        Kind::Other => "sección",
    }
}

/// `backend { … }`.
fn backend(conv: &mut Conv, section: &Section, defaults: &Defaults) -> Result<(), ImportError> {
    backend_body(conv, section, defaults, false)
}

/// `listen { … }`: a backend **and** a frontend with the same name.
fn backend_named(
    conv: &mut Conv,
    section: &Section,
    defaults: &Defaults,
) -> Result<(), ImportError> {
    backend_body(conv, section, defaults, true)
}

fn backend_body(
    conv: &mut Conv,
    section: &Section,
    defaults: &Defaults,
    named: bool,
) -> Result<(), ImportError> {
    let context = format!(
        "{} {}",
        if named { "listen" } else { "backend" },
        section.name
    );
    let name = if named {
        let cleaned = super::sanitize_name(&section.name);
        if cleaned.is_empty() {
            conv.free_backend_name(&section.name)
        } else {
            cleaned
        }
    } else {
        conv.free_backend_name(&section.name)
    };
    let mut balance = defaults.balance.clone().unwrap_or_default();
    if balance != "roundrobin" && balance != "leastconn" {
        balance = String::new();
    }
    let mut backend = super::Backend {
        balance,
        ..super::Backend::default()
    };
    let mut checked = false;
    let mut default_server: BTreeMap<String, String> = BTreeMap::new();

    for args in &section.lines {
        let before = conv.notes.len();
        let text = args.join(" ");
        let keyword = args[0].to_ascii_lowercase();
        match keyword.as_str() {
            "mode" => conv.info(
                1,
                &text,
                &context,
                "el modo (tcp/http) real lo fija cada listener de EQProxy",
            ),
            "balance" => {
                let algorithm = args
                    .get(1)
                    .cloned()
                    .unwrap_or_else(|| "roundrobin".to_owned());
                if algorithm == "roundrobin" || algorithm == "leastconn" {
                    backend.balance = algorithm.clone();
                    conv.done(1, &text, &context, format!("balance = \"{algorithm}\""));
                } else if algorithm == "source" {
                    backend.affinity = Some(super::Affinity {
                        mode: "source".to_owned(),
                        cookie: None,
                    });
                    conv.done(
                        1,
                        &text,
                        &context,
                        "[backend.*.affinity] mode = \"source\" (hash de la IP del cliente)",
                    );
                } else {
                    conv.gap(
                        1,
                        &text,
                        &context,
                        format!(
                            "balance «{algorithm}» sin soporte: EQProxy emite roundrobin ponderado"
                        ),
                    );
                }
            }
            "server" => {
                server_line(
                    conv,
                    args,
                    &context,
                    &mut backend,
                    &default_server,
                    &mut checked,
                );
            }
            "default-server" => {
                server_params(&args[1..], &mut default_server);
                conv.review(
                    1,
                    &text,
                    &context,
                    "default-server: los parámetros se aplican a las líneas server siguientes",
                );
            }
            "option" => {
                let option = args
                    .get(1)
                    .map(|v| v.to_ascii_lowercase())
                    .unwrap_or_default();
                if option == "httpchk" {
                    let mut health = backend
                        .health_check
                        .take()
                        .unwrap_or_else(Conv::default_health_check);
                    health.kind = Some("http");
                    // `option httpchk [METHOD] [URI[/VERSION]]`
                    let uri = args.get(2).filter(|value| value.starts_with('/'));
                    if let Some(uri) = uri {
                        let path = uri
                            .split_whitespace()
                            .next()
                            .unwrap_or("/")
                            .trim_end_matches("HTTP/1.1")
                            .trim_end_matches("HTTP/1.0");
                        health.http_path =
                            Some(if path.is_empty() { "/" } else { path }.to_owned());
                    }
                    backend.health_check = Some(health);
                    checked = true;
                    conv.done(
                        1,
                        &text,
                        &context,
                        "health_check con type = \"http\" (B-H6: status esperado y ruta)",
                    );
                } else if option == "forwardfor" {
                    conv.review(
                        1,
                        &text,
                        &context,
                        "[listener.*].forwarded_headers = \"append\" (se activa en el listener que use este backend)",
                    );
                } else {
                    match supported_manually(&format!("option {option}")) {
                        Some(place) => conv.review(
                            1,
                            &text,
                            &context,
                            format!("EQProxy sí lo cubre en {place}"),
                        ),
                        None => conv.gap(1, &text, &context, "opción sin equivalente conocido"),
                    }
                }
            }
            "http-check" => {
                if let Some(action) = args.get(1).map(|v| v.to_ascii_lowercase())
                    && action == "expect"
                {
                    let what = args.get(2).cloned().unwrap_or_default();
                    let value = args.get(3).cloned().unwrap_or_default();
                    if what == "status" {
                        let mut health = backend
                            .health_check
                            .take()
                            .unwrap_or_else(Conv::default_health_check);
                        health.kind = Some("http");
                        health.expect_status = Some(value.clone());
                        backend.health_check = Some(health);
                        checked = true;
                        conv.done(
                            1,
                            &text,
                            &context,
                            format!("health_check.expect_status = \"{value}\""),
                        );
                    } else {
                        conv.review(
                            1,
                            &text,
                            &context,
                            "http-check expect rstring: EQProxy solo compara el código de estado",
                        );
                    }
                } else {
                    conv.review(
                        1,
                        &text,
                        &context,
                        "http-check: EQProxy envía GET/HEAD con la ruta de health_check.http_path",
                    );
                }
            }
            "cookie" => {
                if let Some(name) = args.get(1) {
                    backend.affinity = Some(super::Affinity {
                        mode: "cookie".to_owned(),
                        cookie: Some(name.clone()),
                    });
                    conv.done(
                        1,
                        &text,
                        &context,
                        format!("[backend.*.affinity] mode = \"cookie\", cookie = \"{name}\""),
                    );
                } else {
                    conv.review(1, &text, &context, "cookie sin nombre: se ignora");
                }
            }
            "timeout" => {
                let kind = args
                    .get(1)
                    .cloned()
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                let value = args.get(2).cloned().unwrap_or_default();
                if matches!(kind.as_str(), "queue" | "tunnel") {
                    conv.gap(
                        1,
                        &text,
                        &context,
                        format!("«timeout {kind}» sin equivalente en este backend"),
                    );
                } else {
                    backend.timeouts.insert(kind.clone(), value);
                    conv.done(1, &text, &context, format!("timeout «{kind}» del backend"));
                }
            }
            "retries" => match args.get(1).and_then(|v| v.parse::<u32>().ok()) {
                Some(value) => {
                    backend.retries = value.min(5);
                    conv.done(1, &text, &context, format!("retries = {}", backend.retries));
                }
                None => conv.review(1, &text, &context, "retries no numérico: se deja 0"),
            },
            "maxqueue" => match args.get(1).and_then(|v| v.parse::<u32>().ok()) {
                Some(value) => {
                    backend.maxqueue = value.min(10_000);
                    conv.done(
                        1,
                        &text,
                        &context,
                        format!("maxqueue = {}", backend.maxqueue),
                    );
                }
                None => conv.review(1, &text, &context, "maxqueue no numérico: se deja 0"),
            },
            keyword => match supported_manually(keyword) {
                Some(place) => conv.review(
                    1,
                    &text,
                    &context,
                    format!("EQProxy sí lo cubre en {place}: transcríbalo a mano"),
                ),
                None => match unsupported(keyword) {
                    Some(reason) => conv.gap(1, &text, &context, reason),
                    None => conv.review(
                        1,
                        text.clone(),
                        &context,
                        "directiva de backend sin traducción automática: revísela a mano",
                    ),
                },
            },
        }
        conv.touch(&text, &context, before)?;
    }

    if checked && backend.health_check.is_none() {
        backend.health_check = Some(Conv::default_health_check());
    }
    if backend.servers.is_empty() {
        conv.reject(
            1,
            format!("{} {}", kind_name(section.kind), section.name),
            &context,
            "backend sin servidores traducibles: se omite",
        );
        return Ok(());
    }
    if name != section.name && !named {
        conv.review(
            1,
            format!("backend {}", section.name),
            &context,
            format!("renombrado a «{name}» (el nombre no es válido o ya estaba usado)"),
        );
    }
    conv.add_backend(name, backend);
    Ok(())
}

/// One `server name address [params]` line.
fn server_line(
    conv: &mut Conv,
    args: &[String],
    context: &str,
    backend: &mut super::Backend,
    defaults: &BTreeMap<String, String>,
    checked: &mut bool,
) {
    if args.len() < 3 {
        conv.review(
            1,
            args.join(" "),
            context,
            "línea server incompleta: se omite",
        );
        return;
    }
    let name = args[1].clone();
    let raw = args[2].clone();
    let mut params = defaults.clone();
    server_params(&args[3..], &mut params);
    let Some(addr) = normalize_addr(conv, &raw, None, &format!("server {name}"), context) else {
        return;
    };
    let mut weight = 1u32;
    if let Some(value) = params.get("weight") {
        match value.parse::<u32>() {
            Ok(parsed) if parsed > 256 => {
                weight = 256;
                conv.review(
                    1,
                    format!("weight {parsed}"),
                    context,
                    "weight > 256: recortado",
                );
            }
            Ok(parsed) => weight = parsed,
            Err(_) => conv.review(
                1,
                format!("weight {value}"),
                context,
                "weight no numérico: 1",
            ),
        }
    }
    if params.contains_key("down") || params.contains_key("disabled") {
        weight = 0;
        conv.review(
            1,
            format!("server {name}"),
            context,
            "«down/disabled» ≈ weight = 0 (drenado: nunca seleccionado, sí chequeado)",
        );
    }
    let backup = params.contains_key("backup");
    if backup {
        conv.done(
            1,
            format!("server {name} backup"),
            context,
            "backup = true (solo se usa cuando ningún primario es elegible)",
        );
    }
    if params.contains_key("send-proxy-v2") {
        conv.reject(
            1,
            format!("server {name} send-proxy-v2"),
            context,
            "PROXY protocol v2: EQProxy solo emite v1",
        );
    } else if params.contains_key("send-proxy") {
        backend.proxy_protocol_v1 = true;
        conv.done(
            1,
            format!("server {name} send-proxy"),
            context,
            "proxy_protocol = \"v1\"",
        );
    }
    if params.contains_key("ssl") {
        let mut tls = backend.tls.take().unwrap_or_default();
        tls.verify = true;
        if let Some(verify) = params.get("verify")
            && matches!(verify.to_ascii_lowercase().as_str(), "none" | "off" | "0")
        {
            tls.verify = false;
            conv.review(
                1,
                format!("server {name} verify none"),
                context,
                "verify = false: EQProxy verifica por defecto; desactivarlo tiene riesgo",
            );
        }
        if let Some(ca) = params.get("ca-file") {
            tls.ca_file = Some(ca.clone());
        }
        if let Some(sni) = params.get("sni") {
            tls.server_name = Some(sni.clone());
        }
        if let Some(alpn) = params.get("alpn") {
            let protocols: Vec<String> = alpn
                .split(',')
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
                .collect();
            tls.alpn = protocols;
        }
        backend.tls = Some(tls);
        conv.done(
            1,
            format!("server {name} ssl"),
            context,
            "[backend.*.tls] (verify, ca_file, server_name, alpn)",
        );
    }
    if params.get("check").is_some_and(|value| value != "no") {
        *checked = true;
        let mut health = backend
            .health_check
            .take()
            .unwrap_or_else(Conv::default_health_check);
        if let Some(inter) = params.get("inter")
            && let Some(value) = convert_duration(conv, inter, "ms", "inter", context)
        {
            health.interval = value;
        }
        if let Some(fall) = params.get("fall").and_then(|v| v.parse::<u32>().ok()) {
            health.fall = fall.max(1);
        }
        if let Some(rise) = params.get("rise").and_then(|v| v.parse::<u32>().ok()) {
            health.rise = rise.max(1);
        }
        backend.health_check = Some(health);
        conv.done(
            1,
            format!("server {name} check"),
            context,
            "health_check activo (interval/fall/rise)",
        );
    }
    // `server … maxconn N` (B-H16): per-server concurrency cap, real field in
    // the schema since v0.8.5. A non-numeric value is a review, never a
    // silent 0.
    let maxconn = match params.get("maxconn") {
        Some(raw) => match raw.parse::<u32>() {
            Ok(value) => {
                conv.done(
                    1,
                    format!("server {name} maxconn {value}"),
                    context,
                    format!(
                        "maxconn = {value} (tope de intercambios concurrentes de este servidor)"
                    ),
                );
                value
            }
            Err(_) => {
                conv.review(
                    1,
                    format!("server {name} maxconn {raw}"),
                    context,
                    "maxconn no numérico: se omite el tope por servidor",
                );
                0
            }
        },
        None => 0,
    };
    if params.contains_key("slowstart") {
        conv.review(
            1,
            format!("server {name} slowstart"),
            context,
            "[backend.*].slow_start (ventana del backend, no por servidor)",
        );
    }
    backend.servers.push(super::Server {
        addr,
        weight,
        backup,
        maxconn,
    });
}

/// `frontend { … }` and the frontend half of `listen { … }`.
fn frontend(
    conv: &mut Conv,
    section: &Section,
    defaults: &Defaults,
    combined_backend: Option<&str>,
) -> Result<(), ImportError> {
    let context = format!(
        "{} {}",
        if combined_backend.is_some() {
            "listen"
        } else {
            "frontend"
        },
        section.name
    );
    let mut mode = defaults.mode.clone().unwrap_or_else(|| "http".to_owned());
    let mut binds: Vec<Vec<String>> = Vec::new();
    let mut default_backend: Option<String> = None;
    let mut timeouts: BTreeMap<String, String> = BTreeMap::new();
    let mut maxconn = defaults.maxconn.unwrap_or(1024);
    let mut forwarded = defaults.forwardfor;
    let mut set_headers: Vec<HeaderOp> = Vec::new();
    let mut deny_rules: Vec<Rule> = Vec::new();
    let mut path_rules: Vec<Rule> = Vec::new();

    for args in &section.lines {
        let before = conv.notes.len();
        let text = args.join(" ");
        let keyword = args[0].to_ascii_lowercase();
        match keyword.as_str() {
            "mode" => {
                mode = args.get(1).cloned().unwrap_or_else(|| "http".to_owned());
                conv.info(1, &text, &context, format!("modo del listener «{mode}»"));
            }
            "bind" => {
                binds.push(args[1..].to_vec());
                conv.done(
                    1,
                    text.clone(),
                    &context,
                    "listener de EQProxy sobre esta dirección",
                );
            }
            "maxconn" => match args.get(1).and_then(|v| v.parse::<u32>().ok()) {
                Some(value) => {
                    maxconn = value;
                    conv.done(1, &text, &context, format!("listener.maxconn = {value}"));
                }
                None => conv.review(1, &text, &context, "maxconn no numérico: se usa 1024"),
            },
            "default_backend" => {
                default_backend = args.get(1).cloned();
                conv.done(
                    1,
                    &text,
                    &context,
                    "backend de respaldo del listener (el `backend` de [listener.*])",
                );
            }
            "use_backend" => {
                let target = args.get(1).cloned().unwrap_or_default();
                let condition = args.iter().position(|arg| arg == "if" || arg == "unless");
                match condition {
                    None => {
                        default_backend = default_backend.or(Some(target.clone()));
                        conv.review(
                            1,
                            &text,
                            &context,
                            format!("use_backend sin condición → backend de respaldo «{target}»"),
                        );
                    }
                    Some(position) => {
                        let negated = args[position] == "unless";
                        let resolved = if conv.has_backend(&super::sanitize_name(&target)) {
                            Some(super::sanitize_name(&target))
                        } else if conv.has_backend(&target) {
                            Some(target.clone())
                        } else {
                            None
                        };
                        match (condition_rule(&args[position + 1..], &target), resolved) {
                            (Some(mut rule), Some(resolved)) if !negated => {
                                rule.use_backend = Some(resolved.clone());
                                conv.done(
                                    1,
                                    &text,
                                    &context,
                                    format!("regla [[listener.*.rules]] → «{resolved}»"),
                                );
                                path_rules.push(rule);
                            }
                            (Some(_), None) => conv.reject(
                                1,
                                &text,
                                &context,
                                format!(
                                    "use_backend «{target}»: el backend no existe o no fue traducible, así que la regla no se emite"
                                ),
                            ),
                            (Some(_), Some(_)) => conv.gap(
                                1,
                                &text,
                                &context,
                                "«unless» no se traduce: las reglas de EQProxy solo expresan la condición positiva",
                            ),
                            (None, _) => conv.gap(
                                1,
                                &text,
                                &context,
                                "condición ACL sin traducción a [[listener.*.rules]]: revísela a mano",
                            ),
                        }
                    }
                }
            }
            "timeout" => {
                let kind = args
                    .get(1)
                    .cloned()
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                let value = args.get(2).cloned().unwrap_or_default();
                if matches!(kind.as_str(), "queue" | "tunnel") {
                    conv.gap(
                        1,
                        &text,
                        &context,
                        format!("«timeout {kind}» sin equivalente"),
                    );
                } else {
                    timeouts.insert(kind, value);
                    conv.done(1, &text, &context, "timeout del listener");
                }
            }
            "option" => {
                let option = args
                    .get(1)
                    .map(|v| v.to_ascii_lowercase())
                    .unwrap_or_default();
                if option == "forwardfor" {
                    forwarded = true;
                    conv.done(
                        1,
                        &text,
                        &context,
                        "forwarded_headers = \"append\" (X-Forwarded-For con la IP del cliente)",
                    );
                } else {
                    match supported_manually(&format!("option {option}")) {
                        Some(place) => conv.review(
                            1,
                            &text,
                            &context,
                            format!("EQProxy sí lo cubre en {place}"),
                        ),
                        None => conv.gap(1, &text, &context, "opción sin equivalente conocido"),
                    }
                }
            }
            "http-request" => {
                http_request(
                    conv,
                    args,
                    &context,
                    &mut set_headers,
                    &mut deny_rules,
                    &mut forwarded,
                );
            }
            keyword => match supported_manually(keyword) {
                Some(place) => conv.review(
                    1,
                    &text,
                    &context,
                    format!("EQProxy sí lo cubre en {place}: transcríbalo a mano"),
                ),
                None => match unsupported(keyword) {
                    Some(reason) => conv.gap(1, &text, &context, reason),
                    None => conv.review(
                        1,
                        &text,
                        &context,
                        "directiva de frontend sin traducción automática: revísela a mano",
                    ),
                },
            },
        }
        conv.touch(&text, &context, before)?;
    }

    // Resolve the fallback backend.
    let backend_name = match combined_backend {
        Some(name) => {
            let wanted = super::sanitize_name(name);
            if conv.has_backend(&wanted) {
                Some(wanted)
            } else {
                None
            }
        }
        None => match default_backend.clone() {
            Some(reference) => {
                let wanted = super::sanitize_name(&reference);
                if conv.has_backend(&wanted) {
                    Some(wanted)
                } else if conv.has_backend(&reference) {
                    Some(reference)
                } else {
                    conv.reject(
                        1,
                        format!("default_backend {reference}"),
                        &context,
                        "el backend referenciado no existe o no fue traducible: listener omitido",
                    );
                    None
                }
            }
            None => {
                let only = conv.only_backend();
                match only {
                    Some(name) => {
                        conv.review(
                            1,
                            &context,
                            &context,
                            format!("sin default_backend: se asume el único backend «{name}»"),
                        );
                        Some(name)
                    }
                    None => {
                        conv.reject(
                            1,
                            &context,
                            &context,
                            "sin default_backend traducible: EQProxy exige un backend por listener",
                        );
                        None
                    }
                }
            }
        },
    };
    let Some(backend_name) = backend_name else {
        return Ok(());
    };

    if binds.is_empty() {
        binds.push(vec!["0.0.0.0:80".to_owned()]);
        conv.review(
            1,
            "bind",
            &context,
            "sin bind: se asume 0.0.0.0:80 (revíselo antes de aplicar)",
        );
    }

    for bind in binds {
        let raw = bind
            .first()
            .cloned()
            .unwrap_or_else(|| "0.0.0.0:80".to_owned());
        let flags: Vec<String> = bind.iter().skip(1).cloned().collect();
        let has = |needle: &str| flags.iter().any(|flag| flag.eq_ignore_ascii_case(needle));
        let ssl = has("ssl");
        let mut cert: Option<String> = None;
        let mut alpn: Vec<String> = Vec::new();
        let mut quic = false;
        let mut index = 0;
        while index < flags.len() {
            let flag = flags[index].to_ascii_lowercase();
            match flag.as_str() {
                "ssl" => {}
                "crt" => {
                    cert = flags.get(index + 1).cloned();
                    index += 1;
                }
                "alpn" => {
                    if let Some(value) = flags.get(index + 1) {
                        alpn = value
                            .split(',')
                            .map(|item| item.trim().to_owned())
                            .filter(|item| !item.is_empty())
                            .collect();
                    }
                    index += 1;
                }
                "quic" | "proto" => {
                    if flag == "quic" || flags.get(index + 1).is_some_and(|v| v == "quic") {
                        quic = true;
                    }
                    if flag == "proto" {
                        index += 1;
                    }
                }
                "name" | "accept-proxy" => {
                    if flag == "name" {
                        index += 1;
                    } else {
                        conv.review(
                            1,
                            "accept-proxy",
                            &context,
                            "[listener.*].proxy_receive + proxy_allow (allowlist obligatoria): actívelo a mano",
                        );
                    }
                }
                "crt-list" => conv.gap(
                    1,
                    "crt-list",
                    &context,
                    "varios certificados por SNI: EQProxy lo soporta en [listener.*.tls].certs; transcríbalo a mano",
                ),
                other => {
                    if matches!(
                        other,
                        "tfo" | "v4v6" | "v6v4" | "deferred" | "prefer-client-ciphers" | "strict-sni"
                            | "allow-0rtt" | "npn" | "extended-negotiation" | "no-tlsv10"
                            | "no-tlsv11" | "no-tlsv12" | "no-tlsv13" | "no-sslv3" | "ssl-min-ver"
                            | "ssl-max-ver" | "ciphers" | "ciphersuites" | "ca-ignore-err"
                            | "crt-ignore-err" | "crl-file" | "ecdhe" | "dhe" | "curves"
                    ) {
                        conv.review(
                            1,
                            other.to_owned(),
                            &context,
                            "flag de bind sin equivalente exacto (se ignora)",
                        );
                        if matches!(other, "ssl-min-ver" | "ssl-max-ver" | "ciphers" | "ciphersuites" | "curves")
                        {
                            index += 1;
                        }
                    } else {
                        conv.gap(
                            1,
                            other.to_owned(),
                            &context,
                            "flag de bind sin equivalente conocido",
                        );
                    }
                }
            }
            index += 1;
        }

        let Some(addr) = normalize_addr(
            conv,
            &raw,
            Some(if ssl { 443 } else { 80 }),
            &format!("bind {raw}"),
            &context,
        ) else {
            continue;
        };

        let tls = if ssl || cert.is_some() {
            match cert {
                Some(cert) => {
                    conv.review(
                        1,
                        format!("crt {cert}"),
                        &context,
                        format!(
                            "HAProxy usa un PEM combinado: EQProxy exige cert y key separados — se emite key = «{cert}.key» y hay que corregirlo"
                        ),
                    );
                    Some(ListenerTls {
                        key: format!("{cert}.key"),
                        cert,
                        alpn: alpn.clone(),
                        min_version: None,
                        client_ca: None,
                    })
                }
                None => {
                    conv.reject(
                        1,
                        "bind ssl",
                        &context,
                        "TLS sin «crt»: no hay certificado; el listener se emite en claro",
                    );
                    None
                }
            }
        } else {
            None
        };

        let name = conv.free_listener_name(&section.name);
        let mut listener = Listener::new(
            addr,
            if mode == "tcp" { "tcp" } else { "http" },
            backend_name.clone(),
        );
        listener.maxconn = maxconn.max(1);
        listener.tls = tls;
        listener.quic = quic && listener.tls.is_some();
        listener.forwarded_headers = if forwarded && listener.mode == "http" {
            Some("append")
        } else {
            None
        };

        let effective = |kind: &str| -> Option<String> {
            timeouts
                .get(kind)
                .cloned()
                .or_else(|| defaults.timeouts.get(kind).cloned())
        };
        if let Some(value) = effective("connect") {
            listener.connect_timeout = convert_duration(
                conv,
                &value,
                "ms",
                &format!("timeout connect {value}"),
                &context,
            );
        }
        if let Some(value) = effective("http-request") {
            listener.client_header_timeout = convert_duration(
                conv,
                &value,
                "ms",
                &format!("timeout http-request {value}"),
                &context,
            );
        }
        if let Some(value) = effective("server") {
            listener.server_header_timeout = convert_duration(
                conv,
                &value,
                "ms",
                &format!("timeout server {value}"),
                &context,
            );
        }
        let client = effective("client");
        let server = effective("server").or_else(|| effective("client"));
        if let Some(value) = client.clone().or(server.clone()) {
            listener.idle_timeout = convert_duration(
                conv,
                &value,
                "ms",
                &format!("timeout client/server {value}"),
                &context,
            );
        }
        if client.is_some() && server.is_some() && client != server {
            conv.review(
                1,
                "timeout client/server",
                &context,
                "EQProxy tiene un solo idle_timeout bidireccional: se usa el menor de los dos",
            );
        }

        // Rules: denies first, then the conditional ones, each carrying the
        // unconditional header edits (HAProxy applies them to every request).
        let mut rules: Vec<Rule> = Vec::new();
        rules.extend(deny_rules.iter().cloned());
        for mut rule in path_rules.iter().cloned() {
            if !set_headers.is_empty() {
                rule.set_headers.extend(set_headers.iter().cloned());
            }
            rules.push(rule);
        }
        if !set_headers.is_empty() && rules.iter().all(|rule| rule.set_headers.is_empty()) {
            // A rule needs at least one match condition, so an unconditional
            // header edit cannot be a rule of its own: it is named instead of
            // inventing a condition that would narrow its scope.
            conv.review(
                1,
                "http-request set-header",
                &context,
                format!(
                    "sin una condición a la que asociarlo no se emite (una regla necesita condición): \
                     añada [[]] a mano en [listener.*.rules] con {}",
                    set_headers
                        .iter()
                        .map(|op| format!("set_headers name = \"{}\"", op.name))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
        }
        listener.rules = rules;

        conv.done(
            1,
            format!("bind {raw}"),
            &context,
            format!(
                "listener «{name}» ({}) → backend «{backend_name}»",
                listener.mode
            ),
        );
        conv.add_listener(name, listener);
    }
    Ok(())
}

/// `http-request {action}` in a frontend.
fn http_request(
    conv: &mut Conv,
    args: &[String],
    context: &str,
    set_headers: &mut Vec<HeaderOp>,
    deny_rules: &mut Vec<Rule>,
    forwarded: &mut bool,
) {
    let text = args.join(" ");
    let action = args
        .get(1)
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    match action.as_str() {
        "set-header" | "add-header" => {
            let (Some(name), Some(value)) = (args.get(2), args.get(3)) else {
                conv.review(1, &text, context, "set-header incompleto: se ignora");
                return;
            };
            if value.contains("%[") {
                conv.review(
                    1,
                    &text,
                    context,
                    "plantilla de HAProxy («%[…]») sin soporte: las cabeceras de EQProxy admiten $remote_addr, $host y $scheme",
                );
                return;
            }
            let op = HeaderOp {
                name: name.clone(),
                value: value.clone(),
            };
            let extra = args.iter().position(|arg| arg == "if" || arg == "unless");
            if extra.is_some() {
                conv.review(
                    1,
                    text.clone(),
                    context,
                    "cabecera condicionada por ACL: EQProxy la aplica a toda petición que case con la regla; revísela",
                );
            }
            if action == "add-header" {
                conv.review(
                    1,
                    &text,
                    context,
                    "add-header: EQProxy tiene add_headers, pero el conversor emite set_headers para no duplicar valores",
                );
            }
            if name.eq_ignore_ascii_case("X-Forwarded-For") {
                *forwarded = true;
            }
            conv.done(
                1,
                &text,
                context,
                format!("set_headers += {{ {name}, {value} }}"),
            );
            set_headers.push(op);
        }
        "deny" | "reject" => {
            let mut rule = Rule {
                name: "deny".to_owned(),
                direct_response: Some((403, None)),
                ..Rule::default()
            };
            let position = args.iter().position(|arg| arg == "if" || arg == "unless");
            match position {
                Some(position) => match condition_rule(&args[position + 1..], "") {
                    Some(condition) => {
                        rule.ip = condition.ip;
                        rule.path_prefix = condition.path_prefix;
                        rule.path = condition.path;
                        rule.host = condition.host;
                        rule.methods = condition.methods;
                        conv.done(
                            1,
                            &text,
                            context,
                            "regla [[listener.*.rules]] con direct_response 403 para la condición",
                        );
                        deny_rules.push(rule);
                    }
                    None => conv.gap(
                        1,
                        &text,
                        context,
                        "deny con condición ACL sin traducción: revíselo a mano",
                    ),
                },
                None => {
                    conv.review(
                        1,
                        &text,
                        context,
                        "deny incondicional: EQProxy responde 403 con direct_response, pero dejaría el listener inútil; se omite",
                    );
                }
            }
        }
        "redirect" => conv.review(
            1,
            &text,
            context,
            "[[listener.*.rules]].redirect cubre redirecciones; el conversor no traslada la plantilla de HAProxy",
        ),
        "return" => conv.review(
            1,
            &text,
            context,
            "[[listener.*.rules]].direct_response cubre respuestas locales; transcríbalo a mano",
        ),
        "replace-path" | "replace-uri" | "replace-header" | "del-header" | "set-uri" => conv.review(
            1,
            &text,
            context,
            "reescritura de cabecera/URI: EQProxy tiene rewrite.path_prefix_rewrite y del_headers; transcríbalo a mano",
        ),
        other => conv.gap(
            1,
            &text,
            context,
            format!("acción «http-request {other}» sin equivalente conocido"),
        ),
    }
}

/// Parses a HAProxy inline ACL (`{ path_beg /api }`) into a rule.
///
/// Only the conditions `[[listener.*.rules]]` evaluates are accepted; anything
/// else returns `None` so the caller classifies the directive instead of
/// emitting a rule that would mean something else.
fn condition_rule(args: &[String], backend: &str) -> Option<Rule> {
    let mut rule = Rule {
        use_backend: if backend.is_empty() {
            None
        } else {
            Some(backend.to_owned())
        },
        ..Rule::default()
    };
    let mut tokens: Vec<&str> = Vec::new();
    let mut negate = false;
    for arg in args {
        match arg.as_str() {
            "{" | "}" => {}
            token if token.starts_with('!') => negate = true,
            token => tokens.push(token),
        }
    }
    if negate {
        return None;
    }
    let mut index = 0;
    let mut seen = 0usize;
    while index < tokens.len() {
        let name = tokens[index].to_ascii_lowercase();
        let value = tokens.get(index + 1)?.to_string();
        match name.as_str() {
            "path_beg" => rule.path_prefix = Some(value),
            "path" => rule.path = Some(value),
            "path_end" | "path_reg" | "path_sub" => return None,
            "hdr" | "hdr_dom" => rule.host = Some(value),
            "src" => {
                rule.ip = vec![if value.contains('/') {
                    value
                } else if value.contains(':') {
                    format!("{value}/128")
                } else {
                    format!("{value}/32")
                }]
            }
            "method" => rule.methods = vec![value],
            "host" => rule.host = Some(value),
            "url_beg" => rule.path_prefix = Some(value),
            _ => return None,
        }
        seen += 1;
        index += 2;
    }
    if seen == 0 { None } else { Some(rule) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_split_on_quotes_and_drop_comments() {
        assert_eq!(
            split_args("server web1 10.0.0.1:80 check weight 5"),
            vec!["server", "web1", "10.0.0.1:80", "check", "weight", "5"]
        );
        assert_eq!(
            split_args("bind :443 ssl crt \"/etc/certs/a b.pem\""),
            vec!["bind", ":443", "ssl", "crt", "/etc/certs/a b.pem"]
        );
        assert_eq!(strip_comment("bind :80 # comentario"), "bind :80 ");
        assert_eq!(
            strip_comment("add_header X \"#no\" # sí"),
            "add_header X \"#no\" "
        );
    }

    #[test]
    fn server_parameters_accept_both_spellings() {
        let mut params = BTreeMap::new();
        server_params(
            &[
                "check".to_owned(),
                "inter".to_owned(),
                "2s".to_owned(),
                "weight=100".to_owned(),
            ],
            &mut params,
        );
        assert_eq!(params.get("check").map(String::as_str), Some("yes"));
        assert_eq!(params.get("inter").map(String::as_str), Some("2s"));
        assert_eq!(params.get("weight").map(String::as_str), Some("100"));
    }

    #[test]
    fn sections_keep_their_lines_and_kind() {
        let parsed = sections(
            "global\n    maxconn 10\n\ndefaults\n    mode http\n\nfrontend fe\n    bind :80\n",
        );
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[1].kind, Kind::Defaults);
        assert_eq!(parsed[2].name, "fe");
        assert_eq!(
            parsed[2].lines[0],
            vec!["bind".to_owned(), ":80".to_owned()]
        );
    }

    #[test]
    fn inline_acls_map_only_what_the_schema_can_evaluate() {
        let rule = condition_rule(
            &[
                "{".to_owned(),
                "path_beg".to_owned(),
                "/api".to_owned(),
                "}".to_owned(),
            ],
            "svc",
        )
        .expect("path_beg");
        assert_eq!(rule.path_prefix.as_deref(), Some("/api"));
        assert_eq!(rule.use_backend.as_deref(), Some("svc"));
        assert!(
            condition_rule(
                &[
                    "{".to_owned(),
                    "path_reg".to_owned(),
                    "^/a.*".to_owned(),
                    "}".to_owned()
                ],
                "svc"
            )
            .is_none(),
            "an unmappable condition must not become a rule"
        );
        assert!(
            condition_rule(
                &[
                    "{".to_owned(),
                    "!".to_owned(),
                    "path_beg".to_owned(),
                    "/x".to_owned(),
                    "}".to_owned()
                ],
                "svc"
            )
            .is_none(),
            "negation has no equivalent"
        );
    }
    #[test]
    fn server_maxconn_becomes_a_per_server_cap() {
        // B-H16: `server … maxconn N` has a real field now; it must be
        // translated, not reported as a gap, and the emitted TOML must carry
        // the number (the list form, since the inline single-server form
        // cannot express it).
        let source = "defaults\n    mode http\n\nfrontend fe\n    bind :80\n    default_backend bk\n\nbackend bk\n    server s1 10.0.0.1:8080 maxconn 50\n";
        let outcome =
            super::super::convert(super::super::Source::Haproxy, source).expect("convert");
        assert!(
            outcome.toml.contains("maxconn = 50"),
            "the cap must reach the generated file:\n{}",
            outcome.toml
        );
        assert!(
            !outcome.report.contains("maxconn por servidor sin soporte"),
            "the old gap note must be gone:\n{}",
            outcome.report
        );
        assert_eq!(
            outcome.counts.rejected, 0,
            "a convertible cap is not a rejection:\n{}",
            outcome.report
        );
    }

    #[test]
    fn non_numeric_server_maxconn_is_reviewed_not_silently_dropped() {
        let source = "defaults\n    mode http\n\nfrontend fe\n    bind :80\n    default_backend bk\n\nbackend bk\n    server s1 10.0.0.1:8080 maxconn many\n";
        let outcome =
            super::super::convert(super::super::Source::Haproxy, source).expect("convert");
        assert!(
            outcome.report.contains("maxconn no numérico"),
            "the bad value must be named:\n{}",
            outcome.report
        );
        assert!(
            !outcome.toml.contains("maxconn ="),
            "an unparseable cap must not be invented:\n{}",
            outcome.toml
        );
    }
}
