//! nginx → EQProxy.
//!
//! Parses the `directive args;` / `block { … }` grammar (comments, quoting and
//! nesting included) and maps what the v1 schema can express today: listeners,
//! upstreams, TLS (including mTLS and SNI-less certificates), timeouts,
//! `client_max_body_size`, gzip, path-based routing with
//! `[[listener.*.rules]]` (nginx `location`), request/response header edits,
//! `deny` and redirects. Everything else is classified, never dropped.

use std::collections::BTreeMap;

use super::{
    Conv, HeaderOp, ImportError, Listener, ListenerTls, Rule, convert_duration, normalize_addr,
    parse_size, sanitize_name,
};

/// Global directives that do not affect `eqproxy.toml`.
const GLOBAL_INFO: &[&str] = &[
    "worker_processes",
    "worker_rlimit_nofile",
    "worker_shutdown_timeout",
    "pid",
    "user",
    "load_module",
    "working_directory",
    "thread_pool",
    "timer_resolution",
    "env",
];

/// Directives EQProxy **does** support in a field the converter does not fill
/// automatically: the operator gets the exact place to configure it.
fn supported_manually(name: &str) -> Option<&'static str> {
    Some(match name {
        "limit_req" | "limit_req_zone" => "[[listener.*.rules.rate_limit]] (rate/per/burst)",
        "limit_conn" | "limit_conn_zone" => "listener.maxconn (límite global, no por cliente)",
        "access_log" | "log_format" => "[access_log] (format = \"json\" | \"combined\")",
        "error_log" => "logs del proceso (fuera de eqproxy.toml)",
        "resolver" => "[backend.*].resolve_interval (re-resolución en caliente)",
        "proxy_cache" | "proxy_cache_path" | "proxy_cache_valid" | "proxy_cache_bypass" => {
            "[listener.*.cache] (default_ttl, max_memory_bytes, disk_path)"
        }
        "map" | "geo" | "split_clients" => "[maps.*] + [[listener.*.rules]].map",
        "limit_rate" | "limit_rate_after" => "no implementado (limitado a la CLI)",
        "auth_request" => "[[listener.*.rules.auth]].url (subpetición de autenticación)",
        "satisfy" => "combinación de auth.url + auth.users",
        "proxy_next_upstream" | "proxy_next_upstream_tries" => "[backend.*].retries",
        "proxy_intercept_errors" | "error_page" => {
            "respuestas locales [[listener.*.rules]].direct_response"
        }
        "real_ip_header" | "real_ip_recursive" | "set_real_ip_from" => {
            "[listener.*].proxy_receive + proxy_allow (PROXY v1 desde orígenes de confianza)"
        }
        "http2" => "[listener.*.tls].alpn (\"h2\")",
        "http3" | "quic" => "[listener.*].quic = true (HTTP/3 sobre QUIC)",
        "ssl_stapling" | "ssl_stapling_verify" => "OCSP stapling: fuera por decisión (ADR-0035)",
        "ssl_session_cache" | "ssl_session_timeout" | "ssl_session_tickets" => {
            "gestión de sesiones TLS: sin mando (la fija el proveedor criptográfico)"
        }
        "ssl_ciphers" | "ssl_prefer_server_ciphers" => {
            "selección de cipher suites: fuera por decisión (ADR-0035)"
        }
        "http3_hq" | "quic_retry" | "quic_gso" => "[listener.*].quic",
        _ => return None,
    })
}

/// Directives with no equivalent in EQProxy today.
fn unsupported(name: &str) -> Option<&'static str> {
    Some(match name {
        "root" | "alias" | "index" | "autoindex" | "try_files" | "types" | "default_type"
        | "charset" | "etag" | "expires" | "open_file_cache" => {
            "EQProxy no sirve ficheros estáticos: hace falta un backend de origen"
        }
        "rewrite" => {
            "reescritura de URI arbitraria: solo [[listener.*.rules]].rewrite.path_prefix_rewrite"
        }
        "if" => "condicionales: [[listener.*.rules]] cubre host/path/method/header/ip/cookie",
        "set" => "variables: sin motor de expresiones",
        "fastcgi_pass" | "uwsgi_pass" | "scgi_pass" | "memcached_pass" => {
            "protocolo sin soporte: EQProxy proxifica HTTP y TCP/gRPC"
        }
        "proxy_method" => "método fijo al backend: sin soporte",
        "proxy_http_version" => {
            "la versión al backend la decide el ALPN de [backend.*.tls] (h2 o HTTP/1.1)"
        }
        "proxy_buffering"
        | "proxy_buffers"
        | "client_body_buffer_size"
        | "large_client_header_buffers" => {
            "buffers: [listener.*.limits] (max_head_bytes, stream_buffer_bytes)"
        }
        "sendfile" | "tcp_nopush" | "tcp_nodelay" => "rendimiento interno, sin mando expuesto",
        "server_tokens" => "cosmético: EQProxy no añade cabecera Server propia",
        "apk_cache" | "spdy" => "obsoleto en nginx y sin equivalente",
        "allow" => "orden allow/deny: use [[listener.*.rules]] con ip + direct_response",
        "underscores_in_headers" | "ignore_invalid_headers" => {
            "framing estricto: EQProxy no relaja las cabeceras"
        }
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Word(String),
    Semi,
    Open,
    Close,
}

#[derive(Debug)]
struct Node {
    name: String,
    args: Vec<String>,
    children: Vec<Node>,
}

fn tokenize(text: &str) -> Result<Vec<Tok>, ImportError> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            c if c.is_whitespace() => i += 1,
            '#' => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            ';' => {
                tokens.push(Tok::Semi);
                i += 1;
            }
            '{' => {
                tokens.push(Tok::Open);
                i += 1;
            }
            '}' => {
                tokens.push(Tok::Close);
                i += 1;
            }
            quote @ ('"' | '\'') => {
                let start = i;
                i += 1;
                let mut word = String::new();
                loop {
                    if i >= chars.len() {
                        return Err(ImportError::new(format!(
                            "cadena sin cerrar (posición {start}): falta la comilla {quote}"
                        )));
                    }
                    let c = chars[i];
                    if c == '\\' && i + 1 < chars.len() {
                        // nginx keeps the escaped byte as written.
                        word.push(chars[i + 1]);
                        i += 2;
                        continue;
                    }
                    if c == quote {
                        i += 1;
                        break;
                    }
                    word.push(c);
                    i += 1;
                }
                tokens.push(Tok::Word(word));
            }
            _ => {
                let mut word = String::new();
                while i < chars.len() {
                    let c = chars[i];
                    if c.is_whitespace() || matches!(c, ';' | '{' | '}' | '#' | '"' | '\'') {
                        break;
                    }
                    word.push(c);
                    i += 1;
                }
                tokens.push(Tok::Word(word));
            }
        }
    }
    Ok(tokens)
}

fn parse(tokens: &[Tok]) -> Result<Vec<Node>, ImportError> {
    let mut pos = 0;
    let nodes = parse_block(tokens, &mut pos, false)?;
    if pos != tokens.len() {
        return Err(ImportError::new(
            "sintaxis nginx: tokens sobrantes tras el último bloque".to_owned(),
        ));
    }
    Ok(nodes)
}

fn parse_block(tokens: &[Tok], pos: &mut usize, nested: bool) -> Result<Vec<Node>, ImportError> {
    let mut nodes = Vec::new();
    loop {
        match tokens.get(*pos) {
            None => {
                if nested {
                    return Err(ImportError::new(
                        "sintaxis nginx: bloque sin cerrar (falta «}»)".to_owned(),
                    ));
                }
                return Ok(nodes);
            }
            Some(Tok::Close) => {
                if nested {
                    *pos += 1;
                    return Ok(nodes);
                }
                return Err(ImportError::new(
                    "sintaxis nginx: «}» sin bloque abierto".to_owned(),
                ));
            }
            Some(Tok::Semi) => {
                return Err(ImportError::new(
                    "sintaxis nginx: «;» sin directiva delante".to_owned(),
                ));
            }
            Some(Tok::Open) => {
                return Err(ImportError::new(
                    "sintaxis nginx: «{» sin nombre de bloque delante".to_owned(),
                ));
            }
            Some(Tok::Word(name)) => {
                let name = name.clone();
                *pos += 1;
                let mut args = Vec::new();
                loop {
                    match tokens.get(*pos) {
                        Some(Tok::Word(arg)) => {
                            args.push(arg.clone());
                            *pos += 1;
                        }
                        Some(Tok::Semi) => {
                            *pos += 1;
                            nodes.push(Node {
                                name,
                                args,
                                children: Vec::new(),
                            });
                            break;
                        }
                        Some(Tok::Open) => {
                            *pos += 1;
                            let children = parse_block(tokens, pos, true)?;
                            nodes.push(Node {
                                name,
                                args,
                                children,
                            });
                            break;
                        }
                        Some(Tok::Close) => {
                            return Err(ImportError::new(format!(
                                "sintaxis nginx: la directiva «{name}» no termina en «;» antes de «}}»"
                            )));
                        }
                        None => {
                            return Err(ImportError::new(format!(
                                "sintaxis nginx: la directiva «{name}» no termina en «;» ni en «{{»"
                            )));
                        }
                    }
                }
            }
        }
    }
}

fn children<'a>(node: &'a Node, name: &str) -> Vec<&'a Node> {
    node.children.iter().filter(|c| c.name == name).collect()
}

fn first<'a>(node: &'a Node, name: &str) -> Option<&'a Node> {
    node.children.iter().find(|c| c.name == name)
}

fn directive(node: &Node) -> String {
    if node.args.is_empty() {
        node.name.clone()
    } else {
        format!("{} {}", node.name, node.args.join(" "))
    }
}

// ---------------------------------------------------------------------------
// Conversion
// ---------------------------------------------------------------------------

/// Defaults inherited by every listener generated from the `http` block.
#[derive(Default)]
struct HttpDefaults {
    gzip: bool,
    gzip_level: Option<u32>,
    gzip_min_size: Option<u64>,
    max_body_bytes: Option<u64>,
    idle_timeout: Option<String>,
    connect_timeout: Option<String>,
    server_header_timeout: Option<String>,
    client_header_timeout: Option<String>,
    cache: bool,
}

pub(super) fn convert(conv: &mut Conv, text: &str) -> Result<(), ImportError> {
    let nodes = parse(&tokenize(text)?)?;
    for node in &nodes {
        let before = conv.notes.len();
        match node.name.as_str() {
            "http" => http(conv, node)?,
            "stream" => stream(conv, node)?,
            "events" | "mail" => conv.info(
                1,
                node.name.clone(),
                "global",
                "bloque de infraestructura sin traducción (no afecta a eqproxy.toml)",
            ),
            name if GLOBAL_INFO.contains(&name) => conv.info(
                1,
                directive(node),
                "global",
                "directiva global sin traducción (no afecta a eqproxy.toml)",
            ),
            name => conv.gap(
                1,
                directive(node),
                "global",
                format!("directiva global «{name}» sin equivalente conocido: revísela a mano"),
            ),
        }
        conv.touch(&directive(node), "global", before)?;
    }
    Ok(())
}

fn http(conv: &mut Conv, http: &Node) -> Result<(), ImportError> {
    let mut defaults = HttpDefaults::default();

    for up in children(http, "upstream") {
        upstream(conv, up)?;
    }

    for child in &http.children {
        if matches!(child.name.as_str(), "upstream" | "server") {
            continue;
        }
        let before = conv.notes.len();
        http_directive(conv, child, &mut defaults);
        conv.touch(&directive(child), "http", before)?;
    }

    // Group server blocks by listen address: EQProxy has one listener per
    // address, so a second vhost on the same address is a conflict to report.
    let mut by_addr: BTreeMap<String, Vec<&Node>> = BTreeMap::new();
    for block in children(http, "server") {
        let listens = children(block, "listen");
        if listens.is_empty() {
            by_addr
                .entry("0.0.0.0:80".to_owned())
                .or_default()
                .push(block);
            continue;
        }
        for listen in listens {
            let raw = listen
                .args
                .first()
                .cloned()
                .unwrap_or_else(|| "0.0.0.0:80".to_owned());
            by_addr.entry(raw).or_default().push(block);
        }
    }

    for (raw_listen, servers) in by_addr {
        // The vhost that gets translated is the `default_server` one when it
        // exists, else the first: the identity is its position, so the rest
        // can be named without comparing pointers.
        let mut chosen_idx = 0usize;
        if servers.len() > 1 {
            if let Some(idx) = servers.iter().position(|node| {
                children(node, "listen")
                    .iter()
                    .any(|l| l.args.iter().any(|a| a == "default_server"))
            }) {
                chosen_idx = idx;
            }
            let chosen = servers[chosen_idx];
            let names: Vec<String> = servers
                .iter()
                .enumerate()
                .filter(|(idx, _)| *idx != chosen_idx)
                .map(|(_, node)| server_label(node))
                .collect();
            conv.gap(
                1,
                "server (varios en la misma dirección)",
                &format!("listen {raw_listen}"),
                format!(
                    "varios vhosts comparten «{raw_listen}»: se traduce «{}» y quedan sin migrar {}. \
                     EQProxy enruta por host con [[listener.*.rules]].host, pero cada vhost puede traer \
                     su propio certificado y un listener sirve un solo [listener.*.tls]",
                    server_label(chosen),
                    names
                        .iter()
                        .map(|n| format!("«{n}»"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
        }
        server(conv, servers[chosen_idx], &raw_listen, &defaults)?;
    }
    Ok(())
}

fn server_label(node: &Node) -> String {
    first(node, "server_name")
        .and_then(|n| n.args.first().cloned())
        .unwrap_or_else(|| "(sin server_name)".to_owned())
}

fn http_directive(conv: &mut Conv, node: &Node, defaults: &mut HttpDefaults) {
    let name = node.name.as_str();
    let arg = node.args.first().map(String::as_str).unwrap_or_default();
    let text = directive(node);
    match name {
        "gzip" => {
            defaults.gzip = arg == "on";
            conv.done(
                1,
                &text,
                "http",
                format!(
                    "[listener.*.compression].gzip = {} en cada listener generado",
                    defaults.gzip
                ),
            );
        }
        "gzip_comp_level" => {
            if let Ok(level) = arg.parse::<u32>() {
                defaults.gzip_level = Some(level.clamp(1, 9));
                conv.done(1, &text, "http", "compression.level (1..9)");
            } else {
                conv.review(1, &text, "http", "nivel de gzip no numérico: se usa el de EQProxy (6)");
            }
        }
        "gzip_min_length" => match parse_size(arg) {
            Some(size) => {
                defaults.gzip_min_size = Some(size);
                conv.done(1, &text, "http", "compression.min_size");
            }
            None => conv.review(1, &text, "http", "tamaño mínimo de gzip no reconocido: se usa 1024"),
        },
        "gzip_types" | "gzip_vary" | "gzip_proxied" | "gzip_static" => conv.review(
            1,
            &text,
            "http",
            "tipos de gzip: EQProxy comprime text/*, application/json y xml por defecto (compression.types)",
        ),
        "client_max_body_size" => match parse_size(arg) {
            Some(size) => {
                defaults.max_body_bytes = Some(size);
                conv.done(
                    1,
                    &text,
                    "http",
                    "listener.limits.max_body_bytes (413 antes de abrir el backend si el cliente lo declara)",
                );
            }
            None => conv.review(1, &text, "http", "tamaño de cuerpo no reconocido: se deja ilimitado"),
        },
        "keepalive_timeout" => {
            if let Some(value) = convert_duration(conv, arg, "s", &text, "http") {
                defaults.idle_timeout = Some(value);
                conv.review(
                    1,
                    &text,
                    "http",
                    "listener.idle_timeout (aproximado: en EQProxy la inactividad es bidireccional)",
                );
            }
        }
        "client_header_timeout" => {
            if let Some(value) = convert_duration(conv, arg, "s", &text, "http") {
                defaults.client_header_timeout = Some(value);
                conv.done(1, &text, "http", "listener.client_header_timeout");
            }
        }
        "proxy_connect_timeout" => {
            if let Some(value) = convert_duration(conv, arg, "s", &text, "http") {
                defaults.connect_timeout = Some(value);
                conv.done(1, &text, "http", "listener.connect_timeout");
            }
        }
        "proxy_read_timeout" | "send_timeout" => {
            if let Some(value) = convert_duration(conv, arg, "s", &text, "http") {
                defaults.server_header_timeout = Some(value);
                conv.review(
                    1,
                    &text,
                    "http",
                    "listener.server_header_timeout (aproximado: EQProxy solo acota la cabecera de respuesta)",
                );
            }
        }
        "proxy_send_timeout" => conv.review(
            1,
            &text,
            "http",
            "sin equivalente: en EQProxy idle_timeout es el único plazo de inactividad",
        ),
        "proxy_cache_path" => conv.review(
            1,
            &text,
            "http",
            "[listener.*.cache].disk_path (la persistencia existe; la zona de nginx no se traduce)",
        ),
        "proxy_temp_path" | "client_body_temp_path" => conv.info(
            1,
            &text,
            "http",
            "rutas temporales de nginx: EQProxy no escribe cuerpos en disco",
        ),
        "server_names_hash_bucket_size" | "server_names_hash_max_size" | "variables_hash_max_size"
        | "types_hash_max_size" | "map_hash_bucket_size" | "map_hash_max_size" => conv.info(
            1,
            &text,
            "http",
            "ajuste de tablas hash de nginx: sin efecto en EQProxy",
        ),
        "include" => conv.review(
            1,
            &text,
            "http",
            format!("include no se expande: revise «{arg}» a mano y vuelva a convertir"),
        ),
        "default_type" | "types" | "charset" | "charset_types" | "source_charset" => {
            conv.info(1, &text, "http", "cosmético de nginx (tipos MIME): EQProxy solo proxifica")
        }
        "log_format" => conv.review(
            1,
            &text,
            "http",
            "[access_log] con format = \"json\" (campos estables) o \"combined\" (forma nginx)",
        ),
        "access_log" => conv.review(
            1,
            &text,
            "http",
            "[access_log].path (una línea por petición; la ruta y el formato se eligen en el TOML)",
        ),
        "error_log" => conv.info(
            1,
            &text,
            "http",
            "log de errores del proceso: el dataplane escribe a stderr",
        ),
        "sendfile" | "tcp_nopush" | "tcp_nodelay" | "aio" | "directio" => conv.info(
            1,
            &text,
            "http",
            "rendimiento interno de nginx sin mando expuesto",
        ),
        "limit_req_zone" => conv.review(
            1,
            &text,
            "http",
            "[[listener.*.rules.rate_limit]] por IP de cliente (rate/per/burst), no una zona compartida",
        ),
        "map" | "geo" => conv.review(
            1,
            &text,
            "http",
            "[maps.*] cubre mapas clave→valor; el conversor no traduce sus entradas",
        ),
        "split_clients" => conv.review(
            1,
            &text,
            "http",
            "[[listener.*.rules]].split (reparto ponderado entre backends)",
        ),
        "ssl_protocols" => conv.review(
            1,
            &text,
            "http",
            "nivel http: el mínimo TLS se emite por listener desde su propio ssl_protocols",
        ),
        "ssl_certificate" | "ssl_certificate_key" => conv.review(
            1,
            &text,
            "http",
            "nivel http: el certificado se emite por listener desde el bloque server",
        ),
        "proxy_set_header" => conv.review(
            1,
            &text,
            "http",
            "nivel http: se traduce donde aparece (location/server); aquí se resume",
        ),
        "proxy_http_version" => conv.gap(
            1,
            &text,
            "http",
            "versión al backend: la decide el ALPN de [backend.*.tls] (h2 o HTTP/1.1)",
        ),
        "proxy_buffering" | "proxy_buffers" | "proxy_busy_buffers_size" | "proxy_max_temp_file_size" => {
            conv.gap(
                1,
                &text,
                "http",
                "buffers: [listener.*.limits] (max_head_bytes, stream_buffer_bytes)",
            );
        }
        "client_body_buffer_size" | "large_client_header_buffers" | "client_header_buffer_size" => {
            conv.gap(
                1,
                &text,
                "http",
                "buffers: [listener.*.limits].max_head_bytes (16 KiB por defecto)",
            );
        }
        "resolver" => conv.review(
            1,
            &text,
            "http",
            "[backend.*].resolve_interval (re-resolución en caliente sin bloqueo)",
        ),
        "resolver_timeout" => conv.info(1, &text, "http", "timeout del resolver: sin mando en EQProxy"),
        "reset_timedout_connection" | "lingering_close" | "lingering_time" | "lingering_timeout" => {
            conv.info(1, &text, "http", "cierre de conexiones: lo gestiona el dataplane")
        }
        name => match supported_manually(name) {
            Some(place) => conv.review(
                1,
                &text,
                "http",
                format!("EQProxy sí lo soporta en {place}: transcríbalo a mano"),
            ),
            None => match unsupported(name) {
                Some(reason) => conv.gap(1, &text, "http", reason),
                None => conv.review(
                    1,
                    &text,
                    "http",
                    "directiva http sin traducción automática: revísela a mano",
                ),
            },
        },
    }
}

/// `upstream { … }` → `[backend.*]`.
fn upstream(conv: &mut Conv, up: &Node) -> Result<(), ImportError> {
    let source_name = up
        .args
        .first()
        .cloned()
        .unwrap_or_else(|| "upstream".to_owned());
    let context = format!("upstream {source_name}");
    let name = conv.free_backend_name(&source_name);
    let mut backend = super::Backend::default();
    let mut balance: Option<String> = None;

    for child in &up.children {
        let before = conv.notes.len();
        let text = directive(child);
        match child.name.as_str() {
            "server" => {
                let Some(raw) = child.args.first() else {
                    conv.review(1, &text, &context, "línea server sin dirección: se omite");
                    continue;
                };
                let mut weight = 1;
                let mut backup = false;
                let mut maxconn = 0;
                for arg in child.args.iter().skip(1) {
                    if let Some(value) = arg.strip_prefix("weight=") {
                        match value.parse::<u32>() {
                            Ok(parsed) if parsed > 256 => {
                                weight = 256;
                                conv.review(
                                    1,
                                    arg.clone(),
                                    &context,
                                    "weight > 256 (máximo de EQProxy): recortado a 256",
                                );
                            }
                            Ok(parsed) => weight = parsed,
                            Err(_) => conv.review(
                                1,
                                arg.clone(),
                                &context,
                                "weight no numérico: se usa 1",
                            ),
                        }
                    } else if arg == "down" {
                        weight = 0;
                        conv.review(
                            1,
                            arg.clone(),
                            &context,
                            "«down» ≈ weight = 0 (drenado: nunca seleccionado, sí chequeado)",
                        );
                    } else if arg == "backup" {
                        backup = true;
                        conv.done(
                            1,
                            arg.clone(),
                            &context,
                            "backup = true (B8: solo se usa cuando ningún primario es elegible)",
                        );
                    } else if arg.starts_with("max_fails=") || arg.starts_with("fail_timeout=") {
                        conv.review(
                            1,
                            arg.clone(),
                            &context,
                            "chequeo pasivo de nginx: EQProxy tiene check TCP activo y detección pasiva (health_check.passive)",
                        );
                    } else if let Some(value) = arg.strip_prefix("max_conns=") {
                        // nginx `max_conns=N` (B-H16): the same per-server cap
                        // as HAProxy `server … maxconn`. `0` means unlimited in
                        // nginx, which is also the schema default.
                        match value.parse::<u32>() {
                            Ok(parsed) if parsed > crate::schema::MAX_SERVER_MAXCONN => {
                                maxconn = crate::schema::MAX_SERVER_MAXCONN;
                                conv.review(
                                    1,
                                    arg.clone(),
                                    &context,
                                    format!(
                                        "max_conns > {} (máximo de EQProxy): recortado a {}",
                                        crate::schema::MAX_SERVER_MAXCONN,
                                        crate::schema::MAX_SERVER_MAXCONN
                                    ),
                                );
                            }
                            Ok(parsed) => {
                                maxconn = parsed;
                                conv.done(
                                    1,
                                    arg.clone(),
                                    &context,
                                    format!(
                                        "maxconn = {parsed} (tope de conexiones de este servidor)"
                                    ),
                                );
                            }
                            Err(_) => conv.review(
                                1,
                                arg.clone(),
                                &context,
                                "max_conns no numérico: se omite el tope por servidor",
                            ),
                        }
                    } else if arg.starts_with("slow_start=") {
                        conv.review(
                            1,
                            arg.clone(),
                            &context,
                            "[backend.*].slow_start (ventana entera, no por servidor)",
                        );
                    } else if arg == "resolve"
                        || arg.starts_with("route=")
                        || arg.starts_with("id=")
                    {
                        conv.info(
                            1,
                            arg.clone(),
                            &context,
                            "metadato del servidor sin equivalente: se ignora",
                        );
                    } else {
                        conv.gap(
                            1,
                            arg.clone(),
                            &context,
                            "parámetro de servidor sin equivalente conocido: revíselo a mano",
                        );
                    }
                }
                if let Some(addr) = normalize_addr(conv, raw, Some(80), &text, &context) {
                    let rendered = addr.clone();
                    backend.servers.push(super::Server {
                        addr,
                        weight,
                        backup,
                        maxconn,
                    });
                    conv.done(
                        1,
                        &text,
                        &context,
                        format!("servidor {rendered} (peso {weight}) en el upstream"),
                    );
                }
            }
            "least_conn" => {
                balance = Some("leastconn".to_owned());
                conv.done(
                    1,
                    &text,
                    &context,
                    "balance = \"leastconn\" (least-connections ponderado)",
                );
            }
            "ip_hash" => {
                backend.affinity = Some(super::Affinity {
                    mode: "source".to_owned(),
                    cookie: None,
                });
                conv.done(
                    1,
                    &text,
                    &context,
                    "[backend.*.affinity] mode = \"source\" (hash de IP del cliente)",
                );
            }
            "keepalive" => conv.review(
                1,
                &text,
                &context,
                "pool de EQProxy: 64 conexiones idle por servidor, expiración 60 s",
            ),
            "random" | "hash" => {
                if balance.is_none() {
                    balance = Some("roundrobin".to_owned());
                }
                conv.gap(
                    1,
                    &text,
                    &context,
                    "algoritmo de balance sin soporte: EQProxy emite roundrobin ponderado",
                );
            }
            "zone" | "queue" | "ntlm" | "sticky" | "state" => conv.gap(
                1,
                &text,
                &context,
                "directiva de upstream sin equivalente en EQProxy",
            ),
            other => conv.gap(
                1,
                &text,
                &context,
                format!(
                    "directiva de upstream «{other}» sin equivalente conocido: revísela a mano"
                ),
            ),
        }
        conv.touch(&directive(child), &context, before)?;
    }

    if backend.servers.is_empty() {
        conv.reject(
            1,
            format!("upstream {source_name}"),
            &context,
            "upstream sin servidores traducibles: se omite (y los listeners que lo usen fallarán)",
        );
        return Ok(());
    }
    if let Some(balance) = balance {
        backend.balance = balance;
    }
    if name != source_name {
        conv.review(
            1,
            format!("upstream {source_name}"),
            &context,
            format!("renombrado a «{name}» (el nombre original no es válido o ya estaba usado)"),
        );
    }
    conv.add_backend(name, backend);
    Ok(())
}

/// One `server { … }` block on one address.
fn server(
    conv: &mut Conv,
    node: &Node,
    raw_listen: &str,
    defaults: &HttpDefaults,
) -> Result<(), ImportError> {
    let label = server_label(node);
    let context = format!("server {label}");

    let listen_args = children(node, "listen")
        .into_iter()
        .find(|l| l.args.first().map(String::as_str) == Some(raw_listen))
        .map(|l| l.args.clone())
        .unwrap_or_else(|| vec![raw_listen.to_owned()]);
    let flags: Vec<String> = listen_args.iter().skip(1).cloned().collect();
    let has = |needle: &str| flags.iter().any(|flag| flag == needle);
    let ssl = has("ssl");
    let http2 = flags
        .iter()
        .any(|flag| flag == "http2" || flag.starts_with("http2"))
        || first(node, "http2")
            .map(|n| n.args.first().map(String::as_str) == Some("on"))
            .unwrap_or(false);
    let http3 = flags
        .iter()
        .any(|flag| flag == "quic" || flag.starts_with("http3") || flag.starts_with("quic"));
    let proxy_protocol = has("proxy_protocol");
    conv.done(
        1,
        format!("listen {raw_listen}"),
        &context,
        format!(
            "listener de EQProxy en {raw_listen}{}{}",
            if ssl { " con TLS" } else { "" },
            if http2 { " y ALPN h2" } else { "" }
        ),
    );

    let Some(addr) = normalize_addr(
        conv,
        raw_listen,
        Some(if ssl { 443 } else { 80 }),
        &format!("listen {raw_listen}"),
        &context,
    ) else {
        conv.reject(
            1,
            format!("listen {raw_listen}"),
            &context,
            "listener omitido: la dirección no es IP:PORT ni HOSTNAME:PORT",
        );
        return Ok(());
    };

    if proxy_protocol {
        conv.review(
            1,
            "proxy_protocol",
            &context,
            "PROXY protocol de entrada: EQProxy lo soporta con [listener.*].proxy_receive + proxy_allow \
             (allowlist obligatoria), pero no se activa a ciegas sin conocer los orígenes de confianza",
        );
    }

    // TLS termination.
    let mut tls: Option<ListenerTls> = None;
    let cert = first(node, "ssl_certificate");
    let key = first(node, "ssl_certificate_key");
    if ssl || cert.is_some() || key.is_some() {
        match (cert.and_then(|n| n.args.first()), key.and_then(|n| n.args.first())) {
            (Some(cert), Some(key)) => {
                tls = Some(ListenerTls {
                    cert: cert.clone(),
                    key: key.clone(),
                    alpn: if http2 || http3 {
                        let mut alpn = Vec::new();
                        if http2 {
                            alpn.push("h2".to_owned());
                        }
                        alpn.push("http/1.1".to_owned());
                        alpn
                    } else {
                        Vec::new()
                    },
                    min_version: None,
                    client_ca: None,
                });
                conv.done(
                    1,
                    "ssl_certificate / ssl_certificate_key",
                    &context,
                    format!("[listener.*.tls] cert = «{cert}», key = «{key}»"),
                );
            }
            _ => conv.reject(
                1,
                "ssl_certificate",
                &context,
                "TLS sin certificado y clave completos: el listener se emite en claro y hay que corregirlo a mano",
            ),
        }
    }
    if let Some(protocols) = first(node, "ssl_protocols") {
        let joined = protocols.args.join(" ");
        if let Some(tls) = tls.as_mut() {
            if joined.contains("TLSv1.3") && !joined.contains("TLSv1.2") {
                tls.min_version = Some("1.3");
            } else if joined.contains("TLSv1.2") {
                tls.min_version = Some("1.2");
            }
        }
        conv.done(
            1,
            directive(protocols),
            &context,
            "[listener.*.tls].min_version (EQProxy nunca acepta TLS 1.0/1.1)",
        );
    }
    if let Some(ca) = first(node, "ssl_client_certificate") {
        let verify = first(node, "ssl_verify_client")
            .and_then(|n| n.args.first())
            .map(String::as_str)
            .unwrap_or("off");
        if verify == "on" || verify == "optional_no_ca" || verify == "optional" {
            if let Some(tls) = tls.as_mut() {
                tls.client_ca = ca.args.first().cloned();
                conv.done(
                    1,
                    directive(ca),
                    &context,
                    "mTLS: [listener.*.tls].client_ca (los certificados de cliente se exigen y verifican)",
                );
            } else {
                conv.review(
                    1,
                    directive(ca),
                    &context,
                    "sin [listener.*.tls] no hay dónde configurar el CA de clientes: se ignora",
                );
            }
        } else {
            conv.info(
                1,
                directive(ca),
                &context,
                "CA de clientes sin ssl_verify_client activo: no hace nada",
            );
        }
    }
    if let Some(verify) = first(node, "ssl_verify_client") {
        conv.info(
            1,
            directive(verify),
            &context,
            "se aplica junto a ssl_client_certificate (mTLS)",
        );
    }

    // Locations: one routing rule each, longest prefix first (nginx semantics).
    struct Planned {
        rule: Rule,
        /// Length of the path prefix, for nginx's longest-match ordering.
        length: usize,
    }
    let mut planned: Vec<Planned> = Vec::new();
    let mut server_headers: Vec<HeaderOp> = Vec::new();
    let mut forwarded = false;
    let mut cache = defaults.cache;

    for child in &node.children {
        let before = conv.notes.len();
        let text = directive(child);
        match child.name.as_str() {
            "listen" | "http2" | "ssl_certificate" | "ssl_certificate_key" | "ssl_protocols"
            | "ssl_client_certificate" | "ssl_verify_client" => conv.info(
                1,
                &text,
                &context,
                "binding y TLS del listener: aplicados arriba en [listener.*.tls]",
            ),
            "server_name" => {
                let names: Vec<&str> = child.args.iter().map(String::as_str).collect();
                if names.len() > 1 {
                    conv.review(
                        1,
                        &text,
                        &context,
                        format!(
                            "varios server_name ({}): EQProxy enruta por host con [[listener.*.rules]].host, \
                             pero el conversor no genera una regla por nombre",
                            names.join(", ")
                        ),
                    );
                } else {
                    conv.info(
                        1,
                        &text,
                        &context,
                        "nombre del vhost: se usa como etiqueta del listener (el enrutado por host \
                         necesita [[listener.*.rules]].host)",
                    );
                }
            }
            "add_header" => {
                let Some(name) = child.args.first() else {
                    conv.review(1, &text, &context, "add_header sin nombre: se ignora");
                    continue;
                };
                let value = child.args.get(1).cloned().unwrap_or_default();
                server_headers.push(HeaderOp {
                    name: name.clone(),
                    value,
                });
                conv.done(
                    1,
                    &text,
                    &context,
                    "[[listener.*.rules]].response_headers (se emite en la regla que cubre el listener)",
                );
            }
            "location" => {
                let (rule, length) = location(conv, child, &context, &mut forwarded)?;
                if let Some(rule) = rule {
                    planned.push(Planned { rule, length });
                }
            }
            "proxy_cache" => {
                cache = true;
                conv.review(
                    1,
                    &text,
                    &context,
                    "[listener.*.cache] con valores por defecto (60 s, 64 MiB, tope 1 MiB): revise TTL y presupuesto",
                );
            }
            "client_header_timeout" | "keepalive_timeout" | "proxy_connect_timeout"
            | "proxy_read_timeout" => conv.info(
                1,
                &text,
                &context,
                "timeout del listener: se aplica al listener generado",
            ),
            "deny" => {
                let cidr = child
                    .args
                    .first()
                    .map(|raw| cidr_of(raw))
                    .unwrap_or_else(|| "0.0.0.0/0".to_owned());
                let mut rule = Rule {
                    name: "deny".to_owned(),
                    direct_response: Some((403, None)),
                    ip: vec![cidr.clone()],
                    ..Rule::default()
                };
                // A deny rule has no backend: it answers 403 locally.
                rule.use_backend = None;
                planned.push(Planned {
                    rule,
                    length: usize::MAX / 2,
                });
                conv.done(
                    1,
                    &text,
                    &context,
                    format!("regla [[listener.*.rules]] ip = [\"{cidr}\"] → 403 local"),
                );
            }
            "allow" => conv.review(
                1,
                &text,
                &context,
                "orden allow/deny de nginx: EQProxy evalúa reglas en orden, pero el conversor no construye \
                 la secuencia completa; transcríbala con ip + direct_response",
            ),
            "return" => conv.review(
                1,
                &text,
                &context,
                "redirección a nivel de server: [[listener.*.rules]].redirect, pero un listener necesita un \
                 backend real; si el bloque solo redirige, créelo a mano",
            ),
            "auth_basic" | "auth_basic_user_file" => conv.review(
                1,
                &text,
                &context,
                "[[listener.*.rules]].auth.users (htpasswd inline): el fichero no se lee, copie las líneas",
            ),
            "gzip" | "gzip_types" | "gzip_min_length" | "gzip_comp_level" => conv.review(
                1,
                &text,
                &context,
                "la compresión se configura por listener: mueva la directiva al bloque http o a [listener.*.compression]",
            ),
            name => match supported_manually(name) {
                Some(place) => conv.review(
                    1,
                    &text,
                    &context,
                    format!("EQProxy sí lo soporta en {place}: transcríbalo a mano"),
                ),
                None => match unsupported(name) {
                    Some(reason) => conv.gap(1, &text, &context, reason),
                    None => conv.review(
                        1,
                        &text,
                        &context,
                        "directiva de server sin traducción automática: revísela a mano",
                    ),
                },
            },
        }
        conv.touch(&directive(child), &context, before)?;
    }

    if planned.is_empty() {
        conv.reject(
            1,
            "location",
            &context,
            "el bloque no tiene ninguna location con proxy_pass ni deny: EQProxy no sirve contenido estático",
        );
        return Ok(());
    }

    // Longest prefix first, denies (huge length) before anything else.
    planned.sort_by_key(|p| std::cmp::Reverse(p.length));

    // The fallback backend is the one covering "/" (or the first rule).
    let fallback = planned
        .iter()
        .find(|p| p.rule.path_prefix.as_deref() == Some("/"))
        .or_else(|| planned.first())
        .and_then(|p| p.rule.use_backend.clone())
        .or_else(|| planned.iter().find_map(|p| p.rule.use_backend.clone()));

    let mut rules: Vec<Rule> = planned.into_iter().map(|p| p.rule).collect();

    if !server_headers.is_empty() {
        let target = rules.iter_mut().find(|rule| rule.use_backend.is_some());
        match target {
            Some(rule) => {
                rule.response_headers.extend(server_headers);
                conv.review(
                    1,
                    "add_header",
                    &context,
                    "las cabeceras se emiten en una regla: las peticiones que no casen con ninguna regla no las llevan",
                );
            }
            None => conv.review(
                1,
                "add_header",
                &context,
                "sin ninguna regla reenviada no hay dónde colgar la cabecera: confígurela a mano",
            ),
        }
    }

    let Some(backend) = fallback else {
        conv.reject(
            1,
            &context,
            &context,
            "ninguna location apunta a un backend traducible: listener omitido",
        );
        return Ok(());
    };

    let name = conv.free_listener_name(&format!("web_{label}"));
    let mut listener = Listener::new(addr, "http", backend);
    listener.maxconn = 1024;
    listener.tls = tls;
    listener.quic = http3 && listener.tls.is_some();
    listener.compression_gzip = defaults.gzip;
    listener.compression_level = defaults.gzip_level;
    listener.compression_min_size = defaults.gzip_min_size;
    listener.max_body_bytes = defaults.max_body_bytes;
    listener.idle_timeout = defaults.idle_timeout.clone();
    listener.connect_timeout = defaults.connect_timeout.clone();
    listener.server_header_timeout = defaults.server_header_timeout.clone();
    listener.client_header_timeout = defaults.client_header_timeout.clone();
    listener.cache = cache;
    if forwarded {
        listener.forwarded_headers = Some("append");
    }
    // Per-server timeouts win over the http-level defaults.
    if let Some(node) = first(node, "client_header_timeout") {
        listener.client_header_timeout = convert_duration(
            conv,
            node.args.first().map(String::as_str).unwrap_or_default(),
            "s",
            &directive(node),
            &context,
        );
    }
    if let Some(node) = first(node, "keepalive_timeout") {
        listener.idle_timeout = convert_duration(
            conv,
            node.args.first().map(String::as_str).unwrap_or_default(),
            "s",
            &directive(node),
            &context,
        );
    }
    listener.rules = rules;
    if http2 {
        conv.info(
            1,
            "http2",
            &context,
            "ALPN h2 en [listener.*.tls] (HTTP/2 nativo)",
        );
    }
    if http3 {
        conv.info(
            1,
            "http3/quic",
            &context,
            "[listener.*].quic = true (HTTP/3 sobre QUIC en el mismo puerto)",
        );
    }
    conv.add_listener(name, listener);
    Ok(())
}

/// One `location { … }`.
fn location(
    conv: &mut Conv,
    node: &Node,
    server_context: &str,
    forwarded: &mut bool,
) -> Result<(Option<Rule>, usize), ImportError> {
    let raw_path = node.args.first().cloned().unwrap_or_else(|| "/".to_owned());
    let context = format!("{server_context} location {raw_path}");
    let (path, exact) = if let Some(rest) = raw_path.strip_prefix('=') {
        (rest.trim().to_owned(), true)
    } else if raw_path.starts_with('~') || raw_path.starts_with("^~") {
        conv.gap(
            1,
            format!("location {raw_path}"),
            &context,
            "location por expresión regular: EQProxy solo tiene path y path_prefix literales \
             ([[listener.*.rules]].path_regex existe, pero el conversor no traslada la expresión)",
        );
        return Ok((None, 0));
    } else {
        (raw_path.clone(), false)
    };

    let mut rule = Rule {
        name: context.clone(),
        ..Rule::default()
    };
    if exact {
        rule.path = Some(path.clone());
    } else {
        rule.path_prefix = Some(path.clone());
    }
    let mut length = path.len();
    let mut has_target = false;

    for child in &node.children {
        let before = conv.notes.len();
        let text = directive(child);
        match child.name.as_str() {
            "proxy_pass" => {
                let Some(target) = child.args.first() else {
                    conv.review(1, &text, &context, "proxy_pass vacío: se ignora");
                    continue;
                };
                if target.contains('$') {
                    conv.review(
                        1,
                        &text,
                        &context,
                        "proxy_pass con variables: sin soporte (EQProxy no evalúa variables)",
                    );
                    continue;
                }
                let without_scheme = target.split_once("//").map(|(_, rest)| rest).unwrap_or(target);
                let (authority, uri) = match without_scheme.split_once('/') {
                    Some((authority, uri)) => (authority.to_owned(), Some(uri.to_owned())),
                    None => (without_scheme.to_owned(), None),
                };
                if let Some(uri) = uri.as_deref() {
                    conv.review(
                        1,
                        text.clone(),
                        &context,
                        format!(
                            "proxy_pass con URI («/{uri}»): use [[listener.*.rules]].rewrite.path_prefix_rewrite"
                        ),
                    );
                }
                let backend_name = resolve_backend(conv, &authority, &context);
                if let Some(backend_name) = backend_name {
                    rule.use_backend = Some(backend_name.clone());
                    has_target = true;
                    conv.done(
                        1,
                        &text,
                        &context,
                        format!("regla con use_backend = «{backend_name}»"),
                    );
                }
            }
            "proxy_set_header" => {
                let (Some(name), Some(value)) = (child.args.first(), child.args.get(1)) else {
                    conv.review(1, &text, &context, "proxy_set_header incompleto: se ignora");
                    continue;
                };
                if value.contains("$proxy_add_x_forwarded_for") {
                    *forwarded = true;
                    conv.review(
                        1,
                        &text,
                        &context,
                        "«$proxy_add_x_forwarded_for» → [listener.*].forwarded_headers = \"append\" \
                         (EQProxy añade la IP de cliente a X-Forwarded-For)",
                    );
                    continue;
                }
                if let Some(bad) = nginx_variable_unsupported(value) {
                    conv.review(
                        1,
                        &text,
                        &context,
                        format!("variable «{bad}» sin soporte en plantillas de cabecera: no se emite"),
                    );
                    continue;
                }
                rule.set_headers.push(HeaderOp {
                    name: name.clone(),
                    value: value.clone(),
                });
                conv.done(
                    1,
                    &text,
                    &context,
                    format!("set_headers += {{ {name}, {value} }}"),
                );
            }
            "proxy_hide_header" | "proxy_pass_header" => conv.review(
                1,
                &text,
                &context,
                "[[listener.*.rules]].del_headers cubre quitar cabeceras de la respuesta; el conversor no la emite",
            ),
            "proxy_connect_timeout" | "proxy_read_timeout" | "proxy_send_timeout"
            | "client_header_timeout" | "keepalive_timeout" => conv.review(
                1,
                &text,
                &context,
                "los timeouts se configuran por listener: la directiva de location se aplica al listener generado",
            ),
            "deny" => {
                let cidr = child
                    .args
                    .first()
                    .map(|raw| cidr_of(raw))
                    .unwrap_or_else(|| "0.0.0.0/0".to_owned());
                conv.review(
                    1,
                    &text,
                    &context,
                    format!(
                        "deny dentro de location: emita una regla ip = [\"{cidr}\"] con direct_response 403 \
                         antes que esta"
                    ),
                );
            }
            "add_header" => {
                if let (Some(name), Some(value)) = (child.args.first(), child.args.get(1)) {
                    rule.response_headers.push(HeaderOp {
                        name: name.clone(),
                        value: value.clone(),
                    });
                    conv.done(
                        1,
                        &text,
                        &context,
                        format!("response_headers += {{ {name}, {value} }}"),
                    );
                } else {
                    conv.review(1, &text, &context, "add_header incompleto: se ignora");
                }
            }
            "limit_req" | "limit_conn" => conv.review(
                1,
                &text,
                &context,
                "[[listener.*.rules]].rate_limit (rate/per/burst) por IP: transcríbalo a mano",
            ),
            "proxy_cache" => conv.review(
                1,
                &text,
                &context,
                "[listener.*.cache] con valores por defecto: revise TTL y presupuesto",
            ),
            name => match supported_manually(name) {
                Some(place) => conv.review(
                    1,
                    &text,
                    &context,
                    format!("EQProxy sí lo soporta en {place}: transcríbalo a mano"),
                ),
                None => match unsupported(name) {
                    Some(reason) => conv.gap(1, &text, &context, reason),
                    None => conv.review(
                        1,
                        &text,
                        &context,
                        "directiva de location sin traducción automática: revísela a mano",
                    ),
                },
            },
        }
        conv.touch(&directive(child), &context, before)?;
    }

    if !has_target {
        return Ok((None, length.max(1)));
    }
    length = length.max(1);
    Ok((Some(rule), length))
}

/// Resolves a `proxy_pass` authority: an upstream name, or a literal address
/// that becomes a single-server backend.
fn resolve_backend(conv: &mut Conv, authority: &str, context: &str) -> Option<String> {
    let cleaned = sanitize_name(authority);
    if conv.has_backend(&cleaned) {
        return Some(cleaned);
    }
    if conv.has_backend(authority) {
        return Some(authority.to_owned());
    }
    let addr = normalize_addr(
        conv,
        authority,
        Some(80),
        &format!("proxy_pass {authority}"),
        context,
    )?;
    let name = conv.free_backend_name(&format!("backend_{}", sanitize_name(authority)));
    let mut backend = super::Backend::default();
    backend.servers.push(super::Server {
        addr: addr.clone(),
        weight: 1,
        backup: false,
        maxconn: 0,
    });
    conv.add_backend(name.clone(), backend);
    conv.done(
        1,
        format!("proxy_pass {authority}"),
        context,
        format!("origen literal convertido en backend «{name}» ({addr})"),
    );
    Some(name)
}

/// `10.9.9.9` → `10.9.9.9/32`, `::1` → `::1/128`; a CIDR is kept.
fn cidr_of(raw: &str) -> String {
    if raw.contains('/') {
        return raw.to_owned();
    }
    if raw.contains(':') {
        format!("{raw}/128")
    } else {
        format!("{raw}/32")
    }
}

/// nginx variables the header templates do not know.
fn nginx_variable_unsupported(value: &str) -> Option<String> {
    let mut rest = value;
    while let Some(index) = rest.find('$') {
        let tail = &rest[index + 1..];
        let name: String = tail
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            return Some("$".to_owned());
        }
        if !matches!(name.as_str(), "remote_addr" | "host" | "scheme") {
            return Some(format!("${name}"));
        }
        rest = &tail[name.len()..];
    }
    None
}

/// `stream { … }` → `mode = "tcp"` listeners.
fn stream(conv: &mut Conv, stream: &Node) -> Result<(), ImportError> {
    conv.info(
        1,
        "stream",
        "stream",
        "el bloque stream (TCP) se traduce a listeners con mode = \"tcp\"",
    );
    for up in children(stream, "upstream") {
        let source_name = up
            .args
            .first()
            .cloned()
            .unwrap_or_else(|| "upstream_tcp".to_owned());
        let context = format!("stream upstream {source_name}");
        let name = conv.free_backend_name(&source_name);
        let mut backend = super::Backend::default();
        for child in &up.children {
            let before = conv.notes.len();
            let text = directive(child);
            if child.name == "server" {
                if let Some(raw) = child.args.first() {
                    if let Some(addr) = normalize_addr(conv, raw, None, &text, &context) {
                        backend.servers.push(super::Server {
                            addr,
                            weight: 1,
                            backup: false,
                            maxconn: 0,
                        });
                        conv.done(1, &text, &context, "servidor TCP del upstream");
                    }
                } else {
                    conv.review(1, &text, &context, "servidor sin dirección: se omite");
                }
            } else {
                conv.gap(
                    1,
                    &text,
                    &context,
                    "directiva de upstream TCP sin equivalente",
                );
            }
            conv.touch(&directive(child), &context, before)?;
        }
        if !backend.servers.is_empty() {
            conv.add_backend(name, backend);
        }
    }

    for srv in children(stream, "server") {
        let context = "stream server".to_owned();
        let Some(listen) = first(srv, "listen") else {
            conv.reject(
                1,
                "server",
                &context,
                "server de stream sin listen: se omite",
            );
            continue;
        };
        let Some(raw) = listen.args.first() else {
            conv.reject(1, "listen", &context, "listen sin dirección: se omite");
            continue;
        };
        let Some(addr) = normalize_addr(conv, raw, None, &directive(listen), &context) else {
            continue;
        };
        let Some(pass) = first(srv, "proxy_pass") else {
            conv.reject(
                1,
                "server",
                &context,
                "server de stream sin proxy_pass: se omite",
            );
            continue;
        };
        let Some(target) = pass.args.first() else {
            conv.reject(1, "proxy_pass", &context, "proxy_pass vacío: se omite");
            continue;
        };
        let backend = match resolve_backend(conv, target, &context) {
            Some(name) => name,
            None => continue,
        };
        let name = conv.free_listener_name(&format!("tcp_{backend}"));
        let mut listener = Listener::new(addr, "tcp", backend.clone());
        for child in &srv.children {
            let before = conv.notes.len();
            let text = directive(child);
            match child.name.as_str() {
                "listen" | "proxy_pass" => {}
                "proxy_timeout" => {
                    listener.idle_timeout = convert_duration(
                        conv,
                        child.args.first().map(String::as_str).unwrap_or_default(),
                        "s",
                        &text,
                        &context,
                    );
                    conv.review(1, &text, &context, "listener.idle_timeout (aprox.)");
                }
                "proxy_connect_timeout" => {
                    listener.connect_timeout = convert_duration(
                        conv,
                        child.args.first().map(String::as_str).unwrap_or_default(),
                        "s",
                        &text,
                        &context,
                    );
                    conv.done(1, &text, &context, "listener.connect_timeout");
                }
                "ssl_preread" => conv.gap(
                    1,
                    &text,
                    &context,
                    "enrutado por SNI (ssl_preread): EQProxy no inspecciona el ClientHello",
                ),
                name => match supported_manually(name) {
                    Some(place) => conv.review(
                        1,
                        &text,
                        &context,
                        format!("EQProxy sí lo soporta en {place}: transcríbalo a mano"),
                    ),
                    None => conv.gap(
                        1,
                        &text,
                        &context,
                        "directiva de stream sin equivalente conocido",
                    ),
                },
            }
            conv.touch(&directive(child), &context, before)?;
        }
        conv.done(
            1,
            format!("listen {raw}"),
            &context,
            format!("listener «{name}» (tcp) → backend «{backend}»"),
        );
        conv.add_listener(name, listener);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_parser_reads_nested_blocks_and_quoted_words() {
        let nodes = parse(
            &tokenize("http {\n  server {\n    listen 80;\n    add_header X \"a;b\" ;\n  }\n}\n")
                .expect("tokenize"),
        )
        .expect("parse");
        assert_eq!(nodes.len(), 1);
        let server = &nodes[0].children[0];
        assert_eq!(server.name, "server");
        assert_eq!(children(server, "listen")[0].args, vec!["80".to_owned()]);
        assert_eq!(
            children(server, "add_header")[0].args,
            vec!["X".to_owned(), "a;b".to_owned()],
            "a «;» inside quotes does not end the directive"
        );
    }

    #[test]
    fn upstream_max_conns_becomes_the_per_server_cap() {
        // nginx `server … max_conns=N` (B-H16): translated, and a value past
        // the schema ceiling is clipped with a note instead of producing an
        // invalid file.
        let source = "http {\n  upstream app {\n    server 10.0.0.1:8080 max_conns=50;\n  }\n  server {\n    listen 80;\n    location / { proxy_pass http://app; }\n  }\n}\n";
        let outcome = super::super::convert(super::super::Source::Nginx, source).expect("convert");
        assert!(
            outcome.toml.contains("maxconn = 50"),
            "the cap must reach the file:\n{}",
            outcome.toml
        );

        let clipped = "http {\n  upstream app {\n    server 10.0.0.1:8080 max_conns=5000000;\n  }\n  server {\n    listen 80;\n    location / { proxy_pass http://app; }\n  }\n}\n";
        let outcome = super::super::convert(super::super::Source::Nginx, clipped).expect("convert");
        assert!(
            outcome.toml.contains("maxconn = 1000000"),
            "an over-ceiling cap is clipped:\n{}",
            outcome.toml
        );
        assert!(
            outcome.report.contains("recortado a 1000000"),
            "and the clipping is named in the report:\n{}",
            outcome.report
        );
    }

    #[test]
    fn comments_are_not_directives() {
        let nodes = tokenize("# comentario\nlisten 80; # otro\n")
            .and_then(|tokens| parse(&tokens))
            .expect("parse");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "listen");
    }

    #[test]
    fn broken_input_fails_with_a_named_cause() {
        for (text, expected) in [
            ("http {", "bloque sin cerrar"),
            ("listen 80", "no termina en «;»"),
            ("}", "sin bloque abierto"),
            ("server_name \"x", "sin cerrar"),
        ] {
            let err = tokenize(text)
                .and_then(|tokens| parse(&tokens))
                .expect_err("must fail");
            assert!(err.message.contains(expected), "{}", err.message);
        }
    }

    #[test]
    fn cidr_and_variable_helpers_are_conservative() {
        assert_eq!(cidr_of("10.1.2.3"), "10.1.2.3/32");
        assert_eq!(cidr_of("::1"), "::1/128");
        assert_eq!(cidr_of("10.0.0.0/8"), "10.0.0.0/8");
        assert_eq!(nginx_variable_unsupported("$remote_addr"), None);
        assert_eq!(
            nginx_variable_unsupported("$proxy_add_x_forwarded_for"),
            Some("$proxy_add_x_forwarded_for".to_owned())
        );
    }
}
