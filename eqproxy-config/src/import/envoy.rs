//! Envoy (v3 bootstrap) → EQProxy.
//!
//! Reads `static_resources.clusters` (endpoints, weights, health checks, TLS,
//! h2), `static_resources.listeners` (socket address, TLS context,
//! `http_connection_manager` routes and `tcp_proxy`) and `admin`, and maps them
//! to listeners, backends and `host`/`path` rules. Envoy's dynamic resources
//! (`cds_config`, xDS), Lua filters, outlier detection and circuit breakers are
//! classified with what is lost — none of them is guessed.

use super::yaml::{self, Value};
use super::{Conv, ImportError, Listener, ListenerTls, Rule, convert_duration, normalize_addr};

/// Envoy filter names the converter understands.
const HCM: &str = "envoy.filters.network.http_connection_manager";
const TCP_PROXY: &str = "envoy.filters.network.tcp_proxy";
const ROUTER: &str = "envoy.filters.http.router";
const CORS: &str = "envoy.filters.http.cors";
const TLS_SOCKET: &str = "envoy.transport_sockets.tls";

pub(super) fn convert(conv: &mut Conv, text: &str) -> Result<(), ImportError> {
    let documents =
        yaml::documents(text).map_err(|err| ImportError::new(format!("YAML no válido: {err}")))?;
    let Some(doc) = documents.first() else {
        return Err(ImportError::new(
            "el bootstrap de Envoy está vacío".to_owned(),
        ));
    };

    let static_resources = doc.get("static_resources");
    if let Some(clusters) = static_resources
        .and_then(|s| s.get("clusters"))
        .map(Value::items)
    {
        for spec in clusters {
            cluster(conv, spec)?;
        }
    }
    if let Some(listeners) = static_resources
        .and_then(|s| s.get("listeners"))
        .map(Value::items)
    {
        for entry in listeners {
            listener(conv, entry)?;
        }
    }

    for (key, value) in doc.entries() {
        let before = conv.notes.len();
        let text = format!("{key}: {}", summarize(value));
        match key.as_str() {
            "static_resources" => conv.info(
                1,
                &text,
                "bootstrap",
                "contenedores de clusters/listeners ya traducidos arriba",
            ),
            "admin" => {
                let address = value
                    .get("address")
                    .and_then(|a| a.get("socket_address"))
                    .and_then(socket_address);
                match address {
                    Some(address) => conv.review(
                        1,
                        &text,
                        "bootstrap",
                        format!(
                            "[admin].listen = \"{address}\" necesita además token_file (bearer obligatorio \
                             en EQProxy) y allow_remote si no es loopback"
                        ),
                    ),
                    None => conv.review(
                        1,
                        &text,
                        "bootstrap",
                        "[admin] (plano de administración con bearer token)",
                    ),
                }
            }
            "dynamic_resources" => conv.gap(
                1,
                &text,
                "bootstrap",
                "xDS (cds/lds/rds/eds) sin soporte: EQProxy lee un fichero local y recarga con SIGHUP \
                 o `config apply` (ADR-0027)",
            ),
            "node" => conv.info(
                1,
                &text,
                "bootstrap",
                "identidad del nodo Envoy: sin equivalente (no hay plano de control)",
            ),
            "layered_runtime" | "cluster_manager" | "stats_sinks" | "stats_config" | "bootstrap_extensions"
            | "default_regex_engine" => conv.info(
                1,
                &text,
                "bootstrap",
                "configuración del propio Envoy sin equivalente en EQProxy",
            ),
            other => conv.review(
                1,
                text.clone(),
                "bootstrap",
                format!("clave «{other}» sin traducción automática: revísela a mano"),
            ),
        }
        conv.touch(&text, "bootstrap", before)?;
    }
    Ok(())
}

/// A one-line summary used as the directive label of a structural node.
fn summarize(value: &Value) -> String {
    match value {
        Value::Scalar(text) => text.clone(),
        Value::Seq(items) => format!("[{} elementos]", items.len()),
        Value::Map(entries) => format!("{{{} claves}}", entries.len()),
        Value::Null => String::new(),
    }
}

/// `address: { socket_address: { address, port_value } }` → `IP:PORT`.
fn socket_address(value: &Value) -> Option<String> {
    let address = value.get("address")?.text()?;
    let port = value.get("port_value").and_then(Value::text)?;
    Some(format!("{address}:{port}"))
}

// ---------------------------------------------------------------------------
// Clusters
// ---------------------------------------------------------------------------

fn cluster(conv: &mut Conv, cluster: &Value) -> Result<(), ImportError> {
    let name = cluster
        .get("name")
        .and_then(Value::text)
        .unwrap_or_default()
        .to_owned();
    if name.is_empty() {
        conv.reject(1, "cluster", "clusters", "cluster sin nombre: se omite");
        return Ok(());
    }
    let context = format!("cluster {name}");
    let backend_name = conv.free_backend_name(&name);
    let mut backend = super::Backend::default();
    let mut http2 = false;

    for (key, value) in cluster.entries() {
        let before = conv.notes.len();
        let text = format!("{key}: {}", summarize(value));
        match key.as_str() {
            "name" => conv.info(1, &text, &context, "nombre del cluster → nombre del backend"),
            "type" => match value.text().unwrap_or_default() {
                "STATIC" => conv.done(1, &text, &context, "endpoints literales del cluster"),
                "STRICT_DNS" | "LOGICAL_DNS" => conv.review(
                    1,
                    &text,
                    &context,
                    "DNS del cluster: EQProxy resuelve HOSTNAME:PORT y lo re-resuelve con resolve_interval",
                ),
                "EDS" => conv.review(
                    1,
                    &text,
                    &context,
                    "EDS (endpoints por xDS): sin plano de control; los endpoints del manifiesto se usan tal cual",
                ),
                other => conv.gap(
                    1,
                    format!("type: {other}"),
                    &context,
                    "tipo de descubrimiento sin equivalente",
                ),
            },
            "connect_timeout" => {
                let value = convert_duration(
                    conv,
                    value.text().unwrap_or_default(),
                    "s",
                    &text,
                    &context,
                );
                if value.is_some() {
                    conv.review(
                        1,
                        &text,
                        &context,
                        "EQProxy no tiene connect_timeout por backend: se aplica el de cada listener",
                    );
                }
            }
            "lb_policy" => match value.text().unwrap_or_default() {
                "ROUND_ROBIN" => {
                    conv.done(1, &text, &context, "balance = \"roundrobin\"");
                }
                "LEAST_REQUEST" => {
                    backend.balance = "leastconn".to_owned();
                    conv.done(1, &text, &context, "balance = \"leastconn\"");
                }
                other => conv.gap(
                    1,
                    format!("lb_policy: {other}"),
                    &context,
                    "algoritmo sin soporte: EQProxy emite roundrobin ponderado",
                ),
            },
            "load_assignment" => {
                for endpoint in value.get("endpoints").map(Value::items).unwrap_or(&[]) {
                    for balancer in endpoint
                        .get("lb_endpoints")
                        .map(Value::items)
                        .unwrap_or(&[])
                    {
                        let Some(address) = balancer
                            .get("endpoint")
                            .and_then(|e| e.get("address"))
                            .and_then(|a| a.get("socket_address"))
                            .and_then(socket_address)
                        else {
                            conv.reject(
                                1,
                                "lb_endpoint",
                                &context,
                                "endpoint sin socket_address (¿pipe o endpoint por xDS?): se omite",
                            );
                            continue;
                        };
                        let weight = balancer
                            .get("load_balancing_weight")
                            .and_then(Value::text)
                            .and_then(|text| text.parse::<u32>().ok())
                            .unwrap_or(1);
                        backend.servers.push(super::Server {
                            addr: address.clone(),
                            weight,
                            backup: false,
                            maxconn: 0,
                        });
                        conv.done(
                            1,
                            format!("endpoint {address}"),
                            &context,
                            format!("servidor con peso {weight}"),
                        );
                    }
                }
            }
            "health_checks" => {
                for check in value.items() {
                    health_check(conv, check, &context, &mut backend);
                }
            }
            "transport_socket" => {
                if value.get("name").and_then(Value::text) == Some(TLS_SOCKET) {
                    let typed = value.get("typed_config").unwrap_or(value);
                    let mut tls = backend.tls.clone().unwrap_or_default();
                    tls.verify = true;
                    let mut done = false;
                    if let Some(sni) = typed.get("sni").and_then(Value::text) {
                        tls.server_name = Some(sni.to_owned());
                        done = true;
                    }
                    if let Some(context) = typed.get("common_tls_context") {
                        if let Some(ca) = context
                            .get("validation_context")
                            .and_then(|v| v.get("trusted_ca"))
                            .and_then(|ca| ca.get("filename"))
                            .and_then(Value::text)
                        {
                            tls.ca_file = Some(ca.to_owned());
                            done = true;
                        }
                        if let Some(alpn) = context.get("alpn_protocols") {
                            tls.alpn = alpn
                                .items()
                                .iter()
                                .filter_map(|item| item.text().map(str::to_owned))
                                .collect();
                            done = true;
                        }
                    }
                    backend.tls = Some(tls);
                    if done {
                        conv.done(
                            1,
                            &text,
                            &context,
                            "[backend.*.tls] (server_name, ca_file, alpn)",
                        );
                    } else {
                        conv.review(
                            1,
                            &text,
                            &context,
                            "UpstreamTlsContext sin sni/ca/alpn: solo se activa la verificación por defecto",
                        );
                    }
                } else {
                    conv.gap(
                        1,
                        &text,
                        &context,
                        "transporte distinto de TLS: sin soporte",
                    );
                }
            }
            "http2_protocol_options" => {
                http2 = true;
                conv.done(
                    1,
                    &text,
                    &context,
                    "[backend.*.tls].alpn = [\"h2\"] (HTTP/2 al backend)",
                );
            }
            "outlier_detection" => conv.review(
                1,
                &text,
                &context,
                "detección pasiva: EQProxy reacciona a fallos de conexión con health_check.passive; \
                 consecutive_5xx no se evalúa",
            ),
            "circuit_breakers" => conv.gap(
                1,
                &text,
                &context,
                "circuit breakers por cluster: EQProxy tiene maxconn/maxqueue, no un presupuesto por ruta",
            ),
            "eds_cluster_config" | "cluster_type" => conv.review(
                1,
                &text,
                &context,
                "descubrimiento dinámico: EQProxy lee los endpoints del fichero",
            ),
            other => match cluster_pointer(other) {
                Some(hint) => conv.review(1, &text, &context, hint),
                None => conv.review(
                    1,
                    text.clone(),
                    &context,
                    format!("clave «{other}» del cluster sin traducción automática: revísela a mano"),
                ),
            },
        }
        conv.touch(&text, &context, before)?;
    }

    if http2 {
        let mut tls = backend.tls.clone().unwrap_or_default();
        if tls.alpn.is_empty() {
            tls.alpn = vec!["h2".to_owned()];
        }
        backend.tls = Some(tls);
    }
    if backend.servers.is_empty() {
        conv.reject(
            1,
            format!("cluster {name}"),
            &context,
            "sin endpoints utilizables: no se emite backend",
        );
        return Ok(());
    }
    if backend_name != name {
        conv.review(
            1,
            format!("cluster {name}"),
            &context,
            format!("renombrado a «{backend_name}»"),
        );
    }
    conv.add_backend(backend_name, backend);
    Ok(())
}

fn health_check(conv: &mut Conv, check: &Value, context: &str, backend: &mut super::Backend) {
    let mut health = Conv::default_health_check();
    let mut kind = "tcp";
    let mut path = None;
    let mut detail = Vec::new();
    if let Some(interval) = check.get("interval").and_then(Value::text) {
        health.interval =
            convert_duration(conv, interval, "s", "interval", context).unwrap_or(health.interval);
        detail.push(format!("interval {interval}"));
    }
    if let Some(timeout) = check.get("timeout").and_then(Value::text)
        && let Some(value) = convert_duration(conv, timeout, "s", "timeout", context)
    {
        health.timeout = value;
        detail.push(format!("timeout {timeout}"));
    }
    if let Some(fall) = check
        .get("unhealthy_threshold")
        .and_then(Value::text)
        .and_then(|text| text.parse::<u32>().ok())
    {
        health.fall = fall.max(1);
    }
    if let Some(rise) = check
        .get("healthy_threshold")
        .and_then(Value::text)
        .and_then(|text| text.parse::<u32>().ok())
    {
        health.rise = rise.max(1);
    }
    if check.get("http_health_check").is_some() {
        kind = "http";
        path = check
            .get("http_health_check")
            .and_then(|h| h.get("path"))
            .and_then(Value::text)
            .map(str::to_owned);
    }
    health.kind = if kind == "http" { Some("http") } else { None };
    health.http_path = path.clone();
    backend.health_check = Some(health);
    let text = format!(
        "health_check {}{}",
        kind.to_uppercase(),
        path.map_or(String::new(), |path| format!(" {path}"))
    );
    conv.done(
        1,
        &text,
        context,
        format!(
            "health_check ({}), fall/rise del manifiesto",
            detail.join(", ")
        ),
    );
}

// ---------------------------------------------------------------------------
// Listeners
// ---------------------------------------------------------------------------

fn listener(conv: &mut Conv, listener: &Value) -> Result<(), ImportError> {
    let name = listener
        .get("name")
        .and_then(Value::text)
        .unwrap_or("listener")
        .to_owned();
    let context = format!("listener {name}");

    if listener.get("udp_listener").is_some() {
        conv.gap(
            1,
            format!("listener {name} (udp_listener)"),
            &context,
            "listener UDP: EQProxy solo habla UDP para QUIC/HTTP3",
        );
        return Ok(());
    }

    let Some(address) = listener
        .get("address")
        .and_then(|a| a.get("socket_address"))
        .and_then(socket_address)
    else {
        conv.reject(
            1,
            format!("listener {name}"),
            &context,
            "sin address.socket_address: se omite",
        );
        return Ok(());
    };
    let Some(address) = normalize_addr(conv, &address, None, &address, &context) else {
        return Ok(());
    };

    let chains = listener
        .get("filter_chains")
        .map(Value::items)
        .unwrap_or(&[]);
    if chains.len() > 1 {
        conv.gap(
            1,
            format!("{} filter_chains", chains.len()),
            &context,
            "varias cadenas de filtros (una por SNI): EQProxy sirve un TLS por listener y selecciona \
             certificado con [listener.*.tls].certs, pero no cambia los filtros por SNI",
        );
    }
    let Some(chain) = chains.first() else {
        conv.reject(
            1,
            format!("listener {name}"),
            &context,
            "sin filter_chains: se omite",
        );
        return Ok(());
    };

    let mut tls: Option<ListenerTls> = None;
    if let Some(socket) = chain.get("transport_socket")
        && socket.get("name").and_then(Value::text) == Some(TLS_SOCKET)
    {
        let typed = socket.get("typed_config").unwrap_or(socket);
        let far = typed.get("common_tls_context").unwrap_or(typed);
        if let Some(cert) = far
            .get("tls_certificates")
            .map(Value::items)
            .unwrap_or(&[])
            .first()
        {
            let cert_file = cert
                .get("certificate_chain")
                .and_then(|c| c.get("filename"))
                .and_then(Value::text);
            let key_file = cert
                .get("private_key")
                .and_then(|c| c.get("filename"))
                .and_then(Value::text);
            if let (Some(cert_file), Some(key_file)) = (cert_file, key_file) {
                let alpn = far
                    .get("alpn_protocols")
                    .map(Value::items)
                    .unwrap_or(&[])
                    .iter()
                    .filter_map(|item| item.text().map(str::to_owned))
                    .collect();
                let min_version = far
                    .get("tls_params")
                    .and_then(|p| p.get("tls_minimum_protocol_version"))
                    .and_then(Value::text)
                    .map(|version| {
                        if version.contains("1.3") {
                            "1.3"
                        } else {
                            "1.2"
                        }
                    });
                tls = Some(ListenerTls {
                    cert: cert_file.to_owned(),
                    key: key_file.to_owned(),
                    alpn,
                    min_version,
                    client_ca: None,
                });
                conv.done(
                    1,
                    "transport_socket tls",
                    &context,
                    "[listener.*.tls] (cert, key, alpn, min_version)",
                );
            } else {
                conv.reject(
                    1,
                    "transport_socket tls",
                    &context,
                    "TLS sin certificate_chain/private_key completos: listener en claro",
                );
            }
        } else if far.get("tls_certificate_sds_secret_configs").is_some() {
            conv.gap(
                1,
                "sds_secret_configs",
                &context,
                "certificados por SDS: EQProxy usa ficheros y recarga en caliente (ADR-0025)",
            );
        }
    }

    let mut mode = "http";
    let mut backend_name: Option<String> = None;
    let mut rules: Vec<Rule> = Vec::new();
    let mut idle_timeout: Option<String> = None;
    let mut client_header_timeout: Option<String> = None;
    let mut forwarded = false;

    for filter in chain.get("filters").map(Value::items).unwrap_or(&[]) {
        let filter_name = filter.get("name").and_then(Value::text).unwrap_or_default();
        let typed = filter.get("typed_config").unwrap_or(filter);
        let before = conv.notes.len();
        match filter_name {
            HCM => {
                if let Some(value) = typed
                    .get("common_http_protocol_options")
                    .and_then(|o| o.get("idle_timeout"))
                    .and_then(Value::text)
                {
                    idle_timeout = convert_duration(conv, value, "s", "idle_timeout", &context);
                }
                if let Some(value) = typed.get("request_headers_timeout").and_then(Value::text) {
                    client_header_timeout =
                        convert_duration(conv, value, "s", "request_headers_timeout", &context);
                }
                if let Some(route_config) = typed.get("route_config") {
                    for host in route_config
                        .get("virtual_hosts")
                        .map(Value::items)
                        .unwrap_or(&[])
                    {
                        let (host_regex, host_exact) = domains(host, conv, &context);
                        for route in host.get("routes").map(Value::items).unwrap_or(&[]) {
                            let Some(rule) =
                                route_rule(conv, route, &context, &host_regex, &host_exact)
                            else {
                                continue;
                            };
                            rules.push(rule);
                        }
                    }
                }
                for http_filter in typed.get("http_filters").map(Value::items).unwrap_or(&[]) {
                    let filter = http_filter
                        .get("name")
                        .and_then(Value::text)
                        .unwrap_or_default();
                    match filter {
                        ROUTER => conv.info(
                            1,
                            "envoy.filters.http.router",
                            &context,
                            "el router de Envoy es implícito en EQProxy",
                        ),
                        CORS => conv.review(
                            1,
                            "envoy.filters.http.cors",
                            &context,
                            "[[listener.*.rules]].cors (allow_origin, métodos, max_age)",
                        ),
                        name if name.contains("lua") => conv.gap(
                            1,
                            name.to_owned(),
                            &context,
                            "filtro Lua: no se ejecuta; el sustituto es un plugin WASM (ADR-0031)",
                        ),
                        name => conv.review(
                            1,
                            name.to_owned(),
                            &context,
                            "filtro HTTP sin traducción automática: revíselo a mano",
                        ),
                    }
                }
                for field in [
                    "stat_prefix",
                    "access_log",
                    "use_remote_address",
                    "server_name",
                ] {
                    if let Some(field_value) = typed.get(field) {
                        let label = format!("{field}: {}", summarize(field_value));
                        conv.review(
                            1,
                            label,
                            &context,
                            if field == "access_log" {
                                "[access_log] con format = \"json\""
                            } else {
                                "ajuste del HCM sin equivalente directo"
                            },
                        );
                    }
                }
                if typed.get("access_log").is_some() {
                    forwarded = true;
                }
                conv.done(1, HCM, &context, "listener en mode = \"http\"");
            }
            TCP_PROXY => {
                mode = "tcp";
                let cluster = typed
                    .get("cluster")
                    .and_then(Value::text)
                    .unwrap_or_default();
                let resolved = super::sanitize_name(cluster);
                if conv.has_backend(&resolved) {
                    backend_name = Some(resolved.clone());
                    conv.done(
                        1,
                        TCP_PROXY,
                        &context,
                        format!("listener en mode = \"tcp\" → backend «{resolved}»"),
                    );
                } else {
                    conv.reject(
                        1,
                        TCP_PROXY,
                        &context,
                        format!("el cluster «{cluster}» no existe o no fue traducible"),
                    );
                }
            }
            name => conv.gap(
                1,
                name.to_owned(),
                &context,
                "filtro de red sin equivalente: solo http_connection_manager y tcp_proxy",
            ),
        }
        conv.touch(filter_name, &context, before)?;
    }

    if rules.is_empty() && backend_name.is_none() {
        conv.reject(
            1,
            format!("listener {name}"),
            &context,
            "sin rutas ni tcp_proxy traducibles: se omite",
        );
        return Ok(());
    }

    // Envoy matches the most specific route; EQProxy the first match.
    rules.sort_by_key(|rule| {
        (
            rule.host.clone().unwrap_or_default(),
            std::cmp::Reverse(rule.path_prefix.as_deref().unwrap_or_default().len()),
        )
    });
    let fallback = backend_name.clone().or_else(|| {
        rules
            .iter()
            .find(|rule| rule.path_prefix.as_deref() == Some("/"))
            .or_else(|| rules.first())
            .and_then(|rule| rule.use_backend.clone())
    });
    let Some(fallback) = fallback else {
        conv.reject(
            1,
            format!("listener {name}"),
            &context,
            "sin backend de respaldo: EQProxy exige uno por listener",
        );
        return Ok(());
    };

    let listener_name = conv.free_listener_name(&name);
    let mut listener_config = Listener::new(address, mode, fallback);
    listener_config.tls = tls;
    listener_config.idle_timeout = idle_timeout;
    listener_config.client_header_timeout = client_header_timeout;
    listener_config.rules = rules;
    if forwarded {
        listener_config.forwarded_headers = Some("append");
    }
    if listener.get("listener_filters").is_some() {
        conv.review(
            1,
            "listener_filters",
            &context,
            "listener_filters (proxy_protocol): EQProxy lo tiene como [listener.*].proxy_receive + proxy_allow",
        );
    }
    if listener.get("per_connection_buffer_limit_bytes").is_some() {
        conv.review(
            1,
            "per_connection_buffer_limit_bytes",
            &context,
            "[listener.*.limits].stream_buffer_bytes",
        );
    }
    conv.done(
        1,
        format!("listener {name}"),
        &context,
        format!("listener «{listener_name}» ({mode})"),
    );
    conv.add_listener(listener_name, listener_config);
    Ok(())
}

/// Translates Envoy `domains` into EQProxy host conditions.
fn domains(host: &Value, conv: &mut Conv, context: &str) -> (Option<String>, Option<String>) {
    let mut exact = None;
    let mut regex = None;
    for domain in host.get("domains").map(Value::items).unwrap_or(&[]) {
        let Some(domain) = domain.text() else {
            continue;
        };
        if let Some(suffix) = domain.strip_prefix("*.") {
            let escaped = suffix.replace('.', "\\.");
            regex = Some(format!("^[^.]+\\.{escaped}$"));
            conv.review(
                1,
                format!("domain {domain}"),
                context,
                format!("host_regex para el comodín de un nivel ({domain})"),
            );
        } else if domain == "*" {
            conv.review(
                1,
                format!("domain {domain}"),
                context,
                "dominio universal: la regla no lleva condición de host",
            );
        } else if exact.is_none() {
            exact = Some(domain.to_owned());
            conv.done(
                1,
                format!("domain {domain}"),
                context,
                "condición host de la regla",
            );
        } else {
            conv.review(
                1,
                format!("domain {domain}"),
                context,
                "segundo dominio exacto del mismo virtual host: una regla por host, revíselo",
            );
        }
    }
    (regex, exact)
}

/// One Envoy route → one `[[listener.*.rules]]`.
fn route_rule(
    conv: &mut Conv,
    route: &Value,
    context: &str,
    host_regex: &Option<String>,
    host_exact: &Option<String>,
) -> Option<Rule> {
    let matched = route.get("match")?;
    let (path, prefix) = match (
        matched.get("prefix").and_then(Value::text),
        matched.get("path").and_then(Value::text),
    ) {
        (Some(prefix), _) => (prefix.to_owned(), true),
        (None, Some(path)) => (path.to_owned(), false),
        _ => {
            conv.gap(
                1,
                "match",
                context,
                "ruta sin prefix/path literal (safe_regex): EQProxy tiene path_regex, el conversor no la traslada",
            );
            return None;
        }
    };
    let action = route.get("route")?;
    let mut rule = Rule {
        name: format!(
            "{}{path}",
            host_exact.clone().unwrap_or_else(|| "-".to_owned())
        ),
        host: host_exact.clone(),
        path_prefix: if prefix { Some(path.clone()) } else { None },
        path: if prefix { None } else { Some(path.clone()) },
        ..Rule::default()
    };
    // A wildcard domain (`*.ejemplo.com`) becomes a one-label host regex.
    if rule.host.is_none() {
        rule.host_regex = host_regex.clone();
    }
    if let Some(cluster) = action.get("cluster").and_then(Value::text) {
        let resolved = super::sanitize_name(cluster);
        if conv.has_backend(&resolved) {
            rule.use_backend = Some(resolved);
        } else {
            conv.reject(
                1,
                format!("route {path}"),
                context,
                format!("el cluster «{cluster}» no existe: la ruta no se emite"),
            );
            return None;
        }
    } else if action.get("weighted_clusters").is_some() {
        conv.gap(
            1,
            format!("route {path} weighted_clusters"),
            context,
            "reparto ponderado: EQProxy tiene split, el conversor no emite los pesos",
        );
        return None;
    } else if let Some(redirect) = action.get("redirect") {
        let location = redirect
            .get("https_redirect")
            .is_some()
            .then(|| "https://$host$request_uri".to_owned())
            .or_else(|| {
                redirect
                    .get("path_redirect")
                    .and_then(Value::text)
                    .map(str::to_owned)
            })
            .or_else(|| {
                redirect
                    .get("host_redirect")
                    .and_then(Value::text)
                    .map(|host| format!("https://{host}$request_uri"))
            });
        match location {
            Some(location) => {
                rule.redirect = Some((None, location));
                conv.done(
                    1,
                    format!("route {path} redirect"),
                    context,
                    "regla con redirect (302 por defecto; fije el código en el TOML)",
                );
            }
            None => {
                conv.gap(
                    1,
                    format!("route {path} redirect"),
                    context,
                    "redirección con plantilla de Envoy sin traducción",
                );
                return None;
            }
        }
    } else if let Some(direct) = action.get("direct_response") {
        let status = direct
            .get("status")
            .and_then(Value::text)
            .and_then(|text| text.parse::<u16>().ok())
            .unwrap_or(200);
        rule.direct_response = Some((status, None));
        conv.done(
            1,
            format!("route {path} direct_response"),
            context,
            format!("regla con direct_response {status}"),
        );
    } else {
        conv.review(
            1,
            format!("route {path}"),
            context,
            "ruta sin cluster, redirect ni direct_response: revísela a mano",
        );
        return None;
    }
    if let Some(policy) = action.get("retry_policy") {
        conv.review(
            1,
            format!("route {path} retry_policy"),
            context,
            format!(
                "[backend.*].retries (num_retries = {})",
                policy
                    .get("num_retries")
                    .and_then(Value::text)
                    .unwrap_or("?")
            ),
        );
    }
    if action.get("timeout").is_some() {
        conv.review(
            1,
            format!("route {path} timeout"),
            context,
            "[listener.*].max_stream_duration (duración total, no solo inactividad)",
        );
    }
    if action.get("prefix_rewrite").is_some() || action.get("host_rewrite_literal").is_some() {
        if let Some(prefix) = action.get("prefix_rewrite").and_then(Value::text) {
            rule.rewrite_prefix = Some(prefix.to_owned());
        }
        conv.done(
            1,
            format!("route {path} rewrite"),
            context,
            "[[listener.*.rules]].rewrite",
        );
    }
    Some(rule)
}

/// Extra keys of a cluster with a known place in `eqproxy.toml`.
fn cluster_pointer(key: &str) -> Option<String> {
    match key {
        "alt_stat_name" | "metadata" | "transport_socket_matches" => None,
        "dns_lookup_family" | "dns_refresh_rate" => {
            Some("[backend.*].resolve_interval (re-resolución en caliente del nombre)".to_owned())
        }
        "respect_dns_ttl" => Some("EQProxy usa resolve_interval, no el TTL del DNS".to_owned()),
        "ignore_health_on_host_removal" | "drain_connections_on_host_removal" => {
            Some("retirada de hosts: la controla el health check de EQProxy".to_owned())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_addresses_are_read_from_the_envoy_shape() {
        let doc = yaml::documents("socket_address:\n  address: 10.0.0.1\n  port_value: 8080\n")
            .expect("parse")
            .remove(0);
        let inner = doc.get("socket_address").expect("socket_address");
        assert_eq!(socket_address(inner).as_deref(), Some("10.0.0.1:8080"));
    }

    #[test]
    fn wildcard_domains_become_a_one_label_regex() {
        let host = yaml::documents("domains: [\"*.ejemplo.com\"]\n")
            .expect("parse")
            .remove(0);
        let mut conv = Conv::default();
        let (regex, exact) = domains(&host, &mut conv, "virtual host");
        assert_eq!(regex.as_deref(), Some("^[^.]+\\.ejemplo\\.com$"));
        assert!(exact.is_none());
    }

    #[test]
    fn empty_yaml_is_an_error_not_an_empty_config() {
        let mut conv = Conv::default();
        let error = convert(&mut conv, "").expect_err("empty bootstrap");
        assert!(error.message.contains("vacío"), "{}", error.message);
    }
}
