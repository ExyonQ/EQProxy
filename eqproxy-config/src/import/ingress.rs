//! ingress-nginx → EQProxy.
//!
//! Reads the multi-document manifest stream (ConfigMaps, Endpoints, Services
//! and Ingress objects), resolves each Ingress backend through its Endpoints
//! (or through the in-cluster service DNS name when the Endpoints object is
//! absent) and emits one listener per public address with `host` + `path`
//! rules — the shape an ingress controller actually has. Annotations map to
//! the fields EQProxy has: CORS, rate limit, IP allowlist, rewrite, HSTS,
//! body size, timeouts and load balancing. Everything else is classified,
//! including `configuration-snippet` (never executed) and `ssl-passthrough`
//! (needs SNI routing EQProxy does not do).

use std::collections::BTreeMap;

use super::yaml::{self, Value};
use super::{Conv, HeaderOp, ImportError, Listener, Rule, convert_duration, parse_size};

/// Listener-level values gathered from the Ingress that first claimed the
/// address (an ingress controller has one configuration for the address).
#[derive(Debug, Default, Clone)]
struct Settings {
    maxconn: Option<u32>,
    max_body_bytes: Option<u64>,
    connect_timeout: Option<String>,
    server_header_timeout: Option<String>,
    idle_timeout: Option<String>,
}

/// Per-Ingress behaviour extracted from its annotations.
#[derive(Debug, Default, Clone)]
struct Behaviour {
    cors: Option<String>,
    rate: Option<u32>,
    ip: Vec<String>,
    rewrite: Option<String>,
    response_headers: Vec<HeaderOp>,
    connect_timeout: Option<String>,
    server_header_timeout: Option<String>,
    max_body_bytes: Option<u64>,
}

/// One routing entry collected from all Ingress objects of one address.
struct Route {
    host: Option<String>,
    path: String,
    prefix: bool,
    backend: String,
    behaviour: Behaviour,
}

pub(super) fn convert(conv: &mut Conv, text: &str) -> Result<(), ImportError> {
    let documents =
        yaml::documents(text).map_err(|err| ImportError::new(format!("YAML no válido: {err}")))?;

    let mut global: BTreeMap<String, String> = BTreeMap::new();
    let mut endpoints: BTreeMap<(String, String), Vec<(String, u16)>> = BTreeMap::new();
    let mut services: BTreeMap<(String, String), u16> = BTreeMap::new();
    let mut tcp_services: Vec<(String, String)> = Vec::new();
    let mut udp_ports: Vec<String> = Vec::new();
    let mut ingresses: Vec<&Value> = Vec::new();

    for doc in &documents {
        match doc.get("kind").and_then(Value::text).unwrap_or_default() {
            "ConfigMap" => {
                let name = doc
                    .get("metadata")
                    .and_then(|m| m.get("name"))
                    .and_then(Value::text)
                    .unwrap_or_default()
                    .to_owned();
                match name.as_str() {
                    "ingress-nginx-controller" | "nginx-configuration" => {
                        for (key, value) in doc.get("data").map(Value::entries).unwrap_or(&[]) {
                            global.insert(key.clone(), value.text().unwrap_or_default().to_owned());
                        }
                    }
                    "tcp-services" => {
                        for (port, target) in doc.get("data").map(Value::entries).unwrap_or(&[]) {
                            tcp_services
                                .push((port.clone(), target.text().unwrap_or_default().to_owned()));
                        }
                    }
                    "udp-services" => {
                        for (port, _) in doc.get("data").map(Value::entries).unwrap_or(&[]) {
                            udp_ports.push(port.clone());
                        }
                    }
                    other => conv.review(
                        1,
                        format!("ConfigMap {other}"),
                        "ConfigMap",
                        "configuración de otro controlador: se ignora",
                    ),
                }
            }
            "Endpoints" => {
                let (namespace, name) = metadata(doc);
                let mut addrs = Vec::new();
                for subset in doc.get("subsets").map(Value::items).unwrap_or(&[]) {
                    let port = subset
                        .get("ports")
                        .map(Value::items)
                        .unwrap_or(&[])
                        .iter()
                        .find_map(|port| port.get("port").and_then(Value::text))
                        .and_then(|text| text.parse::<u16>().ok());
                    let Some(port) = port else { continue };
                    for address in subset.get("addresses").map(Value::items).unwrap_or(&[]) {
                        if let Some(ip) = address.get("ip").and_then(Value::text) {
                            addrs.push((ip.to_owned(), port));
                        }
                    }
                }
                endpoints.insert((namespace, name), addrs);
            }
            "Service" => {
                let (namespace, name) = metadata(doc);
                if let Some(port) = doc
                    .get("spec")
                    .and_then(|s| s.get("ports"))
                    .map(Value::items)
                    .unwrap_or(&[])
                    .first()
                    .and_then(|p| p.get("port"))
                    .and_then(Value::text)
                    .and_then(|text| text.parse::<u16>().ok())
                {
                    services.insert((namespace, name), port);
                }
            }
            "Ingress" => ingresses.push(doc),
            other if !other.is_empty() => conv.review(
                1,
                format!("kind: {other}"),
                "manifiesto",
                "tipo de objeto sin traducción: se ignora",
            ),
            _ => {}
        }
    }

    // Address → routes. An ingress controller serves every host from one
    // address, which is exactly EQProxy's listener + `host` rules shape.
    let mut by_address: BTreeMap<String, Vec<Route>> = BTreeMap::new();
    let mut settings: BTreeMap<String, Settings> = BTreeMap::new();

    for doc in &ingresses {
        let (namespace, name) = metadata(doc);
        let context = format!("Ingress {name}");
        let annotations: BTreeMap<String, String> = doc
            .get("metadata")
            .and_then(|m| m.get("annotations"))
            .map(Value::entries)
            .unwrap_or(&[])
            .iter()
            .map(|(key, value)| {
                (
                    key.trim_start_matches("nginx.ingress.kubernetes.io/")
                        .to_owned(),
                    value.text().unwrap_or_default().to_owned(),
                )
            })
            .collect();

        if annotations
            .get("ssl-passthrough")
            .is_some_and(|value| value == "true")
        {
            conv.gap(
                1,
                "ssl-passthrough",
                &context,
                "passthrough TLS: EQProxy no enruta por SNI sin terminar TLS (haría falta ssl_preread); \
                 Ingress omitido",
            );
            continue;
        }

        let mut behaviour = Behaviour::default();
        let mut tls = false;
        for (key, value) in &annotations {
            let before = conv.notes.len();
            annotation(conv, key, value, &context, &mut behaviour, &mut tls);
            conv.touch(&format!("{key}: {value}"), &context, before)?;
        }

        for entry in doc
            .get("spec")
            .and_then(|s| s.get("tls"))
            .map(Value::items)
            .unwrap_or(&[])
        {
            if let Some(secret) = entry.get("secretName").and_then(Value::text) {
                tls = true;
                conv.review(
                    1,
                    format!("tls secretName {secret}"),
                    &context,
                    "el secreto de Kubernetes no es un fichero: móntelo y configure \
                     [listener.*.tls] cert/key (o [listener.*.tls].certs por host)",
                );
            }
        }

        let address = if tls {
            "0.0.0.0:443".to_owned()
        } else {
            "0.0.0.0:80".to_owned()
        };
        settings.entry(address.clone()).or_insert_with(|| Settings {
            maxconn: global
                .get("max-connections")
                .and_then(|value| value.parse::<u32>().ok()),
            max_body_bytes: behaviour
                .max_body_bytes
                .or_else(|| global.get("proxy-body-size").and_then(|v| parse_size(v))),
            connect_timeout: behaviour.connect_timeout.clone(),
            server_header_timeout: behaviour.server_header_timeout.clone(),
            idle_timeout: global
                .get("keep-alive")
                .and_then(|value| convert_duration(conv, value, "s", "keep-alive", "ConfigMap")),
        });

        let mut routes = 0usize;
        for rule in doc
            .get("spec")
            .and_then(|s| s.get("rules"))
            .map(Value::items)
            .unwrap_or(&[])
        {
            let host = rule.get("host").and_then(Value::text).map(str::to_owned);
            for path in rule
                .get("http")
                .and_then(|h| h.get("paths"))
                .map(Value::items)
                .unwrap_or(&[])
            {
                let raw_path = path
                    .get("path")
                    .and_then(Value::text)
                    .unwrap_or("/")
                    .to_owned();
                let prefix = path
                    .get("pathType")
                    .and_then(Value::text)
                    .unwrap_or("Prefix")
                    != "Exact";
                let backend_service = path
                    .get("backend")
                    .and_then(|backend| backend.get("service"));
                let service_name = backend_service
                    .and_then(|service| service.get("name"))
                    .and_then(Value::text)
                    .unwrap_or_default()
                    .to_owned();
                if service_name.is_empty() {
                    conv.reject(
                        1,
                        format!("path {raw_path}"),
                        &context,
                        "path sin backend.service.name (se admite networking.k8s.io/v1): se omite",
                    );
                    continue;
                }
                let port = backend_service
                    .and_then(|service| service.get("port"))
                    .and_then(|port| port.get("number"))
                    .and_then(Value::text)
                    .and_then(|text| text.parse::<u16>().ok())
                    .or_else(|| {
                        services
                            .get(&(namespace.clone(), service_name.clone()))
                            .copied()
                    });
                let Some(port) = port else {
                    conv.reject(
                        1,
                        format!("service {service_name}"),
                        &context,
                        "sin puerto en el manifiesto ni en el Service: se omite la ruta",
                    );
                    continue;
                };
                let backend =
                    backend_for(conv, &endpoints, &namespace, &service_name, port, &context);
                routes += 1;
                conv.done(
                    1,
                    format!("path {raw_path} → {service_name}:{port}"),
                    &context,
                    format!(
                        "regla {}→ backend «{backend}»",
                        host.as_deref()
                            .map_or(String::new(), |host| format!("host {host} "))
                    ),
                );
                by_address.entry(address.clone()).or_default().push(Route {
                    host: host.clone(),
                    path: raw_path,
                    prefix,
                    backend,
                    behaviour: behaviour.clone(),
                });
            }
        }
        if routes == 0 {
            conv.reject(
                1,
                format!("Ingress {name}"),
                &context,
                "sin rutas con backend resoluble: no genera listener",
            );
        }
    }

    if !global.is_empty() {
        global_config(conv, &global)?;
    }

    for (address, routes) in by_address {
        let mut rules: Vec<Rule> = routes
            .iter()
            .map(|route| Rule {
                name: format!(
                    "{}{}",
                    route.host.clone().unwrap_or_else(|| "-".to_owned()),
                    route.path
                ),
                use_backend: Some(route.backend.clone()),
                host: route.host.clone(),
                path_prefix: if route.prefix {
                    Some(route.path.clone())
                } else {
                    None
                },
                path: if route.prefix {
                    None
                } else {
                    Some(route.path.clone())
                },
                ip: route.behaviour.ip.clone(),
                cors_origin: route.behaviour.cors.clone(),
                rate_limit: route
                    .behaviour
                    .rate
                    .map(|rate| (rate, "1s".to_owned(), None)),
                rewrite_prefix: route.behaviour.rewrite.clone(),
                response_headers: route.behaviour.response_headers.clone(),
                ..Rule::default()
            })
            .collect();
        // Longest prefix first within each host: nginx matches the most
        // specific location, EQProxy takes the first rule that matches.
        rules.sort_by_key(|rule| {
            (
                rule.host.clone().unwrap_or_default(),
                std::cmp::Reverse(rule.path_prefix.as_deref().unwrap_or_default().len()),
            )
        });
        let Some(fallback) = rules
            .iter()
            .find(|rule| rule.path_prefix.as_deref() == Some("/"))
            .or_else(|| rules.first())
            .and_then(|rule| rule.use_backend.clone())
        else {
            continue;
        };
        let name =
            conv.free_listener_name(&format!("ingress_{}", address.replace([':', '.'], "_")));
        let mut listener = Listener::new(address.clone(), "http", fallback);
        listener.rules = rules;
        let config = settings.get(&address).cloned().unwrap_or_default();
        listener.maxconn = config.maxconn.unwrap_or(1024);
        listener.max_body_bytes = config.max_body_bytes;
        listener.connect_timeout = config.connect_timeout;
        listener.server_header_timeout = config.server_header_timeout;
        listener.idle_timeout = config.idle_timeout;
        if address.ends_with(":443") {
            conv.review(
                1,
                address.clone(),
                "listener",
                "sin certificado montado: rellene [listener.*.tls] con cert/key antes de aplicar \
                 (el Ingress declara un secretName, no una ruta de fichero)",
            );
        }
        conv.done(
            1,
            address.clone(),
            "listener",
            format!(
                "listener «{name}» con {} reglas host+path",
                listener.rules.len()
            ),
        );
        conv.add_listener(name, listener);
    }

    for (port, target) in tcp_services {
        let context = "ConfigMap tcp-services".to_owned();
        let Ok(port) = port.parse::<u16>() else {
            conv.reject(
                1,
                format!("{port}: {target}"),
                &context,
                "puerto no numérico",
            );
            continue;
        };
        let (namespace, rest) = target.split_once('/').unwrap_or(("default", &target));
        let (service, port_text) = rest.split_once(':').unwrap_or((rest, "0"));
        let Ok(service_port) = port_text.parse::<u16>() else {
            conv.reject(
                1,
                format!("{port}: {target}"),
                &context,
                "puerto del servicio no numérico",
            );
            continue;
        };
        let backend = backend_for(conv, &endpoints, namespace, service, service_port, &context);
        let name = conv.free_listener_name(&format!("tcp_{port}"));
        conv.done(
            1,
            format!("{port}: {target}"),
            &context,
            format!("listener «{name}» (tcp 0.0.0.0:{port}) → backend «{backend}»"),
        );
        conv.add_listener(
            name,
            Listener::new(format!("0.0.0.0:{port}"), "tcp", backend),
        );
    }
    for port in udp_ports {
        conv.gap(
            1,
            format!("{port}: udp"),
            "ConfigMap udp-services",
            "EQProxy no proxifica UDP (solo QUIC/HTTP3 como servidor)",
        );
    }
    if conv.listener_count() == 0 {
        return Err(ImportError::new(
            "el manifiesto no produjo ningún listener: necesita al menos un Ingress con backend \
             resoluble o una entrada de tcp-services"
                .to_owned(),
        ));
    }
    Ok(())
}

/// `metadata.namespace`/`name` with the API defaults.
fn metadata(doc: &Value) -> (String, String) {
    let meta = doc.get("metadata");
    let namespace = meta
        .and_then(|m| m.get("namespace"))
        .and_then(Value::text)
        .unwrap_or("default")
        .to_owned();
    let name = meta
        .and_then(|m| m.get("name"))
        .and_then(Value::text)
        .unwrap_or("sin-nombre")
        .to_owned();
    (namespace, name)
}

/// Backend for a Service:port, from its Endpoints or the cluster DNS name.
fn backend_for(
    conv: &mut Conv,
    endpoints: &BTreeMap<(String, String), Vec<(String, u16)>>,
    namespace: &str,
    service: &str,
    port: u16,
    context: &str,
) -> String {
    let name = conv.free_backend_name(&format!("{service}_{port}"));
    let mut backend = super::Backend::default();
    match endpoints.get(&(namespace.to_owned(), service.to_owned())) {
        Some(addresses) if !addresses.is_empty() => {
            for (ip, endpoint_port) in addresses {
                backend.servers.push(super::Server {
                    addr: format!("{ip}:{endpoint_port}"),
                    weight: 1,
                    backup: false,
                    maxconn: 0,
                });
                conv.done(
                    1,
                    format!("Endpoints {service}"),
                    context,
                    format!("servidor {ip}:{endpoint_port} del backend «{name}»"),
                );
            }
        }
        _ => {
            let host = format!("{service}.{namespace}.svc.cluster.local:{port}");
            backend.servers.push(super::Server {
                addr: host.clone(),
                weight: 1,
                backup: false,
                maxconn: 0,
            });
            conv.review(
                1,
                format!("Service {service}:{port}"),
                context,
                format!(
                    "sin Endpoints en el manifiesto: se usa el nombre DNS «{host}» (EQProxy lo re-resuelve en caliente)"
                ),
            );
        }
    }
    conv.add_backend(name.clone(), backend);
    name
}

/// One `nginx.ingress.kubernetes.io/*` annotation.
fn annotation(
    conv: &mut Conv,
    key: &str,
    value: &str,
    context: &str,
    behaviour: &mut Behaviour,
    tls: &mut bool,
) {
    let text = format!("{key}: {value}");
    match key {
        "proxy-connect-timeout" => {
            behaviour.connect_timeout = convert_duration(conv, value, "s", &text, context);
            if behaviour.connect_timeout.is_some() {
                conv.done(1, &text, context, "listener.connect_timeout");
            }
        }
        "proxy-read-timeout" => {
            behaviour.server_header_timeout = convert_duration(conv, value, "s", &text, context);
            if behaviour.server_header_timeout.is_some() {
                conv.review(
                    1,
                    &text,
                    context,
                    "listener.server_header_timeout (aproximado: EQProxy solo acota la cabecera de respuesta)",
                );
            }
        }
        "proxy-send-timeout" => conv.review(
            1,
            &text,
            context,
            "sin equivalente: idle_timeout es el único plazo de inactividad",
        ),
        "proxy-body-size" => match parse_size(value) {
            Some(size) => {
                behaviour.max_body_bytes = Some(size);
                conv.done(
                    1,
                    &text,
                    context,
                    format!("listener.limits.max_body_bytes = {size}"),
                );
            }
            None => conv.review(1, &text, context, "tamaño no reconocido"),
        },
        "ssl-redirect" | "force-ssl-redirect" => {
            if !matches!(value, "false" | "off") {
                *tls = true;
            }
            conv.review(
                1,
                &text,
                context,
                "la redirección 80 → 443 es un listener aparte con reglas redirect; este conversor \
                 genera el listener que sirve tráfico",
            );
        }
        "load-balance" => match value {
            "round_robin" | "roundrobin" => conv.done(
                1,
                &text,
                context,
                "balance = \"roundrobin\" en los backends del Ingress",
            ),
            "least_conn" => conv.done(
                1,
                &text,
                context,
                "balance = \"leastconn\" en los backends del Ingress",
            ),
            other => conv.gap(
                1,
                format!("{key}: {other}"),
                context,
                "algoritmo sin soporte: EQProxy emite roundrobin ponderado",
            ),
        },
        "enable-cors" => {
            if value == "true" {
                behaviour.cors = Some("*".to_owned());
                conv.review(
                    1,
                    &text,
                    context,
                    "regla cors con allow_origin = \"*\" hasta que cors-allow-origin diga otro",
                );
            } else {
                conv.info(1, &text, context, "CORS desactivado");
            }
        }
        "cors-allow-origin" => {
            behaviour.cors = Some(value.to_owned());
            conv.done(
                1,
                &text,
                context,
                "[[listener.*.rules]].cors.allow_origin",
            );
        }
        "cors-allow-methods" | "cors-allow-headers" | "cors-expose-headers" | "cors-max-age"
        | "cors-allow-credentials" => conv.review(
            1,
            &text,
            context,
            "[[listener.*.rules]].cors admite métodos, cabeceras y max_age: transcríbalo a mano",
        ),
        "limit-rps" => match value.parse::<u32>() {
            Ok(rate) => {
                behaviour.rate = Some(rate);
                conv.done(
                    1,
                    &text,
                    context,
                    format!("[[listener.*.rules]].rate_limit rate = {rate}, per = \"1s\""),
                );
            }
            Err(_) => conv.review(1, &text, context, "rate no numérico"),
        },
        "limit-rpm" => match value.parse::<u32>() {
            Ok(rate) => {
                behaviour.rate = Some(rate);
                conv.review(
                    1,
                    &text,
                    context,
                    "rate_limit con per = \"60s\" (el conversor emite per = \"1s\")",
                );
            }
            Err(_) => conv.review(1, &text, context, "rate no numérico"),
        },
        "limit-connections" => conv.review(
            1,
            &text,
            context,
            "límite por cliente: EQProxy solo tiene maxconn por listener",
        ),
        "whitelist-source-range" | "allowlist-source-range" => {
            behaviour.ip = value
                .split(',')
                .map(|item| item.trim().to_owned())
                .filter(|item| !item.is_empty())
                .collect();
            conv.done(
                1,
                &text,
                context,
                "[[listener.*.rules]].ip con los rangos declarados",
            );
        }
        "denylist-source-range" => conv.review(
            1,
            &text,
            context,
            "lista negra: EQProxy expresa la positiva (ip); invierta la regla a mano",
        ),
        "affinity" => match value {
            "cookie" => conv.review(
                1,
                &text,
                context,
                "[backend.*.affinity] mode = \"cookie\" (actívelo en el backend del Ingress)",
            ),
            "ip" => conv.review(
                1,
                &text,
                context,
                "[backend.*.affinity] mode = \"source\"",
            ),
            other => conv.gap(
                1,
                format!("{key}: {other}"),
                context,
                "modo de afinidad sin equivalente",
            ),
        },
        "session-cookie-name" => conv.review(
            1,
            &text,
            context,
            "[backend.*.affinity].cookie con este nombre",
        ),
        "rewrite-target" => {
            behaviour.rewrite = Some(value.to_owned());
            conv.done(
                1,
                &text,
                context,
                "[[listener.*.rules]].rewrite.path_prefix_rewrite",
            );
        }
        "enable-hsts" => {
            if value == "true" {
                *tls = true;
                behaviour.response_headers.push(HeaderOp {
                    name: "Strict-Transport-Security".to_owned(),
                    value: "max-age=31536000".to_owned(),
                });
                conv.done(
                    1,
                    &text,
                    context,
                    "response_headers += Strict-Transport-Security: max-age=31536000",
                );
            } else {
                conv.info(1, &text, context, "HSTS desactivado");
            }
        }
        "hsts-max-age" => {
            for header in &mut behaviour.response_headers {
                if header.name.eq_ignore_ascii_case("Strict-Transport-Security") {
                    header.value = format!("max-age={value}");
                }
            }
            conv.done(
                1,
                &text,
                context,
                "response_headers Strict-Transport-Security max-age",
            );
        }
        "backend-protocol" => match value {
            "AUTO_HTTP" | "HTTP" => conv.info(
                1,
                &text,
                context,
                "HTTP/1.1 al backend (por defecto en EQProxy)",
            ),
            "GRPC" => conv.review(
                1,
                &text,
                context,
                "gRPC: [backend.*.tls].alpn = [\"h2\"] (el listener habla h2 al backend)",
            ),
            "HTTPS" | "AUTO_HTTPS" => conv.review(
                1,
                &text,
                context,
                "[backend.*.tls] (verify/ca_file/server_name) hacia el origen",
            ),
            other => conv.gap(
                1,
                format!("{key}: {other}"),
                context,
                "protocolo de backend sin equivalente",
            ),
        },
        "configuration-snippet" | "server-snippet" | "http-snippet" | "location-snippet" => conv.review(
            1,
            &text,
            context,
            "snippet de nginx: no se ejecuta ni se traduce (sustituto: plugin WASM o reglas)",
        ),
        "proxy-set-headers" | "proxy-hide-headers" | "proxy-pass-headers" => conv.review(
            1,
            &text,
            context,
            "[[listener.*.rules]].set_headers / del_headers: transcríbalo a mano",
        ),
        "proxy-next-upstream" | "proxy-next-upstream-tries" => conv.review(
            1,
            &text,
            context,
            "[backend.*].retries + retry_non_idempotent",
        ),
        "use-regex" | "rewrite-target-regex" => conv.gap(
            1,
            &text,
            context,
            "rutas por expresión regular: EQProxy tiene path_regex, el conversor no traslada la expresión",
        ),
        other => conv.review(
            1,
            format!("{key}: {value}"),
            context,
            format!("anotación «{other}» sin traducción automática: revísela a mano"),
        ),
    }
}

/// The controller ConfigMap (`enable-http2`, `ssl-protocols`, …).
fn global_config(conv: &mut Conv, global: &BTreeMap<String, String>) -> Result<(), ImportError> {
    for (key, value) in global {
        let before = conv.notes.len();
        let text = format!("{key}: {value}");
        match key.as_str() {
            "max-connections" => match value.parse::<u32>() {
                Ok(value) => conv.done(
                    1,
                    &text,
                    "ConfigMap",
                    format!("listener.maxconn = {value}"),
                ),
                Err(_) => conv.review(1, &text, "ConfigMap", "valor no numérico"),
            },
            "proxy-body-size" => conv.done(
                1,
                &text,
                "ConfigMap",
                "listener.limits.max_body_bytes",
            ),
            "keep-alive" => conv.review(
                1,
                &text,
                "ConfigMap",
                "listener.idle_timeout (segundos; nginx habla de keep-alive y EQProxy de inactividad)",
            ),
            "load-balance" => conv.done(
                1,
                &text,
                "ConfigMap",
                "balance por defecto de los backends generados",
            ),
            "ssl-protocols" => conv.review(
                1,
                &text,
                "ConfigMap",
                "[listener.*.tls].min_version (EQProxy nunca acepta TLS 1.0/1.1)",
            ),
            "enable-http2" => conv.review(
                1,
                &text,
                "ConfigMap",
                "[listener.*.tls].alpn con \"h2\" cuando el listener tenga TLS",
            ),
            "access-log" | "log-format-upstream" | "log-format-stream" => conv.review(
                1,
                &text,
                "ConfigMap",
                "[access_log] con format = \"json\" o \"combined\"",
            ),
            "enable-metrics" | "enable-prometheus-metrics" => conv.review(
                1,
                &text,
                "ConfigMap",
                "[admin] (GET /metrics con bearer token) en lugar de exponerlo al público",
            ),
            "use-proxy-protocol" => conv.review(
                1,
                &text,
                "ConfigMap",
                "[listener.*].proxy_receive + proxy_allow (allowlist obligatoria)",
            ),
            "default-ssl-certificate" | "ssl-certificate" => conv.review(
                1,
                &text,
                "ConfigMap",
                "el secreto de Kubernetes no es una ruta: móntelo y rellene [listener.*.tls]",
            ),
            "upstream-keepalive-connections" | "upstream-keepalive-timeout" => conv.info(
                1,
                &text,
                "ConfigMap",
                "el pool de EQProxy es fijo: 64 conexiones idle por servidor, 60 s",
            ),
            "allow-snippet-annotations" => conv.review(
                1,
                &text,
                "ConfigMap",
                "los snippets no se ejecutan: EQProxy los sustituye por plugins WASM y reglas",
            ),
            "proxy-connect-timeout" | "proxy-read-timeout" | "proxy-send-timeout" => conv.review(
                1,
                &text,
                "ConfigMap",
                "timeouts por listener: se aplican en cada [listener.*]",
            ),
            other => conv.review(
                1,
                text.clone(),
                "ConfigMap",
                format!("clave «{other}» sin traducción automática: revísela a mano"),
            ),
        }
        conv.touch(&text, "ConfigMap", before)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_defaults_to_the_default_namespace() {
        let doc = yaml::documents("kind: Ingress\nmetadata:\n  name: web\n")
            .expect("parse")
            .remove(0);
        assert_eq!(metadata(&doc), ("default".to_owned(), "web".to_owned()));
    }

    #[test]
    fn backend_without_endpoints_uses_the_cluster_dns_name() {
        let mut conv = Conv::default();
        let endpoints = BTreeMap::new();
        let name = backend_for(&mut conv, &endpoints, "default", "web", 8080, "Ingress web");
        assert_eq!(name, "web_8080");
        let toml = super::super::emit_toml(&conv);
        assert!(
            toml.contains("web.default.svc.cluster.local:8080"),
            "the DNS fallback must be visible in the output: {toml}"
        );
    }
}
