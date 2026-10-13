//! Validación semántica: referencias inexistentes, rangos y advertencias de
//! configuraciones peligrosas. Errores con línea, campo, causa y ejemplo.

use std::net::SocketAddr;
use std::path::Path;

use crate::error::{ConfigError, Location};
use crate::find_line;
use crate::schema::{Config, MAX_SECTIONS, MAX_SERVER_WEIGHT, SCHEMA_VERSION};

/// Resultado de validar una configuración completa.
#[derive(Debug, Default)]
pub struct CheckResult {
    /// Errores que impiden usar la configuración.
    pub errors: Vec<ConfigError>,
    /// Advertencias: la configuración es usable pero arriesgada.
    pub warnings: Vec<String>,
}

impl CheckResult {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Valida `config` (parseada) contra el texto `source` para poder ubicar líneas.
pub fn check(config: &Config, source: &str, file: &Path) -> CheckResult {
    let mut result = CheckResult::default();

    let sections = config.listener.len() + config.backend.len();
    if sections > MAX_SECTIONS {
        result.errors.push(ConfigError {
            file: file.to_path_buf(),
            location: None,
            field: None,
            cause: format!(
                "demasiadas secciones: {sections} entre [listener.*] y [backend.*] (máximo {MAX_SECTIONS})"
            ),
            example: format!(
                "reduce a {MAX_SECTIONS} secciones combinadas; parte la configuración por servicios (ADR-0002)"
            ),
        });
    }

    let mut err = |field: String, cause: String, example: String, needle: &str| {
        result.errors.push(ConfigError {
            file: file.to_path_buf(),
            location: find_line(source, needle).map(|line| Location { line, column: None }),
            field: Some(field),
            cause,
            example,
        });
    };

    if config.schema_version != SCHEMA_VERSION {
        err(
            "schema_version".to_owned(),
            format!(
                "schema_version = {} no soportado por este binario (soportado: {SCHEMA_VERSION})",
                config.schema_version
            ),
            "schema_version = 1".to_owned(),
            "schema_version",
        );
    }

    if config.listener.is_empty() {
        result
            .warnings
            .push("no hay secciones [listener.*]: el dataplane no aceptará conexiones".to_owned());
    }

    if config.shutdown_grace.is_zero() {
        err(
            "shutdown_grace".to_owned(),
            "shutdown_grace debe ser mayor que 0".to_owned(),
            "shutdown_grace = \"10s\"".to_owned(),
            "shutdown_grace",
        );
    }

    for (name, listener) in &config.listener {
        let section = format!("[listener.{name}]");
        let field = |suffix: &str| format!("listener.{name}.{suffix}");

        if listener.listen.parse::<SocketAddr>().is_err() {
            err(
                field("listen"),
                format!(
                    "«{}» no es una dirección válida (se espera IP:PUERTO)",
                    listener.listen
                ),
                "listen = \"127.0.0.1:8080\"".to_owned(),
                &section,
            );
        }

        // Las validaciones de backend son por sección (no por listener):
        // se comprueban en el bucle de backends de abajo.
        if !config.backend.contains_key(&listener.backend) {
            err(
                field("backend"),
                format!("el backend «{}» no existe", listener.backend),
                format!(
                    "backend = \"{}\" requiere una sección [backend.{}] con server = \"127.0.0.1:9000\"",
                    listener.backend, listener.backend
                ),
                &section,
            );
        }

        if listener.maxconn == 0 {
            err(
                field("maxconn"),
                "maxconn debe ser al menos 1".to_owned(),
                "maxconn = 1024".to_owned(),
                &section,
            );
        }

        if listener.connect_timeout.is_zero() {
            err(
                field("connect_timeout"),
                "connect_timeout debe ser mayor que 0".to_owned(),
                "connect_timeout = \"5s\"".to_owned(),
                &section,
            );
        }

        if listener.idle_timeout.is_zero() {
            err(
                field("idle_timeout"),
                "idle_timeout debe ser mayor que 0".to_owned(),
                "idle_timeout = \"60s\"".to_owned(),
                &section,
            );
        }

        if listener.client_header_timeout.is_zero() {
            err(
                field("client_header_timeout"),
                "client_header_timeout debe ser mayor que 0".to_owned(),
                "client_header_timeout = \"5s\"".to_owned(),
                &section,
            );
        }

        if listener.server_header_timeout.is_zero() {
            err(
                field("server_header_timeout"),
                "server_header_timeout debe ser mayor que 0".to_owned(),
                "server_header_timeout = \"30s\"".to_owned(),
                &section,
            );
        }

        if let Ok(addr) = listener.listen.parse::<SocketAddr>() {
            if !addr.ip().is_loopback() && listener.tls.is_none() {
                result.warnings.push(format!(
                    "listener «{name}» escucha en {addr} sin TLS: expónlo solo en redes de confianza o activa [listener.{name}.tls]"
                ));
            }
            if listener.maxconn > 65_535 {
                result.warnings.push(format!(
                    "listener «{name}» maxconn={} necesita ~{} descriptores; verifica `ulimit -n`",
                    listener.maxconn,
                    u64::from(listener.maxconn) * 2
                ));
            }
        }
    }

    for (name, backend) in &config.backend {
        let section = format!("[backend.{name}]");
        let field = |suffix: &str| format!("backend.{name}.{suffix}");

        match (&backend.server, &backend.servers) {
            (None, None) => err(
                field("server"),
                "el backend no define servidores".to_owned(),
                "server = \"127.0.0.1:9000\" (un servidor) o servers = [{ addr = \"127.0.0.1:9000\", weight = 1 }]".to_owned(),
                &section,
            ),
            (Some(_), Some(_)) => err(
                field("servers"),
                "`server` y `servers` son excluyentes: define solo uno".to_owned(),
                "servers = [{ addr = \"127.0.0.1:9000\", weight = 1 }] (elimina `server`)".to_owned(),
                &section,
            ),
            _ => {}
        }

        if let Some(servers) = &backend.servers
            && servers.is_empty()
        {
            err(
                field("servers"),
                "`servers` está vacío: el backend no tendría destino".to_owned(),
                "servers = [{ addr = \"127.0.0.1:9000\", weight = 1 }]".to_owned(),
                &section,
            );
        }

        let mut seen_addrs = std::collections::BTreeSet::new();
        for (idx, (addr, weight)) in backend.server_entries().into_iter().enumerate() {
            let suffix = if backend.server.is_some() {
                "server".to_owned()
            } else {
                format!("servers[{idx}].addr")
            };
            if addr.parse::<SocketAddr>().is_err() {
                err(
                    field(&suffix),
                    format!("«{addr}» no es una dirección válida (se espera IP:PUERTO)"),
                    "addr = \"127.0.0.1:9000\"".to_owned(),
                    &section,
                );
            }
            if weight > MAX_SERVER_WEIGHT {
                err(
                    field(&format!("servers[{idx}].weight")),
                    format!("weight = {weight} fuera de rango (máximo {MAX_SERVER_WEIGHT})"),
                    "weight = 1 (rango 0..=256; 0 = drenado)".to_owned(),
                    &section,
                );
            }
            if !seen_addrs.insert(addr) {
                err(
                    field(&suffix),
                    format!("servidor duplicado: «{addr}» aparece más de una vez"),
                    "cada `addr` debe ser única dentro del backend".to_owned(),
                    &section,
                );
            }
        }

        if let Some(hc) = &backend.health_check {
            if hc.interval.is_zero() {
                err(
                    field("health_check.interval"),
                    "health_check.interval debe ser mayor que 0".to_owned(),
                    "interval = \"2s\"".to_owned(),
                    &section,
                );
            }
            if hc.timeout.is_zero() {
                err(
                    field("health_check.timeout"),
                    "health_check.timeout debe ser mayor que 0".to_owned(),
                    "timeout = \"1s\"".to_owned(),
                    &section,
                );
            }
            if hc.fall == 0 {
                err(
                    field("health_check.fall"),
                    "health_check.fall debe ser al menos 1".to_owned(),
                    "fall = 3".to_owned(),
                    &section,
                );
            }
            if hc.rise == 0 {
                err(
                    field("health_check.rise"),
                    "health_check.rise debe ser al menos 1".to_owned(),
                    "rise = 2".to_owned(),
                    &section,
                );
            }
        }

        if let Some(tls) = &backend.tls {
            for (cause, example) in alpn_problems(&tls.alpn) {
                err(field("tls.alpn"), cause, example, &section);
            }
            if !tls.verify && tls.ca_file.is_some() {
                result.warnings.push(format!(
                    "backend «{name}» define ca_file pero verify = false: la CA no se usa y el backend no se verifica"
                ));
            }
        }
    }

    for (name, listener) in &config.listener {
        if let Some(tls) = &listener.tls {
            let section = format!("[listener.{name}]");
            for (cause, example) in alpn_problems(&tls.alpn) {
                err(
                    format!("listener.{name}.tls.alpn"),
                    cause,
                    example,
                    &section,
                );
            }
        }
    }

    result
}

/// Problemas de una lista ALPN: nombres no vacíos, sin duplicados (A14).
/// Devuelve pares (causa, ejemplo) para insertarlos con el contexto de error.
fn alpn_problems(alpn: &[String]) -> Vec<(String, String)> {
    let mut problems = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for proto in alpn {
        if proto.is_empty() || proto.len() > 255 {
            problems.push((
                format!("protocolo ALPN «{proto}» inválido: debe tener 1..=255 bytes"),
                "alpn = [\"http/1.1\"]".to_owned(),
            ));
        }
        if !seen.insert(proto.as_str()) {
            problems.push((
                format!("protocolo ALPN duplicado: «{proto}»"),
                "alpn = [\"http/1.1\"]".to_owned(),
            ));
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_str;
    use crate::schema::{BackendConfig, ListenerConfig, ListenerMode};
    use std::path::PathBuf;
    use std::time::Duration;

    fn check_source(source: &str) -> CheckResult {
        let file = PathBuf::from("eqproxy.toml");
        let config = parse_str(source, &file).expect("toml válido");
        check(&config, source, &file)
    }

    /// Config con `listeners` [listener.*] y `backends` [backend.*] construida
    /// directamente: el presupuesto vive en `check`, y parsear miles de
    /// secciones TOML bajo el intérprete de miri es coste puro.
    fn config_with_sections(listeners: usize, backends: usize) -> Config {
        use std::collections::BTreeMap;
        let mut config = Config {
            schema_version: SCHEMA_VERSION,
            listener: BTreeMap::new(),
            backend: BTreeMap::new(),
            shutdown_grace: Duration::from_secs(10),
        };
        for i in 0..backends {
            config.backend.insert(
                format!("b{i}"),
                BackendConfig {
                    server: Some("127.0.0.1:9000".to_owned()),
                    ..BackendConfig::default()
                },
            );
        }
        for i in 0..listeners {
            config.listener.insert(
                format!("l{i}"),
                ListenerConfig {
                    listen: "127.0.0.1:0".to_owned(),
                    mode: ListenerMode::Tcp,
                    backend: "b0".to_owned(),
                    maxconn: 1024,
                    connect_timeout: Duration::from_secs(5),
                    idle_timeout: Duration::from_secs(60),
                    client_header_timeout: Duration::from_secs(5),
                    server_header_timeout: Duration::from_secs(30),
                    tls: None,
                },
            );
        }
        config
    }

    fn check_config(config: &Config) -> CheckResult {
        check(config, "", Path::new("eqproxy.toml"))
    }

    #[test]
    fn valid_config_has_no_errors() {
        let result = check_source(
            r#"
schema_version = 1

[listener.web]
listen = "127.0.0.1:8080"
backend = "api"

[backend.api]
server = "127.0.0.1:9000"
"#,
        );
        assert!(result.is_valid(), "errores: {:?}", result.errors);
    }

    #[test]
    fn missing_backend_is_reported_with_line_field_cause_example() {
        let source = "schema_version = 1\n\n[listener.web]\nlisten = \"127.0.0.1:8080\"\nbackend = \"fantasma\"\n";
        let result = check_source(source);
        assert!(!result.is_valid());
        let err = &result.errors[0];
        assert_eq!(err.field.as_deref(), Some("listener.web.backend"));
        let loc = err.location.as_ref().expect("debe ubicar la línea");
        assert_eq!(loc.line, 3, "línea de [listener.web]: {source:?}");
        assert!(err.cause.contains("fantasma"), "causa: {}", err.cause);
        assert!(
            err.example.contains("[backend.fantasma]"),
            "ejemplo: {}",
            err.example
        );
    }

    #[test]
    fn bad_listen_address_is_reported() {
        let result = check_source(
            "schema_version = 1\n[listener.web]\nlisten = \"80x\"\nbackend = \"api\"\n[backend.api]\nserver = \"127.0.0.1:1\"\n",
        );
        let err = &result.errors[0];
        assert_eq!(err.field.as_deref(), Some("listener.web.listen"));
        assert!(err.example.contains("listen = \"127.0.0.1:8080\""));
    }

    #[test]
    fn zero_timeouts_and_maxconn_are_reported() {
        let result = check_source(
            "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\nmaxconn = 0\nconnect_timeout = \"0s\"\nidle_timeout = \"0ms\"\n[backend.api]\nserver = \"127.0.0.1:1\"\n",
        );
        let fields: Vec<_> = result
            .errors
            .iter()
            .filter_map(|e| e.field.clone())
            .collect();
        assert_eq!(
            fields,
            vec![
                "listener.web.maxconn",
                "listener.web.connect_timeout",
                "listener.web.idle_timeout"
            ]
        );
    }

    #[test]
    fn wrong_schema_version_is_reported() {
        let result = check_source("schema_version = 99\n");
        assert!(!result.is_valid());
        assert_eq!(result.errors[0].field.as_deref(), Some("schema_version"));
    }

    #[test]
    fn too_many_sections_are_rejected_with_budget_reason() {
        let result = check_config(&config_with_sections(MAX_SECTIONS + 1, 1));
        assert!(!result.is_valid());
        let err = result
            .errors
            .iter()
            .find(|e| e.cause.contains("demasiadas secciones"))
            .expect("debe reportar el presupuesto de secciones");
        assert!(err.example.contains("ADR-0002"), "ejemplo: {}", err.example);
    }

    #[test]
    fn sections_at_the_budget_are_accepted() {
        let result = check_config(&config_with_sections(MAX_SECTIONS - 1, 1));
        assert!(result.is_valid(), "errores: {:?}", result.errors);
    }

    #[test]
    fn budget_counts_listeners_and_backends_by_their_sum() {
        // 1025 [listener.*] sin [backend.*]: la suma (1025) excede el
        // presupuesto aunque el producto sea 0 — cuenta secciones combinadas.
        let result = check_config(&config_with_sections(MAX_SECTIONS + 1, 0));
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.cause.contains("demasiadas secciones")),
            "esperaba error de presupuesto: {:?}",
            result.errors
        );
    }

    #[test]
    fn maxconn_descriptor_warning_fires_only_above_65535() {
        let config_with = |maxconn: u32| {
            format!(
                "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:8080\"\nbackend = \"api\"\nmaxconn = {maxconn}\n\n[backend.api]\nserver = \"127.0.0.1:9000\"\n"
            )
        };
        let at = check_source(&config_with(65_535));
        assert!(
            !at.warnings.iter().any(|w| w.contains("descriptores")),
            "a 65535 no debe avisar: {:?}",
            at.warnings
        );
        let above = check_source(&config_with(65_536));
        assert!(
            above.warnings.iter().any(|w| w.contains("descriptores")),
            "a 65536 debe avisar: {:?}",
            above.warnings
        );
    }

    #[test]
    fn server_and_servers_are_exclusive() {
        let both = check_source(
            "schema_version = 1\n[backend.api]\nserver = \"127.0.0.1:1\"\nservers = [{ addr = \"127.0.0.1:2\" }]\n",
        );
        assert!(!both.is_valid());
        assert_eq!(both.errors[0].field.as_deref(), Some("backend.api.servers"));

        let neither = check_source("schema_version = 1\n[backend.api]\nbalance = \"roundrobin\"\n");
        assert!(!neither.is_valid());
        assert_eq!(
            neither.errors[0].field.as_deref(),
            Some("backend.api.server")
        );
    }

    #[test]
    fn servers_list_is_validated_for_emptiness_addresses_weights_and_dupes() {
        let empty = check_source("schema_version = 1\n[backend.api]\nservers = []\n");
        assert!(
            empty
                .errors
                .iter()
                .any(|e| e.field.as_deref() == Some("backend.api.servers")),
            "errors: {:?}",
            empty.errors
        );

        let bad = check_source(
            "schema_version = 1\n[backend.api]\nservers = [{ addr = \"80x\", weight = 1 }, { addr = \"127.0.0.1:2\", weight = 257 }, { addr = \"127.0.0.1:2\" }]\n",
        );
        let fields: Vec<_> = bad.errors.iter().filter_map(|e| e.field.clone()).collect();
        assert_eq!(
            fields,
            vec![
                "backend.api.servers[0].addr",
                "backend.api.servers[1].weight",
                "backend.api.servers[2].addr",
            ],
            "errores: {:?}",
            bad.errors
        );

        let ok = check_source(
            "schema_version = 1\n[backend.api]\nservers = [{ addr = \"127.0.0.1:1\", weight = 3 }, { addr = \"127.0.0.1:2\", weight = 0 }]\n",
        );
        assert!(ok.is_valid(), "errores: {:?}", ok.errors);
    }

    #[test]
    fn health_check_values_must_be_positive() {
        let result = check_source(
            "schema_version = 1\n[backend.api]\nserver = \"127.0.0.1:1\"\n[backend.api.health_check]\ninterval = \"0s\"\ntimeout = \"0ms\"\nfall = 0\nrise = 0\n",
        );
        let fields: Vec<_> = result
            .errors
            .iter()
            .filter_map(|e| e.field.clone())
            .collect();
        assert_eq!(
            fields,
            vec![
                "backend.api.health_check.interval",
                "backend.api.health_check.timeout",
                "backend.api.health_check.fall",
                "backend.api.health_check.rise",
            ]
        );
    }

    #[test]
    fn alpn_lists_reject_empty_and_duplicate_protocols() {
        let result = check_source(
            "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\n[listener.web.tls]\ncert = \"c.pem\"\nkey = \"k.pem\"\nalpn = [\"http/1.1\", \"http/1.1\", \"\"]\n[backend.api]\nserver = \"127.0.0.1:1\"\n",
        );
        let alpn_errors: Vec<_> = result
            .errors
            .iter()
            .filter(|e| e.field.as_deref().is_some_and(|f| f.ends_with("tls.alpn")))
            .collect();
        assert_eq!(alpn_errors.len(), 2, "errores: {:?}", result.errors);
        assert!(alpn_errors[0].cause.contains("duplicado"));
        assert!(alpn_errors[1].cause.contains("inválido"));
    }

    #[test]
    fn non_loopback_listener_without_tls_warns_but_with_tls_does_not() {
        let plain = check_source(
            "schema_version = 1\n[listener.web]\nlisten = \"0.0.0.0:8080\"\nbackend = \"api\"\n[backend.api]\nserver = \"127.0.0.1:1\"\n",
        );
        assert!(plain.is_valid());
        assert!(
            plain.warnings.iter().any(|w| w.contains("sin TLS")),
            "warnings: {:?}",
            plain.warnings
        );

        let with_tls = check_source(
            "schema_version = 1\n[listener.web]\nlisten = \"0.0.0.0:8080\"\nbackend = \"api\"\n[listener.web.tls]\ncert = \"c.pem\"\nkey = \"k.pem\"\n[backend.api]\nserver = \"127.0.0.1:1\"\n",
        );
        assert!(with_tls.is_valid());
        assert!(
            !with_tls.warnings.iter().any(|w| w.contains("sin TLS")),
            "warnings: {:?}",
            with_tls.warnings
        );
    }

    #[test]
    fn dangerous_configs_produce_warnings_not_errors() {
        let result = check_source(
            "schema_version = 1\n[listener.web]\nlisten = \"0.0.0.0:8080\"\nbackend = \"api\"\nmaxconn = 100000\n[backend.api]\nserver = \"127.0.0.1:1\"\n",
        );
        assert!(result.is_valid(), "errores: {:?}", result.errors);
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("redes de confianza")),
            "warnings: {:?}",
            result.warnings
        );
        assert!(
            result.warnings.iter().any(|w| w.contains("ulimit")),
            "warnings: {:?}",
            result.warnings
        );
    }
}
