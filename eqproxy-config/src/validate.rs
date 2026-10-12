//! Validación semántica: referencias inexistentes, rangos y advertencias de
//! configuraciones peligrosas. Errores con línea, campo, causa y ejemplo.

use std::net::SocketAddr;
use std::path::Path;

use crate::error::{ConfigError, Location};
use crate::find_line;
use crate::schema::{Config, SCHEMA_VERSION};

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

        match config.backend.get(&listener.backend) {
            None => err(
                field("backend"),
                format!("el backend «{}» no existe", listener.backend),
                format!(
                    "backend = \"{}\" requiere una sección [backend.{}] con server = \"127.0.0.1:9000\"",
                    listener.backend, listener.backend
                ),
                &section,
            ),
            Some(backend) => {
                if backend.server.parse::<SocketAddr>().is_err() {
                    err(
                        format!("backend.{}.server", listener.backend),
                        format!(
                            "«{}» no es una dirección válida (se espera IP:PUERTO)",
                            backend.server
                        ),
                        "server = \"127.0.0.1:9000\"".to_owned(),
                        &format!("[backend.{}]", listener.backend),
                    );
                }
            }
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

        if let Ok(addr) = listener.listen.parse::<SocketAddr>() {
            if !addr.ip().is_loopback() {
                result.warnings.push(format!(
                    "listener «{name}» escucha en {addr}: sin TLS ni PROXY protocol (Fase 2+), expónlo solo en redes de confianza"
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

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_str;
    use std::path::PathBuf;

    fn check_source(source: &str) -> CheckResult {
        let file = PathBuf::from("eqproxy.toml");
        let config = parse_str(source, &file).expect("toml válido");
        check(&config, source, &file)
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
