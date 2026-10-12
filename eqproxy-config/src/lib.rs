//! Configuración de EQProxy: esquema TOML tipado, validación semántica y
//! errores con archivo, línea, campo, causa y ejemplo de corrección.
//!
//! Decisión de formato: ADR-0002 (TOML canónico). Código 100 % safe Rust.

#![forbid(unsafe_code)]

pub mod duration;
pub mod error;
pub mod schema;
pub mod validate;

use std::path::Path;

pub use error::{ConfigError, Location};
pub use schema::{
    BackendConfig, Config, ListenerConfig, ListenerMode, MAX_CONFIG_BYTES, MAX_SECTIONS,
    SCHEMA_VERSION,
};
pub use validate::CheckResult;

/// Carga y parsea un archivo de configuración TOML.
///
/// La validación semántica (referencias, rangos, advertencias) se ejecuta con
/// [`check`]; este parseo solo garantiza estructura y tipos.
pub fn load(path: impl AsRef<Path>) -> Result<Config, ConfigError> {
    let path = path.as_ref();
    let meta = std::fs::metadata(path).map_err(|e| ConfigError {
        file: path.to_path_buf(),
        location: None,
        field: None,
        cause: format!("no se pudo leer el archivo: {e}"),
        example: "crea un eqproxy.toml (ver eqproxy.toml.example) y pasa --config <ruta>"
            .to_owned(),
    })?;
    if meta.len() > MAX_CONFIG_BYTES as u64 {
        return Err(oversized(path, meta.len() as usize));
    }
    let source = std::fs::read_to_string(path).map_err(|e| ConfigError {
        file: path.to_path_buf(),
        location: None,
        field: None,
        cause: format!("no se pudo leer el archivo: {e}"),
        example: "crea un eqproxy.toml (ver eqproxy.toml.example) y pasa --config <ruta>"
            .to_owned(),
    })?;
    parse_str(&source, path)
}

/// Parsea texto TOML ya leído. `file` solo se usa para los mensajes de error.
pub fn parse_str(source: &str, file: &Path) -> Result<Config, ConfigError> {
    if source.len() > MAX_CONFIG_BYTES {
        return Err(oversized(file, source.len()));
    }
    let deserializer = toml::de::Deserializer::new(source);
    match serde_path_to_error::deserialize(deserializer) {
        Ok(config) => Ok(config),
        Err(err) => {
            let field_path = err.path().to_string();
            let inner = err.into_inner();
            let location = inner
                .span()
                .and_then(|span| offset_location(source, span.start));
            let cause = inner.to_string();
            Err(ConfigError {
                file: file.to_path_buf(),
                location,
                example: example_for(&field_path, &cause),
                field: if field_path.is_empty() {
                    None
                } else {
                    Some(field_path)
                },
                cause,
            })
        }
    }
}

/// Error de configuración excedida del presupuesto de recursos (ADR-0002).
fn oversized(file: &Path, size: usize) -> ConfigError {
    ConfigError {
        file: file.to_path_buf(),
        location: None,
        field: None,
        cause: format!("configuración demasiado grande: {size} bytes (máximo {MAX_CONFIG_BYTES})"),
        example: "reduce el archivo o divídelo por servicios; el límite es 1 MiB (ADR-0002)"
            .to_owned(),
    }
}

/// Traduce un offset de byte del texto a línea/columna (1-based).
#[must_use]
pub fn offset_location(source: &str, offset: usize) -> Option<Location> {
    let mut consumed = 0usize;
    for (idx, line) in source.lines().enumerate() {
        let line_len = line.len() + 1;
        if offset < consumed + line_len {
            return Some(Location {
                line: idx + 1,
                column: Some(offset - consumed + 1),
            });
        }
        consumed += line_len;
    }
    None
}

/// Busca la primera línea que contiene `needle` (1-based) para errores
/// semánticos, que no disponen de offset del parser.
#[must_use]
pub fn find_line(source: &str, needle: &str) -> Option<usize> {
    source
        .lines()
        .position(|line| line.contains(needle))
        .map(|idx| idx + 1)
}

/// Ejemplo de corrección según el campo y el mensaje del parser.
fn example_for(field_path: &str, cause: &str) -> String {
    let last = field_path.rsplit('.').next().unwrap_or_default();
    let cause_lower = cause.to_ascii_lowercase();
    if cause_lower.contains("missing field") {
        return match last {
            "listen" => "listen = \"127.0.0.1:8080\"".to_owned(),
            "backend" => "backend = \"api\"".to_owned(),
            "server" => "server = \"127.0.0.1:9000\"".to_owned(),
            "schema_version" => "schema_version = 1".to_owned(),
            _ => "verifica los campos obligatorios en eqproxy.toml.example".to_owned(),
        };
    }
    if cause_lower.contains("unknown field") {
        return "elimina o corrige el nombre del campo; los campos válidos están en eqproxy.toml.example"
            .to_owned();
    }
    match last {
        "listen" | "server" => "listen = \"127.0.0.1:8080\" (formato IP:PUERTO)".to_owned(),
        "connect_timeout"
        | "idle_timeout"
        | "shutdown_grace"
        | "client_header_timeout"
        | "server_header_timeout" => {
            format!("{last} = \"5s\" (sufijos válidos: ms, s, m, h)")
        }
        "maxconn" => "maxconn = 1024".to_owned(),
        "mode" => "mode = \"tcp\" (o \"http\")".to_owned(),
        "schema_version" => "schema_version = 1".to_owned(),
        _ => "ver eqproxy.toml.example".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn offset_location_maps_offsets_to_line_and_column() {
        let source = "a = 1\nbb = 2\n";
        let loc = offset_location(source, 8).expect("offset dentro del texto");
        assert_eq!(loc.line, 2);
        assert_eq!(loc.column, Some(3));
    }

    #[test]
    fn find_line_reports_first_match() {
        let source = "[listener.web]\nlisten = \"127.0.0.1:1\"\n";
        assert_eq!(find_line(source, "[listener.web]"), Some(1));
        assert_eq!(find_line(source, "[listener.nope]"), None);
    }

    #[test]
    fn parse_str_returns_config_on_valid_toml() {
        let source = "schema_version = 1\n";
        let cfg = parse_str(source, &PathBuf::from("t.toml")).expect("debe parsear");
        assert_eq!(cfg.schema_version, 1);
    }

    #[test]
    fn oversized_source_is_rejected_with_actionable_error() {
        let file = PathBuf::from("grande.toml");
        let source = "x".repeat(MAX_CONFIG_BYTES + 1);
        let err = parse_str(&source, &file).expect_err("debe rechazar");
        assert!(
            err.cause.contains("demasiado grande"),
            "causa: {}",
            err.cause
        );
        assert!(err.example.contains("1 MiB"), "ejemplo: {}", err.example);
    }

    #[test]
    fn source_at_the_limit_is_accepted() {
        let file = PathBuf::from("limite.toml");
        let mut source = String::from("schema_version = 1\n");
        source.push_str(&"#".repeat(MAX_CONFIG_BYTES - source.len()));
        assert_eq!(source.len(), MAX_CONFIG_BYTES);
        let cfg = parse_str(&source, &file).expect("en el límite debe parsear");
        assert_eq!(cfg.schema_version, 1);
    }
}
