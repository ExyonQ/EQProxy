//! Error de configuración accionable: archivo, línea, campo, causa y ejemplo.

use std::fmt;
use std::path::PathBuf;

/// Ubicación en el archivo fuente (1-based).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    pub line: usize,
    pub column: Option<usize>,
}

/// Error de configuración con todo el contexto necesario para corregirlo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// Archivo de configuración afectado.
    pub file: PathBuf,
    /// Línea (y columna) cuando se conoce.
    pub location: Option<Location>,
    /// Campo implicado, con ruta serde (p. ej. `listener.web.listen`).
    pub field: Option<String>,
    /// Qué ha fallado.
    pub cause: String,
    /// Ejemplo de corrección listo para copiar.
    pub example: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error de configuración en {}", self.file.display())?;
        if let Some(loc) = &self.location {
            write!(f, ":{}", loc.line)?;
            if let Some(col) = loc.column {
                write!(f, ":{col}")?;
            }
        }
        if let Some(field) = &self.field {
            write!(f, " — campo `{field}`")?;
        }
        write!(f, ": {}", self.cause)?;
        write!(f, "\n  ejemplo: {}", self.example)
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_includes_file_line_field_cause_example() {
        let err = ConfigError {
            file: PathBuf::from("eqproxy.toml"),
            location: Some(Location {
                line: 12,
                column: Some(3),
            }),
            field: Some("listener.web.listen".to_owned()),
            cause: "no es una dirección".to_owned(),
            example: "listen = \"127.0.0.1:8080\"".to_owned(),
        };
        let shown = err.to_string();
        for expected in [
            "eqproxy.toml:12:3",
            "listener.web.listen",
            "no es una dirección",
            "ejemplo: listen = \"127.0.0.1:8080\"",
        ] {
            assert!(shown.contains(expected), "falta {expected:?} en: {shown}");
        }
    }
}
