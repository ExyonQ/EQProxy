//! Actionable configuration error: file, line, field, cause and example.

use std::fmt;
use std::path::PathBuf;

/// Location in the source file (1-based).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    pub line: usize,
    pub column: Option<usize>,
}

/// Configuration error with all the context needed to fix it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// Affected configuration file.
    pub file: PathBuf,
    /// Line (and column) when known.
    pub location: Option<Location>,
    /// Involved field, with serde path (e.g. `listener.web.listen`).
    pub field: Option<String>,
    /// What failed.
    pub cause: String,
    /// Fix example ready to copy.
    pub example: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "configuration error in {}", self.file.display())?;
        if let Some(loc) = &self.location {
            write!(f, ":{}", loc.line)?;
            if let Some(col) = loc.column {
                write!(f, ":{col}")?;
            }
        }
        if let Some(field) = &self.field {
            write!(f, " — field `{field}`")?;
        }
        write!(f, ": {}", self.cause)?;
        write!(f, "\n  example: {}", self.example)
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
            cause: "is not an address".to_owned(),
            example: "listen = \"127.0.0.1:8080\"".to_owned(),
        };
        let shown = err.to_string();
        for expected in [
            "eqproxy.toml:12:3",
            "listener.web.listen",
            "is not an address",
            "example: listen = \"127.0.0.1:8080\"",
        ] {
            assert!(shown.contains(expected), "missing {expected:?} in: {shown}");
        }
    }
}
