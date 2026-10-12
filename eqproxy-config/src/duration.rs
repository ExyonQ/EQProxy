//! Duraciones en formato legible: `500ms`, `5s`, `2m`, `1h`.
//!
//! Solo enteros y sufijos exactos: sin ambigüedad de tipado (ADR-0002, C4).

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serializer};

/// Ejemplo canónico para mensajes de error.
pub const EXAMPLE: &str = "\"5s\" (sufijos válidos: ms, s, m, h)";

/// Error de parseo de duración (causa; el ejemplo lo añade la capa de config).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurationParseError {
    pub input: String,
}

impl fmt::Display for DurationParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "«{}» no es una duración válida", self.input)
    }
}

impl std::error::Error for DurationParseError {}

/// Parsea duraciones como `"<entero><ms|s|m|h>"`.
pub fn parse(input: &str) -> Result<Duration, DurationParseError> {
    let trimmed = input.trim();
    let err = || DurationParseError {
        input: input.to_owned(),
    };
    if trimmed.is_empty() {
        return Err(err());
    }
    let split = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let (number, suffix) = trimmed.split_at(split);
    let Ok(value) = number.parse::<u64>() else {
        return Err(err());
    };
    let millis = match suffix {
        "ms" => Some(value),
        "s" => value.checked_mul(1_000),
        "m" => value.checked_mul(60_000),
        "h" => value.checked_mul(3_600_000),
        _ => return Err(err()),
    };
    match millis {
        Some(ms) => Ok(Duration::from_millis(ms)),
        None => Err(err()),
    }
}

/// Deserializa un campo `String` en [`Duration`] con errores explicables.
pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Duration, D::Error> {
    let raw = String::deserialize(de)?;
    parse(&raw).map_err(|e| serde::de::Error::custom(format!("{e}; ejemplo: {EXAMPLE}")))
}

/// Serializa una duración como milisegundos (para `config export` futuro).
pub fn serialize<S: Serializer>(value: &Duration, ser: S) -> Result<S::Ok, S::Error> {
    ser.serialize_str(&format!("{}ms", value.as_millis()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_accepted_forms() {
        assert_eq!(parse("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse(" 10s ").unwrap(), Duration::from_secs(10));
    }

    #[test]
    fn rejects_invalid_forms_with_named_input() {
        for bad in [
            "",
            "5",
            "5x",
            "s",
            "1.5s",
            "-5s",
            "cinco s",
            "99999999999999999h",
        ] {
            let err = parse(bad).expect_err("debe rechazar");
            assert_eq!(err.input, bad);
        }
    }
}
