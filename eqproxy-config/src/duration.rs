//! Human-readable durations: `500ms`, `5s`, `2m`, `1h`.
//!
//! Only integers and exact suffixes: no typing ambiguity (ADR-0002, C4).

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serializer};

/// Canonical example for error messages.
pub const EXAMPLE: &str = "\"5s\" (valid suffixes: ms, s, m, h)";

/// Duration parse error (cause; the config layer adds the example).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurationParseError {
    pub input: String,
}

impl fmt::Display for DurationParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\" is not a valid duration", self.input)
    }
}

impl std::error::Error for DurationParseError {}

/// Parses durations like `"<integer><ms|s|m|h>"`.
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

/// Deserializes a `String` field into [`Duration`] with explainable errors.
pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Duration, D::Error> {
    let raw = String::deserialize(de)?;
    parse(&raw).map_err(|e| serde::de::Error::custom(format!("{e}; example: {EXAMPLE}")))
}

/// Serializes a duration as milliseconds (for a future `config export`).
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
            "five s",
            "99999999999999999h",
        ] {
            let err = parse(bad).expect_err("must reject");
            assert_eq!(err.input, bad);
        }
    }
}
