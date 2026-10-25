//! EQProxy configuration: typed TOML schema, semantic validation and
//! errors with file, line, field, cause and fix example.
//!
//! Format decision: ADR-0002 (canonical TOML). 100 % safe Rust code.

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

/// Loads and parses a TOML configuration file.
///
/// Semantic validation (references, ranges, warnings) runs in
/// [`check`]; this parse only guarantees structure and types.
pub fn load(path: impl AsRef<Path>) -> Result<Config, ConfigError> {
    let path = path.as_ref();
    let meta = std::fs::metadata(path).map_err(|e| ConfigError {
        file: path.to_path_buf(),
        location: None,
        field: None,
        cause: format!("could not read the file: {e}"),
        example: "create an eqproxy.toml (see eqproxy.toml.example) and pass --config <path>"
            .to_owned(),
    })?;
    if meta.len() > MAX_CONFIG_BYTES as u64 {
        return Err(oversized(path, meta.len() as usize));
    }
    let source = std::fs::read_to_string(path).map_err(|e| ConfigError {
        file: path.to_path_buf(),
        location: None,
        field: None,
        cause: format!("could not read the file: {e}"),
        example: "create an eqproxy.toml (see eqproxy.toml.example) and pass --config <path>"
            .to_owned(),
    })?;
    parse_str(&source, path)
}

/// Parses already-read TOML text. `file` is only used for error messages.
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

/// Parses one `[backend.<name>]` table for a hot write (ADR-0019).
///
/// Accepts both shapes an operator has at hand: the **body** of the table
/// (`server = "…"`, nested tables as inline tables or `[tls]` headers) and the
/// **complete section** copied from the file (`[backend.<name>]` and its
/// nested `[backend.<name>.…]` tables). The caller inserts the result into a
/// candidate document and validates the whole document.
pub fn parse_backend_table(
    source: &str,
    file: &Path,
    name: &str,
) -> Result<BackendConfig, ConfigError> {
    parse_table(source, file, "backend", name)
}

/// Parses one `[listener.<name>]` table for a hot write (ADR-0019).
pub fn parse_listener_table(
    source: &str,
    file: &Path,
    name: &str,
) -> Result<ListenerConfig, ConfigError> {
    parse_table(source, file, "listener", name)
}

/// One table, with the same field-path and example reporting as a whole
/// document. Line numbers are absent: the body arrived over HTTP, not from a
/// file with numbered lines. A body that carries the section itself is
/// unwrapped, so a copy-paste from the config keeps working; a body with only
/// that table's keys is used as-is.
fn parse_table<T: serde::de::DeserializeOwned>(
    source: &str,
    file: &Path,
    kind: &str,
    name: &str,
) -> Result<T, ConfigError> {
    let section = format!("{kind}.{name}");
    let value = toml::from_str::<toml::Value>(source).map_err(|err| ConfigError {
        file: file.to_path_buf(),
        location: err
            .span()
            .and_then(|span| offset_location(source, span.start)),
        example: example_for(&section, &err.to_string()),
        field: Some(section.clone()),
        cause: err.to_string(),
    })?;
    let unwrapped = value
        .get(kind)
        .and_then(|tables| tables.get(name))
        .cloned()
        .unwrap_or(value);
    match serde_path_to_error::deserialize(unwrapped) {
        Ok(value) => Ok(value),
        Err(err) => {
            let reported = err.path().to_string();
            let inner = err.into_inner();
            let cause = inner.to_string();
            // The caller may have sent the section header (`backend.api.…`);
            // strip one copy so the field is named exactly once. A missing
            // field reports `"."`, which is no path at all.
            let prefix = format!("{section}.");
            let trimmed = reported.trim_matches('.');
            let rest = trimmed.strip_prefix(&prefix).unwrap_or(trimmed);
            let rest = rest.trim_matches('.');
            let field = if rest.is_empty() {
                section.clone()
            } else {
                format!("{section}.{rest}")
            };
            Err(ConfigError {
                file: file.to_path_buf(),
                location: None,
                example: example_for(&field, &cause),
                field: Some(field),
                cause,
            })
        }
    }
}

/// Configuration error exceeding the resource budget (ADR-0002).
fn oversized(file: &Path, size: usize) -> ConfigError {
    ConfigError {
        file: file.to_path_buf(),
        location: None,
        field: None,
        cause: format!("configuration too large: {size} bytes (maximum {MAX_CONFIG_BYTES})"),
        example: "shrink the file or split it per service; the limit is 1 MiB (ADR-0002)"
            .to_owned(),
    }
}

/// Translates a byte offset in the text to line/column (1-based).
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

/// Finds the first line containing `needle` (1-based) for semantic
/// errors, which have no parser offset.
#[must_use]
pub fn find_line(source: &str, needle: &str) -> Option<usize> {
    source
        .lines()
        .position(|line| line.contains(needle))
        .map(|idx| idx + 1)
}

/// Fix example by field and parser message.
fn example_for(field_path: &str, cause: &str) -> String {
    let last = field_path.rsplit('.').next().unwrap_or_default();
    let cause_lower = cause.to_ascii_lowercase();
    if cause_lower.contains("missing field") {
        return match last {
            "listen" => "listen = \"127.0.0.1:8080\"".to_owned(),
            "backend" => "backend = \"api\"".to_owned(),
            "server" => "server = \"127.0.0.1:9000\"".to_owned(),
            "schema_version" => "schema_version = 1".to_owned(),
            _ => "check the required fields in eqproxy.toml.example".to_owned(),
        };
    }
    if cause_lower.contains("unknown field") {
        return "remove or fix the field name; the valid fields are in eqproxy.toml.example"
            .to_owned();
    }
    match last {
        "listen" | "server" => "listen = \"127.0.0.1:8080\" (IP:PORT format)".to_owned(),
        "connect_timeout"
        | "idle_timeout"
        | "shutdown_grace"
        | "client_header_timeout"
        | "server_header_timeout"
        | "max_stream_duration" => {
            format!("{last} = \"5s\" (valid suffixes: ms, s, m, h)")
        }
        "maxconn" => "maxconn = 1024".to_owned(),
        "mode" => "mode = \"tcp\" (or \"http\")".to_owned(),
        "schema_version" => "schema_version = 1".to_owned(),
        _ => "see eqproxy.toml.example".to_owned(),
    }
}

/// Public JSON Schema of the configuration (Q1/CE1), generated **from the
/// same Rust types** the parser deserializes — it cannot drift from the
/// accepted format the way a hand-written schema would.
///
/// Editors use it for completion and inline validation of `eqproxy.toml`
/// (Taplo/Even Better TOML: a `#:schema ./eqproxy.schema.json` first line,
/// or pointing the editor at the file). `deny_unknown_fields` is reflected
/// as `additionalProperties: false`, so a typo is flagged before the gate
/// rejects it.
pub fn json_schema() -> Result<String, serde_json::Error> {
    let schema = schemars::schema_for!(Config);
    // Reported, never swallowed: a rendering failure would otherwise print
    // an empty schema as if it were the real one.
    serde_json::to_string_pretty(&schema)
}

/// Repository copy of [`json_schema`], byte-for-byte (the test in this
/// crate is the drift gate: generating a different schema fails it).
pub const SCHEMA_FILE: &str = include_str!("../../eqproxy.schema.json");

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn backend_table_accepts_the_body_and_the_whole_section() {
        let file = PathBuf::from("http.toml");
        let body = parse_backend_table(
            "server = \"127.0.0.1:9000\"\n[tls]\nverify = false\n",
            &file,
            "api",
        )
        .expect("body form");
        assert_eq!(body.server.as_deref(), Some("127.0.0.1:9000"));
        assert_eq!(body.tls.as_ref().map(|tls| tls.verify), Some(false));

        let section = parse_backend_table(
            "[backend.api]\nserver = \"127.0.0.1:9001\"\n\
             [backend.api.health_check]\ntype = \"tcp\"\n",
            &file,
            "api",
        )
        .expect("whole-section form");
        assert_eq!(section.server.as_deref(), Some("127.0.0.1:9001"));
        assert!(section.health_check.is_some());
    }

    #[test]
    fn a_table_typo_is_reported_with_its_section_path() {
        let err = parse_backend_table(
            "[backend.api]\nservers = []\nbalanse = \"leastconn\"\n",
            Path::new("http.toml"),
            "api",
        )
        .expect_err("unknown key");
        assert_eq!(err.field.as_deref(), Some("backend.api.balanse"));
        assert!(err.cause.contains("balanse"), "{err}");
    }

    #[test]
    fn listener_table_accepts_a_full_section_and_requires_its_keys() {
        let file = PathBuf::from("http.toml");
        let listener = parse_listener_table(
            "[listener.web]\nlisten = \"127.0.0.1:8080\"\nbackend = \"api\"\n",
            &file,
            "web",
        )
        .expect("listener section");
        assert_eq!(listener.listen, "127.0.0.1:8080");
        assert_eq!(listener.backend, "api");
        let err = parse_listener_table("mode = \"http\"\n", &file, "web")
            .expect_err("missing listen/backend");
        assert_eq!(err.field.as_deref(), Some("listener.web"));
    }

    #[test]
    fn offset_location_maps_offsets_to_line_and_column() {
        let source = "a = 1\nbb = 2\n";
        let loc = offset_location(source, 8).expect("offset inside the text");
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
        let cfg = parse_str(source, &PathBuf::from("t.toml")).expect("must parse");
        assert_eq!(cfg.schema_version, 1);
    }

    #[test]
    fn oversized_source_is_rejected_with_actionable_error() {
        let file = PathBuf::from("big.toml");
        let source = "x".repeat(MAX_CONFIG_BYTES + 1);
        let err = parse_str(&source, &file).expect_err("must reject");
        assert!(err.cause.contains("too large"), "cause: {}", err.cause);
        assert!(err.example.contains("1 MiB"), "example: {}", err.example);
    }

    #[cfg_attr(
        miri,
        ignore = "1 MiB parse under interpretation: disproportionate cost (>8 min); boundary covered by normal tests and CI"
    )]
    #[test]
    fn source_at_the_limit_is_accepted() {
        let file = PathBuf::from("limit.toml");
        let mut source = String::from("schema_version = 1\n");
        source.push_str(&"#".repeat(MAX_CONFIG_BYTES - source.len()));
        assert_eq!(source.len(), MAX_CONFIG_BYTES);
        let cfg = parse_str(&source, &file).expect("must parse at the limit");
        assert_eq!(cfg.schema_version, 1);
    }

    #[test]
    fn offset_location_handles_line_boundaries() {
        let source = "ab\ncd";
        assert_eq!(
            offset_location(source, 0),
            Some(Location {
                line: 1,
                column: Some(1)
            })
        );
        assert_eq!(
            offset_location(source, 3),
            Some(Location {
                line: 2,
                column: Some(1)
            })
        );
        assert_eq!(
            offset_location(source, 5),
            Some(Location {
                line: 2,
                column: Some(3)
            })
        );
        assert_eq!(offset_location(source, 6), None);
    }

    #[test]
    fn example_for_gives_field_specific_examples() {
        for (field, cause, expected) in [
            (
                "listener.web.listen",
                "missing field `listen`",
                "listen = \"127.0.0.1:8080\"",
            ),
            (
                "listener.web.backend",
                "missing field `backend`",
                "backend = \"api\"",
            ),
            (
                "backend.api.server",
                "missing field `server`",
                "server = \"127.0.0.1:9000\"",
            ),
            (
                "schema_version",
                "missing field `schema_version`",
                "schema_version = 1",
            ),
            (
                "listener.web.bogus",
                "missing field `bogus`",
                "check the required fields in eqproxy.toml.example",
            ),
            (
                "listener.web.listen",
                "unknown field `foo`",
                "remove or fix the field name; the valid fields are in eqproxy.toml.example",
            ),
            (
                "listener.web.listen",
                "invalid string",
                "listen = \"127.0.0.1:8080\" (IP:PORT format)",
            ),
            (
                "backend.api.server",
                "invalid string",
                "listen = \"127.0.0.1:8080\" (IP:PORT format)",
            ),
            (
                "listener.web.connect_timeout",
                "invalid string",
                "connect_timeout = \"5s\" (valid suffixes: ms, s, m, h)",
            ),
            ("listener.web.maxconn", "invalid integer", "maxconn = 1024"),
            (
                "listener.web.mode",
                "unknown variant",
                "mode = \"tcp\" (or \"http\")",
            ),
            ("schema_version", "invalid integer", "schema_version = 1"),
            (
                "listener.web.bogus",
                "invalid string",
                "see eqproxy.toml.example",
            ),
        ] {
            assert_eq!(
                example_for(field, cause),
                expected,
                "field {field}, cause {cause}"
            );
        }
    }

    #[test]
    fn load_enforces_the_size_budget_on_files() {
        let temp = |tag: &str| {
            std::env::temp_dir().join(format!(
                "eqproxy-config-test-{}-{tag}.toml",
                std::process::id()
            ))
        };

        let small = temp("small");
        std::fs::write(&small, "schema_version = 1\n").unwrap();
        let cfg = load(&small).expect("small file must load");
        assert_eq!(cfg.schema_version, 1);

        let over = temp("over");
        let mut content = String::from("schema_version = 1\n");
        content.push('#');
        content.push_str(&"a".repeat(MAX_CONFIG_BYTES - content.len() - 1));
        content.push('\n');
        assert_eq!(content.len(), MAX_CONFIG_BYTES);
        content.push('a');
        std::fs::write(&over, &content).unwrap();
        let err = load(&over).expect_err("one byte more must be rejected");
        assert!(err.cause.contains("too large"), "cause: {}", err.cause);

        let _ = std::fs::remove_file(small);
        let _ = std::fs::remove_file(over);
    }

    /// The "accepts exactly at the limit" side lives apart because its
    /// miri-interpreted 1 MiB parse costs >8 min measured (same cost in
    /// `source_at_the_limit_is_accepted`); the boundary is covered in the
    /// normal suite and CI, with the budget rejection above also running
    /// under miri.
    #[cfg_attr(
        miri,
        ignore = "1 MiB parse under interpretation: >8 min measured under miri; boundary covered by the normal suite and CI"
    )]
    #[test]
    fn load_accepts_a_file_at_the_size_limit() {
        let at = std::env::temp_dir().join(format!(
            "eqproxy-config-test-{}-at-limit.toml",
            std::process::id()
        ));
        let mut content = String::from("schema_version = 1\n");
        content.push('#');
        content.push_str(&"a".repeat(MAX_CONFIG_BYTES - content.len() - 1));
        content.push('\n');
        assert_eq!(content.len(), MAX_CONFIG_BYTES);
        std::fs::write(&at, &content).unwrap();
        load(&at).expect("must load exactly at the limit");
        let _ = std::fs::remove_file(at);
    }

    #[test]
    fn schema_defaults_match_the_documented_values() {
        let source = "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:8080\"\nbackend = \"api\"\n\n[backend.api]\nserver = \"127.0.0.1:9000\"\n";
        let cfg = parse_str(source, &PathBuf::from("t.toml")).expect("must parse");
        assert_eq!(cfg.listener["web"].maxconn, 1024, "default maxconn");
    }
}
