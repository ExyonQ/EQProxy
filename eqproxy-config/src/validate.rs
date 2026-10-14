//! Semantic validation: dangling references, ranges and warnings for
//! dangerous configurations. Errors with line, field, cause and example.

use std::net::SocketAddr;
use std::path::Path;

use crate::error::{ConfigError, Location};
use crate::find_line;
use crate::schema::{Config, MAX_SECTIONS, MAX_SERVER_WEIGHT, SCHEMA_VERSION};

/// Result of validating a full configuration.
#[derive(Debug, Default)]
pub struct CheckResult {
    /// Errors that prevent using the configuration.
    pub errors: Vec<ConfigError>,
    /// Warnings: the configuration is usable but risky.
    pub warnings: Vec<String>,
}

impl CheckResult {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Validates `config` (parsed) against the `source` text to locate lines.
pub fn check(config: &Config, source: &str, file: &Path) -> CheckResult {
    let mut result = CheckResult::default();

    let sections = config.listener.len() + config.backend.len();
    if sections > MAX_SECTIONS {
        result.errors.push(ConfigError {
            file: file.to_path_buf(),
            location: None,
            field: None,
            cause: format!(
                "too many sections: {sections} across [listener.*] and [backend.*] (maximum {MAX_SECTIONS})"
            ),
            example: format!(
                "reduce to {MAX_SECTIONS} combined sections; split the configuration per service (ADR-0002)"
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
                "schema_version = {} not supported by this binary (supported: {SCHEMA_VERSION})",
                config.schema_version
            ),
            "schema_version = 1".to_owned(),
            "schema_version",
        );
    }

    if config.listener.is_empty() {
        result
            .warnings
            .push("no [listener.*] sections: the dataplane will not accept connections".to_owned());
    }

    if config.shutdown_grace.is_zero() {
        err(
            "shutdown_grace".to_owned(),
            "shutdown_grace must be greater than 0".to_owned(),
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
                    "\"{}\" is not a valid address (expected IP:PORT)",
                    listener.listen
                ),
                "listen = \"127.0.0.1:8080\"".to_owned(),
                &section,
            );
        }

        // Backend validations run per section (not per listener):
        // they are checked in the backend loop below.
        if !config.backend.contains_key(&listener.backend) {
            err(
                field("backend"),
                format!("backend \"{}\" does not exist", listener.backend),
                format!(
                    "backend = \"{}\" requires a [backend.{}] section with server = \"127.0.0.1:9000\"",
                    listener.backend, listener.backend
                ),
                &section,
            );
        }

        if listener.maxconn == 0 {
            err(
                field("maxconn"),
                "maxconn must be at least 1".to_owned(),
                "maxconn = 1024".to_owned(),
                &section,
            );
        }

        if listener.connect_timeout.is_zero() {
            err(
                field("connect_timeout"),
                "connect_timeout must be greater than 0".to_owned(),
                "connect_timeout = \"5s\"".to_owned(),
                &section,
            );
        }

        if listener.idle_timeout.is_zero() {
            err(
                field("idle_timeout"),
                "idle_timeout must be greater than 0".to_owned(),
                "idle_timeout = \"60s\"".to_owned(),
                &section,
            );
        }

        if listener.client_header_timeout.is_zero() {
            err(
                field("client_header_timeout"),
                "client_header_timeout must be greater than 0".to_owned(),
                "client_header_timeout = \"5s\"".to_owned(),
                &section,
            );
        }

        if listener.server_header_timeout.is_zero() {
            err(
                field("server_header_timeout"),
                "server_header_timeout must be greater than 0".to_owned(),
                "server_header_timeout = \"30s\"".to_owned(),
                &section,
            );
        }

        if let Ok(addr) = listener.listen.parse::<SocketAddr>() {
            if !addr.ip().is_loopback() && listener.tls.is_none() {
                result.warnings.push(format!(
                    "listener \"{name}\" listens on {addr} without TLS: expose it only on trusted networks or enable [listener.{name}.tls]"
                ));
            }
            if listener.maxconn > 65_535 {
                result.warnings.push(format!(
                    "listener \"{name}\" maxconn={} needs ~{} descriptors; check `ulimit -n`",
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
                "the backend defines no servers".to_owned(),
                "server = \"127.0.0.1:9000\" (one server) or servers = [{ addr = \"127.0.0.1:9000\", weight = 1 }]".to_owned(),
                &section,
            ),
            (Some(_), Some(_)) => err(
                field("servers"),
                "`server` and `servers` are mutually exclusive: define only one".to_owned(),
                "servers = [{ addr = \"127.0.0.1:9000\", weight = 1 }] (remove `server`)".to_owned(),
                &section,
            ),
            _ => {}
        }

        if let Some(servers) = &backend.servers
            && servers.is_empty()
        {
            err(
                field("servers"),
                "`servers` is empty: the backend would have no destination".to_owned(),
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
                    format!("\"{addr}\" is not a valid address (expected IP:PORT)"),
                    "addr = \"127.0.0.1:9000\"".to_owned(),
                    &section,
                );
            }
            if weight > MAX_SERVER_WEIGHT {
                err(
                    field(&format!("servers[{idx}].weight")),
                    format!("weight = {weight} out of range (maximum {MAX_SERVER_WEIGHT})"),
                    "weight = 1 (range 0..=256; 0 = drained)".to_owned(),
                    &section,
                );
            }
            if !seen_addrs.insert(addr) {
                err(
                    field(&suffix),
                    format!("duplicate server: \"{addr}\" appears more than once"),
                    "each `addr` must be unique within the backend".to_owned(),
                    &section,
                );
            }
        }

        if let Some(hc) = &backend.health_check {
            if hc.interval.is_zero() {
                err(
                    field("health_check.interval"),
                    "health_check.interval must be greater than 0".to_owned(),
                    "interval = \"2s\"".to_owned(),
                    &section,
                );
            }
            if hc.timeout.is_zero() {
                err(
                    field("health_check.timeout"),
                    "health_check.timeout must be greater than 0".to_owned(),
                    "timeout = \"1s\"".to_owned(),
                    &section,
                );
            }
            if hc.fall == 0 {
                err(
                    field("health_check.fall"),
                    "health_check.fall must be at least 1".to_owned(),
                    "fall = 3".to_owned(),
                    &section,
                );
            }
            if hc.rise == 0 {
                err(
                    field("health_check.rise"),
                    "health_check.rise must be at least 1".to_owned(),
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
                    "backend \"{name}\" sets ca_file but verify = false: the CA is unused and the backend is not verified"
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

/// Problems of an ALPN list: non-empty names, no duplicates (A14).
/// Returns (cause, example) pairs to insert with the error context.
fn alpn_problems(alpn: &[String]) -> Vec<(String, String)> {
    let mut problems = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for proto in alpn {
        if proto.is_empty() || proto.len() > 255 {
            problems.push((
                format!("invalid ALPN protocol \"{proto}\": must be 1..=255 bytes"),
                "alpn = [\"http/1.1\"]".to_owned(),
            ));
        }
        if !seen.insert(proto.as_str()) {
            problems.push((
                format!("duplicate ALPN protocol: \"{proto}\""),
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
        let config = parse_str(source, &file).expect("valid TOML");
        check(&config, source, &file)
    }

    /// Config with `listeners` [listener.*] and `backends` [backend.*] built
    /// directly: the budget lives in `check`, and parsing thousands of
    /// TOML sections under the miri interpreter is pure cost.
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
        assert!(result.is_valid(), "errors: {:?}", result.errors);
    }

    #[test]
    fn missing_backend_is_reported_with_line_field_cause_example() {
        let source = "schema_version = 1\n\n[listener.web]\nlisten = \"127.0.0.1:8080\"\nbackend = \"ghost\"\n";
        let result = check_source(source);
        assert!(!result.is_valid());
        let err = &result.errors[0];
        assert_eq!(err.field.as_deref(), Some("listener.web.backend"));
        let loc = err.location.as_ref().expect("must locate the line");
        assert_eq!(loc.line, 3, "[listener.web] line: {source:?}");
        assert!(err.cause.contains("ghost"), "cause: {}", err.cause);
        assert!(
            err.example.contains("[backend.ghost]"),
            "example: {}",
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
            .find(|e| e.cause.contains("too many sections"))
            .expect("must report the section budget");
        assert!(err.example.contains("ADR-0002"), "example: {}", err.example);
    }

    #[test]
    fn sections_at_the_budget_are_accepted() {
        let result = check_config(&config_with_sections(MAX_SECTIONS - 1, 1));
        assert!(result.is_valid(), "errors: {:?}", result.errors);
    }

    #[test]
    fn budget_counts_listeners_and_backends_by_their_sum() {
        // 1025 [listener.*] without [backend.*]: the sum (1025) exceeds the
        // budget even though the product is 0 — combined sections count.
        let result = check_config(&config_with_sections(MAX_SECTIONS + 1, 0));
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.cause.contains("too many sections")),
            "expected a budget error: {:?}",
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
            !at.warnings.iter().any(|w| w.contains("descriptors")),
            "must not warn at 65535: {:?}",
            at.warnings
        );
        let above = check_source(&config_with(65_536));
        assert!(
            above.warnings.iter().any(|w| w.contains("descriptors")),
            "must warn at 65536: {:?}",
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
            "errors: {:?}",
            bad.errors
        );

        let ok = check_source(
            "schema_version = 1\n[backend.api]\nservers = [{ addr = \"127.0.0.1:1\", weight = 3 }, { addr = \"127.0.0.1:2\", weight = 0 }]\n",
        );
        assert!(ok.is_valid(), "errors: {:?}", ok.errors);
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
        assert_eq!(alpn_errors.len(), 2, "errors: {:?}", result.errors);
        assert!(alpn_errors[0].cause.contains("duplicate"));
        assert!(alpn_errors[1].cause.contains("invalid"));
    }

    #[test]
    fn non_loopback_listener_without_tls_warns_but_with_tls_does_not() {
        let plain = check_source(
            "schema_version = 1\n[listener.web]\nlisten = \"0.0.0.0:8080\"\nbackend = \"api\"\n[backend.api]\nserver = \"127.0.0.1:1\"\n",
        );
        assert!(plain.is_valid());
        assert!(
            plain.warnings.iter().any(|w| w.contains("without TLS")),
            "warnings: {:?}",
            plain.warnings
        );

        let with_tls = check_source(
            "schema_version = 1\n[listener.web]\nlisten = \"0.0.0.0:8080\"\nbackend = \"api\"\n[listener.web.tls]\ncert = \"c.pem\"\nkey = \"k.pem\"\n[backend.api]\nserver = \"127.0.0.1:1\"\n",
        );
        assert!(with_tls.is_valid());
        assert!(
            !with_tls.warnings.iter().any(|w| w.contains("without TLS")),
            "warnings: {:?}",
            with_tls.warnings
        );
    }

    #[test]
    fn dangerous_configs_produce_warnings_not_errors() {
        let result = check_source(
            "schema_version = 1\n[listener.web]\nlisten = \"0.0.0.0:8080\"\nbackend = \"api\"\nmaxconn = 100000\n[backend.api]\nserver = \"127.0.0.1:1\"\n",
        );
        assert!(result.is_valid(), "errors: {:?}", result.errors);
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("trusted networks")),
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
