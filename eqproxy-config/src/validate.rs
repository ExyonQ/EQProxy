//! Semantic validation: dangling references, ranges and warnings for
//! dangerous configurations. Errors with line, field, cause and example.

use std::net::SocketAddr;
use std::path::Path;

use eqproxy_core::expectation::{IpBlock, RegexMatcher, StatusExpectation};
use eqproxy_core::maps;
use eqproxy_core::rules::{Rule, validate_header_value, validate_location};

use crate::error::{ConfigError, Location};
use crate::find_line;
use crate::schema::{
    Config, ForwardedHeaders, HealthCheckKind, ListenerMode, MAX_AUTH_USERS,
    MAX_LOCAL_RESPONSE_BYTES, MAX_MAP_RELOAD_INTERVAL, MAX_QUEUE, MAX_RETRIES, MAX_RULES,
    MAX_SECTIONS, MAX_SERVER_WEIGHT, MAX_SPLIT_TARGETS, MIN_MAP_RELOAD_INTERVAL, SCHEMA_VERSION,
};

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

    // Compatibility policy (Q3, declared): a binary accepts every
    // schema version it knows — 1 up to its own — so older configs keep
    // working (backward compatible). Newer ones and the invalid 0 are
    // rejected naming the supported range.
    if config.schema_version == 0 || config.schema_version > SCHEMA_VERSION {
        err(
            "schema_version".to_owned(),
            format!(
                "schema_version = {} not supported by this binary (supported: 1..={SCHEMA_VERSION})",
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

    // Data maps (C10/PP-02): one source per map, bounded data, sane
    // reload window. The file itself is read at load time (`run`), like
    // certificates.
    let referenced_maps: std::collections::BTreeSet<&str> = config
        .listener
        .values()
        .flat_map(|listener| listener.rules.iter())
        .filter_map(|rule| rule.map.as_ref().map(|map| map.name.as_str()))
        .collect();
    for (name, map) in &config.maps {
        let section = format!("[maps.{name}]");
        let field = |suffix: &str| format!("maps.{name}.{suffix}");
        match (&map.file, &map.entries) {
            (Some(_), Some(_)) | (None, None) => err(
                field(""),
                "set exactly one of file or entries".to_owned(),
                "file = \"tenants.map\" (hot-reloaded) or entries = { acme = \"vip\" } (static)"
                    .to_owned(),
                &section,
            ),
            (Some(file), None) => {
                if file.trim().is_empty() {
                    err(
                        field("file"),
                        "file is empty".to_owned(),
                        "file = \"tenants.map\" (relative to the config file)".to_owned(),
                        &section,
                    );
                }
            }
            (None, Some(entries)) => {
                if entries.len() > maps::MAX_MAP_ENTRIES {
                    err(
                        field("entries"),
                        format!(
                            "too many entries: {} (maximum {})",
                            entries.len(),
                            maps::MAX_MAP_ENTRIES
                        ),
                        format!(
                            "split the data into at most {} entries per map",
                            maps::MAX_MAP_ENTRIES
                        ),
                        &section,
                    );
                }
                for (key, value) in entries {
                    if let Err(why) = maps::validate_key(key) {
                        err(
                            field("entries"),
                            why,
                            "acme = \"vip\" (keys are single tokens)".to_owned(),
                            &section,
                        );
                    }
                    if let Err(why) = maps::validate_value(value) {
                        err(
                            field("entries"),
                            why,
                            "acme = \"vip\" (values are single-line)".to_owned(),
                            &section,
                        );
                    }
                }
            }
        }
        if let Some(default) = &map.default
            && let Err(why) = maps::validate_value(default)
        {
            err(
                field("default"),
                why,
                "default = \"free\" (value for keys without an entry)".to_owned(),
                &section,
            );
        }
        let interval = map.reload_interval;
        if !interval.is_zero()
            && (interval < MIN_MAP_RELOAD_INTERVAL || interval > MAX_MAP_RELOAD_INTERVAL)
        {
            err(
                field("reload_interval"),
                format!(
                    "reload_interval = {:?} out of range (\"0s\" = load once; otherwise between {:?} and {:?})",
                    interval, MIN_MAP_RELOAD_INTERVAL, MAX_MAP_RELOAD_INTERVAL
                ),
                "reload_interval = \"5s\"".to_owned(),
                &section,
            );
        }
        if !referenced_maps.contains(name.as_str()) {
            result
                .warnings
                .push(format!("[maps.{name}] is never referenced by any rule"));
        }
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

        if listener.proxy_receive {
            if listener.proxy_allow.is_empty() {
                err(
                    field("proxy_allow"),
                    "proxy_receive = true requires at least one trusted origin".to_owned(),
                    "proxy_allow = [\"10.0.0.0/8\"] (IP or CIDR list)".to_owned(),
                    &section,
                );
            }
            for entry in &listener.proxy_allow {
                if let Err(cause) = IpBlock::parse(entry) {
                    err(
                        field("proxy_allow"),
                        cause,
                        "proxy_allow = [\"10.0.0.0/8\", \"192.0.2.1\"]".to_owned(),
                        &section,
                    );
                }
            }
        }

        if listener.forwarded_headers != ForwardedHeaders::Off
            && listener.mode != ListenerMode::Http
        {
            err(
                field("forwarded_headers"),
                "forwarded_headers is only meaningful in mode = \"http\"".to_owned(),
                "mode = \"http\" or forwarded_headers = \"off\"".to_owned(),
                &section,
            );
        }

        if let Some(local) = &listener.local_response {
            if !(400..=599).contains(&local.status) {
                err(
                    field("local_response.status"),
                    format!(
                        "local_response.status = {} out of range (rule: local responses are 400-599)",
                        local.status
                    ),
                    "status = 503".to_owned(),
                    &section,
                );
            }
            if local.body.len() > MAX_LOCAL_RESPONSE_BYTES {
                err(
                    field("local_response.body"),
                    format!(
                        "local_response.body is {} bytes (rule: maximum {MAX_LOCAL_RESPONSE_BYTES})",
                        local.body.len()
                    ),
                    "shorten the body (8 KiB budget)".to_owned(),
                    &section,
                );
            }
            if local.content_type.trim().is_empty() {
                err(
                    field("local_response.content_type"),
                    "local_response.content_type must not be empty".to_owned(),
                    "content_type = \"text/plain; charset=utf-8\"".to_owned(),
                    &section,
                );
            }
            if listener.mode != ListenerMode::Http {
                err(
                    field("local_response"),
                    "local_response is only meaningful in mode = \"http\"".to_owned(),
                    "mode = \"http\" or remove local_response".to_owned(),
                    &section,
                );
            }
        }

        // Routing rules (v0.6, B-H3/B-H4): http only, bounded count, sound
        // references and a compilable matcher (the gate shares the runtime
        // grammar via `Rule::compile`).
        if !listener.rules.is_empty() {
            if listener.mode != ListenerMode::Http {
                err(
                    field("rules"),
                    "routing rules are only meaningful in mode = \"http\"".to_owned(),
                    format!("mode = \"http\" or remove [[listener.{name}.rules]]"),
                    &section,
                );
            }
            if listener.rules.len() > MAX_RULES {
                err(
                    field("rules"),
                    format!(
                        "too many rules: {} (maximum {MAX_RULES} per listener)",
                        listener.rules.len()
                    ),
                    format!("reduce to {MAX_RULES} [[listener.{name}.rules]] tables"),
                    &section,
                );
            }
            for (i, rule) in listener.rules.iter().enumerate() {
                let rule_field = |suffix: &str| {
                    if suffix.is_empty() {
                        field(&format!("rules[{i}]"))
                    } else {
                        field(&format!("rules[{i}].{suffix}"))
                    }
                };
                // Exactly one action per rule (v0.6 slice 2).
                let actions = u8::from(rule.use_backend.is_some())
                    + u8::from(rule.split.is_some())
                    + u8::from(rule.redirect.is_some())
                    + u8::from(rule.direct_response.is_some());
                if actions != 1 {
                    err(
                        rule_field(""),
                        "set exactly one of use_backend, split, redirect or direct_response"
                            .to_owned(),
                        "use_backend = \"api\" (route) | split = [{ backend = \"stable\", weight = 90 }, { backend = \"canary\", weight = 10 }] | redirect = { status = 301, location = \"https://$host$request_uri\" } | direct_response = { status = 200, body = \"ok\" }".to_owned(),
                        &section,
                    );
                }
                // Weighted traffic split (B-I11): sound references,
                // bounded targets, no duplicates, at least one enabled.
                if let Some(targets) = &rule.split {
                    if targets.len() < 2 {
                        err(
                            rule_field("split"),
                            "a split needs at least two targets (use use_backend for one backend)"
                                .to_owned(),
                            "split = [{ backend = \"stable\", weight = 90 }, { backend = \"canary\", weight = 10 }]".to_owned(),
                            &section,
                        );
                    }
                    if targets.len() > MAX_SPLIT_TARGETS {
                        err(
                            rule_field("split"),
                            format!(
                                "too many targets: {} (maximum {MAX_SPLIT_TARGETS})",
                                targets.len()
                            ),
                            format!("reduce split to {MAX_SPLIT_TARGETS} targets"),
                            &section,
                        );
                    }
                    let mut seen = std::collections::BTreeSet::new();
                    for (j, target) in targets.iter().enumerate() {
                        if !seen.insert(target.backend.as_str()) {
                            err(
                                rule_field(&format!("split[{j}].backend")),
                                format!("backend \"{}\" is listed twice", target.backend),
                                "each backend appears exactly once in split".to_owned(),
                                &section,
                            );
                        }
                        if !config.backend.contains_key(&target.backend) {
                            err(
                                rule_field(&format!("split[{j}].backend")),
                                format!("backend \"{}\" does not exist", target.backend),
                                format!(
                                    "split = [{{ backend = \"{}\", weight = 90 }}] requires a [backend.{}] section",
                                    target.backend, target.backend
                                ),
                                &section,
                            );
                        }
                        if target.weight > MAX_SERVER_WEIGHT {
                            err(
                                rule_field(&format!("split[{j}].weight")),
                                format!(
                                    "weight = {} out of range (0..={MAX_SERVER_WEIGHT})",
                                    target.weight
                                ),
                                "weight = 10 (0 = target disabled)".to_owned(),
                                &section,
                            );
                        }
                    }
                    if !targets.iter().any(|target| target.weight > 0) {
                        err(
                            rule_field("split"),
                            "every target has weight = 0 (no request would ever be routed)"
                                .to_owned(),
                            "give at least one target a weight above 0".to_owned(),
                            &section,
                        );
                    }
                }
                if let Some(backend) = &rule.use_backend
                    && !config.backend.contains_key(backend)
                {
                    err(
                        rule_field("use_backend"),
                        format!("backend \"{backend}\" does not exist"),
                        format!(
                            "use_backend = \"{backend}\" requires a [backend.{backend}] section"
                        ),
                        &section,
                    );
                } // `rewrite` modifies a forwarding action only.
                if let Some(rewrite) = &rule.rewrite {
                    if !rule.forwards() {
                        err(
                            rule_field("rewrite"),
                            "rewrite only applies to forwarding rules (use_backend or split)"
                                .to_owned(),
                            "use_backend = \"api\" + [listener.LISTENER.rules.rewrite] (or use redirect)"
                                .to_owned(),
                            &section,
                        );
                    }
                    if rewrite.path_prefix_rewrite.is_none() && rewrite.host_rewrite.is_none() {
                        err(
                            rule_field("rewrite"),
                            "rewrite sets no field".to_owned(),
                            "path_prefix_rewrite = \"/v2\" or host_rewrite = \"internal\""
                                .to_owned(),
                            &section,
                        );
                    }
                    if let Some(prefix) = &rewrite.path_prefix_rewrite {
                        if rule.path_prefix.is_none() {
                            err(
                                rule_field("rewrite.path_prefix_rewrite"),
                                "path_prefix_rewrite needs the rule's path_prefix to replace"
                                    .to_owned(),
                                "path_prefix = \"/api\" plus path_prefix_rewrite = \"/v2\""
                                    .to_owned(),
                                &section,
                            );
                        }
                        if !(prefix.is_empty() || prefix.starts_with('/'))
                            || prefix
                                .bytes()
                                .any(|b| b <= 0x20 || b == 0x7f || b == b'?' || b == b'#')
                        {
                            err(
                                rule_field("rewrite.path_prefix_rewrite"),
                                "not a valid path prefix".to_owned(),
                                "path_prefix_rewrite = \"/v2\" (starts with /; no spaces, ? or #)"
                                    .to_owned(),
                                &section,
                            );
                        }
                    }
                    if let Some(host) = &rewrite.host_rewrite
                        && (host.is_empty() || host.bytes().any(|b| b <= 0x20 || b == 0x7f))
                    {
                        err(
                            rule_field("rewrite.host_rewrite"),
                            "not a valid host value".to_owned(),
                            "host_rewrite = \"internal.svc\" (no spaces or control characters)"
                                .to_owned(),
                            &section,
                        );
                    }
                }
                // Hash policy (B-H3, Envoy `hash_policy`): the key selects
                // among the split targets, so it needs a split with two or
                // more active targets. Per-server stickiness is
                // `[backend.*.affinity]`, not this field.
                if let Some(hash) = &rule.hash_policy {
                    match hash_key_problem(&hash.key) {
                        Some(cause) => err(
                            rule_field("hash_policy.key"),
                            cause,
                            "key = \"cookie:session\" (or header:NAME, source, path, host)"
                                .to_owned(),
                            &section,
                        ),
                        None => match &rule.split {
                            None => err(
                                rule_field("hash_policy"),
                                "hash_policy needs a split action: with one backend there is nothing to hash between (use [backend.*.affinity] for per-server stickiness)"
                                    .to_owned(),
                                "split = [{ backend = \"a\", weight = 1 }, { backend = \"b\", weight = 1 }] + hash_policy = { key = \"cookie:session\" }".to_owned(),
                                &section,
                            ),
                            Some(targets)
                                if targets.iter().filter(|t| t.weight > 0).count() < 2 => err(
                                    rule_field("hash_policy"),
                                    "hash_policy needs at least two targets with weight > 0"
                                        .to_owned(),
                                    "give two split targets a weight above 0".to_owned(),
                                    &section,
                                ),
                            Some(_) => {}
                        },
                    }
                }
                // Mirror policy (B-H3, Envoy `request_mirror_policies`):
                // a copy of the request to another backend, fire-and-forget.
                if let Some(mirror) = &rule.request_mirror {
                    if !rule.forwards() {
                        err(
                            rule_field("request_mirror"),
                            "request_mirror only applies to forwarding rules (use_backend or split)"
                                .to_owned(),
                            "use_backend = \"api\" + [listener.LISTENER.rules.request_mirror] backend = \"shadow\"".to_owned(),
                            &section,
                        );
                    }
                    if !config.backend.contains_key(&mirror.backend) {
                        err(
                            rule_field("request_mirror.backend"),
                            format!("backend \"{}\" does not exist", mirror.backend),
                            format!(
                                "request_mirror = {{ backend = \"{}\" }} requires a [backend.{}] section",
                                mirror.backend, mirror.backend
                            ),
                            &section,
                        );
                    }
                    if mirror.percentage == 0 || mirror.percentage > 100 {
                        err(
                            rule_field("request_mirror.percentage"),
                            format!("percentage = {} out of range (1..=100)", mirror.percentage),
                            "percentage = 10 (one in every ten requests); omit it for 100"
                                .to_owned(),
                            &section,
                        );
                    }
                }
                // Header actions (B-N4/B-I4/B-E17). Request-side ones
                // modify a forwarded request: forwarding actions only
                // (like `rewrite`). The proxy owns the framing headers.
                let request_header_ops = !rule.set_headers.is_empty()
                    || !rule.add_headers.is_empty()
                    || !rule.del_headers.is_empty();
                if request_header_ops && !rule.forwards() {
                    err(
                        rule_field("set_headers"),
                        "set_headers/add_headers/del_headers only apply to forwarding rules (use_backend or split)"
                            .to_owned(),
                        "use_backend = \"api\" + set_headers = [{ name = \"x-beta\", value = \"on\" }] (or use response_headers)".to_owned(),
                        &section,
                    );
                }
                for (op_field, ops) in [
                    ("set_headers", &rule.set_headers),
                    ("add_headers", &rule.add_headers),
                    ("response_headers", &rule.response_headers),
                ] {
                    for (j, op) in ops.iter().enumerate() {
                        let name = op.name.to_ascii_lowercase();
                        if op.name.is_empty()
                            || op.name.bytes().any(|b| b <= 0x20 || b == 0x7f || b == b':')
                        {
                            err(
                                rule_field(&format!("{op_field}[{j}].name")),
                                "not a valid header name".to_owned(),
                                "name = \"x-beta\" (no spaces, control characters or :)".to_owned(),
                                &section,
                            );
                        }
                        if matches!(name.as_str(), "content-length" | "transfer-encoding") {
                            err(
                                rule_field(&format!("{op_field}[{j}].name")),
                                format!("{name} is a framing header the proxy owns"),
                                "a custom header like \"x-backend-hint\" (framing stays the proxy's job)"
                                    .to_owned(),
                                &section,
                            );
                        }
                        if let Err(cause) = validate_header_value(&op.value) {
                            err(
                                rule_field(&format!("{op_field}[{j}].value")),
                                cause,
                                "value = \"$scheme\" (literal text or $remote_addr, $host, $scheme)"
                                    .to_owned(),
                                &section,
                            );
                        }
                    }
                }
                for (j, name) in rule.del_headers.iter().enumerate() {
                    let lowered = name.to_ascii_lowercase();
                    if name.is_empty() || name.bytes().any(|b| b <= 0x20 || b == 0x7f || b == b':')
                    {
                        err(
                            rule_field(&format!("del_headers[{j}]")),
                            "not a valid header name".to_owned(),
                            "del_headers = [\"x-gone\"]".to_owned(),
                            &section,
                        );
                    }
                    if matches!(lowered.as_str(), "content-length" | "transfer-encoding") {
                        err(
                            rule_field(&format!("del_headers[{j}]")),
                            format!("{lowered} is a framing header the proxy owns"),
                            "del_headers = [\"x-gone\"] (a custom header; framing stays the proxy's job)"
                                .to_owned(),
                            &section,
                        );
                    }
                }
                // CORS policy (B-I10).
                if let Some(cors) = &rule.cors {
                    if !rule.forwards() {
                        err(
                            rule_field("cors"),
                            "cors only applies to forwarding rules (use_backend or split)"
                                .to_owned(),
                            "use_backend = \"api\" + [listener.LISTENER.rules.cors]".to_owned(),
                            &section,
                        );
                    }
                    if cors.allow_origin.is_empty()
                        || cors.allow_origin.bytes().any(|b| b <= 0x20 || b == 0x7f)
                    {
                        err(
                            rule_field("cors.allow_origin"),
                            "not a valid origin value".to_owned(),
                            "allow_origin = \"https://app.example.com\"".to_owned(),
                            &section,
                        );
                    }
                    if cors.allow_origin == "*" && cors.allow_credentials {
                        err(
                            rule_field("cors.allow_origin"),
                            "\"*\" cannot be combined with allow_credentials (the browser rejects that pair)"
                                .to_owned(),
                            "allow_origin = \"https://app.example.com\" with allow_credentials = true"
                                .to_owned(),
                            &section,
                        );
                    }
                    for (op_field, value) in [
                        ("cors.allow_methods", cors.allow_methods.as_deref()),
                        ("cors.allow_headers", cors.allow_headers.as_deref()),
                        ("cors.expose_headers", cors.expose_headers.as_deref()),
                    ] {
                        if let Some(value) = value
                            && value.bytes().any(|b| b < 0x20 || b == 0x7f)
                        {
                            err(
                                rule_field(op_field),
                                "value contains control characters".to_owned(),
                                "comma-separated header list (e.g. \"GET, POST\")".to_owned(),
                                &section,
                            );
                        }
                    }
                }
                // Rate limit (B-N8/B-I7/B-E16): explicit values only.
                if let Some(limit) = &rule.rate_limit {
                    if limit.rate == 0 {
                        err(
                            rule_field("rate_limit.rate"),
                            "rate must be at least 1".to_owned(),
                            "rate = 10".to_owned(),
                            &section,
                        );
                    }
                    if limit.per.is_zero() {
                        err(
                            rule_field("rate_limit.per"),
                            "per must be greater than zero".to_owned(),
                            "per = \"1s\"".to_owned(),
                            &section,
                        );
                    }
                    if limit.burst == Some(0) {
                        err(
                            rule_field("rate_limit.burst"),
                            "burst must be at least 1".to_owned(),
                            "burst = 20".to_owned(),
                            &section,
                        );
                    }
                }
                // Authentication (B-N9/B-I9): at least one mechanism;
                // htpasswd entries are parsed with the same code the
                // dataplane verifies with (defined once, Q8).
                if let Some(auth) = &rule.auth {
                    if auth.url.is_none() && auth.kind.is_none() {
                        err(
                            rule_field("auth"),
                            "auth needs at least one of url or type".to_owned(),
                            "url = \"http://127.0.0.1:9000/verify\" (or type = \"basic\")"
                                .to_owned(),
                            &section,
                        );
                    }
                    if let Some(url) = &auth.url
                        && let Err(cause) = eqproxy_core::auth::parse_auth_url(url)
                    {
                        err(
                            rule_field("auth.url"),
                            cause,
                            "url = \"http://127.0.0.1:9000/verify\"".to_owned(),
                            &section,
                        );
                    }
                    if auth.kind.is_none() && (!auth.users.is_empty() || auth.realm.is_some()) {
                        err(
                            rule_field("auth.type"),
                            "users and realm only apply to type = \"basic\"".to_owned(),
                            "type = \"basic\"".to_owned(),
                            &section,
                        );
                    }
                    if auth.kind.is_some() && auth.users.is_empty() {
                        err(
                            rule_field("auth.users"),
                            "basic auth needs at least one user".to_owned(),
                            "users = [\"alice:$apr1$…\"]".to_owned(),
                            &section,
                        );
                    }
                    if auth.users.len() > MAX_AUTH_USERS {
                        err(
                            rule_field("auth.users"),
                            format!(
                                "too many users: {} (maximum {MAX_AUTH_USERS} per rule)",
                                auth.users.len()
                            ),
                            format!("at most {MAX_AUTH_USERS} users entries"),
                            &section,
                        );
                    }
                    if let Err(cause) = eqproxy_core::auth::BasicUsers::parse(&auth.users) {
                        err(
                            rule_field("auth.users"),
                            cause,
                            "users = [\"alice:$apr1$…\"] (htpasswd entries)".to_owned(),
                            &section,
                        );
                    }
                    if let Some(realm) = &auth.realm
                        && (realm.is_empty()
                            || realm
                                .bytes()
                                .any(|b| b < 0x20 || b == 0x7f || b == b'"' || b == b'\\'))
                    {
                        err(
                            rule_field("auth.realm"),
                            "not a valid realm (no control characters, quotes or backslashes)"
                                .to_owned(),
                            "realm = \"EQProxy\"".to_owned(),
                            &section,
                        );
                    }
                }
                if let Some(redirect) = &rule.redirect {
                    if let Some(status) = redirect.status
                        && !matches!(status, 301 | 302 | 303 | 307 | 308)
                    {
                        err(
                            rule_field("redirect.status"),
                            format!(
                                "redirect status {status} is not a redirect (301, 302, 303, 307, 308)"
                            ),
                            "status = 308".to_owned(),
                            &section,
                        );
                    }
                    if let Err(cause) = validate_location(&redirect.location) {
                        err(
                            rule_field("redirect.location"),
                            cause,
                            "location = \"https://$host$request_uri\"".to_owned(),
                            &section,
                        );
                    }
                }
                if let Some(direct) = &rule.direct_response {
                    if !(200..=599).contains(&direct.status) {
                        err(
                            rule_field("direct_response.status"),
                            format!(
                                "direct_response.status = {} out of range (200-599)",
                                direct.status
                            ),
                            "status = 200".to_owned(),
                            &section,
                        );
                    }
                    if let Some(content_type) = &direct.content_type
                        && content_type.bytes().any(|b| b < 0x20 || b == 0x7f)
                    {
                        err(
                            rule_field("direct_response.content_type"),
                            "content_type contains control characters".to_owned(),
                            "content_type = \"text/plain\"".to_owned(),
                            &section,
                        );
                    }
                    if let Some(body) = &direct.body
                        && body.len() > MAX_LOCAL_RESPONSE_BYTES
                    {
                        err(
                            rule_field("direct_response.body"),
                            format!(
                                "direct_response.body is {} bytes (maximum {MAX_LOCAL_RESPONSE_BYTES})",
                                body.len()
                            ),
                            "shorter body, or a backend for large payloads".to_owned(),
                            &section,
                        );
                    }
                }
                // Map-backed condition (C10): the referenced map must
                // exist (shape problems land in Rule::compile below).
                if let Some(map) = &rule.map
                    && !config.maps.contains_key(&map.name)
                {
                    err(
                        rule_field("map.name"),
                        format!("map \"{}\" does not exist", map.name),
                        format!(
                            "map = {{ name = \"{}\", key = \"host\" }} requires a [maps.{}] section",
                            map.name, map.name
                        ),
                        &section,
                    );
                }
                if let Err(cause) = Rule::compile(&rule.to_spec(i)) {
                    let example = if cause.example.is_empty() {
                        format!("rule \"{}\"", rule.name.clone().unwrap_or_default())
                    } else {
                        cause.example
                    };
                    err(rule_field(&cause.field), cause.cause, example, &section);
                }
            }
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
        // Session affinity (B-H8/B-N13/B-I8).
        if let Some(affinity) = &backend.affinity {
            if affinity.mode != "cookie" && affinity.mode != "source" {
                err(
                    field("affinity.mode"),
                    "mode must be \"cookie\" or \"source\"".to_owned(),
                    "mode = \"cookie\"".to_owned(),
                    &section,
                );
            }
            if let Some(cookie) = &affinity.cookie
                && (cookie.is_empty()
                    || cookie
                        .bytes()
                        .any(|b| b <= 0x20 || b == 0x7f || b == b';' || b == b'='))
            {
                err(
                    field("affinity.cookie"),
                    "not a valid cookie name".to_owned(),
                    "cookie = \"eqproxy_affinity\"".to_owned(),
                    &section,
                );
            }
        }

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
            if let Err(why) = crate::schema::parse_server_target(addr) {
                err(
                    field(&suffix),
                    format!("{why} (expected IP:PORT or HOSTNAME:PORT)"),
                    "addr = \"127.0.0.1:9000\" (or \"api.internal:9000\")".to_owned(),
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
            if !seen_addrs.insert(addr.to_ascii_lowercase()) {
                err(
                    field(&suffix),
                    format!("duplicate server: \"{addr}\" appears more than once"),
                    "each `addr` must be unique within the backend".to_owned(),
                    &section,
                );
            }
        }

        // Slow start (B14): bounded like HAProxy `slowstart` (0 = off,
        // maximum 1h). A silent unbounded ramp would be a footgun.
        if backend.slow_start > std::time::Duration::from_secs(3600) {
            err(
                field("slow_start"),
                format!(
                    "slow_start = \"{:?}\" out of range (maximum 1h)",
                    backend.slow_start
                ),
                "slow_start = \"30s\" (0s = disabled; maximum 1h)".to_owned(),
                &section,
            );
        }

        // Re-resolution (B-H13/B-N18/B-E15): bounded. "0s" = resolve
        // once at startup (no periodic re-resolution).
        if backend.resolve_interval > std::time::Duration::from_secs(24 * 3600) {
            err(
                field("resolve_interval"),
                format!(
                    "resolve_interval = \"{:?}\" out of range (maximum 24h)",
                    backend.resolve_interval
                ),
                "resolve_interval = \"30s\" (0s = resolve once at startup; maximum 24h)".to_owned(),
                &section,
            );
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

            if hc.kind == HealthCheckKind::Http {
                if let Err(cause) = StatusExpectation::parse(&hc.expect_status) {
                    err(
                        field("health_check.expect_status"),
                        cause,
                        "expect_status = \"200-299\"".to_owned(),
                        &section,
                    );
                }
                if let Some(rstring) = &hc.expect_rstring
                    && let Err(cause) = RegexMatcher::parse(rstring)
                {
                    err(
                        field("health_check.expect_rstring"),
                        cause,
                        "expect_rstring = \"^ok$\"".to_owned(),
                        &section,
                    );
                }
                if !hc.http_path.starts_with('/') {
                    err(
                        field("health_check.http_path"),
                        format!(
                            "http_path = \"{}\" must start with '/' (rule: origin-form path)",
                            hc.http_path
                        ),
                        "http_path = \"/healthz\"".to_owned(),
                        &section,
                    );
                }
            }
        }

        if backend.maxqueue > MAX_QUEUE {
            err(
                field("maxqueue"),
                format!(
                    "maxqueue = {} exceeds the budget (rule: 0..={MAX_QUEUE})",
                    backend.maxqueue
                ),
                "maxqueue = 64".to_owned(),
                &section,
            );
        }
        if backend.maxqueue > 0 && backend.timeout_queue.is_zero() {
            err(
                field("timeout_queue"),
                "timeout_queue must be greater than 0 when maxqueue > 0".to_owned(),
                "timeout_queue = \"5s\"".to_owned(),
                &section,
            );
        }
        if backend.retries > MAX_RETRIES {
            err(
                field("retries"),
                format!(
                    "retries = {} exceeds the maximum (rule: 0..={MAX_RETRIES})",
                    backend.retries
                ),
                "retries = 2".to_owned(),
                &section,
            );
        }
        if backend.retry_non_idempotent && backend.retries == 0 {
            result.warnings.push(format!(
                "backend \"{name}\" sets retry_non_idempotent but retries = 0: it has no effect"
            ));
        }

        if let Some(tls) = &backend.tls {
            for (cause, example) in alpn_problems(&tls.alpn) {
                err(field("tls.alpn"), cause, example, &section);
            }
            // A backend reached by a `mode = "http"` listener only ever
            // receives HTTP/1.1 from the dataplane; negotiating h2 with it
            // would hand every request to a protocol layer that is not
            // implemented (see `unserved_alpn`).
            if let Some(proto) = unserved_alpn(&tls.alpn)
                && let Some(user) = http_mode_user(config, name)
            {
                err(
                    field("tls.alpn"),
                    format!(
                        "ALPN protocol \"{proto}\" cannot be used with backend \"{name}\": listener \"{user}\" (mode = \"http\") sends HTTP/1.1 over TLS, so a backend that negotiated h2 would receive requests it cannot parse"
                    ),
                    "alpn = [\"http/1.1\"]".to_owned(),
                    &section,
                );
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
            // `mode = "http"` terminates TLS and then parses HTTP/1.1: an
            // h2 entry makes the handshake succeed and every request fail
            // (no HTTP/2 dataplane), so the gate rejects it here instead.
            if listener.mode == ListenerMode::Http
                && let Some(proto) = unserved_alpn(&tls.alpn)
            {
                err(
                    format!("listener.{name}.tls.alpn"),
                    format!(
                        "ALPN protocol \"{proto}\" cannot be served: mode = \"http\" speaks HTTP/1.1 only, so the handshake would succeed and every request would then fail (no HTTP/2 dataplane yet)"
                    ),
                    "alpn = [\"http/1.1\"]".to_owned(),
                    &section,
                );
            }
            // SNI certificates (B-I2/B-H10/B-E9): every entry needs
            // names, each name must be a DNS name (never an IP literal)
            // and no name may be claimed twice.
            let mut claimed: std::collections::BTreeMap<String, usize> =
                std::collections::BTreeMap::new();
            for (index, cert) in tls.certs.iter().enumerate() {
                let field = format!("listener.{name}.tls.certs[{index}].names");
                if cert.names.is_empty() {
                    err(
                        field.clone(),
                        "an SNI certificate needs at least one name (exact DNS name or *.domain)"
                            .to_owned(),
                        "names = [\"api.example.com\", \"*.api.example.com\"]".to_owned(),
                        &section,
                    );
                    continue;
                }
                for raw in &cert.names {
                    if let Some(cause) = sni_name_problem(raw) {
                        err(
                            field.clone(),
                            cause,
                            "names = [\"api.example.com\", \"*.api.example.com\"]".to_owned(),
                            &section,
                        );
                        continue;
                    }
                    let key = raw.trim().trim_end_matches('.').to_ascii_lowercase();
                    if let Some(previous) = claimed.insert(key.clone(), index)
                        && previous != index
                    {
                        err(
                            field.clone(),
                            format!(
                                "\"{key}\" is already claimed by listener.{name}.tls.certs[{previous}]"
                            ),
                            "each SNI name belongs to exactly one certificate".to_owned(),
                            &section,
                        );
                    }
                }
            }
        }
    }

    result
}

/// Problems of a `hash_policy.key` (B-H3): `source`, `path`, `host`,
/// `cookie:NAME` or `header:NAME` (name 1..=255 bytes, no controls).
fn hash_key_problem(raw: &str) -> Option<String> {
    let key = raw.trim();
    match key {
        "source" | "path" | "host" => None,
        _ => match key.split_once(':') {
            Some((kind, name)) if kind == "cookie" || kind == "header" => {
                if name.is_empty() || name.len() > 255 {
                    return Some(format!("\"{raw}\": the {kind} name must be 1..=255 bytes"));
                }
                if name.bytes().any(|b| b <= 0x20 || b == 0x7f) {
                    return Some(format!(
                        "\"{raw}\": the {kind} name must not contain spaces or control characters"
                    ));
                }
                None
            }
            Some((kind, _)) => Some(format!(
                "\"{raw}\": unknown key kind \"{kind}\" (use cookie:NAME or header:NAME)"
            )),
            None => Some(format!(
                "\"{raw}\": use source, path, host, cookie:NAME or header:NAME"
            )),
        },
    }
}

/// Problems of one configured SNI name (B-I2/B-H10/B-E9): a DNS name or
/// a `*.` wildcard for exactly one extra label. IP literals are rejected
/// because a TLS client never sends them as SNI (RFC 6066).
fn sni_name_problem(raw: &str) -> Option<String> {
    let name = raw.trim().trim_end_matches('.');
    if name.is_empty() {
        return Some("the SNI name is empty".to_owned());
    }
    if name.len() > 253 {
        return Some(format!("\"{raw}\" is longer than 253 bytes"));
    }
    if name.parse::<std::net::IpAddr>().is_ok() {
        return Some(format!(
            "\"{raw}\" is an IP literal: clients never send an IP as SNI (RFC 6066), so this name can never match — use a DNS name or drop it"
        ));
    }
    let labels = match name.strip_prefix("*.") {
        Some("") => {
            return Some(format!(
                "\"{raw}\": the wildcard needs a domain after it (*.example.com)"
            ));
        }
        Some(rest) => rest,
        None => {
            if name.contains('*') {
                return Some(format!(
                    "\"{raw}\": the wildcard must be the leftmost label (*.example.com)"
                ));
            }
            name
        }
    };
    if labels.contains('*') {
        return Some(format!(
            "\"{raw}\": only one wildcard label is allowed, as the leftmost one"
        ));
    }
    for label in labels.split('.') {
        if label.is_empty() {
            return Some(format!("\"{raw}\" has an empty label"));
        }
        if label.len() > 63 {
            return Some(format!(
                "\"{raw}\": label \"{label}\" is longer than 63 bytes"
            ));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Some(format!(
                "\"{raw}\": labels must be letters, digits or '-' (got \"{label}\")"
            ));
        }
    }
    None
}

/// The first ALPN protocol in `alpn` that the dataplane cannot speak.
///
/// The HTTP dataplane is HTTP/1.1 only: negotiating `h2` (or `h2c`) with a
/// `mode = "http"` listener is the trap this gate closes — rustls completes
/// the handshake, the client starts sending HTTP/2 frames and every request
/// fails while the proxy's own counters never see an accepted connection.
/// `mode = "tcp"` relays bytes without interpreting them, so an `h2` hint
/// there is a legitimate tunnel choice and is left alone.
fn unserved_alpn(alpn: &[String]) -> Option<&str> {
    alpn.iter()
        .map(String::as_str)
        .find(|proto| matches!(*proto, "h2" | "h2c"))
}

/// Name of the first `mode = "http"` listener that routes to `backend`.
fn http_mode_user<'a>(config: &'a Config, backend: &str) -> Option<&'a str> {
    config
        .listener
        .iter()
        .filter(|(_, listener)| listener.mode == ListenerMode::Http && listener.backend == backend)
        .map(|(name, _)| name.as_str())
        .min()
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

    #[test]
    fn sni_names_accept_dns_and_single_label_wildcards_only() {
        for ok in [
            "api.example.com",
            "API.Example.COM.",
            "*.example.com",
            "a-b.example.test",
        ] {
            assert_eq!(sni_name_problem(ok), None, "{ok} must be accepted");
        }
        for (bad, needle) in [
            ("", "empty"),
            ("127.0.0.1", "IP literal"),
            ("::1", "IP literal"),
            ("api.*.example.com", "leftmost"),
            ("*", "leftmost"),
            ("a..example.com", "empty label"),
            ("api example.com", "labels must be"),
            ("*.com*", "leftmost"),
        ] {
            let problem =
                sni_name_problem(bad).unwrap_or_else(|| panic!("{bad:?} must be rejected"));
            assert!(
                problem.contains(needle),
                "{bad:?}: expected {needle:?}, got {problem:?}"
            );
        }
        let long = format!("{}.example.com", "a".repeat(64));
        assert!(sni_name_problem(&long).is_some_and(|p| p.contains("63")));
    }

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
            maps: BTreeMap::new(),
            shutdown_grace: Duration::from_secs(10),
            metrics: crate::schema::MetricsConfig::default(),
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
                    max_stream_duration: Duration::ZERO,
                    tls: None,
                    proxy_receive: false,
                    proxy_allow: Vec::new(),
                    forwarded_headers: ForwardedHeaders::default(),
                    local_response: None,
                    rules: Vec::new(),
                },
            );
        }
        config
    }

    fn check_config(config: &Config) -> CheckResult {
        check(config, "", Path::new("eqproxy.toml"))
    }

    #[test]
    fn http_check_errors_name_field_and_rule() {
        let result = check_source(
            r#"
            schema_version = 1
            [backend.api]
            server = "127.0.0.1:9000"
            [backend.api.health_check]
            type = "http"
            expect_status = "300-200"
            expect_rstring = "("
            http_path = "healthz"
            "#,
        );
        let fields: Vec<_> = result
            .errors
            .iter()
            .filter_map(|e| e.field.clone())
            .collect();
        for expected in [
            "backend.api.health_check.expect_status",
            "backend.api.health_check.expect_rstring",
            "backend.api.health_check.http_path",
        ] {
            assert!(
                fields.iter().any(|f| f == expected),
                "missing error for {expected}: {fields:?}"
            );
        }
        for e in &result.errors {
            assert!(
                e.cause.contains("rule:"),
                "cause must name the rule: {}",
                e.cause
            );
        }
    }

    #[test]
    fn proxy_receive_forwarded_and_local_response_rules() {
        let result = check_source(
            r#"
            schema_version = 1
            [listener.web]
            listen = "127.0.0.1:8080"
            mode = "tcp"
            backend = "api"
            proxy_receive = true
            forwarded_headers = "append"
            [listener.web.local_response]
            status = 999
            body = "x"
            content_type = ""
            [backend.api]
            server = "127.0.0.1:9000"
            "#,
        );
        let fields: Vec<_> = result
            .errors
            .iter()
            .filter_map(|e| e.field.clone())
            .collect();
        for expected in [
            "listener.web.proxy_allow",
            "listener.web.forwarded_headers",
            "listener.web.local_response.status",
            "listener.web.local_response.content_type",
            "listener.web.local_response",
        ] {
            assert!(
                fields.iter().any(|f| f == expected),
                "missing error for {expected}: {fields:?}"
            );
        }
    }

    /// Authentication (B-N9/B-I9): every bad auth block is rejected
    /// naming its field and the fix; a well-formed pair of mechanisms
    /// validates.
    #[test]
    fn auth_rules_name_the_field_and_the_fix() {
        let source_for = |auth: &str| {
            format!(
                "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:8080\"\nmode = \"http\"\nbackend = \"api\"\n[[listener.web.rules]]\npath = \"/x\"\nuse_backend = \"api\"\n{auth}\n[backend.api]\nserver = \"127.0.0.1:9000\"\n"
            )
        };
        for (auth, field, why) in [
            (
                "[listener.web.rules.auth]\nrealm = \"x\"",
                "listener.web.rules[0].auth",
                "at least one of url or type",
            ),
            (
                "[listener.web.rules.auth]\nurl = \"https://auth.example/verify\"",
                "listener.web.rules[0].auth.url",
                "http:// only",
            ),
            (
                "[listener.web.rules.auth]\ntype = \"basic\"",
                "listener.web.rules[0].auth.users",
                "at least one user",
            ),
            (
                "[listener.web.rules.auth]\nusers = [\"alice:x\"]",
                "listener.web.rules[0].auth.type",
                "only apply to type",
            ),
            (
                "[listener.web.rules.auth]\ntype = \"basic\"\nusers = [\"alice:$2y$05$abcdefghijklmnopqrstuv\"]",
                "listener.web.rules[0].auth.users",
                "openssl passwd -apr1",
            ),
            (
                "[listener.web.rules.auth]\ntype = \"basic\"\nusers = [\"alice:x\"]\nrealm = \"bad\\\"realm\"",
                "listener.web.rules[0].auth.realm",
                "realm",
            ),
        ] {
            let result = check_source(&source_for(auth));
            let err = result
                .errors
                .iter()
                .find(|err| err.field.as_deref() == Some(field))
                .unwrap_or_else(|| panic!("no error for {field}: {:?}", result.errors));
            assert!(
                err.cause.contains(why),
                "cause must contain {why:?}: {}",
                err.cause
            );
        }
        for auth in [
            "[listener.web.rules.auth]\ntype = \"basic\"\nusers = [\"alice:$apr1$eqpr0xyS$DDjQzF4.2qDil6v9iW4Xo1\"]\nrealm = \"EQProxy\"",
            "[listener.web.rules.auth]\nurl = \"http://127.0.0.1:9000/verify\"",
            "[listener.web.rules.auth]\nurl = \"http://auth.example/verify\"\ntype = \"basic\"\nusers = [\"alice:x\"]",
        ] {
            let result = check_source(&source_for(auth));
            assert!(result.is_valid(), "unexpected errors: {:?}", result.errors);
        }
    }

    #[test]
    fn queue_and_retries_rules() {
        let result = check_source(
            r#"
            schema_version = 1
            [backend.api]
            server = "127.0.0.1:9000"
            maxqueue = 100000
            timeout_queue = "0s"
            retries = 9
            "#,
        );
        let fields: Vec<_> = result
            .errors
            .iter()
            .filter_map(|e| e.field.clone())
            .collect();
        for expected in [
            "backend.api.maxqueue",
            "backend.api.timeout_queue",
            "backend.api.retries",
        ] {
            assert!(
                fields.iter().any(|f| f == expected),
                "missing error for {expected}: {fields:?}"
            );
        }
    }

    #[test]
    fn v05_full_config_is_valid() {
        let result = check_source(
            r#"
            schema_version = 1
            [metrics]
            detailed = true
            [listener.web]
            listen = "127.0.0.1:8080"
            mode = "http"
            backend = "api"
            proxy_receive = true
            proxy_allow = ["10.0.0.0/8", "192.0.2.1"]
            forwarded_headers = "append"
            [listener.web.local_response]
            status = 503
            body = "gone"
            [listener.web.tls]
            cert = "c.pem"
            key = "k.pem"
            client_ca = "ca.pem"
            [backend.api]
            servers = [{ addr = "127.0.0.1:9000", weight = 1 }]
            maxqueue = 64
            timeout_queue = "2s"
            retries = 2
            [backend.api.health_check]
            type = "http"
            http_path = "/healthz"
            expect_status = "200-299,301"
            expect_rstring = "ok"
            passive = true
            "#,
        );
        assert!(result.is_valid(), "unexpected errors: {:?}", result.errors);
    }

    #[test]
    fn schema_version_policy_accepts_known_rejects_newer() {
        // Backward compatibility (Q3): every known version is accepted.
        let result = check_source(
            "schema_version = 1\n\n[listener.web]\nlisten = \"127.0.0.1:8080\"\nbackend = \"api\"\n\n[backend.api]\nserver = \"127.0.0.1:9000\"\n",
        );
        assert!(result.is_valid(), "errors: {:?}", result.errors);
        // Newer (and the invalid 0) are rejected, naming the range.
        for version in ["0", "2", "99"] {
            let source = format!(
                "schema_version = {version}\n\n[listener.web]\nlisten = \"127.0.0.1:8080\"\nbackend = \"api\"\n\n[backend.api]\nserver = \"127.0.0.1:9000\"\n"
            );
            let result = check_source(&source);
            assert!(!result.is_valid(), "version {version} must be rejected");
            let err = &result.errors[0];
            assert_eq!(err.field.as_deref(), Some("schema_version"));
            assert!(
                err.cause.contains("not supported by this binary"),
                "cause: {}",
                err.cause
            );
            assert!(
                err.cause.contains("supported: 1..="),
                "must name the supported range: {}",
                err.cause
            );
        }
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
    fn hostname_servers_parse_and_validate_actionably() {
        use crate::schema::{ServerTarget, parse_server_target};

        // Parser (shared by validate and the dataplane translation).
        assert_eq!(
            parse_server_target("127.0.0.1:9000").expect("literal"),
            ServerTarget::Ip("127.0.0.1:9000".parse().expect("addr"))
        );
        assert_eq!(
            parse_server_target("[::1]:9000").expect("v6"),
            ServerTarget::Ip("[::1]:9000".parse().expect("addr"))
        );
        assert_eq!(
            parse_server_target("API.Internal:9000").expect("name"),
            ServerTarget::Name {
                host: "api.internal".to_owned(),
                port: 9000,
            },
            "hostnames are lowercased (DNS is case-insensitive)"
        );
        let missing_port = parse_server_target("api.internal").expect_err("no port");
        assert!(missing_port.contains(":PORT"), "{missing_port}");
        let bad_host = parse_server_target("bad host:80").expect_err("space");
        assert!(bad_host.contains("letters, digits"), "{bad_host}");
        let bad_port = parse_server_target("api.internal:http").expect_err("port");
        assert!(bad_port.contains("between 0 and 65535"), "{bad_port}");
        let raw_v6 = parse_server_target("::1:8080").expect_err("unbracketed v6");
        assert!(raw_v6.contains("brackets"), "{raw_v6}");

        // Validation: hostnames accepted, errors name field + cause.
        let ok = check_source(
            "schema_version = 1\n[backend.api]\nresolve_interval = \"30s\"\nservers = [{ addr = \"api.internal:9000\" }]\n",
        );
        assert!(ok.is_valid(), "errors: {:?}", ok.errors);

        let bad = check_source(
            "schema_version = 1\n[backend.api]\nresolve_interval = \"25h\"\nservers = [{ addr = \"bad host:80\" }]\n",
        );
        let fields: Vec<_> = bad.errors.iter().filter_map(|e| e.field.clone()).collect();
        assert_eq!(
            fields,
            vec![
                "backend.api.servers[0].addr",
                "backend.api.resolve_interval"
            ],
            "errors: {:?}",
            bad.errors
        );
        assert!(
            bad.errors[0].cause.contains("letters, digits"),
            "the address error must name the cause: {:?}",
            bad.errors[0]
        );
        assert!(
            bad.errors[1].cause.contains("maximum 24h"),
            "the interval error must name the bound: {:?}",
            bad.errors[1]
        );
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
    fn http_listener_rejects_h2_alpn_with_actionable_reason() {
        for proto in ["h2", "h2c"] {
            let result = check_source(&format!(
                "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nmode = \"http\"\nbackend = \"api\"\n[listener.web.tls]\ncert = \"c.pem\"\nkey = \"k.pem\"\nalpn = [\"{proto}\"]\n[backend.api]\nserver = \"127.0.0.1:1\"\n"
            ));
            assert!(!result.is_valid(), "{proto} must be rejected");
            assert_eq!(result.errors.len(), 1, "errors: {:?}", result.errors);
            let error = &result.errors[0];
            assert_eq!(error.field.as_deref(), Some("listener.web.tls.alpn"));
            assert!(
                error.cause.contains(&format!("\"{proto}\"")),
                "{}",
                error.cause
            );
            assert!(error.cause.contains("HTTP/1.1"), "{}", error.cause);
            assert_eq!(error.example, "alpn = [\"http/1.1\"]");
        }
    }

    #[test]
    fn http_listener_accepts_http1_alpn_and_no_alpn() {
        for alpn in ["alpn = [\"http/1.1\"]\n", ""] {
            let result = check_source(&format!(
                "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nmode = \"http\"\nbackend = \"api\"\n[listener.web.tls]\ncert = \"c.pem\"\nkey = \"k.pem\"\n{alpn}[backend.api]\nserver = \"127.0.0.1:1\"\n"
            ));
            assert!(result.is_valid(), "errors: {:?}", result.errors);
        }
    }

    #[test]
    fn tcp_listener_keeps_h2_alpn_for_byte_tunnels() {
        // mode = "tcp" relays bytes without parsing them, so advertising h2
        // there is a legitimate tunnel hint, not the HTTP/1.1 trap.
        let result = check_source(
            "schema_version = 1\n[listener.tunnel]\nlisten = \"127.0.0.1:0\"\nmode = \"tcp\"\nbackend = \"api\"\n[listener.tunnel.tls]\ncert = \"c.pem\"\nkey = \"k.pem\"\nalpn = [\"h2\"]\n[backend.api]\nserver = \"127.0.0.1:1\"\n",
        );
        assert!(result.is_valid(), "errors: {:?}", result.errors);
    }

    #[test]
    fn backend_h2_alpn_is_rejected_when_an_http_listener_uses_it() {
        let result = check_source(
            "schema_version = 1\n[listener.web]\nlisten = \"127.0.0.1:0\"\nmode = \"http\"\nbackend = \"api\"\n[backend.api]\nserver = \"127.0.0.1:1\"\n[backend.api.tls]\nalpn = [\"h2\"]\n",
        );
        assert!(!result.is_valid());
        let error = result
            .errors
            .iter()
            .find(|e| e.field.as_deref() == Some("backend.api.tls.alpn"))
            .unwrap_or_else(|| panic!("errors: {:?}", result.errors));
        assert!(error.cause.contains("\"h2\""), "{}", error.cause);
        assert!(error.cause.contains("listener \"web\""), "{}", error.cause);
        assert_eq!(error.example, "alpn = [\"http/1.1\"]");
    }

    #[test]
    fn backend_h2_alpn_is_allowed_for_a_tcp_tunnel() {
        let result = check_source(
            "schema_version = 1\n[listener.tunnel]\nlisten = \"127.0.0.1:0\"\nbackend = \"api\"\n[backend.api]\nserver = \"127.0.0.1:1\"\n[backend.api.tls]\nalpn = [\"h2\"]\n",
        );
        assert!(result.is_valid(), "errors: {:?}", result.errors);
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

    // --- B-I11 (split) and C10 (hot maps) gate ---

    fn split_config(targets: &str) -> String {
        format!(
            "schema_version = 1\n\
             [listener.web]\n\
             listen = \"127.0.0.1:8080\"\n\
             mode = \"http\"\n\
             backend = \"stable\"\n\
             [[listener.web.rules]]\n\
             name = \"canary\"\n\
             path_prefix = \"/\"\n\
             split = [{targets}]\n\
             [backend.stable]\n\
             server = \"127.0.0.1:9000\"\n\
             [backend.canary]\n\
             server = \"127.0.0.1:9001\"\n"
        )
    }

    #[test]
    fn split_targets_are_validated_with_actionable_fields() {
        let ok = check_source(&split_config(
            "{ backend = \"stable\", weight = 90 }, { backend = \"canary\", weight = 10 }",
        ));
        assert!(ok.is_valid(), "errors: {:?}", ok.errors);

        let ghost = check_source(&split_config(
            "{ backend = \"stable\", weight = 9 }, { backend = \"ghost\", weight = 1 }",
        ));
        let err = ghost
            .errors
            .iter()
            .find(|e| e.field.as_deref() == Some("listener.web.rules[0].split[1].backend"))
            .expect("names split[1].backend");
        assert!(err.cause.contains("ghost"), "{err:?}");
        assert!(err.example.contains("[backend.ghost]"), "{err:?}");

        let dupe = check_source(&split_config(
            "{ backend = \"stable\", weight = 1 }, { backend = \"stable\", weight = 1 }",
        ));
        assert!(
            dupe.errors.iter().any(|e| e.cause.contains("listed twice")),
            "errors: {:?}",
            dupe.errors
        );

        let single = check_source(&split_config("{ backend = \"stable\", weight = 1 }"));
        assert!(
            single
                .errors
                .iter()
                .any(|e| e.cause.contains("at least two targets")),
            "errors: {:?}",
            single.errors
        );

        let zero = check_source(&split_config(
            "{ backend = \"stable\", weight = 0 }, { backend = \"canary\", weight = 0 }",
        ));
        assert!(
            zero.errors
                .iter()
                .any(|e| e.cause.contains("weight = 0 (no request")),
            "errors: {:?}",
            zero.errors
        );

        let heavy = check_source(&split_config(
            "{ backend = \"stable\", weight = 257 }, { backend = \"canary\", weight = 1 }",
        ));
        assert!(
            heavy.errors.iter().any(|e| e.field.as_deref()
                == Some("listener.web.rules[0].split[0].weight")
                && e.cause.contains("out of range")),
            "errors: {:?}",
            heavy.errors
        );
    }

    #[test]
    fn split_is_an_exclusive_action_and_forwards() {
        let both = check_source(
            &split_config(
                "{ backend = \"stable\", weight = 1 }, { backend = \"canary\", weight = 1 }",
            )
            .replace("split = ", "use_backend = \"stable\"\nsplit = "),
        );
        assert!(
            both.errors
                .iter()
                .any(|e| e.cause.contains("set exactly one of use_backend, split")),
            "errors: {:?}",
            both.errors
        );

        // A split forwards: rewrite and request-side header ops apply.
        let forwards = check_source(
            &split_config(
                "{ backend = \"stable\", weight = 1 }, { backend = \"canary\", weight = 1 }",
            )
            .replace(
                "split = ",
                "set_headers = [{ name = \"x-beta\", value = \"on\" }]\nrewrite = { host_rewrite = \"internal\" }\nsplit = ",
            ),
        );
        assert!(forwards.is_valid(), "errors: {:?}", forwards.errors);
    }

    // --- B-H3 (hash_policy and request_mirror) gate ---

    /// Split rule (two live targets) plus the `extra` rule keys and a
    /// `shadow` backend the mirror can point at.
    fn hashed_source(extra: &str) -> String {
        format!(
            "schema_version = 1\n\
             [listener.web]\n\
             listen = \"127.0.0.1:8080\"\n\
             mode = \"http\"\n\
             backend = \"stable\"\n\
             [[listener.web.rules]]\n\
             name = \"hashed\"\n\
             path_prefix = \"/\"\n\
             split = [{{ backend = \"stable\", weight = 1 }}, {{ backend = \"canary\", weight = 1 }}]\n\
             {extra}\n\
             [backend.stable]\n\
             server = \"127.0.0.1:9000\"\n\
             [backend.canary]\n\
             server = \"127.0.0.1:9001\"\n\
             [backend.shadow]\n\
             server = \"127.0.0.1:9002\"\n"
        )
    }

    #[test]
    fn hash_policy_and_request_mirror_accept_the_supported_forms() {
        for extra in [
            "hash_policy = { key = \"cookie:session\" }",
            "hash_policy = { key = \"header:x-user\" }",
            "hash_policy = { key = \"source\" }",
            "request_mirror = { backend = \"shadow\" }",
            "request_mirror = { backend = \"shadow\", percentage = 10 }",
            "hash_policy = { key = \"path\" }\nrequest_mirror = { backend = \"shadow\", percentage = 100 }",
        ] {
            let result = check_source(&hashed_source(extra));
            assert!(
                result.is_valid(),
                "{extra:?} must be valid: {:?}",
                result.errors
            );
        }
    }

    #[test]
    fn hash_policy_errors_name_the_field_the_cause_and_a_fix() {
        // Unknown key kind: names the field and the accepted grammar.
        let unknown = check_source(&hashed_source("hash_policy = { key = \"iphash\" }"));
        let err = unknown
            .errors
            .iter()
            .find(|e| e.field.as_deref() == Some("listener.web.rules[0].hash_policy.key"))
            .expect("names hash_policy.key");
        assert!(
            err.cause
                .contains("use source, path, host, cookie:NAME or header:NAME"),
            "{err:?}"
        );
        assert!(err.example.contains("cookie:session"), "{err:?}");

        // An empty cookie/header name is rejected with its own cause.
        let empty = check_source(&hashed_source("hash_policy = { key = \"cookie:\" }"));
        assert!(
            empty
                .errors
                .iter()
                .any(|e| e.cause.contains("name must be 1..=255 bytes")),
            "errors: {:?}",
            empty.errors
        );

        // Without a split there is nothing to hash between: the error says
        // so and points at the per-server stickiness instead.
        let no_split = check_source(
            &hashed_source("hash_policy = { key = \"source\" }")
                .replace(
                    "split = [{ backend = \"stable\", weight = 1 }, { backend = \"canary\", weight = 1 }]",
                    "use_backend = \"stable\"",
                ),
        );
        let err = no_split
            .errors
            .iter()
            .find(|e| e.field.as_deref() == Some("listener.web.rules[0].hash_policy"))
            .expect("names hash_policy");
        assert!(err.cause.contains("needs a split action"), "{err:?}");
        assert!(
            err.cause.contains("affinity"),
            "the cause names the real alternative for one backend: {err:?}"
        );
        assert!(err.example.contains("split ="), "{err:?}");

        // One live target is the same problem: no key to spread.
        let one_target = check_source(
            &hashed_source("hash_policy = { key = \"source\" }").replace(
                "split = [{ backend = \"stable\", weight = 1 }, { backend = \"canary\", weight = 1 }]",
                "split = [{ backend = \"stable\", weight = 1 }, { backend = \"canary\", weight = 0 }]",
            ),
        );
        assert!(
            one_target
                .errors
                .iter()
                .any(|e| e.cause.contains("at least two targets with weight > 0")),
            "errors: {:?}",
            one_target.errors
        );
    }

    #[test]
    fn request_mirror_errors_name_the_field_the_cause_and_a_fix() {
        // Unknown backend: names the field and shows the missing section.
        let ghost = check_source(&hashed_source("request_mirror = { backend = \"ghost\" }"));
        let err = ghost
            .errors
            .iter()
            .find(|e| e.field.as_deref() == Some("listener.web.rules[0].request_mirror.backend"))
            .expect("names request_mirror.backend");
        assert!(err.cause.contains("ghost"), "{err:?}");
        assert!(err.example.contains("[backend.ghost]"), "{err:?}");

        // Percentage outside 1..=100 is rejected, never clamped.
        for bad in ["0", "101"] {
            let percentage = check_source(&hashed_source(&format!(
                "request_mirror = {{ backend = \"shadow\", percentage = {bad} }}"
            )));
            let err = percentage
                .errors
                .iter()
                .find(|e| {
                    e.field.as_deref() == Some("listener.web.rules[0].request_mirror.percentage")
                })
                .unwrap_or_else(|| panic!("percentage = {bad} must be rejected: {percentage:?}"));
            assert!(err.cause.contains("1..=100"), "{err:?}");
        }

        // A local answer has no request to mirror.
        let redirect = check_source(&hashed_source("request_mirror = { backend = \"shadow\" }")
            .replace(
                "split = [{ backend = \"stable\", weight = 1 }, { backend = \"canary\", weight = 1 }]",
                "redirect = { status = 301, location = \"https://example.com\" }",
            ));
        assert!(
            redirect.errors.iter().any(|e| e.field.as_deref()
                == Some("listener.web.rules[0].request_mirror")
                && e.cause.contains("forwarding rules")),
            "errors: {:?}",
            redirect.errors
        );
    }

    #[test]
    fn map_sections_validate_sources_budgets_and_reload_window() {
        let both = check_source(
            "schema_version = 1\n[maps.t]\nfile = \"t.map\"\nentries = { a = \"1\" }\n",
        );
        assert!(
            both.errors
                .iter()
                .any(|e| e.cause.contains("set exactly one of file or entries")),
            "errors: {:?}",
            both.errors
        );
        let neither = check_source("schema_version = 1\n[maps.t]\ndefault = \"x\"\n");
        assert!(
            neither
                .errors
                .iter()
                .any(|e| e.cause.contains("set exactly one of file or entries")),
            "errors: {:?}",
            neither.errors
        );
        let fast = check_source(
            "schema_version = 1\n[maps.t]\nfile = \"t.map\"\nreload_interval = \"100ms\"\n",
        );
        let err = fast
            .errors
            .iter()
            .find(|e| e.field.as_deref() == Some("maps.t.reload_interval"))
            .expect("names maps.t.reload_interval");
        assert!(err.cause.contains("out of range"), "{err:?}");

        let bad_key =
            check_source("schema_version = 1\n[maps.t]\nentries = { \"has space\" = \"1\" }\n");
        assert!(
            bad_key
                .errors
                .iter()
                .any(|e| e.cause.contains("whitespace")),
            "errors: {:?}",
            bad_key.errors
        );

        // Unreferenced maps warn; referenced ones do not.
        let orphan = check_source("schema_version = 1\n[maps.t]\nfile = \"t.map\"\n");
        assert!(orphan.is_valid(), "errors: {:?}", orphan.errors);
        assert!(
            orphan.warnings.iter().any(|w| w.contains("[maps.t]")),
            "warnings: {:?}",
            orphan.warnings
        );
    }

    #[test]
    fn map_conditions_need_an_existing_map_and_valid_shape() {
        let ghost = check_source(
            "schema_version = 1\n\
             [listener.web]\n\
             listen = \"127.0.0.1:8080\"\n\
             mode = \"http\"\n\
             backend = \"api\"\n\
             [[listener.web.rules]]\n\
             name = \"gate\"\n\
             map = { name = \"ghost\", key = \"host\" }\n\
             use_backend = \"api\"\n\
             [backend.api]\n\
             server = \"127.0.0.1:9000\"\n",
        );
        let err = ghost
            .errors
            .iter()
            .find(|e| e.field.as_deref() == Some("listener.web.rules[0].map.name"))
            .expect("names map.name");
        assert!(err.cause.contains("does not exist"), "{err:?}");
        assert!(err.example.contains("[maps.ghost]"), "{err:?}");

        let ambiguous = check_source(
            "schema_version = 1\n\
             [maps.t]\n\
             file = \"t.map\"\n\
             [listener.web]\n\
             listen = \"127.0.0.1:8080\"\n\
             mode = \"http\"\n\
             backend = \"api\"\n\
             [[listener.web.rules]]\n\
             name = \"gate\"\n\
             map = { name = \"t\", key = \"host\", header = \"x-a\" }\n\
             use_backend = \"api\"\n\
             [backend.api]\n\
             server = \"127.0.0.1:9000\"\n",
        );
        assert!(
            ambiguous.errors.iter().any(|e| e.field.as_deref()
                == Some("listener.web.rules[0].map.key")
                && e.cause.contains("exactly one of key or header")),
            "errors: {:?}",
            ambiguous.errors
        );

        // Cookies: a bad name is rejected with the shared matcher grammar.
        let bad_cookie = check_source(
            "schema_version = 1\n\
             [listener.web]\n\
             listen = \"127.0.0.1:8080\"\n\
             mode = \"http\"\n\
             backend = \"api\"\n\
             [[listener.web.rules]]\n\
             name = \"canary\"\n\
             cookies = [{ name = \"bad name\", present = true }]\n\
             use_backend = \"api\"\n\
             [backend.api]\n\
             server = \"127.0.0.1:9000\"\n",
        );
        assert!(
            bad_cookie.errors.iter().any(|e| e.field.as_deref()
                == Some("listener.web.rules[0].cookies[0]")
                && e.cause.contains("cookie name")),
            "errors: {:?}",
            bad_cookie.errors
        );
    }
}
