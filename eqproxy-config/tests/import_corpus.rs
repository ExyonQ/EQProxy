//! Corpus gate for `eqproxy config import` (Phase 8a, CE6/Q9/CE8).
//!
//! The four reference configurations in `docs/evidence/v085-config-import/raw/`
//! are real files (a HAProxy, an nginx, an ingress-nginx multi-document
//! manifest and an Envoy v3 bootstrap). For each one this test asserts the
//! contract the converter promises:
//!
//! 1. the generated `eqproxy.toml` parses **and** validates with the product's
//!    own parser (`import::convert` does it, and the test re-parses the text
//!    independently so a regression in `convert` cannot hide it);
//! 2. every walked source directive produced a classification — the report's
//!    "leídas" and "clasificadas" counters agree, and the report lists all of
//!    them;
//! 3. the conversion is not empty and names what it refused: each corpus file
//!    exercises features EQProxy does not have (syslog, Lua, ssl-passthrough,
//!    xDS), and those must appear as rejected, never disappear;
//! 4. converting twice yields the same bytes (deterministic: `BTreeMap`s and no
//!    timestamps).
//!
//! It does not claim traffic equivalence: that would need the origin backends
//! of each file. What it proves is the shape of the artifact and the honesty of
//! the report.

use std::path::{Path, PathBuf};

use eqproxy_config::import::{self, Outcome, Source};

fn corpus(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/evidence/v085-config-import/raw")
        .join(name)
}

fn convert(name: &str, source: Source) -> (String, Outcome) {
    let path = corpus(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("corpus file {} must be readable: {err}", path.display()));
    let outcome = import::convert(source, &text).unwrap_or_else(|err| {
        panic!("{name} must convert: {err}");
    });
    (text, outcome)
}

fn assert_contract(name: &str, text: &str, outcome: &Outcome) {
    // 1. The file validates with the real parser, not with a replica.
    let parsed = eqproxy_config::parse_str(&outcome.toml, Path::new(name))
        .unwrap_or_else(|err| panic!("{name}: generated TOML must parse: {err}"));
    let check = eqproxy_config::validate::check(&parsed, &outcome.toml, Path::new(name));
    assert!(
        check.is_valid(),
        "{name}: generated configuration must validate: {:?}",
        check
            .errors
            .iter()
            .map(|err| (err.field.clone(), err.cause.clone()))
            .collect::<Vec<_>>()
    );

    // 2. Every walked directive was classified and appears in the report.
    let walked = counter(&outcome.report, "Directivas leídas:");
    let classified = counter(&outcome.report, "clasificadas:");
    assert_eq!(
        walked, classified,
        "{name}: a walked directive produced no classification (silent omission)"
    );
    assert!(
        walked > 0,
        "{name}: the converter must walk the source, not skip it"
    );

    // 3. What the source has and EQProxy does not must be named.
    let rejected = outcome.counts.rejected;
    assert!(
        rejected > 0,
        "{name}: this corpus file exercises features EQProxy does not have today, \
         so at least one directive must be classified as rejected"
    );
    assert!(
        outcome.report.contains("Qué no se ha traducido"),
        "{name}: the report must summarise what was not translated"
    );
    assert!(
        !listeners_summary(&outcome.report).is_empty(),
        "{name}: at least one listener must be generated"
    );

    // 4. Deterministic output.
    let again = import::convert(source_of(name), text).expect("second pass");
    assert_eq!(
        again.toml, outcome.toml,
        "{name}: TOML must be deterministic"
    );
    assert_eq!(
        again.report, outcome.report,
        "{name}: report must be deterministic"
    );
}

/// Extracts the integer that follows `label` in the report header.
fn counter(report: &str, label: &str) -> usize {
    let start = report
        .find(label)
        .unwrap_or_else(|| panic!("report must carry «{label}»"));
    let rest = &report[start + label.len()..];
    let digits: String = rest
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(char::is_ascii_digit)
        .collect();
    digits
        .parse()
        .unwrap_or_else(|_| panic!("«{label}» must be followed by a number"))
}

fn source_of(name: &str) -> Source {
    if name.ends_with(".cfg") {
        Source::Haproxy
    } else if name.ends_with(".yaml") {
        Source::detect(&std::fs::read_to_string(corpus(name)).expect("read"))
    } else {
        Source::Nginx
    }
}

/// First listener row of the report table, proving the table is not empty.
fn listeners_summary(report: &str) -> String {
    report
        .lines()
        .skip_while(|line| !line.starts_with("| listener |"))
        .nth(2)
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn haproxy_frontend_backend_and_httpchk_convert() {
    let (text, outcome) = convert("haproxy.cfg", Source::Haproxy);
    assert_contract("haproxy.cfg", &text, &outcome);
    // HTTP health check is a real field since B-H6, not a gap.
    assert!(
        outcome.toml.contains("type = \"http\""),
        "option httpchk must become an HTTP health check:\n{}",
        outcome.toml
    );
    assert!(
        outcome.toml.contains("path_prefix = \"/api\"") || outcome.toml.contains("[[listener."),
        "rules must be emitted for the frontends that need them"
    );
    // A hostname server is accepted now (B-H13), not an error.
    assert!(
        outcome.report.contains("ejemplocpuerta.local"),
        "the hostname server must appear in the report"
    );
}

#[test]
fn nginx_locations_become_rules_and_vhosts_are_reported() {
    let (text, outcome) = convert("nginx.conf", Source::Nginx);
    assert_contract("nginx.conf", &text, &outcome);
    assert!(
        outcome.toml.contains("path_prefix = \"/api/\""),
        "the /api/ location must become a path rule:\n{}",
        outcome.toml
    );
    assert!(
        outcome.report.contains("vhost"),
        "the second server block on :443 must be reported as a vhost conflict"
    );
    assert!(
        outcome.toml.contains("gzip = true"),
        "gzip on must enable compression:\n{}",
        outcome.toml
    );
}

#[test]
fn ingress_nginx_resolves_endpoints_and_annotations() {
    let (text, outcome) = convert("ingress-nginx.yaml", Source::Ingress);
    assert_contract("ingress-nginx.yaml", &text, &outcome);
    assert!(
        outcome.toml.contains("10.0.0.10:8080") && outcome.toml.contains("10.0.1.20:8080"),
        "Endpoints must resolve to backend servers:\n{}",
        outcome.toml
    );
    assert!(
        outcome.toml.contains("rate_limit") && outcome.toml.contains("cors"),
        "limit-rps and CORS annotations must land in the rules:\n{}",
        outcome.toml
    );
    assert!(
        outcome.report.contains("ssl-passthrough"),
        "ssl-passthrough has no equivalent and must be reported"
    );
}

#[test]
fn envoy_clusters_tls_and_routes_convert() {
    let (text, outcome) = convert("envoy.yaml", Source::Envoy);
    assert_contract("envoy.yaml", &text, &outcome);
    assert!(
        outcome.toml.contains("10.0.0.10:8080"),
        "cluster endpoints must become backend servers:\n{}",
        outcome.toml
    );
    assert!(
        outcome.toml.contains("server_name = \"api.interno\""),
        "UpstreamTlsContext.sni must become server_name:\n{}",
        outcome.toml
    );
    assert!(
        outcome.report.contains("xDS"),
        "dynamic_resources must be reported as unsupported"
    );
}

#[test]
fn detection_picks_the_right_dialect_for_each_corpus_file() {
    for (name, expected) in [
        ("haproxy.cfg", Source::Haproxy),
        ("nginx.conf", Source::Nginx),
        ("ingress-nginx.yaml", Source::Ingress),
        ("envoy.yaml", Source::Envoy),
    ] {
        let text = std::fs::read_to_string(corpus(name)).expect("read");
        assert_eq!(Source::detect(&text), expected, "{name}");
    }
}
