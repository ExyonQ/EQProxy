#![no_main]

//! v0.6 (B-H3/B-H4) — Live fuzz target for the routing-rule evaluator.
//! Fed with `fuzz/seeds/rules/*`.
//!
//! Oracle: `Rule::compile` must never panic on arbitrary strings (regexes
//! included) and every rejection must carry a non-empty cause and example;
//! `matches`/`explain` must never panic and must always agree. The
//! committed corpus replay lives in `eqproxy-core/tests/rules_fuzz_corpus.rs`.

use eqproxy_core::rules::{HeaderSpec, RequestFacts, Rule, RuleSpec};
use libfuzzer_sys::fuzz_target;

/// Config strings are UTF-8; invalid bytes become U+FFFD, which is itself
/// a useful case.
fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fuzz_target!(|data: &[u8]| {
    // Rule specs are bounded config, not streams.
    let data = &data[..data.len().min(64 * 1024)];

    // `;`-separated chunks map onto the spec fields in declaration order.
    let chunks: Vec<&[u8]> = data.split(|b| *b == b';').collect();
    let at = |i: usize| -> String {
        chunks.get(i).map(|c| text(c)).unwrap_or_default()
    };
    let opt = |i: usize| -> Option<String> {
        chunks.get(i).filter(|c| !c.is_empty()).map(|c| text(c))
    };

    let mut spec = RuleSpec {
        name: at(0),
        host: opt(1),
        host_prefix: opt(2),
        host_regex: opt(3),
        path: opt(4),
        path_prefix: opt(5),
        path_regex: opt(6),
        ..RuleSpec::default()
    };
    if !at(7).is_empty() {
        spec.methods = at(7).split(',').map(str::to_owned).collect();
    }
    // 8: `name=value` (exact), 9: `name~regex`, 10: `name!` (present).
    for (chunk, kind) in [(8usize, 0u8), (9, 1), (10, 2)] {
        if let Some(raw) = opt(chunk) {
            let (name, value) = match kind {
                0 => raw.split_once('=').unwrap_or((raw.as_str(), "")),
                1 => raw.split_once('~').unwrap_or((raw.as_str(), "")),
                _ => (raw.trim_end_matches('!'), ""),
            };
            spec.headers.push(HeaderSpec {
                name: name.to_owned(),
                exact: (kind == 0).then(|| value.to_owned()),
                regex: (kind == 1).then(|| value.to_owned()),
                present: kind == 2,
            });
        }
    }
    if !at(11).is_empty() {
        spec.ip = at(11).split(',').map(str::to_owned).collect();
    }

    // Facts: same chunk mapping over the tail, plus a peer from raw bytes.
    let headers = vec![(at(12), at(13))];
    let tail = data.len().saturating_sub(8);
    let peer = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
        data.get(tail).copied().unwrap_or(127),
        data.get(tail + 1).copied().unwrap_or(0),
        data.get(tail + 2).copied().unwrap_or(0),
        data.get(tail + 3).copied().unwrap_or(1),
    ));

    match Rule::compile(&spec) {
        Ok(rule) => {
            let facts = RequestFacts {
                method: &at(14),
                host: &at(15),
                path: &at(16),
                headers: &headers,
                peer,
            };
            let verdict = rule.matches(&facts);
            let explained = rule.explain(&facts);
            assert_eq!(
                verdict,
                explained.is_ok(),
                "matches/explain disagree for spec={spec:?} facts={facts:?}"
            );
            if let Err(reason) = explained {
                assert!(!reason.is_empty(), "explain must say why for {facts:?}");
            }
        }
        Err(why) => {
            assert!(!why.cause.is_empty(), "rejection must explain itself");
            assert!(!why.example.is_empty(), "rejection must show an example");
        }
    }
});
