#![no_main]

//! v0.8.5 (CE6/Q9/CE8) — Live fuzz target for `eqproxy config import`.
//!
//! Seeded with the four reference configurations in
//! `docs/evidence/v085-config-import/raw/`, then mutated freely. Oracle for
//! arbitrary bytes, in every dialect:
//!
//! 1. `convert` never panics (the parser is fed hostile text, not config);
//! 2. whenever it returns `Ok`, the emitted TOML re-parses with the crate's
//!    own parser and declares at least one listener — the promise that the
//!    importer cannot hand back a file the product rejects;
//! 3. the conversion is deterministic: the same input yields the same bytes
//!    for the TOML and for the report;
//! 4. the ternary counts are consistent with the report it returns (the
//!    report prints the same three numbers), so a note that is counted but
//!    not written — or the reverse — fails here.
//!
//! It does not check semantic equivalence with the source configuration:
//! that needs the origin backends of each file, and is covered (where it can
//! be) by `eqproxy-config/tests/import_corpus.rs` and the container E2E.

use eqproxy_config::import::{self, Source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Configurations are bounded text; the importer enforces the same cap.
    let data = &data[..data.len().min(64 * 1024)];
    let text = String::from_utf8_lossy(data);

    for source in [
        Source::Nginx,
        Source::Haproxy,
        Source::Ingress,
        Source::Envoy,
    ] {
        let Ok(first) = import::convert(source, &text) else {
            continue;
        };

        let config = eqproxy_config::parse_str(&first.toml, std::path::Path::new("<fuzz>"))
            .unwrap_or_else(|err| {
                panic!(
                    "{}: emitted TOML does not parse: {} — input:\n{text}",
                    source.as_str(),
                    err.cause
                )
            });
        assert!(
            !config.listener.is_empty(),
            "{}: converted output has no listener — input:\n{text}",
            source.as_str()
        );

        let second = import::convert(source, &text).expect("deterministic conversion");
        assert_eq!(
            first.toml,
            second.toml,
            "{}: TOML is not deterministic",
            source.as_str()
        );
        assert_eq!(
            first.report,
            second.report,
            "{}: report is not deterministic",
            source.as_str()
        );

        let counts = first.counts;
        let total = counts.converted + counts.review + counts.rejected;
        assert!(
            total > 0,
            "{}: converted output with no classified directive",
            source.as_str()
        );

        // The header prints walked/classified and the three buckets; the
        // detail section prints one bullet per directive. Both must agree
        // with `Outcome::counts`, otherwise the report lies about its own
        // completeness.
        let header = first
            .report
            .lines()
            .find(|line| line.starts_with("- Directivas leídas:"))
            .unwrap_or_else(|| panic!("{}: report has no counts header", source.as_str()));
        let numbers: Vec<usize> = header
            .split(|c: char| !c.is_ascii_digit())
            .filter(|token| !token.is_empty())
            .filter_map(|token| token.parse().ok())
            .collect();
        let (read, classified, converted, review, rejected) = match numbers.as_slice() {
            [read, classified, converted, review, rejected] => {
                (*read, *classified, *converted, *review, *rejected)
            }
            other => panic!(
                "{}: unexpected counts header {other:?} in {:?}",
                source.as_str(),
                header
            ),
        };
        assert_eq!(
            read,
            classified,
            "{}: walked != classified",
            source.as_str()
        );
        assert_eq!(
            classified,
            total,
            "{}: header total != counts",
            source.as_str()
        );
        assert_eq!(
            (converted, review, rejected),
            (counts.converted, counts.review, counts.rejected),
            "{}: header buckets != Outcome::counts",
            source.as_str()
        );
        let bullets = first
            .report
            .lines()
            .filter(|line| line.starts_with("- `"))
            .count();
        assert_eq!(
            bullets,
            total,
            "{}: {bullets} directive bullets for {total} classified",
            source.as_str()
        );
    }
});
