#![no_main]

//! Phase 2c — Live fuzz target for the HTTP/1.1 framing head parsers
//! (THREAT_MODEL T01-T03). Fed with `fuzz/seeds/framing/*`.
//!
//! Oracle: the parsers must never panic and must reject explicitly —
//! requests with 400/431/501/505, responses with 502. Any panic or
//! off-spec status fails the fuzzer.

use eqproxy_net::http1::{parse_request_head, parse_response_head};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Cap the input so a run stays within the parser's threat model
    // (oversized heads are rejected by the read layer with 431 first).
    let input = &data[..data.len().min(64 * 1024)];
    match parse_request_head(input) {
        Ok(_) => {}
        Err(reject) => {
            assert!(
                matches!(reject.status, 400 | 431 | 501 | 505),
                "request rejection must be explicit, got {}",
                reject.status
            );
        }
    }
    match parse_response_head(input, false) {
        Ok(_) => {}
        Err(reject) => {
            assert_eq!(
                reject.status, 502,
                "upstream rejection must map to 502, got {}",
                reject.status
            );
        }
    }
    // HEAD-request mode shares the same no-panic contract.
    let _ = parse_response_head(input, true);
});
