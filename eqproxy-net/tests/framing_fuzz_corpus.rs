//! Phase 2c — Deterministic fuzz-style corpus for the HTTP/1.1 framing parser.
//!
//! Security property under test (THREAT_MODEL T01-T03): the head parsers
//! [`eqproxy_net::http1::parse_request_head`] and
//! [`eqproxy_net::http1::parse_response_head`] must **never panic** on
//! arbitrary bytes, and every rejection must carry an explicit status:
//! requests fail with 400/431/501/505, responses with 502. Anything else is a
//! defect (fail-open or crash). Size caps (MAX_HEAD_BYTES / MAX_LINE_BYTES)
//! live in the async read layer; the parsers enforce header-count limits.
//!
//! This is the committed, always-run part of parser fuzzing: a fixed seed
//! corpus plus a deterministic PRNG mutator (xorshift64, fixed seed), so the
//! test is reproducible without libFuzzer. The live `cargo-fuzz` target in
//! `fuzz/fuzz_targets/framing.rs` reuses the same seeds for open-ended runs.

use eqproxy_net::http1::{MAX_HEADERS, parse_request_head, parse_response_head};

/// Fixed seeds: valid traffic plus the T01-T03 attack corpus.
fn request_seeds() -> Vec<Vec<u8>> {
    let mut seeds = vec![
        b"GET /a HTTP/1.1\r\nHost: x\r\n".to_vec(),
        b"GET /a HTTP/1.0\r\nHost: x\r\nConnection: keep-alive\r\n".to_vec(),
        b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n".to_vec(),
        b"POST /a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n".to_vec(),
        b"HEAD /a HTTP/1.1\r\nHost: x\r\n".to_vec(),
        b"OPTIONS * HTTP/1.1\r\nHost: x\r\n".to_vec(),
        // T01: ambiguous framing must be rejected, never forwarded.
        b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n".to_vec(),
        b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 4\r\n".to_vec(),
        b"POST /a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n".to_vec(),
        b"POST /a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n".to_vec(),
        b"GET /a HTTP/1.1\r\nHost: x\r\nHost: y\r\n".to_vec(),
        // T02: malformed lines.
        b"GET /a HTTP/1.1\r\nHost: x\r\n Bad: fold\r\n".to_vec(),
        b"GET /a HTTP/1.1\r\nHost: x\r\nNoColon\r\n".to_vec(),
        b"GET /a HTTP/1.1\r\nHost: x\r\nBad Name: v\r\n".to_vec(),
        b"GET /a HTTP/1.1\r\nBad\x7fName: v\r\nHost: x\r\n".to_vec(),
        b"GET /a HTTP/1.1\r\nHost: \x01bad\r\n".to_vec(),
        b"GET /a HTTP/1.1\nHost: x\n".to_vec(),
        b"GET  /a  HTTP/1.1\r\nHost: x\r\n".to_vec(),
        b"get /a HTTP/1.1\r\nHost: x\r\n".to_vec(),
        b"GET http://x/a HTTP/1.1\r\nHost: x\r\n".to_vec(),
        b"GET /a HTTP/2.0\r\nHost: x\r\n".to_vec(),
        b"CONNECT x:443 HTTP/1.1\r\nHost: x\r\n".to_vec(),
        b"GET /a HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n".to_vec(),
        b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 03\r\n".to_vec(),
        b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: -5\r\n".to_vec(),
        b"".to_vec(),
        b"\r\n".to_vec(),
        b"\x00\x01\x02\xff\xfe\xfd".to_vec(),
    ];
    // T03: header-count limit (valid at exactly MAX_HEADERS, rejected above).
    let mut at_limit = b"GET /a HTTP/1.1\r\nHost: x\r\n".to_vec();
    for i in 0..MAX_HEADERS - 1 {
        at_limit.extend_from_slice(format!("X-Pad-{i}: v\r\n").as_bytes());
    }
    seeds.push(at_limit.clone());
    at_limit.extend_from_slice(b"X-One-More: v\r\n");
    seeds.push(at_limit);
    seeds
}

/// Fixed seeds for the response parser (backend-controlled bytes).
fn response_seeds() -> Vec<Vec<u8>> {
    vec![
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n".to_vec(),
        b"HTTP/1.1 204 No Content\r\n".to_vec(),
        b"HTTP/1.1 304 Not Modified\r\n".to_vec(),
        b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n".to_vec(),
        b"HTTP/1.1 99 X\r\n".to_vec(),
        b"HTTP/1.1 200OK\r\n".to_vec(),
        b"HTTP/9.9 200 OK\r\n".to_vec(),
        b"NOTHTTP 200 OK\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nBad Header: v\r\n".to_vec(),
        b"".to_vec(),
        b"\xff\xfe\x00\r\n".to_vec(),
    ]
}

/// Deterministic xorshift64*; fixed seed => reproducible mutants.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n as u64).max(1)) as usize
    }
}

const ALPHABET: &[u8] = b"\r\n\0 :\t/,.-_HTPhtp0123456789+%;\x7f\x80\xffCLchunked";

/// Apply one random structural mutation to `input`.
fn mutate(rng: &mut Rng, input: &[u8]) -> Vec<u8> {
    let mut out = input.to_vec();
    match rng.below(6) {
        // Truncate at a random point (may cut mid-line: must reject, not panic).
        0 => {
            let at = rng.below(out.len().saturating_add(1));
            out.truncate(at);
        }
        // Flip random bytes to alphabet bytes.
        1 => {
            let n = 1 + rng.below(4);
            for _ in 0..n {
                if out.is_empty() {
                    break;
                }
                let i = rng.below(out.len());
                out[i] = ALPHABET[rng.below(ALPHABET.len())];
            }
        }
        // Insert 1-4 alphabet bytes at a random position.
        2 => {
            let n = 1 + rng.below(4);
            let mut ins = Vec::with_capacity(n);
            for _ in 0..n {
                ins.push(ALPHABET[rng.below(ALPHABET.len())]);
            }
            let at = rng.below(out.len().saturating_add(1));
            out.splice(at..at, ins);
        }
        // Duplicate a random CRLF-terminated line (header-count pressure).
        3 => {
            if let Some(end) = find_crlf(&out) {
                let line = out[..end + 2].to_vec();
                let at = rng.below(out.len().saturating_add(1));
                out.splice(at..at, line);
            } else {
                out.extend_from_slice(b"\r\nHost: x\r\n");
            }
        }
        // Delete a random span.
        4 => {
            if !out.is_empty() {
                let at = rng.below(out.len());
                let len = 1 + rng.below(out.len() - at);
                out.drain(at..at + len);
            }
        }
        // Append a hostile suffix (smuggling-shaped tails).
        _ => {
            const SUFFIXES: &[&[u8]] = &[
                b"Content-Length: 5\r\n",
                b"Transfer-Encoding: chunked\r\n",
                b"Host: evil\r\n",
                b"\r\nGET /evil HTTP/1.1\r\nHost: x\r\n",
                b"\x00",
                b" X-Ambig: 1\r\n",
            ];
            out.extend_from_slice(SUFFIXES[rng.below(SUFFIXES.len())]);
        }
    }
    out
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

const MUTANTS_PER_SEED: usize = 200;

#[test]
fn request_parser_never_panics_and_rejects_explicitly() {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let mut exercised_ok = 0usize;
    let mut exercised_err = 0usize;
    for seed in request_seeds() {
        let mut inputs = vec![seed];
        for _ in 0..MUTANTS_PER_SEED {
            let next = mutate(&mut rng, &inputs[inputs.len() - 1]);
            inputs.push(next);
        }
        for input in &inputs {
            match parse_request_head(input) {
                Ok(_) => exercised_ok += 1,
                Err(reject) => {
                    exercised_err += 1;
                    assert!(
                        matches!(reject.status, 400 | 431 | 501 | 505),
                        "request rejection must be explicit (400/431/501/505), got {} for {input:?}",
                        reject.status
                    );
                }
            }
        }
    }
    // Both sides of the oracle must be exercised or the test is vacuous.
    assert!(exercised_ok > 0, "no valid parse exercised");
    assert!(exercised_err > 1000, "too few rejections exercised");
}

#[test]
fn response_parser_never_panics_and_maps_to_502() {
    let mut rng = Rng(0xC2B2AE3D27D4EB4F);
    let mut exercised_ok = 0usize;
    let mut exercised_err = 0usize;
    for seed in response_seeds() {
        let mut inputs = vec![seed];
        for _ in 0..MUTANTS_PER_SEED {
            let next = mutate(&mut rng, &inputs[inputs.len() - 1]);
            inputs.push(next);
        }
        for input in &inputs {
            match parse_response_head(input, false) {
                Ok(_) => exercised_ok += 1,
                Err(reject) => {
                    exercised_err += 1;
                    assert_eq!(
                        reject.status, 502,
                        "ambiguous upstream response must map to 502, got {} for {input:?}",
                        reject.status
                    );
                }
            }
            // HEAD-request mode must not panic either.
            let _ = parse_response_head(input, true);
        }
    }
    assert!(exercised_ok > 0, "no valid parse exercised");
    assert!(exercised_err > 1000, "too few rejections exercised");
}

#[test]
fn known_attack_seeds_are_rejected_with_documented_status() {
    let cases: &[(&[u8], u16)] = &[
        (
            b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n",
            400,
        ),
        (
            b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 4\r\n",
            400,
        ),
        (b"GET /a HTTP/1.1\r\nHost: x\r\n Bad: fold\r\n", 400),
        (b"CONNECT x:443 HTTP/1.1\r\nHost: x\r\n", 501),
        (b"GET /a HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n", 501),
        (b"GET /a HTTP/2.0\r\nHost: x\r\n", 505),
        (b"GET http://x/a HTTP/1.1\r\nHost: x\r\n", 400),
    ];
    for (input, status) in cases {
        let err = parse_request_head(input).expect_err("attack seed must be rejected");
        assert_eq!(err.status, *status, "wrong status for {input:?}");
    }
    // Header-count boundary: exactly MAX_HEADERS parses, MAX_HEADERS+1 is 431.
    let mut at_limit = b"GET /a HTTP/1.1\r\nHost: x\r\n".to_vec();
    for i in 0..MAX_HEADERS - 1 {
        at_limit.extend_from_slice(format!("X-Pad-{i}: v\r\n").as_bytes());
    }
    assert!(parse_request_head(&at_limit).is_ok());
    at_limit.extend_from_slice(b"X-One-More: v\r\n");
    let err = parse_request_head(&at_limit).expect_err("must reject over the header limit");
    assert_eq!(err.status, 431);
}
