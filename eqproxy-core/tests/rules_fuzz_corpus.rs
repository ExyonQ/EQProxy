//! v0.6 (B-H3/B-H4) — Deterministic fuzz-style corpus for the routing-rule
//! evaluator.
//!
//! Oracle (semantics frozen by Q8), for arbitrary specs and request facts:
//!
//! 1. [`Rule::compile`] never panics and every rejection is actionable:
//!    non-empty cause and example (the config gate shows them verbatim).
//! 2. [`Rule::matches`] and [`Rule::explain`] never panic and never
//!    disagree; an `explain` error is never empty. Conforming facts match;
//!    a single non-conforming field never does.
//! 3. Host verdicts are invariant under case folding and a `:port` suffix
//!    (the [`host_key`] contract — a regression here silently breaks
//!    routing for every deployment behind a port).
//!
//! This is the committed, always-run part of evaluator fuzzing: fixed
//! seeds plus a deterministic PRNG mutator (xorshift64, fixed seed), so
//! the test is reproducible without libFuzzer. The live `cargo-fuzz`
//! target in `fuzz/fuzz_targets/rules.rs` maps raw bytes onto the same
//! shapes for open-ended runs.

use std::net::IpAddr;

use eqproxy_core::rules::{HeaderSpec, RequestFacts, Rule, RuleSpec, host_key};

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

    /// True with probability 1/`n`.
    fn chance(&mut self, n: usize) -> bool {
        self.below(n) == 0
    }

    fn pick(&mut self, pool: &[&str]) -> String {
        pool[self.below(pool.len())].to_owned()
    }
}

/// Hostile field-value pool: boundary shapes and the Q8-sensitive spots
/// (regex metacharacters, case, trailing slash, ports, unicode, NUL, DEL).
const STRINGS: &[&str] = &[
    "",
    "api.example.com",
    "API.Example.COM",
    "API.Example.COM:8443",
    "[::1]:8080",
    "::1",
    "api.",
    ".",
    "/",
    "/v1/",
    "/v1",
    "/v10",
    "/Exact",
    "/a?x=1",
    "*",
    "//a",
    "/\u{1f680}",
    "GET",
    "get",
    "POST",
    "HEAD",
    "G T",
    "\u{e9}",
    "^api-[0-9]+\\.",
    "\\.json$",
    ".*",
    "^$",
    "(",
    "(?=x)",
    "a{1000}{1000}",
    "[z-a]",
    "a**",
    "\\p{Emoji}",
    "10.0.0.0/8",
    "0.0.0.0/0",
    "2001:db8::/32",
    "not-an-ip",
    "1.2.3.4/33",
    "1.2.3.4",
    "x-tenant",
    "X-Tenant",
    "x:a",
    "bad name",
    "\u{0}",
    "acme",
    "^req-",
    "\u{7f}",
];

const ALPHABET: &[u8] = b"abcXY0123456789^$.[](){}*+?|\\-_/:\x00\x7f\xc3\xa9\x0a\x20;,";

const SUFFIXES: &[&[u8]] = &[
    b"^",
    b"$",
    b"(.*)",
    b"{1000}",
    b":8443",
    b"\x00",
    b";",
    b"\xc3\xa9",
    b"/",
    b"*",
];

/// One random structural mutation of `input` (truncate / flip / insert /
/// delete / hostile suffix); invalid UTF-8 becomes U+FFFD, which is a
/// legal config string and a useful case on its own.
fn mutate_string(rng: &mut Rng, input: &str) -> String {
    let mut out = input.as_bytes().to_vec();
    match rng.below(5) {
        0 => {
            let at = rng.below(out.len() + 1);
            out.truncate(at);
        }
        1 => {
            if !out.is_empty() {
                let n = 1 + rng.below(4);
                for _ in 0..n {
                    let i = rng.below(out.len());
                    out[i] = ALPHABET[rng.below(ALPHABET.len())];
                }
            }
        }
        2 => {
            let n = 1 + rng.below(4);
            let mut ins = Vec::with_capacity(n);
            for _ in 0..n {
                ins.push(ALPHABET[rng.below(ALPHABET.len())]);
            }
            let at = rng.below(out.len() + 1);
            out.splice(at..at, ins);
        }
        3 => {
            if !out.is_empty() {
                let at = rng.below(out.len());
                let len = 1 + rng.below(out.len() - at);
                out.drain(at..at + len);
            }
        }
        _ => {
            let suffix = SUFFIXES[rng.below(SUFFIXES.len())];
            out.extend_from_slice(suffix);
        }
    }
    String::from_utf8(out)
        .unwrap_or_else(|why| String::from_utf8_lossy(why.as_bytes()).into_owned())
}

fn random_string(rng: &mut Rng) -> String {
    let mut s = rng.pick(STRINGS);
    if rng.chance(2) {
        s = mutate_string(rng, &s);
    }
    s
}

/// Random *hostile* spec: every field drawn from hostile pools; often
/// invalid by construction (two host variants, several header kinds).
fn random_spec(rng: &mut Rng) -> RuleSpec {
    let mut spec = RuleSpec {
        name: random_string(rng),
        ..RuleSpec::default()
    };
    if rng.chance(2) {
        spec.host = Some(random_string(rng));
    }
    if rng.chance(2) {
        spec.host_prefix = Some(random_string(rng));
    }
    if rng.chance(2) {
        spec.host_regex = Some(random_string(rng));
    }
    if rng.chance(2) {
        spec.path = Some(random_string(rng));
    }
    if rng.chance(2) {
        spec.path_prefix = Some(random_string(rng));
    }
    if rng.chance(2) {
        spec.path_regex = Some(random_string(rng));
    }
    for _ in 0..rng.below(3) {
        spec.methods.push(random_string(rng));
    }
    for _ in 0..rng.below(3) {
        let mut header = HeaderSpec {
            name: random_string(rng),
            exact: None,
            regex: None,
            present: false,
        };
        match rng.below(3) {
            0 => header.exact = Some(random_string(rng)),
            1 => header.regex = Some(random_string(rng)),
            _ => header.present = true,
        }
        if rng.chance(6) {
            // Corrupt into the "set exactly one kind" rejection.
            header.present = true;
            header.exact = Some(random_string(rng));
        }
        spec.headers.push(header);
    }
    for _ in 0..rng.below(3) {
        spec.ip.push(random_string(rng));
    }
    spec
}

// --- Valid pools: (condition value, conforming sample, anti-sample) ---
// Anti-samples miss every condition of their kind in these pools, so a
// one-field perturbation is a guaranteed non-match.

/// Exact conditions match their own value (identity sample).
const VALID_EXACT_HOSTS: &[&str] = &["api.example.com", "api.", "x", "example.com"];
/// Prefix conditions pair with a sample that extends the prefix.
const VALID_HOST_PREFIXES: &[(&str, &str)] = &[("api.", "api.x"), ("x", "xx")];
const VALID_HOST_REGEXES: &[(&str, &str)] = &[("^api-[0-9]+\\.", "api-7.example.com")];
const VALID_PATHS: &[&str] = &["/Exact", "/v1", "/a"];
const VALID_PATH_PREFIXES: &[(&str, &str)] = &[("/v1/", "/v1/a"), ("/", "/a")];
const VALID_PATH_REGEXES: &[(&str, &str)] = &[("\\.json$", "/data.json"), ("^/v[0-9]/", "/v1/a")];
const VALID_HEADER_REGEXES: &[(&str, &str)] = &[("^req-", "req-1")];
const VALID_METHODS: &[&str] = &["GET", "PUT", "POST", "HEAD"];
const VALID_HEADER_NAMES: &[&str] = &["x-a", "x-tenant", "x-trace"];
const VALID_IP: &[(&str, &str)] = &[
    ("10.0.0.0/8", "10.1.2.3"),
    ("192.0.2.1", "192.0.2.1"),
    ("2001:db8::/32", "2001:db8::1"),
    ("0.0.0.0/0", "203.0.113.9"),
];
const ANTI_HOST: &str = "zz.invalid";
/// No leading slash: misses even the `"/"` path prefix.
const ANTI_PATH: &str = "nope";
const ANTI_METHOD: &str = "ZZZ";

/// Pick the condition value (`.0`) of one pool pair.
fn pick_key(rng: &mut Rng, pairs: &[(&str, &str)]) -> String {
    pairs[rng.below(pairs.len())].0.to_owned()
}

/// Random spec that always compiles: exactly one host variant, optionally
/// one path variant and further ANDed conditions.
fn random_valid_spec(rng: &mut Rng) -> RuleSpec {
    let mut spec = RuleSpec {
        name: format!("r{}", rng.below(1_000_000)),
        ..RuleSpec::default()
    };
    match rng.below(3) {
        0 => spec.host = Some(rng.pick(VALID_EXACT_HOSTS)),
        1 => spec.host_prefix = Some(pick_key(rng, VALID_HOST_PREFIXES)),
        _ => spec.host_regex = Some(pick_key(rng, VALID_HOST_REGEXES)),
    }
    if rng.chance(2) {
        match rng.below(3) {
            0 => spec.path = Some(rng.pick(VALID_PATHS)),
            1 => spec.path_prefix = Some(pick_key(rng, VALID_PATH_PREFIXES)),
            _ => spec.path_regex = Some(pick_key(rng, VALID_PATH_REGEXES)),
        }
    }
    for method in VALID_METHODS {
        if rng.chance(3) {
            spec.methods.push((*method).to_owned());
        }
    }
    // Unique names: the evaluator reads the first value of a name, so two
    // conditions over one name would fight over a single facts slot.
    for name in VALID_HEADER_NAMES {
        if !rng.chance(2) {
            continue;
        }
        let name = (*name).to_owned();
        let header = match rng.below(3) {
            0 => HeaderSpec {
                name,
                exact: Some("acme".to_owned()),
                regex: None,
                present: false,
            },
            1 => HeaderSpec {
                name,
                exact: None,
                regex: Some(pick_key(rng, VALID_HEADER_REGEXES)),
                present: false,
            },
            _ => HeaderSpec {
                name,
                exact: None,
                regex: None,
                present: true,
            },
        };
        spec.headers.push(header);
    }
    if rng.chance(3) {
        spec.ip.push(pick_key(rng, VALID_IP));
    }
    spec
}

/// Owned request facts (the evaluator borrows them).
struct OwnedFacts {
    method: String,
    host: String,
    path: String,
    headers: Vec<(String, String)>,
    peer: IpAddr,
}

impl OwnedFacts {
    fn view(&self) -> RequestFacts<'_> {
        RequestFacts {
            method: &self.method,
            host: &self.host,
            path: &self.path,
            headers: &self.headers,
            peer: self.peer,
            maps: eqproxy_core::MapRegistry::empty(),
        }
    }
}

/// Facts constructed to satisfy `spec` exactly (from the conforming
/// samples of the valid pools).
fn conforming_facts(rng: &mut Rng, spec: &RuleSpec) -> OwnedFacts {
    let sample = |pairs: &[(&str, &str)], want: &Option<String>| -> Option<String> {
        want.as_ref().map(|value| {
            pairs
                .iter()
                .find(|(v, _)| v == value)
                .map(|(_, s)| (*s).to_owned())
                .unwrap_or_else(|| value.clone())
        })
    };
    let mut facts = OwnedFacts {
        method: spec
            .methods
            .first()
            .cloned()
            .unwrap_or_else(|| rng.pick(&["GET", "POST"])),
        host: spec
            .host
            .clone()
            .or_else(|| sample(VALID_HOST_PREFIXES, &spec.host_prefix))
            .or_else(|| sample(VALID_HOST_REGEXES, &spec.host_regex))
            .unwrap_or_default(),
        path: spec
            .path
            .clone()
            .or_else(|| sample(VALID_PATH_PREFIXES, &spec.path_prefix))
            .or_else(|| sample(VALID_PATH_REGEXES, &spec.path_regex))
            .unwrap_or_default(),
        headers: Vec::new(),
        peer: "127.0.0.1".parse().expect("static peer is valid"),
    };
    for header in &spec.headers {
        let value = if let Some(exact) = &header.exact {
            exact.clone()
        } else if let Some(regex) = &header.regex {
            VALID_HEADER_REGEXES
                .iter()
                .find(|(v, _)| v == regex)
                .map(|(_, s)| (*s).to_owned())
                .unwrap_or_default()
        } else {
            "1".to_owned()
        };
        facts.headers.push((header.name.clone(), value));
    }
    if let Some(block) = spec.ip.first() {
        let member = VALID_IP
            .iter()
            .find(|(v, _)| v == block)
            .map(|(_, s)| (*s).to_owned())
            .unwrap_or_else(|| "10.1.2.3".to_owned());
        facts.peer = member.parse().expect("static members are valid");
    }
    facts
}

/// Flip exactly one *constrained* field to a value that misses it — a
/// guaranteed non-match by construction of the valid pools.
fn perturb_constrained(rng: &mut Rng, spec: &RuleSpec, facts: &mut OwnedFacts) {
    let mut choices = Vec::new();
    if spec.host.is_some() || spec.host_prefix.is_some() || spec.host_regex.is_some() {
        choices.push(0);
    }
    if spec.path.is_some() || spec.path_prefix.is_some() || spec.path_regex.is_some() {
        choices.push(1);
    }
    if !spec.methods.is_empty() {
        choices.push(2);
    }
    if !spec.headers.is_empty() {
        choices.push(3);
    }
    if !spec.ip.is_empty() {
        choices.push(4);
    }
    match choices[rng.below(choices.len())] {
        0 => facts.host = ANTI_HOST.to_owned(),
        1 => facts.path = ANTI_PATH.to_owned(),
        2 => facts.method = ANTI_METHOD.to_owned(),
        3 => facts.headers.clear(),
        _ => {
            // Other address family: every block in the pool is
            // family-exact (expectation.rs), so this cannot land inside.
            facts.peer = if facts.peer.is_ipv4() {
                "::1".parse().expect("static peer is valid")
            } else {
                "203.0.113.9".parse().expect("static peer is valid")
            };
        }
    }
}

/// Fixed specs exercising every rejection the gate documents (field names
/// asserted: the config layer prints them as `listener.web.rules[i].field`).
fn known_specs() -> Vec<(RuleSpec, &'static str)> {
    vec![
        (
            RuleSpec {
                name: "two-hosts".to_owned(),
                host: Some("a".to_owned()),
                host_regex: Some("b".to_owned()),
                ..RuleSpec::default()
            },
            "host",
        ),
        (
            RuleSpec {
                name: "two-paths".to_owned(),
                path: Some("/a".to_owned()),
                path_prefix: Some("/b".to_owned()),
                ..RuleSpec::default()
            },
            "path",
        ),
        (RuleSpec::default(), ""),
        (
            RuleSpec {
                name: "bad-regex".to_owned(),
                host_regex: Some("(".to_owned()),
                ..RuleSpec::default()
            },
            "host_regex",
        ),
        (
            RuleSpec {
                name: "huge-repeat".to_owned(),
                path_regex: Some("a{1000000}".to_owned()),
                ..RuleSpec::default()
            },
            "path_regex",
        ),
        (
            RuleSpec {
                name: "bad-method".to_owned(),
                methods: vec!["BAD METHOD".to_owned()],
                ..RuleSpec::default()
            },
            "methods",
        ),
        (
            RuleSpec {
                name: "bad-header-name".to_owned(),
                headers: vec![HeaderSpec {
                    name: "bad name".to_owned(),
                    exact: Some("1".to_owned()),
                    regex: None,
                    present: false,
                }],
                ..RuleSpec::default()
            },
            "headers[0]",
        ),
        (
            RuleSpec {
                name: "three-kinds".to_owned(),
                headers: vec![HeaderSpec {
                    name: "x-a".to_owned(),
                    exact: Some("1".to_owned()),
                    regex: Some("2".to_owned()),
                    present: true,
                }],
                ..RuleSpec::default()
            },
            "headers[0]",
        ),
        (
            RuleSpec {
                name: "bad-cidr".to_owned(),
                ip: vec!["not-an-ip".to_owned()],
                ..RuleSpec::default()
            },
            "ip",
        ),
    ]
}

const MUTANTS_PER_SEED: usize = 200;

/// Property 1: compile never panics; every rejection is actionable.
#[test]
fn compile_never_panics_and_rejections_are_actionable() {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let mut exercised_ok = 0usize;
    let mut exercised_err = 0usize;
    for (seed, _) in known_specs() {
        let mut inputs = vec![seed];
        for _ in 0..MUTANTS_PER_SEED {
            let next = random_spec(&mut rng);
            inputs.push(next);
        }
        for _ in 0..MUTANTS_PER_SEED {
            let base = rng.below(inputs.len());
            let mut mutated = inputs[base].clone();
            if let Some(host) = mutated.host.as_mut() {
                *host = mutate_string(&mut rng, host);
            }
            if let Some(regex) = mutated.host_regex.as_mut() {
                *regex = mutate_string(&mut rng, regex);
            }
            if let Some(regex) = mutated.path_regex.as_mut() {
                *regex = mutate_string(&mut rng, regex);
            }
            inputs.push(mutated);
        }
        for spec in &inputs {
            match Rule::compile(spec) {
                Ok(_) => exercised_ok += 1,
                Err(why) => {
                    exercised_err += 1;
                    assert!(
                        !why.cause.is_empty(),
                        "rejection must explain itself: {spec:?}"
                    );
                    assert!(
                        !why.example.is_empty(),
                        "rejection must show a valid example: {spec:?}"
                    );
                }
            }
        }
    }
    // Both sides of the oracle must be exercised or the test is vacuous.
    assert!(exercised_ok > 50, "too few valid specs: {exercised_ok}");
    assert!(exercised_err > 100, "too few rejections: {exercised_err}");
}

/// Property 2: `matches` and `explain` never disagree; conforming facts
/// match and a single non-conforming field never does.
#[test]
fn matches_and_explain_never_disagree_over_generated_traffic() {
    let mut rng = Rng(0xC2B2AE3D27D4EB4F);
    let mut matched = 0usize;
    let mut missed = 0usize;
    for _ in 0..5_000 {
        let spec = random_valid_spec(&mut rng);
        let rule = Rule::compile(&spec).expect("valid generator must compile");
        let mut owned = conforming_facts(&mut rng, &spec);

        // Probe 1: conforming facts must match…
        let verdict = rule.matches(&owned.view());
        let explained = rule.explain(&owned.view());
        assert_eq!(
            verdict,
            explained.is_ok(),
            "matches/explain disagree: spec={spec:?} facts={:?}",
            owned.view()
        );
        assert!(
            verdict,
            "conforming facts must match: spec={spec:?} facts={:?}",
            owned.view()
        );
        matched += 1;

        // Probe 2: …and one non-conforming field must flip the verdict.
        perturb_constrained(&mut rng, &spec, &mut owned);
        let verdict = rule.matches(&owned.view());
        let explained = rule.explain(&owned.view());
        assert_eq!(
            verdict,
            explained.is_ok(),
            "matches/explain disagree: spec={spec:?} facts={:?}",
            owned.view()
        );
        assert!(
            !verdict,
            "one bad field must not match: spec={spec:?} facts={:?}",
            owned.view()
        );
        if let Err(reason) = explained {
            assert!(!reason.is_empty(), "explain must say why");
        }
        missed += 1;
    }
    assert_eq!(matched, 5_000, "conforming probes lost");
    assert_eq!(missed, 5_000, "perturbed probes lost");
}

/// Property 3: host verdicts are invariant under case folding and a
/// `:port` suffix — for every rule, not only host-conditioned ones (the
/// other conditions see identical facts in both probes).
#[test]
fn host_verdict_is_invariant_under_case_and_port_suffix() {
    let mut rng = Rng(0x243F6A8885A308D3);
    for _ in 0..5_000 {
        let spec = random_valid_spec(&mut rng);
        let rule = Rule::compile(&spec).expect("valid generator must compile");
        let owned = conforming_facts(&mut rng, &spec);
        let base = owned.view();
        let transformed = format!("{}:8443", base.host.to_ascii_uppercase());
        let probe = RequestFacts {
            host: &transformed,
            ..base
        };
        assert_eq!(
            host_key(base.host),
            host_key(&transformed),
            "host_key lost the contract for {:?}",
            base.host
        );
        assert_eq!(
            rule.matches(&base),
            rule.matches(&probe),
            "host verdict changed under case/port: spec={spec:?} host={:?}",
            base.host
        );
    }
}

/// Deterministic anchors: every documented rejection names its field.
#[test]
fn known_bad_specs_name_their_field() {
    for (spec, field) in known_specs() {
        let err = Rule::compile(&spec).expect_err("known-bad spec must be rejected");
        assert_eq!(
            err.field, field,
            "wrong field for spec {spec:?}: {}",
            err.field
        );
    }
}
