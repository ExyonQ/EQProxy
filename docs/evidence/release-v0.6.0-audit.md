# Release audit — v0.6.0 (pre-publication)

Audit date: 2026-10-20. Scope: the `main` working tree that becomes the
`v0.6.0` tag — version pin, the v0.6 rules/traffic dataplane, the two
Docker-gated harnesses, documentation, and the mandatory toolchain audits
(Veyra Proof, Rust Audit, EvoForge slice eval). Everything below was executed
on this tree, on this machine; nothing is inferred.

## 1. Environment

- Darwin 25.5.0 (macOS 26.5.1), arm64; Docker 29.8.2.
- rustc 1.97.1 (8bab26f4f 2026-07-14), cargo 1.97.1.
- Workspace version `0.6.0` (matches the release tag; the pipeline rejects a
  tag that differs from `Cargo.toml`).
- Binaries under test: `target/debug/eqproxy`, sha256
  `31ef7e1004810056745a481aa41de7552feeab846c3bfc332ced37e98f2b0ed3`
  (the same tree also produced `8fdefe8d…f753c` before the version pin; the
  gate harness ran green on both).

## 2. Format, lint, tests

| Check | Command | Result |
|---|---|---|
| Format | `cargo fmt --check` | exit 0 |
| Lint | `cargo clippy --workspace --all-targets` | exit 0, 0 warnings |
| Tests | `cargo test --workspace` | exit 0 — **21 suites, 302 passed, 0 failed, 2 ignored** |

The two ignored tests are the Docker-gated harnesses; both were executed
explicitly for this release (below), so nothing in the suite is left
unverified.

## 3. Version-gate harnesses

| Gate | Command | Result |
|---|---|---|
| Differential corpus | `cargo test -p eqproxy-cli --test differential -- --ignored` | exit 0 — **23/23 cases**, 0 exclusions, HAProxy 3.4.6 + nginx + ingress-nginx data plane + static Envoy 1.34.2 + the real binary |
| Migration matrix | `cargo test -p eqproxy-cli --test migration -- --ignored` | exit 0 — **13/13 cases × 5 implementations = 65/65 checks** |

Raw reports (written unedited by the harnesses):
[differential](v06-differential/report.md) and
[migration](v06-migration/report.md) (reproduction details in
[v06-migration/README.md](v06-migration/README.md)).

The checked-in translation is also valid on its own:
`eqproxy config validate --config docs/migration/eqproxy.toml` → `config OK:
1 listener(s), 5 backend(s)` (exit 0; the only stderr line is the expected
plaintext-listener warning).

## 4. Veyra Proof

```bash
veyra audit . --profile standard
```

- **Decision: ACCEPTED** — exit code **0**.
- Evidence: `.veyra/evidence/20261020T130852Z/` (`report.md`, `report.json`,
  `manifest.json`, `hashes/`, `tools/`).
- OK: rustfmt, cargo check, clippy, cargo test, cargo-audit, anti-theater,
  nextest, llvm-cov, cargo-deny, cargo-machete, veyra-e2e.
- Skipped: dylint (no lint configuration — refuses to invent lints),
  cargo-semver-checks (no baseline for unpublished crates).
- Error, not a pass: cargo-geiger INCONCLUSIVE (coverage warnings in 4 runs —
  unsafe counts are a lower bound), same as every previous delivery.

## 5. Rust Audit (static)

```bash
python3.13 $RUST_AUDIT_HOME/scripts/rust_audit.py scan . \
  --format terminal,md,json,sarif --fail-on high
```

- Exit code **1** (findings at/above `--fail-on high` — reported, not hidden).
- 182 findings: 2 critical, 15 high, 135 medium, 30 low.
  Reports: `report/rust-audit-20261020-150909.{md,json,sarif}` and
  `report/not-executed-2026-10-20.md` (maintainer-local: `report/` is not
  published, like `scripts/`).
- New code in this slice (`eqproxy-cli/tests/migration.rs`): 6 findings, all
  **R08** (sleep / wall-clock reads in a test) — the same shapes the existing
  Docker harnesses carry, inherent to waiting for containers.
- The 17 critical/high are previously documented false positives or
  intentional patterns, each verified by reading the code in this run:
  - `thiserror` requirement `2` "published majors end at 1" — stale crates.io
    snapshot; 2.x is published and in the lockfile.
  - `eqproxy_core` "hallucinated naming pattern" — the workspace's own crate.
  - `default_weight`/`default_rise`/… "always returns a constant" — serde
    `#[serde(default = …)]` helpers; constant by definition.
  - `not_implemented` "stub signature" — the explicit failure for
    `config import` (Phase 8): it prints the reason and exits 2, never fakes
    success.
  - `.expect("backend referenced by a listener")` in `plan_report` — a
    validated invariant of the config gate, not request input.
- No fix applied: none of the new-code findings is a stub, swallowed error or
  faked test; the auto-fix pass would only churn test timing helpers.

## 6. EvoForge slice eval

`mcp_submit_eval` on a real slice of `eqproxy-core::rules` (host normalization,
literal path prefixes, RFC 6265 cookie pairs, first-match evaluation — the
semantics the migration matrix asserts):

- Fitness **F = 1.0**, sandbox compiled and ran **3 real tests** (`3 passed; 0
  failed`), clippy pass, trace `f02254cd-f77a-49bf-99c3-b4f5a0ce3dab`.
- Host proof first: `cargo test --workspace` (section 2).

## 7. Not executed (declared, never implied as pass)

- dylint and cargo-semver-checks (Veyra: no configuration / no baseline).
- cargo-geiger above: INCONCLUSIVE, not green.
- Online dependency checks of Rust Audit (`--online`, OSV/docs.rs): not run in
  this pass; no new dependency was added in this slice.
- Post-publication verification of the release assets (download + checksum +
  binary E2E from GitHub Releases and both registries): happens after the tag
  is published by `.github/workflows/release.yml`; not covered here.
- Full 24h soak re-run and the full BENCHMARK_PLAN matrix: unchanged from
  v0.5.0/v0.6 campaigns, not repeated for this tag.
