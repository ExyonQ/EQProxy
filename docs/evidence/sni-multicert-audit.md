# Slice audit — multi-certificate TLS per SNI (B-I2/B-H10/B-E9)

Date: 2026-10-20 (after the v0.6.0 release). Scope: the SNI certificate
slice on `main` — `[[listener.*.tls.certs]]`, the resolver, the config gate,
`config explain`/`plan` output and the tests. Everything below was executed on
this tree; nothing is inferred.

## 1. Environment

- Darwin 25.5.0 (macOS 26.5.1), arm64; rustc 1.97.1, cargo 1.97.1.
- Tree: `main` at `d82ffd7` plus this slice (uncommitted).

## 2. Format, lint, tests

| Check | Command | Result |
|---|---|---|
| Format | `cargo fmt --check` | exit 0 |
| Lint | `cargo clippy --workspace --all-targets` | exit 0, 0 warnings |
| Tests | `cargo test --workspace` | exit 0 — **22 suites, 311 passed, 0 failed, 2 ignored** |

The 2 ignored tests are the Docker harnesses (differential corpus and
migration matrix); they were **not re-run for this slice** (they exercise
routing, unchanged here) — their v0.6.0 results stand in
[release-v0.6.0-audit.md](release-v0.6.0-audit.md) §3.

## 3. What the tests cover

- **Name grammar** (`eqproxy-config::validate::tests`): DNS names, wildcard
  as the leftmost label, trailing dot, IP literals rejected (RFC 6066),
  empty/misplaced wildcard, empty label, 64-byte label.
- **Resolver preference** (`eqproxy-net::tls::tests`): exact name, longest
  wildcard, unknown name → default, no SNI → default, case-insensitive and
  trailing-dot names, duplicate names and empty entries rejected.
- **Dataplane E2E with real handshakes** (`eqproxy-net/tests/e2e_sni.rs`):
  the client verifier records the leaf actually presented — exact, wildcard,
  two-label miss → default, unclaimed name → default, no SNI → default,
  uppercase name, traffic through the SNI tunnel; and
  `sni_set_swaps_in_hot_with_the_certificate_reload` proves the reloaded SNI
  set is live on the same listener (alpha certificate before, beta after).
- **Real binary E2E** (`eqproxy-cli/tests/cli_e2e.rs`): `openssl s_client
  -servername … -showcerts` compared per name (alpha exact, `*.beta`
  wildcard, unknown name, no SNI) plus traffic through the tunnel, and the
  config gate rejecting a duplicate name (`listener.web.tls.certs[1].names`
  "already claimed") and invalid names ("IP literal", "leftmost label").

Manual check of the diagnostics (same tree):

```
config explain → listener "web": … tls=yes sni=[alpha.example.test,*.alpha.example.test; *.beta.example.test]
config plan    → listener "web": … tls=yes(alpn=[http/1.1] sni=[…]) backend="api"
```

## 4. Veyra Proof

```bash
veyra audit . --profile standard
```

- **Decision: ACCEPTED** — exit code **0**.
- Evidence: `.veyra/evidence/20261020T143407Z/` (`report.md`, `report.json`,
  `manifest.json`, `hashes/`, `tools/`).
- OK: rustfmt, cargo check, clippy, cargo test, nextest, llvm-cov, cargo-deny,
  anti-theater, veyra-e2e.
- Skipped: dylint (no configuration), cargo-semver-checks (no baseline).
- Error, not a pass: cargo-geiger INCONCLUSIVE (coverage warnings), as before.

## 5. Rust Audit (static)

```bash
python3.13 $RUST_AUDIT_HOME/scripts/rust_audit.py scan . \
  --format terminal,md,json,sarif --fail-on high
```

- Exit code **1** (findings at/above `--fail-on high`; reported, not hidden):
  185 findings — 2 critical, 15 high, 138 medium, 30 low. Reports:
  `report/rust-audit-20261020-163439.{md,json,sarif}`,
  `report/not-executed-2026-10-20.md` (maintainer-local).
- The critical/high findings are the same documented false positives verified
  in [release-v0.6.0-audit.md](release-v0.6.0-audit.md) §5 (stale crates.io
  snapshot, own crate names, serde default helpers, the explicit
  `not_implemented` failure, a validated `.expect`).
- In the files this slice touches, one finding remains: **R08** (wall-clock
  read in the reload E2E's bounded wait loop) — inherent to waiting for a
  reload; the R02 "assertion roulette" in the SNI grammar test was fixed by
  giving every assertion its own message (re-scan confirms it is gone).

## 6. EvoForge slice eval

`mcp_submit_eval` on a real slice of `eqproxy-net::tls` (SNI name grammar and
selection order: exact → longest wildcard → default):

- Fitness **F = 1.0**, 3 real tests run (`3 passed; 0 failed`), clippy pass,
  trace `9df74443-100b-4661-9b80-94ec0728af59`.
- Host proof first: `cargo test --workspace` (section 2).

## 7. Not executed (declared, never implied as pass)

- The two Docker harnesses for this slice (unaffected code paths; see §2).
- dylint, cargo-semver-checks, cargo-geiger (inconclusive), Rust Audit
  `--online` (no new dependency).
- A published release: this slice is committed/tagged only when the owner
  asks (no `git push` for it).
