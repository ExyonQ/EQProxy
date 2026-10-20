# Evidence — B-H3 (`hash_policy` / `request_mirror`), Q1/CE1 (public JSON Schema) and B-E4 (equivalence table)

Date: 2026-10-20. Host: macOS aarch64, Rust `1.97.1-aarch64-apple-darwin`,
workspace `/Volumes/Lexar/Cursor/EQProxy`.

This is the increment that closes the v0.6 roadmap: all 32 scope boxes of
`ROADMAP/Roadmap 0.6.md` are `[x]` and the §3 gate is 6/6.

## 1. Implemented behaviour

| Item | Code | Behaviour |
|---|---|---|
| `hash_policy` (B-H3) | `eqproxy-net/src/proxy.rs` (`HashPolicy`, `SplitTargets::pick_hashed`, `mix64`, `fnv1a`), `eqproxy-config/src/schema.rs`, `eqproxy-config/src/validate.rs`, `eqproxy-cli/src/main.rs` | Keys `source`/`path`/`host`/`cookie:NAME`/`header:NAME`; the split target is chosen by weighted rendezvous hashing (sticky, weighted, consistent under removal); a request without the key falls back to the smooth weighted rotation; `None` when no target is active (no index, no panic). |
| `request_mirror` (B-H3) | `eqproxy-net/src/mirror.rs`, `eqproxy-net/src/http1.rs` (`MirrorTee` + spawn), `eqproxy-core/src/metrics.rs` | Copy of the matching request to the shadow backend on a detached task, sharing the forwarded head and the teed body (≤ 256 KiB, larger is counted `mirror_skipped`, never truncated); client answer unaffected; `requests_mirrored` / `mirror_failures` / `mirror_skipped`. |
| Public JSON Schema (Q1/CE1) | `eqproxy-config/src/lib.rs` (`json_schema()`), `eqproxy-config/src/schema.rs` (`JsonSchema` derives), `eqproxy-cli/src/main.rs` (`config schema [--output]`), `eqproxy.schema.json` | Draft 2020-12 schema generated from the same structs the parser deserializes; `additionalProperties: false` from `deny_unknown_fields`; durations typed as strings. |
| B-E4 equivalence table | `docs/equivalences.md` | CORS / `ext_authz` / `rate_limit` mapped from Envoy, nginx, HAProxy and ingress-nginx, with the declared differences. Documentation only (owner decision: the three filters already existed). |

## 2. Checks actually run (final tree, after the last code change)

| Check | Command | Result |
|---|---|---|
| Format | `cargo fmt --check` | exit 0 (`FMT_OK`) |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0, **0 warnings** |
| Tests | `cargo test --workspace` | exit 0 — **23 suites, 327 passed, 0 failed, 2 ignored** |
| Schema gates | `cargo test -p eqproxy-config --test schema` | 4/4 pass |
| Real binary, schema | `cargo test -p eqproxy-cli --test cli_e2e config_schema` | pass (stdout/`--output`/repo file byte-identical) |
| Real binary, hash + mirror | `cargo test -p eqproxy-cli --test cli_e2e hash_policy` | pass (sticky key, both targets, copy observed on the shadow socket, `config explain` lines) |
| Dataplane E2E | `cargo test -p eqproxy-net --test e2e_rules hash_policy request_mirror` | pass |
| veyra | `veyra audit . --profile standard` | **ACCEPTED**, exit 0, evidence `.veyra/evidence/20261020T155720Z` |
| Rust Audit | `python3.13 "$RUST_AUDIT_HOME/scripts/rust_audit.py" scan . --format terminal,json --fail-on high` | exit 1 — 190 findings, **0 in the two new files** (`eqproxy-net/src/mirror.rs`, `eqproxy-config/tests/schema.rs`); remaining hits in touched files are the documented patterns (R18d on the `eqproxy_core` name, R03 serde default fns, R09 `expect` on poisoned mutexes/infallible paths, R08 bounded waits in tests, R10 `let _ = write!`) |
| Rust Audit `--online` | same with `--online` | `schemars: ok`, `serde_json: ok` (crates.io); `md-5` flagged as alias of `md5` (pre-existing, documented); the workspace's own `eqproxy-*` crates "do not exist" (expected: path crates) |

The 2 ignored tests are the Docker harnesses (differential corpus and
migration matrix). **Not re-executed in this increment**: they do not touch
routing or TLS code paths, and their last real runs before the release are
recorded in `docs/evidence/v06-migration/` and
`docs/evidence/release-v0.6.0-audit.md`.

## 3. E2E evidence detail

Dataplane (`eqproxy-net/tests/e2e_rules.rs`):

- `hash_policy_keeps_a_key_on_its_target_and_only_remaps_owned_keys`: one key
  over 11 exchanges keeps its target; 30 different keys spread over ≥ 2 of 3
  targets; a request without the cookie rotates (≥ 2 targets seen); after
  removing `gamma`, every key owned by `alpha`/`beta` keeps its target and
  only `gamma`'s keys move.
- `request_mirror_copies_the_request_and_never_changes_the_client_answer`: a
  real recording backend receives `POST /api/orders` (head observed on its own
  socket) while the client gets the primary body; a non-matching path is not
  mirrored; a dead shadow backend (`127.0.0.1:1`) leaves the client answer
  intact and increments `mirror_failures`.

Unit (`eqproxy-net/src/proxy.rs`, `eqproxy-net/src/mirror.rs`):

- Distribution: 300 keys over 3 equal targets give each ~1/3 (the original
  FNV-only version put **all** keys on two of them — caught by this test and
  fixed with the splitmix64 finalizer); 9:1 weights give `a` 200–299 of 300.
- Sampling: exactly 1/10/25/50/99/100 of every 100-request block.

Real binary (`eqproxy-cli/tests/cli_e2e.rs`, `CARGO_BIN_EXE_eqproxy`):
`run_hash_policy_and_request_mirror_end_to_end` runs `config explain` twice
(`hash cookie:session`, `mirror 100% -> shadow`), starts `eqproxy run`, sends
18 keyed requests (6 for one key, 12 distinct keys → both targets) and one
mirrored POST, and reads the copy from the shadow backend's recorded request
line.

Schema: `config_schema_publishes_the_generated_json_schema` asserts the draft,
the published definitions, `--output == stdout` and that the repository file
equals what the binary renders.

## 4. EvoForge MCP eval — real results, not a pass

Host proof first: `cargo test --workspace` exit 0 (327 passed) before any
submission.

- **Slice A — weighted rendezvous selection** (`pick_hashed`, `mix64`,
  `fnv1a`, 2 tests): `compiles: true`, `clippy_pass: true`,
  `tests_pass: true` (**2 real tests ran and passed**), but
  `fitness_score: 0.0` with
  `deny_reason: failed_layers: pattern.unchecked_div, pattern.wrapping`
  (trace `2208aec1-d005-428b-b1fa-eb9c1d5e1cf2`; earlier attempt
  `5acb0442-…` also failed `pattern.unchecked_index`, which was removed by
  returning `Option` instead of indexing).
- **Slice B — mirror sampling** (`MirrorPolicy`, 2 tests): four attempts
  (`177d95a1…`, `4c52a9e3…`, `76a55e1d…`, `124c42d8…`) were misdetected as
  JavaScript (`.mjs` with `use std::…` → `SyntaxError`), and forcing
  `test_command: "cargo test"` failed because the sandbox has no `Cargo.toml`.
  **NOT EXECUTED as a Rust eval.**

Interpretation, declared rather than glossed over: the pattern layer rejects
arithmetic that these algorithms are *defined* with — FNV-1a and splitmix64
are modular 64-bit multiplications (`wrapping_mul`), and the rendezvous score
is a division (`weight / -ln(u)`). Getting F=1 would require rewriting the
documented algorithms into look-alikes, so it was not done; the eval is
reported as F=0 for slice A and not executed for slice B.

## 5. Limitations

- The mirror copies the body only up to `BODY_BUDGET` (256 KiB); beyond it the
  request is not mirrored (counted), never truncated.
- Mirror sampling is deterministic (every 100 requests mirror exactly
  `percentage`), unlike Envoy's random sampling — documented in the config
  docs.
- `hash_policy` needs a `split` with at least two live targets (gate-enforced);
  the all-zero case returns `None` and the caller rotates.
- No OCSP stapling, no certificate-chain validation (operator's chain served
  as configured) — unchanged from the previous increment.
- veyra: `dylint` and `cargo-semver-checks` remain skipped (no configuration /
  no published baseline); `cargo-geiger` is INCONCLUSIVE (coverage warnings),
  reported by veyra, not a pass.
