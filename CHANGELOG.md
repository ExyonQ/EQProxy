# Changelog — EQProxy

Language: **English**. Format follows "Keep a Changelog" (Added / Changed /
Fixed); versions are `vMAJOR.MINOR.PATCH` git tags.

## [Unreleased]

## [v0.4.4] — 2026-10-15

### Added

- `eqproxy doctor [--config <file>]`: pre-flight environment diagnostics
  (Phase 3). With a config it gates exactly like `run`, then reports one
  `ok:`/`warn:`/`err:` line per check: a momentary TCP bind per listener
  (proves the port is free and permitted), the TLS state per listener
  (material already parsed by the gate), and the FD budget from SPEC §7.3
  and T07 (2 FDs per connection across all `maxconn` plus one per
  listener with 10 % margin, against the soft `NOFILE` limit; a short
  budget warns, never fails). Verdict line last (`doctor: PASS/FAIL` with
  counts); exit 0 unless the gate fails or any check errors. With no
  `--config`, environment only (FD limit + pointer to `--config`).
  Backend reachability is deliberately not probed: a down backend is not
  a config error, and dialing would pollute backends. New dependency:
  `rlimit` 0.10 (safe `NOFILE` reads; `unsafe` stays forbidden).

## [v0.4.3] — 2026-10-15

### Fixed

- `config apply` consumed `/dev/stdin` (or any pipe) on its first read
  and then failed gating on the empty second read. It now reads the
  candidate once and gates from those bytes (found by the Veyra audit's
  `apply-stores-first-configuration` scenario; no released file-based
  workflow was affected).
- Two Clippy lints in the new code (`collapsible_if` in history listing,
  `needless_borrow` in the SIGINT-shutdown test helper).

## [v0.4.2] — 2026-10-15

### Added

- `config apply` / `config rollback` (offline versioned state): `apply`
  gates the candidate exactly like `run` (load, validate, resolve; exit 1
  leaves the state untouched), pushes the previous `current.toml` to
  `history/` (capped at 32, oldest pruned) and installs the candidate via
  atomic rename; re-applying identical bytes is a no-op report.
  `rollback` re-gates the newest backup (relative cert paths resolve
  against the apply-time directory recorded in its header) and pops it
  into current, so walking back takes one rollback per apply. State lives
  in `./.eqproxy` (`EQPROXY_STATE_DIR` overrides it). Hot-apply to a
  running process stays pending (S-CFG-01).

### Changed

- Dependencies: `equivalent` 1.0.2 → 1.0.3 (transitive, semver-compatible).

## [v0.4.1] — 2026-10-15

### Added

- `config plan`: dry run of `run` — loads, validates and resolves (real
  certificate reads, address parsing, backend assembly), then reports the
  full activation inventory (listeners, timeouts, backends, servers)
  without binding or dialing. Exit 1 carries the same actionable errors
  `run` would fail with.

## [v0.4.0] — 2026-10-14

First distributable release: containers and binaries, English-only docs.

### Added

- Backend keep-alive pool (A16): per-server idle pool with a reuse-safety
  contract (clean exchanges only), reuse/dial counters.
- `config explain`: offline simulation of one routing decision (listener,
  backend, selected server with health state), no side effects (SPEC §8).
- `config diff`: offline comparison of two configurations (`+`/`-`/`~`
  vocabulary) for the pre-apply safety workflow.
- Official multi-arch container image (`docker/Dockerfile`, linux/amd64 +
  linux/arm64): locked release build, `debian:bookworm-slim` runtime as
  `nobody`, `ca-certificates` for `ca_file` against the system bundle.
- Reproducible release pipeline (`scripts/release.sh`): four binaries +
  SHA256SUMS + SBOM, every artifact E2E-verified before checksums are
  written.

### Changed

- **Documentation is English-only** from this release (code, messages,
  comments and all published docs). ADRs renamed to English slugs.

### Scope honesty

- This release is **not declared production ready** (Phase 9 gate pending):
  no hot config reload, no rollback, HTTP/1.1 + TCP only, no HTTP/2/3.
  See ROADMAP.md for the verified scope per phase.

## [v0.3.0] — 2026-10-13

- Real HTTP/1.1 proxy with strict framing (smuggling rejected pre-backend),
  TLS termination and verified backend TLS, weighted round-robin, TCP health
  checks, PROXY v1 send, per-phase timeouts, framing fuzz corpus.

## [v0.2.0] — 2026-10-12

- Real minimal TCP proxy with validated TOML config, resource budgets,
  graceful shutdown, basic metrics.

## [v0.1.0] — 2026-10-12

- Research and architecture: SPEC, threat model, parity matrix, ADRs,
  benchmark plan.
