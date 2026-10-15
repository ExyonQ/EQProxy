# Changelog — EQProxy

Language: **English**. Format follows "Keep a Changelog" (Added / Changed /
Fixed); versions are `vMAJOR.MINOR.PATCH` git tags.

## [Unreleased]

## [v0.4.5] — 2026-10-15

### Fixed

- HTTP/1.1 interim responses (1xx) no longer desync a keep-alive client or a
  pooled backend connection. Before, a `100`/`103` head from the backend was
  mistaken for the final response: the client saw the interim as its only
  answer and the real response stayed queued for the next exchange. Interim
  responses are now forwarded (RFC 9112 §6.2) and the loop keeps reading
  until the final message; a redundant backend `100` after the proxy's own
  is consumed exactly once. `101 Switching Protocols` is refused with 502
  (upgrade tunneling is unsupported) and 1xx floods are bounded (8 max).
- `Expect: 100-continue` deadlocked until the inactivity timeout: the client
  waited for an interim response that never came while the proxy waited for
  the body. The proxy now releases the client with a real `100 Continue`
  (RFC 9112 §10.1.2) once the request head has reached the backend.
- Unsupported `Expect` values are rejected explicitly with 417 instead of
  being silently forwarded (RFC 9112 §10.1.2). HTTP/1.0 requests ignore the
  `100-continue` expectation as the RFC requires.
- Malformed backend status lines (`HTTP/1.1 999 …`, `016`, …) are rejected
  with 502; status codes outside 100–599 were previously accepted.
- Backend bytes sent past the end of a response were silently discarded and
  the connection returned to the keep-alive pool, breaking the A16
  byte-alignment contract (the next exchange could consume the stale tail).
  The connection is now dropped instead of pooled, the bytes are never
  forwarded to the client, and the drop increments the new bounded
  `backend_connections_discarded` counter (metrics snapshot) so operators
  can alert on it (audit finding on the interim-response change; also
  reachable before it via `response_carry`).
- `100 Continue` is only generated when the request actually expects a body
  (a bodiless request with `Expect: 100-continue` gets no interim).
- Upstream failures are now diagnosable: invalid response heads, refused
  protocol switches (101) and interim floods log a WARN with listener,
  backend and peer (no secrets); pool drops are counted in the metrics
  (`backend_connections_discarded`).

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
