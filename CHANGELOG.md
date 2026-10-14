# Changelog — EQProxy

Language: **English**. Format follows "Keep a Changelog" (Added / Changed /
Fixed); versions are `vMAJOR.MINOR.PATCH` git tags.

## [Unreleased]

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
