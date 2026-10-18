# Changelog — EQProxy

Language: **English**. Format follows "Keep a Changelog" (Added / Changed /
Fixed); versions are `vMAJOR.MINOR.PATCH` git tags.

## [Unreleased]

Nothing yet. Next: v0.6 «Reglas, enrutado y tráfico».

## [v0.5.0] — 2026-10-18

«Operabilidad y confianza» (completa Phase 3). The two blocks that sat
under `Unreleased` (planned as 0.4.6 — hot reload and release
automation) fold into this release.

### Added

- HTTP health checks with `expect` matching (B-H6/B-N11/B-I19/B-E5):
  `type = "http"` with `http_path`, `http_method`, `http_host`,
  `expect_status` (ranges like `"200-299"`) and `expect_rstring`
  (regex over the body). One real exchange per probe with a hard
  timeout; E2E-verified (a backend answering 500 is marked DOWN and
  traffic moves to the healthy server).
- Passive failure detection (B-N10): with `passive = true` on the health
  check, live-traffic verdicts feed the same fall/rise machine —
  connect-phase failures and HTTP 5xx responses count as failures, other
  completed exchanges as success. Passive marks only apply when an
  active checker exists that can bring the server back (safe restart).
- Safe connect-phase retries and bounded backend queues (B-H7/B-E7):
  `retries` (extra dials, max 5) with the documented replay rule
  (idempotent methods only unless `retry_non_idempotent = true` opts in;
  the failed server is excluded from redials), and `maxqueue` +
  `timeout_queue` (never more than `maxqueue` waiters, never unbounded
  waits). A full queue is rejected immediately with 503 and an expired
  waiter with 503 — never a silent hang. Counters: `queue_full`,
  `queue_timeout`, `retry_attempts`.
- Incoming PROXY protocol v1 with an origin allowlist (B-H9/B-E10):
  `proxy_receive = true` + `proxy_allow = ["10.0.0.0/8", …]` turns the
  listener into a strict front door — non-allowlisted origins and
  malformed or timed-out headers are closed without a byte forwarded
  (`proxy_protocol_denied`, `proxy_protocol_invalid`). The claimed
  client address becomes the peer for logs, forwarded headers and
  outgoing PROXY.
- mTLS (A15): `client_ca` under `[listener.*.tls]` requires client
  certificates issued by that CA (verified E2E: no cert and foreign
  certs are rejected, the right cert round-trips).
- Forwarded headers (B-N4, first step): `forwarded_headers =
  "off" | "append" | "replace"` handles `X-Forwarded-For` /
  `X-Real-IP` on the forwarded copy of the head — `append` keeps the
  chain and grows it, `replace` drops spoofed hops. Off by default.
- Custom local responses (C9 minimal): `local_response` (status,
  content_type, body) serves the "no server available" class with the
  configured body; counted in `local_responses_served`.
- Hot certificates (D7): a reload now applies new TLS material on kept
  sockets (verified E2E: after rotation the old root fails and the new
  one works on the same socket), and the swap latency is measured and
  published (`cfg[… last_swap_us=N]`, PP-04/05 — measured, never
  assumed).
- `config explain` documents what each timeout does when it fires
  (Q4/H5/CE5): `timeout_on_fire` maps every phase to its client-visible
  outcome (408/502/504/close), plus the queue, retry and local-response
  policy of the backend.
- Soak harness (`scripts/soak.py`) with published budgets (BENCHMARK_PLAN
  §9): the real binary under sustained load with RSS/CPU sampled from
  `/proc`, and an honest verdict (no measurement, no PASS). The 24h gate
  itself passed on netcup-bench (2026-10-18): 17.28M requests, 0 errors,
  0 bad status, steady RSS 8.86 MiB (budget 64), peak 9.32 MiB (budget
  128), clean SIGINT shutdown (exit 0).

### Changed

- Keep-alive pool hardening (A16): before pooling, the connection is
  probed for EOF — a backend that closed (even without announcing
  `Connection: close`) is dropped instead of handed to the next
  exchange, which used to fail with 502 on its first write.
- Metrics snapshot rendering groups counters by failure origin
  (client/proxy/network/backend/phases; Q4/H5/CE5) with bounded
  cardinality (CE4: fixed counter set, no labels).

### Added (folded from the planned 0.4.6)

- Hot config reload (S-CFG-01): `kill -HUP` re-reads the config file and
  applies it to the running proxy. The candidate goes through the same
  gate as startup (parse + validate + resolve); a rejected one logs
  `config reload rejected` with the cause and the running config keeps
  serving (fail-closed). Accepted swaps match listeners by name: same
  name + address keeps the socket (no rejection window for new
  connections), missing addresses are bound before anything mutates
  (all-or-nothing), removed listeners stop, and established connections
  drain with the config they were accepted with. Counters never reset
  (PP-03) and the new `cfg[reloads=N reload_failures=N]` metrics group
  makes reloads alertable.

- Release automation (`.github/workflows/release.yml`): pushing a `v*`
  tag runs the exact `scripts/release.sh` stages on the runners that can
  execute them (macos-15 for darwin, ubuntu + containers for linux),
  E2E-verifies every artifact (real CLI journeys and live proxied
  traffic) before anything is published, then creates the GitHub release
  (binaries + SHA256SUMS + SBOM) and builds, verifies and pushes the
  multi-arch image to ghcr. `release.sh` gained stages (`darwin`, `linux`,
  `sbom`, `sums`, `verify-image`) so local runs and CI share one verified
  pipeline; the image artifact itself is verified (version, config gate
  and live proxied traffic through the container).

### Fixed

- Release-pipeline E2E backend no longer starts Python's `http.server`
  CLI: on Python 3.14 `HTTPServer.server_bind` resolves reverse DNS
  (`socket.getfqdn()`) between `bind()` and `listen()`, which hung on the
  macOS runners and left the probe bound but never listening. The
  verification backend is now a raw socket with zero name resolution,
  and the loopback wait in CI reports what actually blocked.

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
  The verified scope per phase is tracked in the maintainer's plan.

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
