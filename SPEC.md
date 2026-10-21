# SPEC.md — ExyonQ Proxy (EQProxy) Specification

Language: **English**.

- Document version: 0.1 (Phase 0)
- Date: 2026-10-12
- Project state: **Phase 0 — Research and scope. No code exists.**

## 1. Purpose

EQProxy is a reverse proxy and load balancer in Rust with two goals:

1. **Progressive functional parity** with the OSS reference proxy (pinned
   reference: 3.4.6 LTS primary, 3.0.29 LTS legacy — see
   [ADR-0003](docs/adr/0003-multiversion-reference.md)).
2. **Verifiable improvements** in diagnostics, configuration experience,
   administration, extensibility and security.

"Beating the reference proxy" is a **hypothesis validated with reproducible
tests**, not a conclusion (brief, section 15). Explicit product goal (user
decision, 2026-10-12): **match or beat the reference proxy 3.4.6 LTS on RPS,
connections, memory, CPU and P50/P95/P99 latencies** in the scenarios of
[BENCHMARK_PLAN.md](BENCHMARK_PLAN.md). This is a goal with an acceptance
criterion, **not an asserted result**: no measurements yet.

## 2. State taxonomy (mandatory)

Every artifact in this project uses exactly these states, in this order:

| State | Meaning |
|---|---|
| **Designed** | Decided and documented. No code that runs it. |
| **Implemented** | Code that does it exists, in the tree. |
| **Compiled** | `cargo build --release` passes on the tier 1 platform. |
| **Tested** | Automated tests (unit + integration with real sockets) pass. |
| **Validated under load** | Measured with the BENCHMARK_PLAN.md protocol; raw data published. |
| **Production ready** | All of the above + hardening, long-running tests and external review (Phase 9). |

Rules:
- "Designed (scope)" = designed only at scope level in this phase; the detailed
  design comes with its phase.
- A state is never promoted without the corresponding evidence. If a test
  cannot be run, it is marked **pending** with its exact command.
- Forbidden: mocks as evidence of real network, TLS or storage behaviour (unit
  test mocks are labelled as such).

## 3. Goals

1. Efficient and reliable dataplane (priority: correctness first).
2. Typed, validatable and understandable configuration (see §7 and [ADR-0002](docs/adr/0002-configuration-format.md)).
3. Diagnostics that explain traffic decisions (explain/trace mode, §8).
4. Safe and atomic configuration updates with respect to the visible view.
5. Accessible administration: CLI, API and web panel (the proxy never depends
   on the panel to run).
6. Extensions with explicit permissions and limits (WASM, §10).
7. Integrated observability (metrics, structured logs, tracing).
8. Recovery and rollback.
9. Reproducible tests (brief section 11 → [BENCHMARK_PLAN.md](BENCHMARK_PLAN.md)
   and the project plan).
10. Documentation oriented to real tasks.
11. **HTTP/3 (QUIC) to clients: mandatory requirement** (user decision,
    2026-10-12), implemented in Phase 5 and labelled experimental until it
    passes interoperability tests.

## 4. Non-goals (explicit)

- It is not a WAF. It does not promise total DDoS protection (rate limiting is
  not anti-DDoS).
- We do not implement our own cryptography; we do not parse complex protocols
  with our own code if maintained libraries exist.
- All our own Rust code is **safe**: `#![forbid(unsafe_code)]` in every crate,
  **no exceptions** (user decision, 2026-10-12). `unsafe` and FFI live only
  inside dependencies, inventoried and audited as residual risk
  ([THREAT_MODEL.md](THREAT_MODEL.md) §5).
- There is no parity with the commercial editions of the reference proxy
  (Enterprise, the One platform, ALOHA, Fusion): **excluded from parity scope**
  by decision (2026-10-12); the exclusion is only documented in the parity
  matrix (internal documentation) §E.
- There is no full compatibility with the reference proxy's config syntax.
  Migration is done with the **configuration converter** (migration tool; CLI
  `eqproxy config import --input reference-config --output eqproxy.toml`,
  `eqproxy-config-import` crate), which converts compatible directives, reports
  those needing review and **explicitly rejects** those that cannot be
  translated without altering behaviour. Directives are never silently
  dropped: "file generated correctly" ≠ "functionally equivalent migration".
- Distributed "atomic" multi-instance updates are not promised without a
  protocol that guarantees them.

## 5. Priorities (inviolable)

**correctness → security → operability → performance → feature breadth.**

Isolation, resource limits or correct semantics are never sacrificed to win a
benchmark. If EQProxy loses a scenario, the loss is recorded and profiled
before optimizing.

## 6. Support platform

See [ADR-0001](docs/adr/0001-production-platform.md): tier 1 production on
**Linux x86_64 glibc**; experimental tier 2 (aarch64, macOS, musl); Windows
unsupported.

## 7. Architecture

### 7.1 Plane separation

- **Dataplane** (`eqproxy-net`): client traffic. It does not depend on the
  panel or on admin storage to serve already-configured traffic. A control
  plane failure does **not** stop configured traffic.
- **Control plane** (`eqproxy-config`, `eqproxy-cli`, later `eqproxy-control`):
  validation, planning, application and administration.

### 7.2 Configuration snapshots

- Each config application produces an **immutable, coherent snapshot** (shared
  `Arc`) that the dataplane reads without per-request locking.
- No per-request storage accesses when not needed.
- Activation is **atomic with respect to the visible configuration**: either
  the complete new config is visible, or the complete previous one (transition
  by snapshot swap). Change classification: hot-applicable / require draining /
  require process replacement / unsupported (classification table in phase 3;
  the API and the CLI share the same validation).
- If preparing a change fails, nothing is activated (prior resource
  compilation: listeners, pools, certs). Irreversible external effects (e.g. an
  already-issued drain order) are **not promised to be revertible**.

### 7.3 Resource budgets (design; to be validated by measurement)

Visible assumptions: HTTP/1.1 proxying, 16 KiB buffers per direction, active
connections without compression or caching.

| Scenario | Design budget (unmeasured) | Assumption | Validated in |
|---|---|---|---|
| TCP proxy connection | ≤ 36 KiB/connection (2 × 16 KiB buffers + ~4 KiB state) | bidirectional streaming | Phase 2c (measured ~37.8 KiB on darwin/arm64, +5% allocator rounding; Linux re-measurement pending) |
| HTTP/1.1 connection | ≤ 48 KiB/connection (2 buffers + state + parser) | keep-alive to backend | Phase 2c (measured ~15.1 KiB idle keep-alive on darwin/arm64) |
| FDs | 2 FDs per proxied connection + listeners + admin. E.g. maxconn 100 000 → ≥ 200 000 FDs + 10 % margin | `ulimit -n` limit documented in `eqproxy doctor` | Phase 1 |
| Queues | Bounded queue per backend (`maxqueue`); rejection with 503/explicit timeout when full; **never unlimited queues** | burst traffic | Phase 3 |
| Tasks | 1 task per connection (not per request on keep-alive); task cap = connection cap | — | Phase 1 |
| Metric cardinality | Labels bounded by config (frontend/backend/server); labelling with URLs, client IPs or tokens is forbidden | — | Phase 3 |

Behaviour on exhaustion: exhausting FDs, memory or queues produces explicit
rejection (clear error + metric + log), never a process that "returns simulated
success". The numbers above are design targets; they are revised with profiling
data (no "optimization" without evidence).

### 7.4 Crate workspace

See [ADR-0004](docs/adr/0004-network-stack-and-crate-layout.md): 4 initial crates
(`eqproxy-core`, `eqproxy-config`, `eqproxy-net`, `eqproxy-cli`); new crates
only under the documented separation rule.

### 7.5 TLS, balancing and health checks (Phase 2b)

- **TLS termination (A11):** per-listener certificate chain + private key
  (PEM); the handshake is part of the client phase (`client_header_timeout`).
  Min TLS 1.2; ALPN explicit per listener (A14).
- **Backend TLS (A12):** per-backend; certificate **and hostname verified by
  default** (Mozilla roots + `ca_file` for private CAs). The SNI/verified name
  defaults to the server's IP literal, overridable with `server_name`.
  The handshake is bounded by `connect_timeout`.
- **Balancing (B1/B7 + B-H5/B-N12/B-E6 + B14):** one shared balancer per
  backend (also shared between listeners referencing it). Two algorithms:
  `balance = "roundrobin"` (default; smooth weighted round-robin) and
  `balance = "leastconn"` (weighted least-connections — HAProxy `leastconn`,
  nginx `least_conn`, Envoy `LEAST_REQUEST`, all accepted as names: the
  pick minimizes `active exchanges / effective weight`, ties smoothed by
  SWRR). **Dynamic weighting:** the weight used at pick time is the
  *effective weight* = `weight` × the slow-start ramp — with
  `slow_start = "30s"` (B14; `"0s"` = off, maximum `"1h"`) every
  transition to operational (startup or recovery after `rise`) ramps it
  linearly from ~0 to `weight` over the window. `weight` 0..=256.
- **Health checks (B11 TCP):** one task per backend with checks configured;
  `interval`/`timeout`/`fall`/`rise`. Servers start up; `fall` consecutive
  failures take a server down, `rise` consecutive successes bring it back.
- **No servers available:** HTTP answers 503 before touching any server; TCP
  closes the connection immediately. Both count `no_available_server`.
- **PROXY protocol v1 (A9 send):** header written to the chosen server before
  the payload (inside the TLS stream when backend TLS is on).

### 7.6 Backend keep-alive pool (A16, Phase 3 first slice)

- Per backend, shared by its listeners: at most 64 idle connections per
  server, 60 s idle expiry; excess and stale connections are dropped.
- A connection returns to the pool **only after a fully clean exchange**
  (request sent, response forwarded, no framing error/truncation/timeout,
  server did not signal close). A checkout therefore always yields a
  message-aligned connection; unread leftover bytes disqualify the entry.
- Reuse and dial counts are observable (`pool[reused=… opened=…]`).
  A server-side idle close racing a checkout surfaces as one explicit 502
  plus `connect_failures`, identical to a dial failure — fail-explicit.

## 8. Explainable diagnostics (explain/trace mode)

Designed (scope); implementation in Phases 3–4. The static subset
(listener, backend, selected server + state; items 1–3) is delivered as
`config explain`, offline with no side effects. The explain mode for a request
(real, sampled, or **simulated with no external effects**) must show:

1. Listener and frontend used.
2. Rules evaluated, in order; rules that matched and why.
3. Selected backend and reason; selected server and its state (UP/DOWN/DRAIN/MAINT).
4. Per-phase timings (accept, TLS handshake, request, backend connect, TTFB, transfer).
5. Retries and redistributions.
6. The concrete timeout that fired (client, connect, server, tunnel…).
7. Error origin when determinable: client, proxy, network or backend.
8. Explicit difference between *successful health check* and *functional
   application success*.

Requirements of the diagnostic mode:
- Off or sampled by default; bounded in memory and time.
- Protected by permissions (authenticated control plane).
- Redacted: no tokens, cookies or personal data in the clear.
- **Simulation ≠ execution**: rule simulation issues no requests and has no
  external effects, and is labelled as a simulation in its output.

Associated observability: structured logs (JSON), correlation identifiers,
operational events, metrics exportable in a standard format (Prometheus),
`tracing` integration where it helps. Diagnostics propose concrete actions
without asserting undemonstrated causes.

## 9. Administration and web panel

Designed (scope); implementation in Phase 6. The panel exposes: listener/backend
state, server health, connections/queues/latencies, change history, diffs
between configurations, validation before applying, certificate management,
drain/maintenance, authorised request diagnostics, alerts and multi-instance
management (desired vs applied revisions, drift).

Panel security (detail in [THREAT_MODEL.md](THREAT_MODEL.md)):
authentication, RBAC, write auditing, session and CSRF protection, strict
separation between public endpoint and administration, minimal permissions,
concurrency control on write operations (optimistic concurrency with revision),
forbidden to expose secrets, documented data retention policy. **The panel is
not a requirement to operate the proxy.**

Multi-instance: nothing that is not atomic is declared "atomic"; behaviour
under network partitions and partial failures is documented.

## 10. Extensions (WASM)

Designed (scope); implementation in Phase 7. Single route:

- **WASM (wasmtime)** for untrusted plugins: fuel/epoch interruption, per-store
  memory limits, deadlines.
- **Lua is discarded** by the 100 % safe code policy (user decision,
  2026-10-12): mlua is C FFI with substantial `unsafe`, and Lua is not a
  sandbox for hostile code. If compatibility with the reference proxy's Lua API
  is ever needed, it would be in an isolated process outside the binary and
  with a new ADR.

For each plugin (plugin template) is defined: extension points (fetch,
converter, action, service, task — equivalent to the reference proxy's),
execution model (never arbitrary blocking tasks on dataplane workers; a timeout
does **not** magically cancel a block; isolation in another process when the
plugin may block), allowed capabilities (network and files **denied by
default**), instruction budget, deadlines, cancellation, fail-open/fail-closed
policy **per extension**, plugin API versioning, pre-activation validation and
isolation tests.

Rules: plugins do not run on every request by default; the cost with and
without plugins is measured (BENCHMARK_PLAN.md, scenario S-PLG-01). WASM is
not presented as perfect isolation: host capabilities, residual risks and
runtime dependency are documented.

## 11. Security

See [THREAT_MODEL.md](THREAT_MODEL.md). Cross-cutting principles: per-phase and
per-protocol limits, consistent HTTP message normalization, safe rejection of
ambiguous messages (request smuggling: ambiguous framing is rejected, never
"guessed"), secret protection, dependency and license inventory, vulnerability
reporting procedure.

## 12. Testing and verification

Full strategy in [BENCHMARK_PLAN.md](BENCHMARK_PLAN.md) and the project
invariants: unit, integration with real sockets,
end-to-end, property-based, fuzzing (own parsers, config, rules), differential
tests against the reference proxy where semantics must match, protocol
conformance, sustained load, fault injection, certificate renewal, config
changes under traffic, slow clients/backends, backend failures, long streaming,
changing DNS, resource exhaustion, restart/recovery, plugins exceeding limits.

Tools and their declared limits: `cargo fmt`, `cargo clippy`,
`cargo test`, dependency and license audit (`cargo-deny` or equivalent), Miri
**only** for compatible components (it does not prove the absence of bugs in
the whole service), sanitizers/concurrency tools where appropriate.

## 13. Semantic difference log vs the reference proxy

- Every capability in the parity matrix declares the semantics it preserves and
  the known differences. "Similar feature" ≠ "compatible".
- Documented semantic differences (initial selection, to grow):
  1. **Configuration reload:** the reference proxy spawns a new process and
     inherits sockets; EQProxy applies hot snapshots within the process.
     Metrics are **not** reset on a config application (intentional
     difference; see PP-03). "Process replacement" is only contemplated for
     changes that require it.
  2. **Configuration format:** canonical TOML (proposed, ADR-0002), not the
     reference proxy's syntax; the reference proxy → EQProxy converter
     translates a subset with a per-directive equivalence report (pipeline:
     `reference-config` → lossless reference proxy parser → structured
     representation → translation → validation and generation → `eqproxy.toml`
     + conversion report).
  3. **Server state DRAIN vs MAINT:** own explicit semantics, documented by
     comparison with `set server ... state drain/maint`.
  4. **HTTP framing (Phase 2a):** EQProxy rejects every ambiguous message
     (CL+TE, duplicates, TE ≠ `chunked`, absolute-form, obs-fold) instead of
     normalizing it as the reference proxy may do in some cases;
     `CONNECT` and `Upgrade` are tunnelled since v0.6 (B-H15/B-I18/B-E11,
     per-direction idle timeouts). Trailers only empty or without framing
     headers.
  5. **TLS and ALPN (Phase 2b + v0.6.x SNI):** certificates are selected by
     SNI (exact name, then the longest `*.` wildcard, then the listener's
     default certificate; an unknown name never fails the handshake), and
     only TLS 1.2/1.3 (TLS 1.0/1.1 never);
     ALPN offers only the configured protocols (`http/1.1` and, since v0.7,
     `h2` on client listeners; the backend side still offers `http/1.1` only)
     and the handshake **fails** when there is no common protocol instead of
     negotiating nothing silently. Backend TLS verifies certificate **and
     hostname by default** (Mozilla roots + `ca_file`); `verify = false` is an
     explicit opt-out with documented risk (THREAT_MODEL).
  6. **Load balancing (Phase 2b + v0.6 slice):** smooth weighted round-robin
     (deterministic; ties broken by configuration order) and weighted
     least-connections (`leastconn`; `active / effective weight`, ties
     smoothed by SWRR); slow start (B14) ramps the effective weight after
     every transition to operational; `weight = 0` means drained (never
     picked, still health-checked).
  7. **Health checks (Phase 2b/3):** TCP connect, or HTTP with `expect
     status|rstring`; check OK ≠ functional success (§8.8). HTTP checks
     complete at the HTTP message boundary (RFC 9112 §6, v0.6 fix), so a
     keep-alive origin never flaps a healthy server.
  8. **PROXY protocol (Phase 2b + v0.6):** v1 send (header before the
     payload; `PROXY UNKNOWN` for mixed families) and v2 send; reception is
     autodetected (v1/v2) and gated by the origin allowlists of Phase 3 —
     PROXY is never trusted from unauthorized sources.
  9. (Living log: each matrix row extends it.)
  10. **HTTP/2 termination (v0.7, first slice):** a client that negotiates
      `h2` (ALPN on TLS) or starts with the h2c connection preface on a
      plaintext listener is served as HTTP/2; the backend side still speaks
      HTTP/1.1, so each stream is one HTTP/1.1 exchange through the same
      engine (same rules, actions, timeouts and errors).
      Framing translation is explicit: `content-length` preserved, a body
      without it sent upstream as `chunked`, chunked responses decoded into
      DATA and their trailers forwarded as trailing HEADERS, hop-by-hop
      headers never crossing in either direction (RFC 9113 §8.2.2).
      A `101` from a backend resets the stream (h2 has no protocol switch),
      `CONNECT` over h2 answers `501`, and a body shorter than its declared
      length resets the stream instead of ending it. At most 128 concurrent
      streams per connection, DATA read in 16 KiB units with capacity
      reserved before every frame. Upstream HTTP/2, extended CONNECT
      (WebSockets over h2), gRPC end to end and HTTP/3 are **not** part of
      this slice; design in [ADR-0006](docs/adr/0006-http2-termination.md).

## 14. Project state and evidence

| Area | State | Evidence |
|---|---|---|
| Phase 0 research (the reference proxy, user pain, Rust ecosystem) | Tested* | Sources with URL in docs; *verified by reading sources, not by execution |
| Specification and scope | Designed | This document |
| Parity matrix | Designed | Internal documentation (incomplete by design, gaps declared) |
| Phase 1 code (TCP proxy, TOML config, CLI) | **Tested** (2026-10-12) | 30 tests green: 19 unit + 6 E2E with real sockets + 5 E2E through the real `eqproxy` binary (incl. SIGINT). fmt/clippy `-D warnings` green; 0 own `unsafe` (`forbid(unsafe_code)`); cargo-deny and cargo-machete green; SBOM in `sbom/` |
| Phase 2a code (strict HTTP/1.1, T01–T03, per-phase timeouts, streaming) | **Tested** (2026-10-12) | 47 tests green: 27 unit + 14 E2E with real sockets (6 TCP + 8 HTTP) + 6 E2E through the real binary (incl. smuggling rejected with 400 and SIGINT). fmt/clippy `-D warnings` green |
| Phase 2b code (TLS termination/backend TLS/ALPN, weighted RR, TCP health checks, PROXY v1 send) | **Tested** (2026-10-13) | 93 tests green: 57 unit + 26 E2E with real sockets (6 TCP + 8 HTTP + 12 Phase 2b) + 10 E2E through the real `eqproxy` binary (incl. real TLS traffic via `openssl s_client`). Veyra audit ACCEPTED + EvoForge slice eval F=1. Details in the 0.2.0 delivery |
| Phase 2c code (framing fuzz corpus + live fuzz, first benchmarks, measured budgets) | **Tested** (2026-10-14) | 3 new corpus tests (~10k parser mutants, no-panic + explicit statuses); live cargo-fuzz `framing` 3.83M execs, 0 crashes; S-TCP-01 Comparable, S-H1-01/S-TLS-01 Worse under sustained concurrency (verified EADDRNOTAVAIL root cause, pool in Phase 3); RSS/conn measured (TCP ~37.8, HTTP ~15.1 KiB). Evidence in `docs/evidence/phase2c/bench.md` |
| Benchmarks | **Measured (Phase 2 scope)** | First runs S-TCP-01, S-H1-01, S-TLS-01 vs 3.4.6 with raw data ([docs/evidence/phase2c/bench.md](docs/evidence/phase2c/bench.md)); full matrix remains Phase 9 |
| HTTP health-check response framing (close at the message boundary, RFC 9112 §6) | **Tested** (2026-10-19) | 5 unit tests (Content-Length / chunked / HEAD / close-delimited / 64 KiB budget) + 2 E2E interop journeys against keep-alive origins that never close a connection (library level and through the real binary): no check timeout, no flapping to `down` |
| Multi-certificate TLS per SNI (B-I2/B-H10/B-E9) | **Tested** (2026-10-20) | 4 unit tests (name grammar: exact/wildcard/IP-literal/misplaced wildcard/label length; resolver preference: exact, longest wildcard, unknown→default, no SNI→default, case-insensitive and trailing dot) + dataplane E2E with real handshakes recording the presented leaf for every branch + 2 through the real binary (`openssl s_client -servername -showcerts`: alpha exact, `*.beta` wildcard, unknown name and no-SNI → default, traffic through the SNI tunnel) + config-gate E2E (duplicate name names `listener.web.tls.certs[1].names` and says "already claimed"; IP literal and misplaced wildcard rejected with the fix) |
| Envoy rule actions `hash_policy` and `request_mirror` (B-H3) | **Tested** (2026-10-20) | Unit: hash-key grammar (`source`/`path`/`host`/`cookie:NAME`/`header:NAME`, bad keys rejected), sticky+weighted+consistent selection (300 keys, equal weights give each target ~1/3, removing a target moves only its keys, 9:1 weighting), mirror sampling (exactly 25 of every 100) and a copy written to a real TCP sink plus a dead shadow backend counting a failure. E2E over real sockets: same key keeps its target, keys spread, no-key requests rotate, consistent removal; mirror copy observed on the shadow socket with the client keeping the primary answer, non-matching paths not mirrored, dead mirror without client impact. Through the real binary: stickiness and both targets served, shadow receiving the copy, `config explain` showing `hash cookie:session` and `mirror 100% -> shadow`. Gate: 3 new tests naming field/cause/example for hash without split, too few live targets, unknown key, missing mirror backend, percentage outside 1..=100 and mirror on a local action |
| Public configuration JSON Schema and autocompletion (Q1/CE1) | **Tested** (2026-10-20) | `eqproxy config schema [--output]` renders a draft 2020-12 schema derived from the same structs the parser deserializes; 4 gates: generated schema == repository file byte for byte, documented example validated by the schema *and* by the real gate, typo (`listner`) and numeric duration rejected by the schema, every rule action present in the published properties; plus the real binary reproducing the file with `--output` |
| v0.6 routing rules and traffic control (B-H3/B-H4/B-N2/B-N3/B-N4/B-I4/B-E17/B-N5/B-I6/B-I11/B-H5/B-N8/B-I7/B-I10/B-H8/B-N13/B-N9/B-I9/C10) | **Tested** (2026-10-20, v0.6.1) | 327 tests green across 23 suites (unit, property, E2E over real sockets and the real binary) plus two Docker-gated harnesses: differential corpus **23/23** cases (HAProxy 3.4.6, nginx, ingress-nginx data plane, static Envoy v1.34.2) and migration matrix **13/13 cases × 5 implementations = 65/65 checks** ([docs/migration/](docs/migration/README.md), evidence in `docs/evidence/v06-migration/`) |
| HTTP/2 client termination (B-H1/B-N1/B-I1/B-E2, v0.7 slice 1) | **Tested** (2026-10-22) | 7 unit tests (origin-form translation, `:authority`→`host`, content-length vs chunked, hop-by-hop stripping, response-header filtering) + 6 E2E over real sockets with a real h2 client: h2c prior knowledge, three streams that only complete when they advance in parallel, a body without `content-length` reaching the origin as `chunked`, chunked response with trailers arriving as trailing HEADERS, truncated backend body resetting the stream, 502 on a dead backend and a rule `308` answered locally, TLS ALPN `h2`; plus 1 E2E through the real binary with real `curl` (`HTTP/2 200` over h2c and TLS, HTTP/1.1 still served on the same listener). Evidence in [docs/evidence/v07-http2.md](docs/evidence/v07-http2.md) |
| Non-blocking dynamic DNS (B-H13/B-N18/B-E15, CE7) | **Tested** (2026-10-19) | 8 tests: 4 balancer-slot unit + 3 resolver-loop unit (stub seam) + 2 dataplane E2E (hot re-resolution, hung DNS → immediate 503 + recovery) + 2 through the real binary with the OS resolver (broken `.invalid` name → listeners announced < 3 s + counted 503; `localhost` backend → traffic + periodic rounds in METRICS) |
