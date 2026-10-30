# SPEC.md — ExyonQ Proxy (EQProxy) Specification

Language: **English**.

- Document version: 0.2 — state refreshed after v0.8.0
- Date: 2026-10-12 (created)
- Project state: **v0.8.0 published (2026-10-27); not declared production
  ready (the Phase 9 hardening gate is pending).** §14 carries the per-area
  state and its evidence.

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
criterion, **not an asserted result**: campaigns are published as they run,
losses included (benchmark evidence pages under `docs/evidence/`), and the
full matrix remains Phase 9.

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
  **Backup servers (B8):** a slot declared `backup = true` forms a second
  tier. While at least one primary is eligible (up, `ready`, weight > 0,
  resolved, not excluded by a retry) only primaries are picked; backups are
  picked only when that tier is empty, and primaries take the traffic back on
  the next request after recovery — no timer, no state to reset. Inside the
  backup tier the reference default is **one rung at a time**: only the first
  operational backup serves ("only the first operational backup server is
  used"), and **failover order** is the EQProxy extension `priority`
  (0..=255, higher fails over first, ties keep configuration order; rejected
  on a non-backup slot because it would be a silent no-op). A recovered
  higher rung takes the traffic back on the next request. **`all_backups =
  true`** is the reference's `option allbackups`: when no primary is eligible
  every operational backup is a candidate, so the algorithm (`roundrobin` /
  `leastconn`) and the weights spread load across the whole pool — and, as
  the reference states, "there will not be any priority order between the
  backup servers anymore". Pairing `all_backups` with a `priority` slot, or
  enabling it in a backend with no `backup = true` slot to balance, is a
  configuration error instead of a silent no-op. A backend whose slots are
  all backups follows the same mode.
- **Health checks (B11 TCP):** one task per backend with checks configured;
  `interval`/`timeout`/`fall`/`rise`. Servers start up; `fall` consecutive
  failures take a server down, `rise` consecutive successes bring it back.
- **No servers available:** HTTP answers 503 before touching any server; TCP
  closes the connection immediately. Both count `no_available_server`.
- **PROXY protocol v1 (A9 send):** header written to the chosen server before
  the payload (inside the TLS stream when backend TLS is on).

### 7.6 Backend keep-alive pool (A16, Phase 3 first slice)

- Per backend, shared by its listeners: the idle cap per server follows the
  peak of exchanges in flight on that server (floor 64, ceiling 4 096,
  ADR-0015), with a 60 s idle expiry; excess and stale connections are
  dropped. A workload with 400 streams in flight therefore keeps ~400
  connections instead of re-dialling every request beyond the 64th.
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

Implemented (v0.8) as a server-rendered client of the administration API
([ADR-0029](docs/adr/0029-panel-sessions-and-csrf.md)), opt-in behind
`[admin] panel = true`. It exposes today: listener/backend/server state with
health, in-flight counts and `drained`, validation before applying (the API's
own validation and `If-Match` revision), certificate management and
drain/maintenance per server. Still pending from the design list below:
change history, diffs between configurations, authorised request diagnostics,
alerts, a live-updating topology view (the dashboard is rendered per request)
and multi-instance management (desired vs applied revisions, drift).

Panel security (detail in [THREAT_MODEL.md](THREAT_MODEL.md)):
authentication, RBAC, write auditing, session and CSRF protection, strict
separation between public endpoint and administration, minimal permissions,
concurrency control on write operations (optimistic concurrency with revision),
forbidden to expose secrets, documented data retention policy. **The panel is
not a requirement to operate the proxy.** Implemented today: the bearer token
is exchanged once for an in-memory session (`HttpOnly`, `SameSite=Strict`,
`Path=/panel`) with a per-session CSRF token checked on every form; the role
comes from the token that opened it (read reads, write writes) and every
attempt writes its `AUDIT` line; sessions expire after 30 idle minutes, at
most 16 are kept, and stopping the process ends them.

Multi-instance: nothing that is not atomic is declared "atomic"; behaviour
under network partitions and partial failures is documented.

**Implemented so far (v0.8; [ADR-0017](docs/adr/0017-read-only-admin-plane.md)
to [ADR-0029](docs/adr/0029-panel-sessions-and-csrf.md), each cited where it
applies):**
an optional `[admin]` table opens a listener of its own with a bearer token
(`token` or `token_file`, loopback unless `allow_remote = true`). The endpoint
is exactly one of `listen` (TCP) or `unix_socket` (a Unix domain socket,
relative paths resolved against the configuration file; ADR-0021). The socket
is mode `0600` by default or opt-in `0660` with a numeric `unix_socket_gid`,
and an optional `unix_socket_allow_uids` list is checked against the kernel's
peer credential (`SO_PEERCRED`/`getpeereid`) before any HTTP byte is read; a
non-empty list refuses a peer without a reported uid, and the bearer token
still gates the routes (ADR-0022). `unix_socket_acl_uids` names users in the
file's POSIX access ACL (Linux), so they may `connect` without joining the
group; the list requires `0660` + a gid, is bounded to 64 entries and is
removed (attribute included) when it empties — the kernel, not the process,
checks it before `accept` (ADR-0023). Mode, group, ACL and allowlist are hot: a
`SIGHUP` applies them to the socket already bound, before the dataplane swap
and restoring the previous policy if the swap is refused, so a rejected
candidate neither widens the file nor the list; the endpoint and the tokens
stay fixed at startup and a reload that changes them warns. It serves
`GET /api/v1/status` (version, uptime, validated topology, per-server
`ready`/`drain`/`maintenance` state with health, in-flight count and `drained` — the drain
finished, ADR-0024 — and live counters as JSON), `GET /metrics` (the same
counters as Prometheus text with a fixed series set, plus the label-free
`eqproxy_backend_servers_draining` gauge and
`eqproxy_backend_drains_completed_total` counter, and — only with
`[metrics] detailed = true` — the budgeted per-server and per-route families,
ADR-0026) and one write, `PUT
/api/v1/backends/{backend}/servers/{target}/state` (`ready`, `drain` or
`maintenance`).
Writes need their own secret (`write_token`/`write_token_file`, distinct from
the read one); without it the plane is read-only and every write is
`403 write_disabled`. The write rejects `Origin` (no browser caller), needs
`application/json`, a declared body of at most 1 KiB and an idempotent
`{state}` document, and emits one `AUDIT` line per attempt (role, peer,
outcome, transition; never the secret). A drained server takes no new
requests, finishes its in-flight exchanges, and the state survives a `SIGHUP`
reload. The exchange that ends a drain is logged once
(`INFO server drained: backend=… target=… active=0`), with no timer and no
poll: the event is written where the last in-flight guard drops. `maintenance`
is the same removal plus closing the slot's idle material at the transition —
the keep-alive pool and the backend HTTP/2 session leave the hub —, so nothing
of the proxy's stays parked on a machine about to be patched; the line
`INFO server ready for maintenance: backend=… target=… active=0` is written
the same way, the label-free `eqproxy_backend_servers_maintenance` gauge counts
the windows, and a maintenance window never moves
`eqproxy_backend_drains_completed_total` ([ADR-0028](docs/adr/0028-maintenance-closes-the-idle-pool.md)).

Per-server and per-route metrics ([ADR-0026](docs/adr/0026-opt-in-detail-metrics-budget.md),
CE4) are opt-in and bounded by their own budget: `[metrics] detailed = true`
(off by default) adds `eqproxy_server_requests_total` and
`eqproxy_server_errors_total` (`backend`, `server` — the address that served
the exchange) and `eqproxy_route_requests_total` (`listener`, `route` — only
for a matched rule; traffic on the default backend has no invented label).
`max_series` (default 128, 1..=4096) counts leaves across both families: a
series that would exceed it is refused, the observation is counted in
`eqproxy_metrics_detail_dropped_total`, and an existing series keeps counting,
so the index never grows past the operator's number. Four label-free series
describe the budget in every scrape — `eqproxy_metrics_detail_enabled`,
`_series`, `_budget` and `_dropped_total` — so "no traffic", "detail off"
and "budget refused it" are distinguishable. `GET /api/v1/status` carries the
same rows under `metrics_detail`. `detailed` is hot (enabling starts an empty
window; disabling drops it); `max_series` is fixed at startup and a reload
that changes it warns and keeps the live budget. Detail follows
`http_requests_proxied`: h1, h2 and h3 exchanges and gRPC streams; protocol
switches (including WebSocket) are pending.

Certificate renewal ([ADR-0025](docs/adr/0025-certificate-renewal-without-restart.md),
D7) is one action: `POST /api/v1/certificates/reload` (write token, no
`Origin`, no body) re-reads the configuration and its certificate files
through the same single writer as `SIGHUP` and answers after the dataplane
committed, with `listener`, `listen`, `fingerprint` (`sha256:<hex>` of the
leaf actually served), `changed` and `quic` for every TLS listener. The
material lives behind a resolver consulted on every handshake, so a renewal
is an atomic swap: established connections are untouched, new h1/h2/h3
handshakes get the new certificate, and no socket, port or QUIC endpoint is
rebuilt. A candidate that fails validation (a PEM that does not parse, a key
that does not match) answers `400`, moves `config_reload_failures`, logs the
reason and leaves the previous certificate serving; ALPN, the mTLS client CA
and the minimum TLS version still need a restart on a live HTTP/3 listener.
`GET /api/v1/status` reports each listener's live `tls_fingerprint`.
Every other route is `404`, every other method `405`; bodies are
bounded (8 KiB head, 5 s exchange) and no secret appears in an answer or a
log line. The plane is a separate socket and task: the dataplane keeps
serving with it dead or unbound-by-config, and a configured plane that cannot
bind fails startup. On a Unix socket (ADR-0021) a live socket is never
stolen, a stale one left by a crash is replaced, any other file at the path
is preserved, and a clean shutdown removes only the inode this process
created; the bearer token is still required on every route.

Hot configuration (v0.8, ADR-0019) adds `PUT /api/v1/backends/{name}` and
`PUT /api/v1/listeners/{name}`: the body is that TOML table (`application/toml`,
declared length up to 64 KiB, no `Origin`, write role), either the bare body
or the complete section copied from the file, and it replaces the table,
creating the name when absent. `GET /api/v1/status`
returns a `revision` and an `ETag`; every write must send `If-Match` with it
(missing: `428`; stale: `412` with the current revision). One configuration
task serializes API writes and `SIGHUP`: it validates and resolves the whole
candidate before the dataplane swaps, answers `200` only after the commit,
and moves the revision and the reported topology only then. A valid candidate
the dataplane refuses (bind conflict, frozen QUIC TLS) is `409`; a parse or
validation failure is `400`; neither changes the running generation. A
listener kept by name and address keeps its socket, and established
connections drain on the generation they were accepted with. The changes are
runtime-only: the file remains the baseline and the next `SIGHUP` replaces
them. Still pending: `DELETE`, persistence/drift, a durable audit sink,
identities beyond the read/write roles (a per-user model), a live-updating
topology view and multi-instance drift. The panel UI
([ADR-0029](docs/adr/0029-panel-sessions-and-csrf.md)), certificate
management ([ADR-0025](docs/adr/0025-certificate-renewal-without-restart.md))
and `maintenance` with its idle-pool closure
([ADR-0028](docs/adr/0028-maintenance-closes-the-idle-pool.md)) landed in v0.8.

Structured access log (v0.8, ADR-0020): an optional `[access_log]` writes one
line per HTTP request answered by the dataplane engine — HTTP/1.1, each HTTP/2
stream and each HTTP/3 request — to stdout or an append-only file, as JSON or
the nginx combined shape. Each entry carries the listener, client, protocol,
method, path without its query, host, status, duration, the chosen
backend/server and the response byte count when it is exactly known; a head
that never parsed is logged with `-` fields, and an exchange that ended before
a response carries status 0. The sink is a bounded channel (4096 entries)
drained by its own task: a full or failed sink drops lines and advances
`access_log_dropped`, never delaying a request. Destination and format are
fixed at startup; a `SIGHUP` that edits them warns and keeps the running sink.

## 10. Extensions (WASM)

Implemented in v0.8.5 as a **request filter** ([ADR-0031](docs/adr/0031-wasm-plugin-host.md));
response filters, body access and the other extension points remain future
slices. Single route:

- **WASM (wasmtime)** for untrusted plugins: fuel/epoch interruption, per-store
  memory limits, deadlines.
- **Lua is discarded** by the 100 % safe code policy (user decision,
  2026-10-12): mlua is C FFI with substantial `unsafe`, and Lua is not a
  sandbox for hostile code. If compatibility with the reference proxy's Lua API
  is ever needed, it would be in an isolated process outside the binary and
  with a new ADR.

ABI v1 (v0.8.5) compiles **one module per HTTP listener** and runs it inline on
the dataplane worker for every request of that listener. The guest exports
`memory`, `eqproxy_alloc` and `eqproxy_on_request`, and may import only
`eqproxy.set_request_header` and `eqproxy.remove_request_header`; there is no
WASI, network or filesystem import to grant, and any other import rejects the
configuration. The plugin can add, replace or remove forwarded request headers
or reject with 400..=599; framing and connection headers are reserved. Fuel
(10 M instructions by default), a 50 ms epoch deadline, a 16 MiB memory cap
and a mutation budget bound each call; `on_error = "closed"` answers 503 on a
trap/timeout and `"open"` forwards unchanged. A fresh store per request keeps
plugins stateless. Metrics are `plugin_requests`, `plugin_denied` and
`plugin_errors`, label-free.

For any further extension point (fetch, converter, action, service, task —
equivalent to the reference proxy's) the same contract must be defined before
code: execution model (never arbitrary blocking tasks on dataplane workers; a
timeout does **not** magically cancel a block; isolation in another process
when the plugin may block), allowed capabilities (network and files **denied by
default**), instruction budget, deadlines, cancellation, fail-open/fail-closed
policy **per extension**, plugin API versioning, pre-activation validation and
isolation tests.

Rules: plugins are opt-in per listener and, once configured, run on every
request of that listener; the cost with and without plugins is measured
(BENCHMARK_PLAN.md, scenario S-PLG-01). WASM is not presented as perfect
isolation: host capabilities, residual risks and runtime dependency are
documented.

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
  3. **Server state DRAIN vs MAINT:** own explicit semantics (`ready`,
     `drain` and `maintenance`; the window also closes the slot's idle pool and
     backend h2 session), documented by comparison with
     `set server ... state drain/maint`
     ([ADR-0028](docs/adr/0028-maintenance-closes-the-idle-pool.md)).
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
     `h2` on client listeners; on backends `h2` opts into HTTP/2 to the
     origin — see item 11 — and an empty list keeps `http/1.1`)
     and the handshake **fails** when there is no common protocol instead of
     negotiating nothing silently. Backend TLS verifies certificate **and
     hostname by default** (Mozilla roots + `ca_file`); `verify = false` is an
     explicit opt-out with documented risk (THREAT_MODEL).
  6. **Load balancing (Phase 2b + v0.6 slice):** smooth weighted round-robin
     (deterministic; ties broken by configuration order) and weighted
     least-connections (`leastconn`; `active / effective weight`, ties
     smoothed by SWRR); slow start (B14) ramps the effective weight after
     every transition to operational; `weight = 0` means drained (never
     picked, still health-checked); `backup = true` (B8) is a second tier,
     consulted only while no primary is eligible, where `priority` orders the
     rungs (higher first, one rung serving at a time) unless the backend sets
     `all_backups = true`, which then balances the whole backup tier by weight
     (`option allbackups`).
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
      plaintext listener is served as HTTP/2; this slice keeps the backend on
      HTTP/1.1 (item 11 lifts that), so each stream is one HTTP/1.1 exchange
      through the same engine (same rules, actions, timeouts and errors).
      Framing translation is explicit: `content-length` preserved, a body
      without it sent upstream as `chunked`, chunked responses decoded into
      DATA and their trailers forwarded as trailing HEADERS, hop-by-hop
      headers never crossing in either direction (RFC 9113 §8.2.2).
      A `101` from a backend resets the stream (h2 has no protocol switch),
      `CONNECT` over h2 answers `501`, and a body shorter than its declared
      length resets the stream instead of ending it. At most 128 concurrent
      streams per connection, DATA read in 16 KiB units with capacity
      reserved before every frame. Upstream HTTP/2 is its own entry (item 11);
      extended CONNECT (WebSockets over h2), gRPC end to end and HTTP/3 are
      **not** part of this entry; design in
      [ADR-0006](docs/adr/0006-http2-termination.md).
  11. **HTTP/2 to the backend (v0.7, second slice):** a backend whose TLS
      handshake negotiates `h2` (its `[backend.X.tls] alpn` lists it) is
      reached with a real HTTP/2 session; an empty ALPN list keeps HTTP/1.1.
      The handshake happens in the connect phase, so a backend that cannot
      speak h2 is a connect failure (retried, answered `502`), never an open
      connection that fails per request. The engine still owns routing,
      actions, retries, the pool and the errors: one HTTP/1.1 message per h2
      stream crosses a bounded 64 KiB pipe. `content-length` is kept only
      when the h1 side declared one, chunked bodies become DATA and h1
      trailers trailing HEADERS; a backend `content-length` is preserved and
      anything else is relayed as `chunked`, with h2 trailers becoming h1
      trailers. `CONNECT` and host-less requests are refused (`502`), and a
      body shorter or longer than declared cuts the connection. Sessions are
      **multiplexed**: each backend server owns one h2 session, every exchange
      takes its own stream behind a private 64 KiB pipe (never pooled), the
      first exchange to a cold server handshakes under a per-address gate so
      concurrent first requests share it, and a dead session is replaced by
      the next exchange. The session has a lifecycle: it **closes when idle**
      for the listener's `idle_timeout` (never while an exchange is in
      flight), a peer `GOAWAY` **drains** the accepted streams and retires it,
      and a stream the peer refused before processing it (received `GOAWAY`
      or `RST_STREAM(REFUSED_STREAM)`) is **replayed once** on a fresh session
      when no request body was consumed; a stream cut after processing is
      never replayed. Design in
      [ADR-0007](docs/adr/0007-http2-backend.md),
      [ADR-0008](docs/adr/0008-http2-backend-multiplexing.md) and
      [ADR-0009](docs/adr/0009-http2-session-lifecycle.md).
  12. **Response compression, gzip and Brotli (v0.7):** a `http` listener with
      `[listener.X.compression]` can enable `gzip = true` (`level` 1–9) and/or
      `brotli = true` (`brotli_quality` 0–11) and compresses eligible responses
      when the request's `Accept-Encoding` accepts the coding (RFC 9110
      §12.5.3 subset: explicit entries decide, `q=0` refuses, `*` covers the
      coding, malformed q-values refuse). The coding with the higher q-value
      wins and a tie goes to Brotli; a coding the listener did not enable is
      never selected. The body is compressed while it is relayed — never
      buffered whole — into an h1 chunked response whose head drops
      `Content-Length`, adds `Content-Encoding: gzip`/`br`,
      `Transfer-Encoding: chunked` and `Vary: Accept-Encoding` once, and is
      presented as HTTP/1.1 (chunked requires it). Eligibility excludes
      HTTP/1.0 clients, `HEAD`, 1xx/204/206/304, bodies with
      `Content-Encoding`/`Content-Range`/`Cache-Control: no-transform`,
      media types outside the configured list and declared bodies below
      `min_size` (responses without a declared length cannot be filtered by
      it). Backend chunked trailers are validated and re-emitted after the
      compressed stream; h2 clients get the same compressed body as DATA
      through the existing h1⇄h2 translation, not a second implementation.
      Counters: `compression[gzip=… brotli=… bytes_in=… bytes_out=…]`. Design
      in [ADR-0010](docs/adr/0010-response-compression.md); raw numbers for
      both codings in
      [docs/evidence/v07-compression/bench.md](docs/evidence/v07-compression/bench.md).
      Request bodies are **never decompressed**: a client's `Content-Encoding`
      and its body reach the backend untouched, so the proxy offers no
      decompression surface for a zip bomb (THREAT_MODEL T09).

  13. **gRPC over HTTP/2 (v0.7, seventh slice):** a `POST` whose
      `content-type` is `application/grpc` (or `application/grpc+…`, never
      `grpc-web`) is **relayed** end to end when the chosen backend is
      configured for HTTP/2 (ALPN `h2`), instead of being translated to
      HTTP/1.1: the request HEADERS are built from the same h1 head the h1
      engine would forward (routing rules, rate limiter, auth, rule header
      actions, forwarded headers and rewrite all run through the same
      helpers), `te: trailers` is sent to the backend, and the client's
      DATA/trailers and the backend's HEADERS/DATA/trailers are relayed
      concurrently with HTTP/2 flow control as the only buffer. The final
      `grpc-status` reaches the client in trailing HEADERS, including a
      trailers-only answer. `idle_timeout` cuts a stream with no DATA in
      either direction (counted as inactivity); `max_stream_duration` ends a
      running stream with `grpc-status: 4` (DEADLINE_EXCEEDED) trailers, or a
      `504` before the response head. A refused stream is never replayed
      (gRPC is not idempotent); connect-phase failures keep the B-H7 retry
      rule. Compression and mirroring are not applied to gRPC streams, and a
      redirect/direct rule or a non-h2 backend keeps the existing h1
      translation. Design in
      [ADR-0011](docs/adr/0011-grpc-http2-passthrough.md).

  14. **HTTP/3 over QUIC (v0.7, ninth slice):** a listener with `quic = true`
      and a TLS table serves **h3 on its own address and port over UDP**
      (QUIC, TLS 1.3, ALPN `h3` forced; the same certificate, SNI entries and
      client CA as the TCP listener). The gate requires `mode = "http"`,
      rejects `alpn = ["h3"]` on the TCP table (the QUIC endpoint offers it
      automatically) and rejects `proxy_receive` (QUIC has no preamble for a
      PROXY line). QUIC connections count in `maxconn` and are refused
      explicitly when full. Each h3 request becomes **one HTTP/1.1 exchange
      through the same engine** (routing, auth, rate limiting, header
      actions, mirroring, retries, keep-alive pool, compression):
      `:authority` becomes `host`, hop-by-hop headers never cross,
      `content-length` is preserved, a stream without END_STREAM on HEADERS
      goes upstream as `chunked`, a body-less request keeps no framing, and
      h3 trailers map to h1 trailers (and back). `CONNECT` answers `501`; a
      backend `101` resets the stream (h3 has no protocol switch); a body
      shorter than declared resets the stream instead of ending it cleanly;
      interim 1xx are not forwarded (h3 0.0.8 has no informational frame); a
      dead backend is the engine's `502`. Startup is fail-closed (the UDP
      endpoint opens before any traffic); a hot reload keeps a kept endpoint
      and can turn QUIC on or off, but a **TLS material change on a live
      endpoint needs a restart** (the swap is rejected, never half-applied).
      Grease is disabled on the server connection for interoperability with
      aioquic (ADR-0013). Design in
      [ADR-0013](docs/adr/0013-http3-quic.md); evidence in
      [docs/evidence/v07-http3.md](docs/evidence/v07-http3.md). WebSockets
      over h3, gRPC over h3, 0-RTT, connection migration and HTTP/3 to
      backends are out of this slice.

  15. **Dynamic configuration and xDS (v0.8, ADR-0027):** EQProxy implements
      no xDS — neither a control-plane client (CDS/EDS/LDS/RDS/SDS, SotW or
      delta) nor an xDS server — because the equivalent is the runtime write
      API: one TOML table per write, the same `eqproxy_config::check` and
      resolution as startup, `If-Match` against a process-local `revision`, a
      single writer shared with `SIGHUP`, and a fail-closed atomic swap after
      which `200` is answered. The file remains the baseline and the next
      `SIGHUP` replaces the runtime generation; nothing persists the applied
      tables, and no second path with weaker checks exists (SPEC §9). This is a
      deliberate **E2** difference, not an unimplemented feature: an Envoy
      deployment driven exclusively by xDS is not migrated by the static
      converter (it reads `static_resources`), and an optional xDS **client**
      adapter that maps CDS/EDS/LDS/RDS onto the same candidate document — no
      SDS, delta or ADS — would need its own ADR and mapping table. Test:
      `run_admin_plane_applies_backend_config_under_traffic` (release binary,
      backend created under live traffic, `elapsed_ms < 1000` on every apply,
      a kept connection finishes on its accepted generation). Design in
      [ADR-0027](docs/adr/0027-xds-bridge-decision.md); migration note in
      [docs/migration/README.md](docs/migration/README.md).

## 14. Project state and evidence

| Area | State | Evidence |
|---|---|---|
| Phase 0 research (the reference proxy, user pain, Rust ecosystem) | Tested* | Sources with URL in docs; *verified by reading sources, not by execution |
| Specification and scope | Designed | This document |
| Parity matrix | Designed | Internal documentation (incomplete by design, gaps declared) |
| Phase 1 code (TCP proxy, TOML config, CLI) | **Tested** (2026-10-12) | 30 tests green: 19 unit + 6 E2E with real sockets + 5 E2E through the real `eqproxy` binary (incl. SIGINT). fmt/clippy `-D warnings` green; 0 own `unsafe` (`forbid(unsafe_code)`); cargo-deny and cargo-machete green; SBOM in `sbom/` |
| Backend idle-pool sizing (S-H2-01, v0.7 slice 10) | **Tested** (2026-10-23) | 2 new unit tests (the cap follows the reported peak: 400 in flight keeps 400; the ceiling clamps an absurd report) plus the existing floor test, and 1 dataplane E2E with a real h2 client and a real keep-alive h1 origin: 4 connections × 100 streams (400 in flight) in two waves — the second wave dials **zero** new backend connections and reuses all 400, the origin sees exactly the connections the proxy reports opening, and no exchange is discarded. The same test fails (wave 2 re-dials ~336) with the previous fixed 64-slot cap. Design in [ADR-0015](docs/adr/0015-backend-idle-pool-sizing.md). |
| Keep-alive idle bound (v0.7 slice 3 fix) | **Tested** (2026-10-22) | 1 dataplane E2E with a 150 ms header phase and a 1200 ms inactivity window: a connection idle 450 ms serves the next request, then closes silently past 1200 ms with `header_timeouts = 0` and `idle_timeouts = 1`. The hot-maps binary E2E (keep-alive held across a data swap) now passes deterministically. |
| Response compression, gzip and Brotli (v0.7 slices 5–6) | **Tested** (2026-10-22) | 16 tests (3 core unit on q-values, coding choice and media types; 8 dataplane on both encoders and the response decision; 5 CLI E2E through the release binary: gzip negotiation and every refusal case, Brotli preference/q-values/refusals/trailers with the decoded body compared, validate/explain for both codings, and h2c with real curl for gzip and Brotli). Raw wire-byte data for identity, gzip 1/6/9 and Brotli 1/5/11 in [docs/evidence/v07-compression/bench.md](docs/evidence/v07-compression/bench.md); evidence in [docs/evidence/v07-compression.md](docs/evidence/v07-compression.md) |
| gRPC end to end over HTTP/2 (B-I12/Q5, v0.7 slice 7) | **Tested** (2026-10-23) | 12 new tests: 4 unit (gRPC content-type detection — `grpc-web` excluded —, `te: trailers` without h1 framing, declared length, missing authority) and 8 dataplane E2E over real sockets with a real TLS `h2` origin: two messages echoed **before** the client half-closes with `grpc-status: 0`, a 256 KiB message across both flow-control windows, two concurrent streams on **one** backend session (origin barrier + one accepted connection), a silent stream cut by `idle_timeout` (counted), `max_stream_duration` ending with `grpc-status: 4`, forwarded headers crossing, the h1 translation kept for a non-h2 backend, and a dead backend answered `502`. Real `grpcio` 1.66.1 (TLS server, h2c client through the release binary): bidi, 256 KiB, `NOT_FOUND` in trailers and a **6-minute** stream with a message every 20 s; raw output in [docs/evidence/v07-grpc/](docs/evidence/v07-grpc/). <!-- soak:gate:start -->The 24-hour soak gate **PASSED** on 2026-10-23T23:09:55Z: 86400.0 s, 4267 messages, 0 broken streams, 0 failed probes, final `grpc-status: OK` (binary `0672763af6af`); evidence in [docs/evidence/v07-grpc-soak-24h.md](docs/evidence/v07-grpc-soak-24h.md).<!-- soak:gate:end --> |
| HTTP/3 over QUIC (B-H2/B-E2/B-E13, v0.7 slice 9) | **Tested** (2026-10-23) | 8 new tests: 7 dataplane E2E over real sockets with a real `quinn` + `h3` client (GET relayed with the origin seeing `host` and no hop-by-hop headers; 256 KiB without `content-length` chunked upstream with every byte in order; chunked response + trailer as h3 trailers; a `direct_response` rule and gzip applied by the same engine; `CONNECT` `501` and a dead backend `502`; `maxconn` refusing a second QUIC handshake; reload rejecting a TLS change while serving and turning QUIC off in place) and 1 configuration-gate test (TLS, `http` mode, `proxy_receive`, reserved `alpn = ["h3"]`). Two independent clients through the release binary (sha256 `f1d0aecb…`): `aioquic` 1.2.0 (QUIC + h3 + QPACK, no TCP fallback) with GET, 256 KiB streaming POST, trailers, gzip, rule `418` and `CONNECT` `501`, clean SIGINT and `proxied=4`; and `quic-go` 0.64.1 (its own QUIC/h3/QPACK stack) with GET, 256 KiB streaming POST without `content-length`, trailers, gzip and rule `418`, `proxied=4`. Both exit 0. Suite: **414 tests**, exit 0. Design in [ADR-0013](docs/adr/0013-http3-quic.md), evidence in [docs/evidence/v07-http3.md](docs/evidence/v07-http3.md) |
| h3 clean-close classification (S-H3-02 confounder, v0.7) | **Tested** (2026-10-24) | A client's normal session end (`H3_NO_ERROR` or QUIC application code `0`) counts `h3_clean_closes` and logs nothing; a protocol code, transport error, reset or timeout still counts `h3_connection_errors` and logs one `WARN` with the cause. 4 unit tests pin the classification one close code at a time and the two operator lines; 3 dataplane E2E tests close a real QUIC connection with code `0`, with `0x0100` and with a protocol error, asserting the counters and that the listener keeps serving. Release binary `a902bce9…` with `aioquic` 1.2.0: two clean closes leave 0 `WARN`, an `H3_GENERAL_PROTOCOL_ERROR` close leaves exactly 1, and `h3[clean_closes=3 connection_errors=1]`. S-H3-02 before/after on `netcup-bench` (two amd64 images from one tree, 5 repetitions each): **15 227 → 26** `WARN` lines and **1.67 MiB → 5.08 KiB** of log per 10 s run; handshakes/s 1 251.5 → 1 331.7 (**+6.4 %**, inside the −4.4 % drift of the HAProxy control, so not claimed as a speedup). Evidence in [docs/evidence/v07-h3-close.md](docs/evidence/v07-h3-close.md) |
| WebSockets over HTTP/2 (RFC 8441 extended CONNECT, B-I18, v0.7 slice 8) | **Tested** (2026-10-23) | 10 new tests: 4 unit (base64 RFC vector, 24-character per-handshake key, h1 head with upgrade and no hop-by-hop/key/version, non-path target refused or defaulted) and 6 dataplane E2E over real sockets with a real `h2` client and a real TCP WebSocket origin: bytes echoed both ways on one stream with `:status 200` (never `101`), the client's subprotocol returned, the origin seeing the h1 upgrade with a generated key, a refused handshake relayed as `404` with its body, a `direct_response` rule answering `403` before any backend contact, an unknown `:protocol` and a classic CONNECT answered `501`, and a silent tunnel cut by `idle_timeout`. Independent `hyper-h2` 4.2.0 client through the release binary (sha256 `1c9f040a…`): tunnel, refusal and `501`; raw output in [docs/evidence/v07-ws/](docs/evidence/v07-ws/). A backend that speaks only h2 stays out (ADR-0012). |
| Phase 2a code (strict HTTP/1.1, T01–T03, per-phase timeouts, streaming) | **Tested** (2026-10-12) | 47 tests green: 27 unit + 14 E2E with real sockets (6 TCP + 8 HTTP) + 6 E2E through the real binary (incl. smuggling rejected with 400 and SIGINT). fmt/clippy `-D warnings` green |
| Phase 2b code (TLS termination/backend TLS/ALPN, weighted RR, TCP health checks, PROXY v1 send) | **Tested** (2026-10-13) | 93 tests green: 57 unit + 26 E2E with real sockets (6 TCP + 8 HTTP + 12 Phase 2b) + 10 E2E through the real `eqproxy` binary (incl. real TLS traffic via `openssl s_client`). Veyra audit ACCEPTED + EvoForge slice eval F=1. Details in the 0.2.0 delivery |
| Phase 2c code (framing fuzz corpus + live fuzz, first benchmarks, measured budgets) | **Tested** (2026-10-14) | 3 new corpus tests (~10k parser mutants, no-panic + explicit statuses); live cargo-fuzz `framing` 3.83M execs, 0 crashes; S-TCP-01 Comparable, S-H1-01/S-TLS-01 Worse under sustained concurrency (verified EADDRNOTAVAIL root cause, pool in Phase 3); RSS/conn measured (TCP ~37.8, HTTP ~15.1 KiB). Evidence in `docs/evidence/phase2c/bench.md` |
| Benchmarks | **Measured (Phase 2 scope)** | First runs S-TCP-01, S-H1-01, S-TLS-01 vs 3.4.6 with raw data ([docs/evidence/phase2c/bench.md](docs/evidence/phase2c/bench.md)); full matrix remains Phase 9 |
| HTTP health-check response framing (close at the message boundary, RFC 9112 §6) | **Tested** (2026-10-19) | 5 unit tests (Content-Length / chunked / HEAD / close-delimited / 64 KiB budget) + 2 E2E interop journeys against keep-alive origins that never close a connection (library level and through the real binary): no check timeout, no flapping to `down` |
| Multi-certificate TLS per SNI (B-I2/B-H10/B-E9) | **Tested** (2026-10-20) | 4 unit tests (name grammar: exact/wildcard/IP-literal/misplaced wildcard/label length; resolver preference: exact, longest wildcard, unknown→default, no SNI→default, case-insensitive and trailing dot) + dataplane E2E with real handshakes recording the presented leaf for every branch + 2 through the real binary (`openssl s_client -servername -showcerts`: alpha exact, `*.beta` wildcard, unknown name and no-SNI → default, traffic through the SNI tunnel) + config-gate E2E (duplicate name names `listener.web.tls.certs[1].names` and says "already claimed"; IP literal and misplaced wildcard rejected with the fix) |
| Envoy rule actions `hash_policy` and `request_mirror` (B-H3) | **Tested** (2026-10-20) | Unit: hash-key grammar (`source`/`path`/`host`/`cookie:NAME`/`header:NAME`, bad keys rejected), sticky+weighted+consistent selection (300 keys, equal weights give each target ~1/3, removing a target moves only its keys, 9:1 weighting), mirror sampling (exactly 25 of every 100) and a copy written to a real TCP sink plus a dead shadow backend counting a failure. E2E over real sockets: same key keeps its target, keys spread, no-key requests rotate, consistent removal; mirror copy observed on the shadow socket with the client keeping the primary answer, non-matching paths not mirrored, dead mirror without client impact. Through the real binary: stickiness and both targets served, shadow receiving the copy, `config explain` showing `hash cookie:session` and `mirror 100% -> shadow`. Gate: 3 new tests naming field/cause/example for hash without split, too few live targets, unknown key, missing mirror backend, percentage outside 1..=100 and mirror on a local action |
| Public configuration JSON Schema and autocompletion (Q1/CE1) | **Tested** (2026-10-20) | `eqproxy config schema [--output]` renders a draft 2020-12 schema derived from the same structs the parser deserializes; 4 gates: generated schema == repository file byte for byte, documented example validated by the schema *and* by the real gate, typo (`listner`) and numeric duration rejected by the schema, every rule action present in the published properties; plus the real binary reproducing the file with `--output` |
| v0.6 routing rules and traffic control (B-H3/B-H4/B-N2/B-N3/B-N4/B-I4/B-E17/B-N5/B-I6/B-I11/B-H5/B-N8/B-I7/B-I10/B-H8/B-N13/B-N9/B-I9/C10) | **Tested** (2026-10-20, v0.6.1) | 327 tests green across 23 suites (unit, property, E2E over real sockets and the real binary) plus two Docker-gated harnesses: differential corpus **23/23** cases (HAProxy 3.4.6, nginx, ingress-nginx data plane, static Envoy v1.34.2) and migration matrix **13/13 cases × 5 implementations = 65/65 checks** ([docs/migration/](docs/migration/README.md), evidence in `docs/evidence/v06-migration/`) |
| HTTP/2 backend session lifecycle (B-H1/B-N1/B-I1/B-E2, v0.7 slice 4) | **Tested** (2026-10-22) | 3 new dataplane E2E journeys over real sockets: an idle session closed after the listener's window — but not while an exchange (480 ms of DATA 120 ms apart, window 300 ms) is in flight — and the next exchange dialing a fresh one; a real server `graceful_shutdown` draining its accepted stream (the slow answer still returns `200` after the GOAWAY) while the next exchange takes a fresh session; and a `RST_STREAM(REFUSED_STREAM)` sent by the peer being replayed exactly once with the same request head, one copy reaching the origin. Plus two release-binary journeys against an independent Python `hyper-h2` origin: idle close (`opened=2`, `h2[sessions_idle_closed=1]`) and GOAWAY + replay (`h2[goaway=1 refused_retried=1]`, the replayed request served once on a new session). Suite: **368 tests**, exit 0. Design in [ADR-0009](docs/adr/0009-http2-session-lifecycle.md), evidence in [docs/evidence/v07-http2-session-lifecycle.md](docs/evidence/v07-http2-session-lifecycle.md) |
| HTTP/2 backend multiplexing (B-H1/B-N1/B-I1/B-E2, v0.7 slice 3) | **Tested** (2026-10-22) | 3 new dataplane E2E journeys over real sockets: two in-flight exchanges that only complete when both streams are inside the origin (the second is answered on the **same** session: one accepted backend connection), a backend that hangs its session up being replaced by exactly one fresh session (the racing request gets `502` and delivers nothing), and a `tcp` listener relaying bytes unchanged although its backend negotiates `h2`. Plus the release-binary journey: 4 concurrent `curl` requests, each held 1.2 s by an independent hyper-h2 origin, all answer in 1.20–1.21 s (1.29 s wall) over **one** connection with streams 1/3/5/7, once with an h1 listener and once with an h2/TLS listener, and a kill/restart of the origin producing `200 → 502 → 200` with `opened=2 connect_failures=1`. Suite: **365 tests**, exit 0. Design in [ADR-0008](docs/adr/0008-http2-backend-multiplexing.md), evidence in [docs/evidence/v07-http2-multiplexing.md](docs/evidence/v07-http2-multiplexing.md) |
| HTTP/2 to the backend (B-H1/B-N1/B-I1/B-E2, v0.7 slice 2) | **Tested** (2026-10-22) | 4 unit tests (h1-only headers never cross, chunked keeps no length, `CONNECT`/host-less refused, absolute-form keeps its authority) + 7 E2E over real sockets with a real h2 server over TLS: h1 client → h2 backend (backend sees HTTP/2, `:authority` from `Host`, headers/body intact), h2 client end to end, one pooled backend session serving consecutive requests, request and response trailers in both directions, `HEAD` keeping its declared length and the session usable, `CONNECT` refused without reaching the backend, and a backend that cannot negotiate h2 producing an explicit `502` with the handshake counted; plus 1 CLI E2E (`config validate` accepting `alpn = ["h2"]` on a backend) and a journey through the real release binary and real `curl` against an independent Python `h2` origin. Evidence in [docs/evidence/v07-http2-backend.md](docs/evidence/v07-http2-backend.md) |
| HTTP/2 client termination (B-H1/B-N1/B-I1/B-E2, v0.7 slice 1) | **Tested** (2026-10-22) | 7 unit tests (origin-form translation, `:authority`→`host`, content-length vs chunked, hop-by-hop stripping, response-header filtering) + 6 E2E over real sockets with a real h2 client: h2c prior knowledge, three streams that only complete when they advance in parallel, a body without `content-length` reaching the origin as `chunked`, chunked response with trailers arriving as trailing HEADERS, truncated backend body resetting the stream, 502 on a dead backend and a rule `308` answered locally, TLS ALPN `h2`; plus 1 E2E through the real binary with real `curl` (`HTTP/2 200` over h2c and TLS, HTTP/1.1 still served on the same listener). Evidence in [docs/evidence/v07-http2.md](docs/evidence/v07-http2.md) |
| v0.8 administration, hot configuration and observability (slices 1–11: B-H12/B-H14/B-N14/B-I14/B-I15/B-E1/B-E8, D6/D7, H2/H3/CE2/CE4, Q1/Q9/CE1/CE8(p)) | **Tested** (2026-10-25 to 2026-10-27) | An optional `[admin]` plane of its own (ADR-0017) on TCP or a Unix socket — mode/gid/peer-uid allowlist/POSIX ACL, all hot on `SIGHUP` (ADR-0021/0022/0023) —, per-server `ready`/`drain` (ADR-0018) and `maintenance`, which also closes the slot's idle h1 pool and backend h2 session (ADR-0028), hot backend/listener writes with `If-Match` and an atomic swap (ADR-0019), observable draining (ADR-0024), certificate renewal without a restart (ADR-0025), opt-in per-server/per-route metrics under an explicit budget (ADR-0026), the structured access log (ADR-0020) and the opt-in server-rendered panel with bearer sessions and CSRF (ADR-0029). Evidence: the `v08-*` pages under [docs/evidence/](docs/evidence/) (17 pages, several with journeys over the release binary), the route×role matrix in [docs/evidence/v08-endpoint-authorization.md](docs/evidence/v08-endpoint-authorization.md), and the suite: **559 tests in 30 targets, 0 failed** on Linux (558 on macOS, where one test is Linux-only; `cargo test --workspace`, 2026-10-27) |
| Non-blocking dynamic DNS (B-H13/B-N18/B-E15, CE7) | **Tested** (2026-10-19) | 8 tests: 4 balancer-slot unit + 3 resolver-loop unit (stub seam) + 2 dataplane E2E (hot re-resolution, hung DNS → immediate 503 + recovery) + 2 through the real binary with the OS resolver (broken `.invalid` name → listeners announced < 3 s + counted 503; `localhost` backend → traffic + periodic rounds in METRICS) |
| Per-listener HTTP response cache (B-N7/H1, v0.8.5) | **Tested** (2026-10-30) | Opt-in `[listener.<name>.cache]` (`http` mode only): 13 dataplane E2E over real sockets with a recording origin (MISS→HIT byte-identical; sessions never share; `Set-Cookie` never stored; `Vary` variants; `ETag`/`304` revalidation without a body; TTL expiry; 10 concurrent sharing one fetch and one dial; `HEAD` from the `GET` entry; `Authorization`/`Range` bypass; unstorable statuses/directives; oversized bodies; cookie-affinity runtime bypass; disk entries surviving a restart with the origin dark) plus store unit tests and the config gate. The revalidation journey caught a real proxy bug: the conditional appended without a leading CRLF glued onto the last header, so the origin never saw the validator. Every served response carries `X-Cache: HIT \| MISS \| REVALIDATED`; `GET /api/v1/cache` lists entries. Design in [ADR-0034](docs/adr/0034-http-response-cache.md), evidence in [docs/evidence/v085-http-cache.md](docs/evidence/v085-http-cache.md) |
