# v0.7 slice 7 — gRPC end to end over HTTP/2

Language: **English**. Evidence for the seventh v0.7 increment, collected on
2026-10-23 (macOS 26.5.1 arm64 host, `rustc 1.97.1`, `grpcio` 1.66.1 on
Python 3.9.6 and hyper-h2 4.2.0). Unreleased: it lands on top of `b93883e`,
after [slice 6](v07-compression.md).

## 1. Objective

gRPC needs one HTTP/2 stream with two independent directions: the client keeps
sending while the server answers, and the final status travels in trailers.
The h1 translation that serves every other h2 request forwards the whole
request body before reading the response head, so a bidirectional stream never
sees its first answer before the client half-closes (`B-I12`, `Q5`). This slice
relays such a stream end to end when the chosen backend speaks HTTP/2.

Not covered: HTTP/3 (`B-H2`), WebSockets over h2 (`B-I18`), compression or
mirroring of gRPC streams, the S-H2/S-H3 scenarios against HAProxy, the
24-hour soak, and both-architecture Docker gates (no image is built for this
increment).

## 2. Artifact under test

| Item | Value |
|---|---|
| Base commit | `b93883e` (`docs: record the backend HTTP/2 session lifecycle slice`) plus the working tree of this increment |
| Binary | `target/release/eqproxy`, sha256 `0672763af6afad189cd24fa6f30673b2bd3a02f3d90c467cffc23f79daab6dd6` (`cargo build --release -p eqproxy-cli`, rebuilt from the final tree before the journeys) |
| Toolchain | `rustc 1.97.1 (8bab26f4f 2026-07-14)`, cargo 1.97.1 |
| Real gRPC stack | `grpcio` 1.66.1 / `grpc-c` 43.0.0 (origin **and** client), Python 3.9.6 |
| Design | [ADR-0011](../adr/0011-grpc-http2-passthrough.md) |
| Raw runs | [`v07-grpc/quick.txt`](v07-grpc/quick.txt), [`v07-grpc/long-360s.txt`](v07-grpc/long-360s.txt), harness `scripts/evidence/v07-grpc/run.py` (maintainer-local), binary hash [`v07-grpc/binary.sha256`](v07-grpc/binary.sha256) |

## 3. What the implementation does

`eqproxy-net/src/grpc.rs` serves a request when **all** of these hold: method
`POST`, `content-type` `application/grpc` or `application/grpc+…` (never
`grpc-web`), the route decision is `Proxy`, and the chosen backend has an h2
hub (`[backend.X.tls] alpn` includes `h2`). Otherwise the request returns
untouched to the h1 translation.

For a pass-through request:

1. The h2 request is rendered as the same h1 head the h1 engine would forward
   (`http2::build_request_head`), parsed with the strict parser, and passed
   through the **same** helpers: `cfg.decide` for routing rules,
   `rate_limiter`, `auth::check`, `apply_header_actions`, `apply_forwarded`
   and `apply_rewrite` — no second implementation of any decision.
2. `proxy::open_grpc_stream` selects a server with the normal
   balancer/queue policy, takes the single-flight handshake
   (`session_for`), admits the stream (`Session::enter`) and sends the request
   HEADERS with `te: trailers`.
3. Both directions are relayed concurrently: client DATA/trailers → backend,
   backend HEADERS/DATA/trailers → client. HTTP/2 flow control is the only
   buffer; capacity is released only after the peer accepted the chunk.
4. `idle_timeout` cuts a stream with no DATA (counted in `idle_timeouts`);
   `max_stream_duration` ends a running stream with `grpc-status: 4` and
   `grpc-message: max stream duration exceeded` trailers, or answers `504`
   before the response head.
5. A stream the peer refused after opening it is never replayed (gRPC is not
   idempotent). Connect-phase failures keep the B-H7 retry/queue rule.

New counters: `grpc[streams=… errors=…]` in the metrics snapshot.

## 4. Journeys and results

### 4.1 Dataplane E2E with real sockets (cargo)

`cargo test -p eqproxy-net --test e2e_grpc` — **8 passed, 0 failed**, 10.4 s.
The origin is a real TLS HTTP/2 server that speaks the gRPC wire protocol
(length-prefixed messages, `te: trailers`, status trailers); the client is the
`h2` implementation over loopback TCP.

| Journey | What it proves | Result |
|---|---|---|
| `grpc_bidi_answers_before_the_client_half_closes` | the first two messages are echoed **while the request stream is still open**; the final trailers carry `grpc-status: 0`; the origin saw `te: trailers` and `application/grpc` | pass |
| `grpc_large_messages_cross_flow_control` | a 300 000-byte payload (293 KiB message plus framing) crosses both flow-control windows byte-for-byte | pass |
| `grpc_concurrent_streams_share_one_backend_session` | two streams from two client connections are inside the origin **at the same time** (barrier) and arrive over **one** accepted backend connection | pass |
| `grpc_silent_stream_is_cut_by_the_idle_timeout` | a stream with no DATA after the headers ends explicitly after a 200 ms window; `idle_timeouts` counts it | pass |
| `grpc_max_stream_duration_ends_with_deadline_status` | a 300 ms cap ends the running stream with `grpc-status: 4` + `grpc-message` trailers | pass |
| `grpc_forwarded_headers_cross_the_pass_through` | `forwarded_headers = "append"` reaches the origin as `x-forwarded-for: 127.0.0.1` (same policy as h1) | pass |
| `grpc_without_an_h2_backend_keeps_the_h1_translation` | a backend without `h2` keeps the existing translation and still answers the request | pass |
| `grpc_dead_backend_is_an_explicit_502` | a backend whose TLS port is closed produces an explicit `502` and counts a connect failure | pass |

Unit tests in `eqproxy-net/src/grpc.rs` — **4 passed**: content-type detection
(`application/grpc`, `+proto`, `+json`; `grpc-web` and `text/plain` excluded),
outbound request carries `te: trailers` and no h1 framing, keeps a declared
`content-length` only, and refuses a missing authority.

### 4.2 Real `grpcio` through the release binary

`python3 scripts/evidence/v07-grpc/run.py --long-seconds 0` and
`... --long-seconds 360 --long-interval 20` — both **PASS**.

The origin is a genuine `grpcio` TLS server (ALPN h2, self-signed fixture
certificate); the client is `grpcio` over **h2c** to the release binary, which
talks TLS/h2 to the origin (`alpn = ["h2"]`, `ca_file`, `server_name =
"localhost"`, `forwarded_headers = "append"`, `idle_timeout = 120s`).

| Journey | Observable result |
|---|---|
| `bidi` | first echo in **0.060 s** while the stream was open (`grpc-python/1.66.1 grpc-c/43.0.0`), second echo, then `grpc-status: OK`; origin metadata: `x-forwarded-for: 127.0.0.1`, `x-forwarded-proto: http` |
| `bulk` | 262 144 bytes echoed, byte-identical, `grpc-status: OK` |
| `status` | a unary `context.abort(NOT_FOUND, "no such item")` reaches the client as `NOT_FOUND` with the same details (status passed through trailers) |
| `long` | **360.0 s / 6 min**, 18 messages one every 20 s, slowest round trip **0.020 s**, `grpc-status: OK` — the Q5 journey (> 5 min) |

Raw output: [`v07-grpc/long-360s.txt`](v07-grpc/long-360s.txt) (the `quick.txt`
run has the same three first journeys without the long one).

## 5. Test suite

- `cargo fmt --all -- --check` → clean.
- `cargo clippy --workspace --all-targets -- -D warnings` → clean.
- `cargo test --workspace` → **396 passed, 0 failed** (up from 384: 4 unit and
  8 dataplane E2E tests). The two Docker-gated harnesses remain ignored as
  before.

## 6. Error and boundary cases

- Non-gRPC, `grpc-web`, non-`POST`, `CONNECT`, redirect/direct rules and a
  backend without `h2` keep the h1 translation (no half-broken pass-through).
- No server / full queue / expired queue → `503` (honoring `local_response`);
  a failed connect → `502`; both before any stream is opened.
- No response HEADERS within `server_header_timeout` (or the total cap) →
  `504` and `header_timeouts`.
- Silent stream → `idle_timeout`, counted and reset; running stream past
  `max_stream_duration` → `grpc-status: 4` trailers.
- Client request direction fails → the client stream is cancelled; the
  backend request stream is dropped (RST_STREAM) rather than left half-open.
- A trailers-only backend answer ends the client stream without DATA.

## 7. Verification tooling

- **Rust Audit** (`python3.13 scripts/rust_audit.py scan /Volumes/Lexar/Cursor/EQProxy
  --format terminal,md,json,sarif --fail-on high`): **exit 1**, 230 findings
  (2 critical, 24 high, 164 medium, 40 low), report
  `report/rust-audit-20261023-005204.json` in the tool clone. Diagnosis of the
  critical/high ones on this increment: `thiserror = "2"` is a published
  major and the workspace compiles against it; `eqproxy_core` is a workspace
  crate, not a registry dependency; the `default_*` functions are serde
  defaults (constants by definition); `h2`/`http`/`md-5` are the crates the
  project already builds on; the `let _ =` in `grpc.rs` are deliberate
  best-effort answers on an already-ending stream; `session_for` awaits a
  `tokio::sync::Mutex`, not a std guard. The tool also reported an
  **untracked file that is not part of this increment**,
  `eqproxy-net/src/codegraph_daemon_probe2.rs` (created by another agent in
  the shared checkout; not referenced by `lib.rs`, not committed).
- **EvoForge** `mcp_submit_eval` on the gRPC content-type gate (host
  `cargo test --workspace` ran first: 396 passed): `fitness_score: 1.0`,
  `compiles: true`, `tests_pass: true`, 2 tests executed in the sandbox
  (`trace_id 5f5172e3-25ec-4ccd-a9af-ef6bd78393b8`). The first attempt used
  `http::HeaderMap` and failed to compile because the sandbox has no `http`
  crate (0 tests, F=0); the second uses a local header slice and the exact
  MIME predicate from `grpc.rs`.
- **Veyra Proof**: `veyra audit . --profile standard` → **ACCEPTED**, exit 0,
  evidence in `.veyra/evidence/20261022T223646Z/` (`report.md`,
  `report.json`, per-tool logs). 11 tools OK (rustfmt, cargo check, clippy,
  cargo test, cargo-audit, anti-theater, nextest, llvm-cov, deny, machete,
  veyra-e2e); `cargo-geiger` reported **INCONCLUSIVE** (4 runs with coverage
  warnings, unsafe counts are a lower bound, not a pass); `dylint` and
  `cargo-semver-checks` were **skipped** (no Dylint configuration; no
  registry baseline for unpublished crates), exactly as the report states.
  A first attempt hit the 10-minute command cap before writing a verdict;
  that attempt is not cited as evidence.

## 8. Limits and NOT EXECUTED

- **24-hour soak**: **PASS**, closed 2026-10-23T23:09:55Z by the harness.
  The run started on 2026-10-22T23:09:36Z against this same binary and
  completed the full 86 400.0 s: 4 267 messages, **0 broken streams**, 1 420
  probes with **0 failures**, final `grpc-status: OK`, one backend h2 session
  (`opened=1`, `reused`=1 420), proxy RSS 3 568 KiB at the end and
  `grpc[errors=0]` in every metric snapshot. Raw evidence, the gate criterion
  and the limits of what this proves are in
  [v07-grpc-soak-24h.md](v07-grpc-soak-24h.md).
- Docker image and Docker Scout on both architectures: **NOT EXECUTED** (no
  release build for this slice).
- S-H2/S-H3 scenarios against HAProxy 3.4.6: **NOT EXECUTED** (still open in
  the version gate).
- Response compression and request mirroring do not apply to gRPC streams
  (documented in ADR-0011 and SPEC §13 item 13).
- Throughput/latency of gRPC is not measured: the numbers above are
  correctness observations from one loopback host, not performance claims.
- The binary hash is from the working tree; the increment was not committed
  when the runs were recorded.
