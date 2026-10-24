# v0.7 slice 4 — backend HTTP/2 session lifecycle

Language: **English**. Evidence for the fourth v0.7 increment, collected on
2026-10-22 (macOS 26 arm64 host, `rustc 1.97.1`, Python 3.14 + hyper-h2 4.2.0
for the independent origin, curl 8.7.1). Unreleased: it lands on top of
v0.6.3, after [slice 1](v07-http2.md), [slice 2](v07-http2-backend.md) and
[slice 3](v07-http2-multiplexing.md).

## 1. Objective

A shared backend session (slice 3) had no lifecycle: an unused backend kept
its TLS+h2 session for the process lifetime, a `GOAWAY` was only implicit in
the `h2` crate, and a request that raced the peer's shutdown failed with
`502` even when the peer had said it never processed the stream. This slice
gives the session the lifecycle its name implies — **idle close**, **GOAWAY
drain** and **safe refusal replay** — with the invariant that a request is
never run twice.

Not covered: a client-side GOAWAY (the h2 client API has none), replay of a
request whose body was already forwarded, gRPC, h2c to the backend, HTTP/3,
and any throughput or latency figure.

## 2. Artifact under test

| Item | Value |
|---|---|
| Commit | `34a5925` (`feat(net): close idle backend h2 sessions and replay refused streams`) |
| Binary | `target/release/eqproxy` from that commit, sha256 `fdbbbfe19bd590387e62475b60f2585b2ec552bb9269a6adb4841cebe3c8d439` |
| Toolchain | `rustc 1.97.1`, cargo 1.97.1 |
| New dependencies | none |
| Design | [ADR-0009](../adr/0009-http2-session-lifecycle.md) (supersedes ADR-0008 §Consequences) |

## 3. Changes

| File | Change |
|---|---|
| `eqproxy-net/src/backend_h2.rs` | `Session` state (`sender`, `active`, `last_idle`, `going_away`) under one lock; `ExchangeSlot` guard; per-address identity; idle monitor (window / 4, clamped 10 ms–500 ms) that closes an idle session and aborts its connection; `going_away`/`retire`; `SessionDialer` trait and `Exchange` replay loop (one retry, same request head, fresh session) |
| `eqproxy-net/src/proxy.rs` | `H2Dialer` owns what a fresh session needs (addresses, TLS client, PROXY mode, timeouts, metrics); `DialSpec` for `dial_transport`; `&Arc<Metrics>` through the dial path |
| `eqproxy-net/src/http2.rs` | `StreamError::Refused` (GOAWAY) and `StreamRefused` (`RST_STREAM(REFUSED_STREAM)`) |
| `eqproxy-core/src/metrics.rs` | `h2_sessions_idle_closed`, `h2_goaway_received`, `h2_refused_retried` and the `h2[...]` METRICS group |
| `eqproxy-net/tests/e2e_backend_h2.rs` | 3 new journeys; one-shot origin fixed to poll its connection while answering (see §5) |

## 4. End-to-end journeys against the built binary

Origin: the independent Python `hyper-h2` implementation (`/tmp/h2life/origin.py`,
hyper-h2 4.2.0 over real TLS, ALPN `h2`), extended with `/goaway`
(`close_connection(last_stream_id=this stream)`) and session open/close
records. Config: `mode = "http"`, `idle_timeout = "1s"`, backend
`alpn = ["h2"]`, `config validate` → `config OK: 1 listener(s), 1 backend(s)`.

### 4.1 Idle close and replacement

Two requests 2.2 s apart (the window is 1 s):

```
1) first:      ok:first
2) after-idle: ok:after-idle

origin log:
{"session_opened": 1}
{"t": …, "connection": 1, "stream": 1, "path": "/echo", "x_req": "first"}
{"session_closed": 1}
{"session_opened": 2}
{"t": …, "connection": 2, "stream": 1, "path": "/echo", "x_req": "after-idle"}
{"session_closed": 2}

proxy log:
INFO [web] closed an idle HTTP/2 session to 127.0.0.1:28454 after 1s
METRICS … backend[connect_failures=0 … reused=0 opened=2 proxied=2] …
        h2[sessions_idle_closed=1 goaway=0 refused_retried=0] (final)
```

One session per request: the first closed after the window (the origin sees
`session_closed: 1` before the second is opened), and the second was dialed
fresh. No connection was kept for the process lifetime.

### 4.2 GOAWAY and refusal replay

Warm request, a 1.2 s in-flight request, then `/goaway`; the next request is
sent while the drained session is still alive:

```
B1 warm:         ok:warm
B3 goaway:       ok:g1
B4 after-goaway: ok:after-goaway time=0.014643s
B2 in-flight:    502 time=1.006827s

origin log (trimmed):
{"session_opened": 1}
{"connection": 1, "stream": 1, "path": "/echo", "x_req": "warm"}
{"connection": 1, "stream": 3, "path": "/hold?ms=1200", "x_req": "inflight"}
{"connection": 1, "stream": 5, "path": "/goaway", "x_req": "g1"}
{"connection": 1, "goaway_sent": 5}
{"session_opened": 2}
{"connection": 2, "stream": 1, "path": "/echo", "x_req": "after-goaway"}
{"session_closed": 1}

proxy log:
WARN [web] backend 127.0.0.1:28454 is closing its HTTP/2 session (GOAWAY):
     in-flight streams drain, new exchanges dial a fresh session
METRICS … backend[connect_failures=0 … reused=3 opened=2 proxied=3] …
        h2[sessions_idle_closed=0 goaway=1 refused_retried=1] (final)
```

`after-goaway` was refused by the drained session and replayed on connection
2 (14.6 ms, one copy at the origin: a single request line for `x_req:
after-goaway`, on connection 2). The in-flight `/hold?ms=1200` answered `502` at 1.006 s
because it exceeds this test's `idle_timeout = 1s` per-operation bound — the
documented inactivity timeout, not a GOAWAY cut. The Python origin cannot
serve an accepted stream after `close_connection` either (hyper-h2 moves to
`CLOSED`), so a clean drain is demonstrated at the dataplane level (§5), not
by this origin.

## 5. Dataplane E2E (real sockets, real h2 server)

`cargo test -p eqproxy-net --test e2e_backend_h2` → **13 passed** (10.1 s).
The three new journeys:

| Test | What it demonstrates |
|---|---|
| `an_idle_session_is_closed_and_the_next_exchange_dials_again` | A `/drip` answer (five DATA frames 120 ms apart, 480 ms total) outlives the 300 ms window and still completes `200` on the same connection — the session is never closed under an admitted exchange. Afterwards the origin observes the connection end, `h2_sessions_idle_closed == 1`, and the next request opens a **second** session. |
| `a_goaway_drains_in_flight_streams_and_the_next_exchange_dials_a_fresh_one` | A real `h2::server::Connection::graceful_shutdown` announced while a `/slow` stream is being answered: that stream still returns `200 slow-done` (drain), the next exchange dials a fresh session (2 accepted connections) and `h2_goaway_received == 1`. |
| `a_stream_the_peer_refuses_is_replayed_once_on_a_fresh_session` | The origin serves one stream, then resets the next with `RST_STREAM(REFUSED_STREAM)` without reading or answering it: the client still gets `200`, exactly one copy of the request reaches the origin (with the same `x-replay` header), the replayed session is a second connection, `h2_refused_retried == 1` and `h2_goaway_received == 0`. |

### 5.1 A GOAWAY that races an admission (fixed after the first tag attempt)

The first v0.7.0 tag run failed this journey on Linux (`40060841889`, job
`Binaries linux`): `next.status` was `502` with
`WARN [web] HTTP/2 backend exchange ended: HTTP/2 protocol error`, and the
same failure had already happened on the previous `main` (`40046969558`), so
it was not caused by the release commit. It is timing-dependent: the suite
passed on macOS and failed on Linux.

Reproduced with the real suite in a Linux container, natively on arm64,
limited to 2 CPUs like a CI runner:

```bash
docker run --rm --platform linux/arm64 --cpus=2 -v "$PWD":/src -w /src \
  -u "$(id -u):$(id -g)" -e CARGO_TARGET_DIR=/tmp/eq-target \
  -v /tmp/eq-target-linux:/tmp/eq-target rust:1.97-bookworm \
  cargo test -p eqproxy-net --test e2e_backend_h2 \
  a_goaway_drains_in_flight_streams_and_the_next_exchange_dials_a_fresh_one
```

It failed in **0.10 s**, before any timeout. A temporary diagnostic on the
response-error path named the cause:

```text
DIAG response: eos=true remote=true goaway=false reset=true reason=Some(CANCEL) usable=true
```

The origin had sent `GOAWAY` (the test waits for that), but the proxy's next
bodiless request was admitted before the client library reported it, and the
peer answered that stream with `RST_STREAM(CANCEL)` rather than a GOAWAY
error. The old classifier replayed only `is_go_away()` or
`RST_STREAM(REFUSED_STREAM)`, so this reset became `StreamError::H2` and the
client saw a `502` — a real defect, not a flaky assertion: a request that
races a GOAWAY must not fail while nothing of it reached the origin.

The fix has two parts, both on the backend side:

1. `Session::enter` probes the h2 handle (`SendRequest::poll_ready`, which
   reports the stored GOAWAY) before admitting a stream, and retires the
   session when the peer already announced it. `hub.lookup` then dials a
   fresh session instead of handing out a draining one.
2. If the GOAWAY lands between the lookup and the admission, the exchange
   either finds the retired session (the proxy retries the open once on a
   fresh session) or loses the race on the wire; on that error path EQProxy
   probes the session again and, only for a request that carried **no body**,
   replays it once on a fresh session. A body-carrying request is never
   replayed, because it may have been processed.

Verification after the fix:

| Command | Result |
|---|---|
| Linux container, the single journey ×5 | **5/5 passed**, 0.6 s each (previously deterministic failure) |
| Linux container, whole `e2e_backend_h2` ×3 | **13/13 passed** each run, 11.4 s |
| Linux container, whole `eqproxy-net` suite | **all result lines ok**, 0 failed |
| macOS, whole `e2e_backend_h2` ×3 | **13/13 passed** each run, 10.1 s |
| macOS, `cargo test --workspace` | **424 passed, 0 failed**, 2 ignored, 28 suites |
| `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |

The journeys that carry a body (`trailers_and_chunked_bodies_cross_in_both_directions`,
the gRPC and WebSocket suites) stayed green, which is what the no-replay rule
protects.

The one-shot origin used by `a_dead_session_is_replaced_by_a_fresh_one` had a
latent bug that the new timing exposed: it answered **inline**, so the only
poller of its h2 connection was busy inside `RecvStream::data()` and could
not read a body that arrived in a later packet. The test failed ~30 % of the
time under CPU load (8 `yes` hogs, 1/5 runs) and always when the head and
body arrived separately. The origin now spawns the answer and keeps polling
the connection concurrently (as a real server does); the suite passed 8/8
under the same load afterwards. The product code was not changed for this:
the failure was in the test's fake server, and the test's assertions were
untouched.

## 6. Suite, format and lints

| Check | Command | Result |
|---|---|---|
| Format | `cargo fmt --all --check` | exit 0 |
| Lints | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | exit 0 |
| Tests | `cargo test --workspace` | **368 passed, 0 failed**, 25 result lines, exit 0 (`/tmp/h2life/tests.log`) |

Suite arithmetic: 365 (slice 3) + 3 new backend-h2 journeys = **368**.

## 7. Audits

- **Veyra Proof**: `veyra audit . --profile standard` on the delivered tree
  (code commit `34a5925` plus this slice's documentation on top of it) →
  **ACCEPTED**,
  exit **0**, `.veyra/evidence/20261022T182346Z/manifest.json`, 280.5 s;
  `rustfmt`, `cargo check`, `clippy`, `cargo test`, `cargo-audit`,
  `veyra-anti-theater`, `cargo-nextest`, `cargo-llvm-cov`, `cargo-deny`,
  `cargo-machete` and `veyra-e2e` all OK, no blocking findings.
  Not executed and reported as such: `dylint` (no configuration) and
  `cargo-semver-checks` (no registry baseline for unpublished crates).
  `cargo-geiger` **INCONCLUSIVE** (4 coverage warnings): unsafe counts are a
  lower bound, not a pass. An earlier run of the same tree reported the same
  verdict (`.veyra/evidence/20261022T181052Z`, 456.65 s); the first audit of
  this increment was **REJECTED** (`nextest-failure`) because it ran while the
  failing test-origin bug above was still in the tree, and the accepted run is
  the one cited.
- **Rust Audit**: `python3.13 scripts/rust_audit.py scan <repo>
  --format terminal,json,md --fail-on high` → exit **1**, **203 findings**
  (2 critical, 21 high, 145 medium, 35 low); reports
  `report/rust-audit-20261022-201109.{md,json}`. New findings against the
  previous slice: `R02 low` (magic status code in the new test — the contract
  under test) and one `R17` count increase on the test file (test
  infrastructure). Reviewed highs: `R18c`×2 (`h2`/`http` "near-miss" — real
  crates), `R16` on `open_h2_exchange` (claims a synchronous guard across
  `.await`; the only guard there is the async `tokio::sync::Mutex` gate, so
  false positive), `R09`×2 on `proxy.rs` (pre-existing `.expect`). An earlier
  `R11` on `std::ptr` was removed by design: the hub now compares a
  process-unique session id instead of a pointer. The two critical findings
  are the pre-existing heuristics (`thiserror = "2"` impossible; workspace
  crates absent from crates.io — they are path dependencies).
- **EvoForge**: `mcp_submit_eval` after `cargo test` passed, on a std-only
  condensed replica of the lifecycle (enter/retire atomicity, id-scoped
  `forget`, idle reap only with no exchange and past the window) with three
  tests → `fitness_score 1.0`, `tests_pass true`, `clippy_pass true`, exit 0,
  trace `8d1c250c-e10d-44f2-8b74-4ae15e312ef6` (3 tests ran in the sandbox).
  The first submissions failed the sandbox's `-D dead-code`/unwrap oracle
  until every item was public and locks used a poison-tolerant helper; those
  are sandbox constraints, and the slice is a replica, **not** a substitute
  for §4–§5.

## 8. Pending and limitations (not claimed)

- **No client-side GOAWAY on idle close.** `h2 0.4` exposes
  `go_away_gracefully` only for server connections, so an idle session ends
  the connection after its last stream instead of announcing it. Nothing is
  in flight at that point.
- **A refused stream with a request body is not replayed**: the body was
  consumed from the engine's pipe, and replaying it would need a buffer. It
  fails explicitly (no duplicate side effects).
- **A per-stream `REFUSED_STREAM` retires the whole session** (one fresh
  handshake) instead of retrying into the same refusal.
- **No benchmark**: the close and the replay add connections; no throughput
  or latency figure is measured or claimed.
- **No Docker image rebuild or container journey** for this slice: **NOT
  EXECUTED**. The release workflow rebuilds and exercises the image before
  any tag; this increment is unreleased.
- **No soak or interop matrix** beyond the Rust `h2` server, the Python
  `hyper-h2` origin and `curl`.

## 9. Reproduction

```bash
cargo test -p eqproxy-net --test e2e_backend_h2
cargo test --workspace

# binary journeys
cargo build --release -p eqproxy-cli
python3 /tmp/h2life/origin.py eqproxy-net/tests/fixtures/cert.pem \
  eqproxy-net/tests/fixtures/key.pem 28454 /tmp/h2life/seen-idle.jsonl &
./target/release/eqproxy config validate --config /tmp/h2life/eqproxy.toml
./target/release/eqproxy run --config /tmp/h2life/eqproxy.toml &
curl -sS -H 'x-req: first' http://127.0.0.1:28092/echo
sleep 2.2
curl -sS -H 'x-req: after-idle' http://127.0.0.1:28092/echo
# (SIGINT to the proxy; the final METRICS line carries the h2[...] group)
```
