# v0.7 slice 3 — HTTP/2 backend multiplexing

Language: **English**. Evidence for the third v0.7 increment, collected on
2026-10-22 (macOS 26 arm64 host, `rustc 1.97.1`, curl 8.7.1 with nghttp2
1.68.1, hyper-h2 4.2.0 on Python 3.9.6). Unreleased: it lands on top of
v0.6.3, after [slice 1](v07-http2.md) and [slice 2](v07-http2-backend.md).

## 1. Objective

An `h2` backend kept the engine's exclusive pool, so one session served one
exchange at a time — the multiplexing that justifies HTTP/2 upstream was not
used (`B-H1`/`B-N1`/`B-I1`/`B-E2`, the `http2_protocol_options` part). This
slice makes concurrent exchanges share one backend session. It also fixes a
keep-alive defect found while verifying it: an idle connection was closed at
`client_header_timeout` (default 5 s) although `idle_timeout` (default 60 s)
is the documented inactivity window.

Not covered: gRPC (`B-I12`), WebSockets over h2 (`B-I18`), HTTP/3 (`B-H2`),
compression (`B-H6`), h2c to the backend, and any throughput or latency
figure.

## 2. Artifact under test

| Item | Value |
|---|---|
| Commit | `758c9e7` (`feat(net): multiplex backend HTTP/2 exchanges on one session`) |
| Binary | `target/release/eqproxy` rebuilt from that commit after the journeys, sha256 `4be880ec88030c537bbe483987a15fa19288dbdb3ae3642dae243e7791cbd438` — byte-identical to the binary the journeys ran on (`cargo build --release -p eqproxy-cli`; the commit was amended only to refactor a test, which does not change the binary) |
| Toolchain | `rustc 1.97.1`, cargo 1.97.1 |
| New dependencies | none: `h2 0.4.20`, `hyper-h2 4.2.0` (test origin) were already in the graph/used by slice 2 |
| Design | [ADR-0008](../adr/0008-http2-backend-multiplexing.md) (supersedes ADR-0007 §pooling) |

## 3. Changes

| File | Change |
|---|---|
| `eqproxy-net/src/backend_h2.rs` | `Hub` gains a per-address connect gate (`connect_gate`) and keeps the live-session map; `connect` installs the session and its connection task marks it dead and removes it; `open` builds one bounded 64 KiB pipe per exchange and spawns the h1⇄h2 relay for it |
| `eqproxy-net/src/proxy.rs` | `ResolvedBackend.h2` (created when the backend TLS offers `h2`), `open_h2_exchange` (fast path on a live session, single-flight handshake on a cold one, `stream_on_session`), `Transport` (dial result before splitting), `BackendConn.poolable`, `DialTimeouts.http` (only an `http` listener multiplexes) |
| `eqproxy-net/src/http1.rs` | the pool check-in is skipped for a non-poolable connection (an h2 exchange's pipe); keep-alive waits use `idle_timeout` and count `idle_timeouts` instead of `header_timeouts` |
| `eqproxy-net/src/tls.rs` | `ClientTls.alpn`: the configured ALPN list, so `with_tls` knows whether the backend opted into h2 |
| `eqproxy-net/src/mirror.rs` | mirror dials pass `http: true` (a mirror to an h2 backend is h2) |
| `eqproxy-net/tests/e2e_backend_h2.rs` | 3 new journeys: `concurrent_exchanges_multiplex_one_backend_session`, `a_dead_session_is_replaced_by_a_fresh_one`, `a_tcp_listener_relays_bytes_even_when_the_backend_negotiates_h2` |
| `eqproxy-net/tests/e2e_http1.rs` | `keepalive_wait_is_bounded_by_idle_timeout_not_the_header_one` |
| `docs/adr/0007-…`, `docs/adr/0008-…` | ADR-0007 marked superseded in part; ADR-0008 records the hub, the gate and the explicit limits |

## 4. End-to-end journeys against the built binary

Origin: `python3 /tmp/h2mux/origin.py …` — an **independent** implementation
(hyper-h2 4.2.0 over a real TLS socket, ALPN `h2`), not a mock and not the
Rust `h2` crate. It records every stream (connection id, stream id, path,
`x-req`) as JSONL and offers `/hold?ms=N` (sleeps inside the handler, logging
its start and end) and `/sessions`.

`config validate` on both configurations used below:

```
config OK: 1 listener(s), 1 backend(s) in eqproxy.toml         # http listener
config OK: 1 listener(s), 1 backend(s) in eqproxy-h2.toml      # h2/TLS listener
```

### 4.1 HTTP/1.1 client → HTTP/2 backend (plaintext listener `127.0.0.1:28082`)

Four concurrent `curl --http1.1` requests, each to `/hold?ms=1200`:

```
warmup(http=1) status=200 time=0.053371 body=7B        # GET /echo → "ok:warm"
--- four concurrent /hold?ms=1200 ---
req=four  status=200 client_time=1.203480s
req=one   status=200 client_time=1.204027s
req=two   status=200 client_time=1.207255s
req=three status=200 client_time=1.210307s
wall_seconds=1.294
req=one body=ok:one   req=two body=ok:two
req=three body=ok:three   req=four body=ok:four

GET /sessions → {"sessions": 1, "streams": 6}
```

Origin log (trimmed to the identifying fields):

```
{"session_opened": 1}
{"t": 1792679580.34,  "connection": 1, "stream": 1,  "path": "/echo",         "x_req": "warm"}
{"t": 1792679580.451, "connection": 1, "stream": 3,  "path": "/hold?ms=1200", "x_req": "three"}
{"t": 1792679580.452, "connection": 1, "stream": 7,  "path": "/hold?ms=1200", "x_req": "two"}
{"t": 1792679580.452, "connection": 1, "stream": 5,  "path": "/hold?ms=1200", "x_req": "one"}
{"t": 1792679580.453, "connection": 1, "stream": 9,  "path": "/hold?ms=1200", "x_req": "four"}
… end events at 1792679581.653–659, held_ms 1200
{"t": 1792679581.83,  "connection": 1, "stream": 11, "path": "/sessions"}
```

Four holds start within **1 ms** of each other and end ~1.2 s later: if the
proxy serialized upstream exchanges, the last would finish at ≥ 4.8 s. All six
streams landed on **one** connection (`connection: 1`), with odd, monotonic
h2 stream ids.

Final METRICS from the proxy's clean SIGINT shutdown:

```
METRICS client[accepted=6 active=0 completed=6 …] network[… bytes_b2c=63]
backend[connect_failures=0 tls_failures=0 discarded=0 reused=5 opened=1 proxied=6]
phases[header_timeouts=0] …
shutdown complete
```

`opened=1 reused=5 proxied=6` is the multiplexing contract: one TLS+h2 session
for six exchanges, five of them streams on it, no connect failure.

### 4.2 HTTP/2 client → HTTP/2 backend (h2/TLS listener `127.0.0.1:28083`)

The same journey with `curl --http2` against a TLS listener that offers only
`h2`, so HTTP/2 runs end to end:

```
h2 warmup version=2 status=200 time=0.088758       # GET /echo → "ok:h2warm"
--- four concurrent h2 /hold?ms=1200 ---
req=h3 version=2 status=200 client_time=1.217505s
req=h1 version=2 status=200 client_time=1.217697s
req=h2 version=2 status=200 client_time=1.218359s
req=h4 version=2 status=200 client_time=1.218292s
wall_seconds=1.291

origin: {"session_opened": 1}
        streams 1 (/echo), 3 (h3), 5 (h1), 7 (h2), 9 (h4), all "connection": 1
        starts 1792679632.213–215, ends 1792679633.423–425 (held_ms 1200)

METRICS client[accepted=5 active=0 completed=5 …]
backend[connect_failures=0 tls_failures=0 discarded=0 reused=4 opened=1 proxied=5] (final)
```

### 4.3 Session death and replacement

With the plaintext listener: serve one request, kill the origin process, send
another, restart the origin, send a third.

```
1) first: 200
2) origin killed
3) during outage: 502
5) after restart: 200 body=ok:after

origin log (two origin processes, each numbering its own session from 1):
{"session_opened": 1}
{"connection": 1, "stream": 1, "path": "/echo", "x_req": "first"}
{"session_opened": 1}
{"connection": 1, "stream": 1, "path": "/echo", "x_req": "after"}

proxy log:
WARN  [web] HTTP/2 backend connection failed: peer closed connection without sending TLS close_notify …
ERROR [web] could not connect to 127.0.0.1:28444 (peer …): Connection refused (os error 61)
METRICS client[accepted=3 completed=3 …] backend[connect_failures=1 … opened=2 proxied=2] (final)
```

A stale session is not retried in a loop: one failed dial during the outage
(`connect_failures=1`), exactly one replacement session after the restart
(`opened=2`), and both served requests delivered once.

## 5. Dataplane E2E (real sockets, real h2 servers)

`cargo test -p eqproxy-net --test e2e_backend_h2` → **10 passed** (10.16 s).
The three new journeys:

| Test | What it demonstrates |
|---|---|
| `concurrent_exchanges_multiplex_one_backend_session` | Two clients send `/barrier` at once; the origin only answers when **two streams are inside it simultaneously**, so a proxy that queues the second exchange never finishes. Both complete, `origin.connections == 1` (one accepted backend TCP connection) and both requests reached the backend as `HTTP_2`. This test failed with 2 accepted connections before the connect gate existed — the gate is the fix, not a hypothesis. |
| `a_dead_session_is_replaced_by_a_fresh_one` | A one-shot h2 origin serves one stream and hangs up. The next requests are retried until served (attempts are bounded by a timeout, no fixed sleeps); exactly one replacement session is dialed, and the origin saw **2** requests in total, so the `502` that races the death delivered nothing twice. |
| `a_tcp_listener_relays_bytes_even_when_the_backend_negotiates_h2` | `mode = "tcp"` with a backend whose TLS selects `h2`: the raw bytes are echoed unchanged (the ALPN is recorded as `h2` by the origin), proving a tunnel never becomes a protocol proxy. |

The two older journeys still cover translation (`h1→h2`, `h2→h2`, trailers,
`HEAD`, `CONNECT` refusal, failed ALPN), and
`consecutive_exchanges_share_one_backend_session` (renamed from
`one_pooled_h2_session_serves_consecutive_requests`: the pipe is no longer
pooled) asserts that consecutive exchanges still use **one** session.

Unit tests: `cargo test -p eqproxy-net --lib backend_h2` → **4 passed**.

Keep-alive fix: `cargo test -p eqproxy-net --test e2e_http1` → **17 passed**
(2.12 s), including
`keepalive_wait_is_bounded_by_idle_timeout_not_the_header_one` (header phase
150 ms, inactivity 1200 ms: a connection idle 450 ms serves the next request;
past 1200 ms it closes with `header_timeouts = 0`, `idle_timeouts = 1`). The
CLI E2E that holds a keep-alive connection across a hot-map swap (the test
that exposed the defect) now passes deterministically — it failed 3/3 under
load before the fix and passes 5/5 after it.

## 6. Suite, format and lints

| Check | Command | Result |
|---|---|---|
| Format | `cargo fmt --all --check` | exit 0 |
| Lints | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | exit 0 |
| Tests | `cargo test --workspace` | **365 passed, 0 failed**, 25 result lines, exit 0 (`/tmp/h2mux/final-tests.log`, run at HEAD `758c9e7`) |

Suite arithmetic: 361 (slice 2) + 3 new backend-h2 journeys + 1 keep-alive
journey = **365**. The two `0 passed; 1 ignored` lines are the miri-gated
suites, unchanged.

## 7. Audits

- **Veyra Proof**: `veyra audit . --profile standard` → **ACCEPTED**,
  exit **0**, `.veyra/evidence/20261022T144256Z/manifest.json`
  (`decision.exit_code = 0`, "All required profile tools executed without
  blocking findings"), 448 s wall. OK: `rustfmt`, `cargo check`, `clippy`,
  `cargo test`, `cargo-audit`, `veyra-anti-theater`, `cargo-nextest`,
  `cargo-llvm-cov`, `cargo-deny`, `cargo-machete`, `veyra-e2e`. **No
  problems.** Not executed, reported as such: `dylint` (no configuration) and
  `cargo-semver-checks` (no registry baseline for unpublished crates).
  `cargo-geiger` **INCONCLUSIVE** (coverage warnings in 4 runs): unsafe counts
  are a lower bound, not a pass.
- **Rust Audit**: `python3.13 scripts/rust_audit.py scan <repo>
  --format terminal,json,md --fail-on high` → exit **1**, **202 findings**
  (2 critical, 21 high, 145 medium, 34 low); reports
  `report/rust-audit-20261022-165413.{md,json}` and
  `report/not-executed-2026-10-22.md`. Findings that touch this increment,
  all reviewed:
  - `R18c high` ×2 on `backend_h2.rs` (`h2` "near-miss of `cc`", `http`
    "near-miss of `tap`"): false positives — both crates are real, already in
    the graph since slice 1.
  - `R16 high` on `open_h2_exchange`: claims a synchronous mutex guard is
    held across `.await`. The gate is a `tokio::sync::Mutex` whose guard is
    designed to be held across `await`; the only `std::sync::Mutex` guards in
    that path (`Hub::lookup`, `Hub::connect_gate`,
    `Hub::forget`) are acquired and released inside those functions, so none
    is alive across an `await`. False positive.
  - `R02 low` on the new tests (magic numbers): status codes and stream
    counts are the contract under test.
  - The critical findings are pre-existing heuristics (`thiserror = "2"`
    "impossible"; the three workspace crates "not on crates.io" — they are
    path dependencies), unchanged from the slice-2 audit.
  - One finding was real and fixed before the report above: `R08 medium`
    "wall-clock read in test" on the new session-replacement test. The test
    now wraps its retry loop and its wait in `tokio::time::timeout` instead of
    reading `Instant::now()`; `R08` went from 67 to 66 findings and the one
    left in `e2e_http1` is pre-existing (a `max_stream_duration` test).
- **EvoForge**: `mcp_submit_eval` after the host suite passed, on a std-only
  condensed replica of the `Hub` (install, dead entry removed on lookup, a
  stale session cannot evict its replacement, one handshake gate per server)
  with three tests → `fitness_score 1.0`, `tests_pass true`,
  `clippy_pass true`, exit 0, trace `a7af4259-12ea-4f05-86c9-d6cbb686ec7e`
  (3 tests ran; the sandbox log shows them). The first submission was refused
  by the sandbox deny pattern `\bstd\s*::\s*net\b` (the replica used
  `SocketAddr`); the resubmission uses a `u16` key, which is the same
  addressing semantics without the import. The slice is a replica for the
  sandbox and is **not** a substitute for §4–§5.

## 8. Pending and limitations (not claimed)

- **No benchmark.** No throughput, latency, CPU or memory figure is measured
  or claimed for the multiplexed path. §4 shows overlap and session sharing,
  not performance.
- **No idle session close.** An unused backend keeps one TLS+h2 session open
  for the process lifetime; sessions are replaced on death, not on idleness.
- **A request that races a session death gets one `502`.** It sends nothing,
  so nothing is delivered twice, and the next request dials a fresh session.
- **No graceful GOAWAY drain.** The `h2` crate refuses new streams once a
  GOAWAY arrives and the hub replaces the session on the next exchange;
  in-flight streams across a GOAWAY are not drained or replayed.
- **Stream concurrency follows the peer's SETTINGS**; when the limit is
  reached the `h2` crate queues the stream. Queue depth and latency under a
  saturated session are not measured.
- **No h2c to the backend** and **no gRPC (`B-I12`)**, WebSockets over h2
  (`B-I18`), `CONNECT` to an h2 backend (refused with `502`) or HTTP/3.
- **No Docker image rebuild or container journey** for this slice: **NOT
  EXECUTED**. The image is rebuilt and exercised by the release workflow
  before any tag; this increment is unreleased.
- **No soak or interop matrix** beyond the Rust `h2` server, one Python
  `hyper-h2` origin and `curl`.

## 9. Reproduction

```bash
# unit + dataplane E2E
cargo test -p eqproxy-net --lib backend_h2
cargo test -p eqproxy-net --test e2e_backend_h2
cargo test -p eqproxy-net --test e2e_http1 keepalive_wait

# the binary journeys of §4
cargo build --release -p eqproxy-cli
python3 /tmp/h2mux/origin.py eqproxy-net/tests/fixtures/cert.pem \
  eqproxy-net/tests/fixtures/key.pem 28444 /tmp/h2mux/seen.jsonl &
./target/release/eqproxy config validate --config /tmp/h2mux/eqproxy.toml
./target/release/eqproxy run --config /tmp/h2mux/eqproxy.toml &
for n in one two three four; do
  curl -sS -H "x-req: $n" 'http://127.0.0.1:28082/hold?ms=1200' &
done; wait
# (SIGINT to the proxy; proxy.log holds the final METRICS line)
```
