# v0.8 — A finished drain is observable (ADR-0024, H3)

Language: **English**. Raw data: [`v08-drain-observability/raw/`](v08-drain-observability/raw/).

## What was proved

A drained server reports **how many exchanges are left** and **that the drain
finished**, with the finish recorded at the moment it happens instead of being
inferred from two polls:

- while one proxied exchange is held open on a `drain`ed slot,
  `GET /api/v1/status` reports `"state":"drain","active":1,"drained":false`,
  and `PUT …/state` answers the same pair;
- `/metrics` reports `eqproxy_backend_servers_draining 1` and
  `eqproxy_backend_drains_completed_total 0` while the drain is open;
- when that exchange ends, the same slot reads `"active":0,"drained":true`,
  the counter reaches `1`, and the process writes **one** line naming the
  slot: `INFO server drained: backend=api target=127.0.0.1:49586 active=0
  events=1`;
- a drained slot still takes no new exchange: the next request is `503`;
- a drain declared on an idle slot reads `"drained":true` immediately and
  produces **no** event line — nothing finished after it was declared.

Both new Prometheus series are label-free, so a scrape cannot grow the index
(CE4); the per-slot detail stays in the JSON status, whose budget is the
configured topology.

## Artifact and environment

- Release binary `target/release/eqproxy`, sha256
  `0e9be6be3c8da431e7bafd1349bf1a7550586432bed0120e70a9594c119043d7`
  (`raw/binary.sha256`), `eqproxy 0.7.0`, `file(1)`: *Mach-O 64-bit executable
  arm64*.
- Host: `Darwin arm64` (macOS 26.5.1), `rustc 1.97.1 (8bab26f4f 2026-07-14)`,
  `cargo 1.97.1`. Built with `cargo build --release --locked -p eqproxy-cli`.
- Journey harness: [`scripts/evidence/v08-drain-observability/journey.py`](../../scripts/evidence/v08-drain-observability/journey.py)
  (local-only, like every harness in `scripts/evidence/`). It starts the real
  binary through its public CLI, talks to the admin plane over TCP with real
  HTTP requests, and holds one exchange on a Python origin that reads the
  request head and waits for the release signal.
- Transcript: `raw/journey.log`.

## Commands and results

### Format and lint

```console
$ cargo fmt --all -- --check
(no output, exit 0)
$ cargo clippy --workspace --all-targets -- -D warnings
Finished `dev` profile [unoptimized + debuginfo] target(s) in 7.05s
(exit 0)
```

### Suite

```console
$ cargo test --workspace
...
29 test binaries: 485 → 488 tests, 0 failed, exit 0
```

The three new ones are the two balancer unit tests
(`drain_completion_is_counted_when_the_last_exchange_finishes`,
`drain_of_an_idle_slot_reports_finished_without_an_event`) and the E2E
`run_admin_plane_reports_drain_progress_and_completion`; the extended
`servers_view_reports_target_health_mode_and_in_flight`,
`status_reports_live_servers_and_the_live_counters` and
`metrics_are_prometheus_text_with_bounded_cardinality` assertions ride in the
existing tests.

### Journey against the release binary

```console
$ python3 scripts/evidence/v08-drain-observability/journey.py
binary: /Volumes/Lexar/Cursor/EQProxy/target/release/eqproxy
version: eqproxy 0.7.0
dataplane 127.0.0.1:49282 · admin 127.0.0.1:49283

$ client: GET /held through the proxy (origin holds the answer)
origin received the request head and is holding the exchange

$ before the drain: status and /metrics
PASS active exchanges before the drain: 1
PASS drained flag before the drain: False
PASS servers_draining before any drain: 0.0
PASS drains_completed_total before any drain: 0.0

$ PUT /api/v1/backends/api/servers/127.0.0.1:49281/state  {"state":"drain"}
PASS drain accepted: 200
{"active":1,"backend":"api","changed":true,"drained":false,"healthy":true,"previous":"ready","server":"127.0.0.1:49281","state":"drain"}
PASS PUT reports the in-flight exchange: 1
PASS PUT reports the drain as not finished: False
PASS status active after drain: 1
PASS status drained after drain: False
PASS servers_draining with the drain open: 1.0
PASS drains_completed_total with the drain open: 0.0

$ release the held exchange
PASS held exchange answered: True
PASS held exchange body: held-exchange
PASS active exchanges once the drain finished: 0
PASS drained flag once the drain finished: True
PASS servers_draining (finished drain, still declared): 1.0
PASS drains_completed_total (finished drain): 1.0

$ client: GET /after-drain (a drained slot takes no new exchange)
PASS drained slot answers 503: True

$ SIGINT
PASS clean shutdown exit code: 0
  INFO server drained: backend=api target=127.0.0.1:49586 active=0 events=1
PASS exactly one drain event line: 1
PASS the event names the slot and the count: True
PASS no secret in the log: True
PASS no ERROR/WARN line: []
RESULT: all assertions passed
(exit 0; 25 assertions)
```

The first run of this harness **failed**, and the failure was mine, not the
feature's: it asserted `eqproxy_backend_servers_draining 1` *before* declaring
the drain, where `0` is correct. The assertion moved to after the `PUT` and to
the finished state, and the run above is the accepted one. The rejected run is
not kept on disk (the transcript was overwritten); the correction is recorded
here because it explains the shape of the assertions.

### The journey is not green by construction

With the drain event disabled in the source (`let drained = false;` in the
in-flight guard, one line, no behaviour change anywhere else) the same journey
fails at the counter, and restoring it turns it green again
(`raw/control-event-disabled.log`, `raw/restored-after-control.log`):

```console
$ cargo test -p eqproxy-cli --test cli_e2e run_admin_plane_reports_drain_progress_and_completion
thread '...' panicked at eqproxy-cli/tests/cli_e2e.rs:6312:5:
assertion `left == right` failed: exactly one drain finished on that exchange
test result: FAILED. 0 passed; 1 failed
(exit 101)

# restored
test result: ok. 1 passed; 0 failed
(exit 0)
```

## Audits

| Leg | Tool and command | Result |
|---|---|---|
| 1. Veyra Proof | `veyra audit . --profile standard` | **ACCEPTED**, exit 0, `.veyra/evidence/20261025T163910Z/` (528.87 s of tool time). OK: `rustfmt`, `cargo-check`, `clippy`, `cargo-test` (**488 passed, 0 failed**), `audit`, `veya-anti-theater` (1 informational), `nextest`, `llvm-cov`, `deny`, `machete`, `veya-e2e` (**17/17 scenario(s)**). INCONCLUSIVE: `cargo-geiger` (coverage warnings in 4 runs: a lower bound, not a pass). SKIPPED: `dylint`, `semver-checks` |
| 2. Rust Audit | `python3.13 …/rust_audit.py scan . --format md --out report --fail-on high` (0.2.7, engine sha256 `84b5ba5b…`) | exit 0: **0 critical, 0 high, 219 medium, 66 low** (`report/rust-audit-20261025-173904.md`, local-only). The increment adds **five** findings, and every one is in a test: three `R08` (a `sleep` and two `Instant::now` reads in the E2E's bounded polling and in `Gate::wait_until_reached` — the same idiom the other sixty E2E journeys already use) and two `R02` (bare numeric literals in the new assertions). The new **production** code adds none. A first scan of the slice (17:37) reported 221/66 because `prometheus_body` used `let _ = writeln!(…)`; that was changed to `push_str(&format!(…))`, and the two `R10` findings on it disappeared |
| 3. CodeGraph Rust | `codegraph-rust index . --batch-size 16 --stats-json /tmp/cg-drain.json` (after the last edit), then `agent context` on where a drain ends, is counted and is exported | 59 files, 54 911 lines, **6 157 nodes, 11 211 edges**, `graph_complete: true`, `vector_index_ready: true`, `errors: 0`, 587 239 ms. The context answer named all three places correctly — `impl Drop for ActiveGuard` `balancer.rs:248`, the `fetch_add` and the event line `balancer.rs:265-275`, the accessor `:335`, `servers_view` `:365`, `prometheus_body` `admin.rs:1481`, the two series `admin.rs:1501-1503` — with two spans off by one or two lines (it said 249 for the drop and 1497 for the series) and it declared the gap it could not reach |
| 4. Hindsight | `hindsight-note --project EQProxy` | note stored, exit 0 |

## Limits of this run

- **One host, one architecture.** The journey ran on macOS arm64 only; the
  feature itself is portable (an atomic decrement in the drop guard plus a
  `eprintln!`), but no Linux run is claimed here.
- **One backend, one slot, one held exchange.** The assertions are exact for
  that shape; multiple simultaneous drains across backends (each producing its
  own event) are covered by the unit test, not by the journey.
- **The counter restarts on `SIGHUP`.** It lives in the `Balancer`, and a
  reload builds a fresh one (ADR-0024 records the same lifetime limit for the
  drain registry). The gauge has no such issue: it is derived from the live
  topology on every scrape.
- **`maintenance` is still not a state** and idle pooled connections on a
  drained server age out on their own timer, unchanged by this slice
  (ADR-0018's pending item).
- **No image or release gate was touched**, so Docker/Scout are unchanged and
  were not re-run for this slice.
