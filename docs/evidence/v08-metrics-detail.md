# CE4 — per-server and per-route metrics, opt-in and budgeted (v0.8)

Language: **English**.

**Increment:** roadmap v0.8, CE4 — \"useful metrics without a cardinality
explosion: per-server/per-route stats **opt-in** with an explicit budget\"
(Envoy #21685 / #3351). Decision: [ADR-0026](../adr/0026-opt-in-detail-metrics-budget.md).

**Binary under test:** `target/release/eqproxy`, `eqproxy 0.7.0`,
sha256 `4dcac3f9a3abf9a1274ef8cd3473800c891ba40614e2d46214f740a11d0094ad`
(built from the delivered tree: `cargo build --release -p eqproxy-cli`).
**Host:** macOS arm64 (Darwin), `python3` 3.13. **Date:** 2026-10-25.

## What the increment does

`[metrics]` had a `detailed` flag since the admin plane landed, but nothing
behind it: the status JSON reported the boolean and `/metrics` never carried a
labelled series. CE4 makes the flag real and puts a number on it:

```toml
[metrics]
detailed = true     # default false: one relaxed load, no allocation
max_series = 128    # default 128, validated 1..=4096
```

- Every completed exchange is attributed — once, where
  `http_requests_proxied` moves — to `(backend, server)` and, when a rule
  matched, to `(listener, route)`:
  `eqproxy_server_requests_total`, `eqproxy_server_errors_total` (5xx from
  that server) and `eqproxy_route_requests_total`. Traffic on the default
  backend has no rule label: no `route=""` pseudo-series is invented.
- `max_series` counts leaves across both families. A series that would exceed
  it is refused and the observation is counted in
  `eqproxy_metrics_detail_dropped_total`; an existing series keeps counting.
- Four label-free series describe the budget in every scrape:
  `eqproxy_metrics_detail_enabled`, `_series`, `_budget`, `_dropped_total`.
- `detailed` moves on `SIGHUP` (enabling starts an empty window, disabling
  drops it); `max_series` is fixed at startup and a reload that changes it
  warns and keeps the live budget.
- `GET /api/v1/status` carries the same rows under `metrics_detail`.

## E2E journey (real binary, real origins, real admin plane)

Harness (local-only, `scripts/` is excluded from the repository):
`scripts/evidence/v08-metrics-detail/journey.py`. It starts the release
binary, reads the two ephemeral ports from its log, drives real HTTP through
the proxy to two real origins (one `200`, one `500`), and checks `/metrics`
and `/api/v1/status` over the authenticated admin endpoint.

```console
$ cargo build --release -p eqproxy-cli
$ shasum -a 256 target/release/eqproxy
4dcac3f9a3abf9a1274ef8cd3473800c891ba40614e2d46214f740a11d0094ad  target/release/eqproxy
$ python3 scripts/evidence/v08-metrics-detail/journey.py
binary: /Volumes/Lexar/Cursor/EQProxy/target/release/eqproxy
version: eqproxy 0.7.0
phase A: dataplane 127.0.0.1:65080 · admin 127.0.0.1:65081

$ phase 0: default configuration (no [metrics]): detail off
PASS proxied before enabling: 3.0
PASS detail enabled (default): 0.0
PASS detail series (default): 0.0
PASS detail budget (default): 128.0
PASS detail dropped (default): 0.0
PASS no server family while off: False
PASS no route family while off: False
PASS status says off: False
PASS status has no rows: 0

$ SIGHUP with [metrics] detailed = true
PASS reload committed: v2
PASS status says on: True
PASS status budget: 128

$ phase 1: three /alpha and two /boom after enabling
PASS /alpha status: True ×3 · PASS /boom status: True ×2
PASS alpha server requests: 3.0     PASS alpha server errors: 0.0
PASS boom server requests: 2.0      PASS boom server errors (5xx split): 2.0
PASS route alpha requests: 3.0      PASS route boom requests: 2.0
PASS detail series (4 expected): 4.0
PASS detail dropped with room: 0.0
PASS global counter saw every exchange: 8.0
PASS no route label invented for default traffic: False
PASS status rows: 4
PASS status rows name the servers and the rules:
     [('route','alpha'),('route','boom'),('server','127.0.0.1:65078'),('server','127.0.0.1:65079')]
PASS status row errors: 2

$ SIGHUP with detailed = false (hot disable drops the window)
PASS status says off after disable: False
PASS series dropped on disable: 0
PASS enabled series after disable: 0.0
PASS no labelled family after disable: False
PASS the global counter keeps counting: 8.0
PASS clean shutdown exit code: 0
PASS the enable/disable pair is logged: True
PASS no secret in the log: True

phase B: budget 2 · dataplane 127.0.0.1:65113 · admin 127.0.0.1:65114
$ phase 3: three /alpha across two servers = three series, budget 2
PASS /alpha status: True ×3
PASS budget is the configured one: 2.0
PASS series capped at the budget: 2.0
PASS one observation refused: 1.0
PASS exactly one server series fits: 1
PASS the fitting series kept counting: 2.0
PASS route series fits and sees every exchange: 3.0
PASS global counter is not bounded by the budget: 3.0
PASS status reports the refusal: 1
PASS status reports the live budget: 2
PASS clean shutdown exit code: 0
PASS no secret in the log: True

RESULT: all assertions passed        # 52 assertions, exit 0
```

Raw capture: [`raw/journey.txt`](v08-metrics-detail/raw/journey.txt).
The scrape it asserted, captured in that same run, is
[`raw/metrics-on.txt`](v08-metrics-detail/raw/metrics-on.txt):

```
eqproxy_metrics_detail_enabled 1
eqproxy_metrics_detail_series 4
eqproxy_metrics_detail_budget 128
eqproxy_metrics_detail_dropped_total 0
eqproxy_server_requests_total{backend="api",server="127.0.0.1:65078"} 3
eqproxy_server_requests_total{backend="errors",server="127.0.0.1:65079"} 2
eqproxy_route_requests_total{listener="web",route="alpha"} 3
eqproxy_route_requests_total{listener="web",route="boom"} 2
```

and the JSON API rows it compared against:
[`raw/status-on.json`](v08-metrics-detail/raw/status-on.json).

### Control run (the journey is not green by construction)

With one injected early return in `DetailMetrics::record` (so
`detailed = true` measures nothing), the same journey fails 16 assertions and
exits 1 — `alpha server requests: expected [3.0], got [None]`, no series, no
rows. The injection was reverted; the delivered binary rebuilt **byte for
byte** to `4dcac3f9…` and the journey passed 52/52 again.
Raw: [`raw/control-run.txt`](v08-metrics-detail/raw/control-run.txt).

## Unit / contract tests

```console
$ cargo fmt --all -- --check          → ok
$ cargo clippy --workspace --all-targets -- -D warnings → exit 0
$ cargo test --workspace              → 29 binaries, 499 passed, 0 failed
```

Raw: [`raw/full-suite.txt`](v08-metrics-detail/raw/full-suite.txt). New tests:

| Test | Asserts |
|---|---|
| `eqproxy-core` `detail_is_opt_in_and_counts_nothing_while_disabled` | default off; no rows; `enabled 0`; no labelled family |
| `detail_series_carry_their_counts` | requests, 5xx split, route key/scope, exact exposition lines |
| `detail_budget_refuses_and_counts_new_series` | budget 2 with a third series refused twice; existing series keeps counting; `dropped_total 3` |
| `detail_disable_drops_the_window` | disable clears; recording while off is a no-op; re-enable starts empty |
| `detail_labels_are_escaped` | `"` and `\` in a rule name produce a parseable sample |
| `metrics_series_budget_is_validated_not_clamped` | default 128; `1`/`4096` accepted; `0`/`4097` rejected naming `metrics.max_series` |
| admin `metrics_are_prometheus_text_with_bounded_cardinality` (extended) | the four accounting series exist while detail is off and no labelled line does |
| admin `detail_series_and_their_budget_are_exported_when_enabled` | labelled families, 5xx split, `series` gauge and the same rows in `metrics_detail` |
| `eqproxy.schema.json` drift gate | regenerated schema is committed |

## Audits (the four legs)

| Leg | Command | Result |
|---|---|---|
| 1. Veyra Proof | `veyra audit . --profile standard` | **ACCEPTED**, exit 0, `.veyra/evidence/20261025T202724Z/` (500 s). `cargo-test` 29 binaries / 499 passed / 0 failed, `cargo-nextest` OK, `llvm-cov` 89.35 % lines (31 408 lines, 3 344 missed), `deny`/`machete`/`audit` OK. INCONCLUSIVE `cargo-geiger` (coverage warnings in 4 runs). SKIPPED `dylint` (no configuration) and `cargo-semver-checks` (no published baseline) |
| 2. Rust Audit | `python3.13 …/rust_audit.py scan . --format md --out report --fail-on high` (0.2.7) | exit 0: **0 critical, 0 high, 222 medium, 73 low** (`report/rust-audit-20261025-212110.md`, local-only). The increment adds **seven `R02` low** findings, all bare numeric literals in the new test assertions — the same idiom the rest of the suite uses — and none in production code. A first scan of the slice (21:19) showed 236 medium because the new renderer used `let _ = writeln!(…)`; it was rewritten with `push_str(&format!(…))` and the 14 `R10` findings disappeared. The eight `R10` still reported at `metrics.rs:611-627` are the pre-existing `MetricsSnapshot::prometheus` |
| 3. CodeGraph Rust | `codegraph-rust index . --batch-size 16 --stats-json /tmp/cg-ce4.json`, then `agent impact` on `DetailMetrics::record` and `agent context` on where a route is counted/exported | First attempt failed (`Transaction write conflict` in the key-value store, exit 1); the retry succeeded: 59 files, 56 237 lines, **6 341 nodes, 11 336 edges**, `graph_complete: true`, `vector_index_ready: true`, `errors: 0`, 67.6 s. Both answers' spans were checked in the source: `record` `metrics.rs:416`, wrappers `:404`/`:412`, `record_detail` `grpc.rs:653` with its three call sites `:336/:359/:372`, the status wire-up `admin.rs:1349`, the route `format!` `metrics.rs:248`. The model also declared its own bad edges (a `put_server_state` closure named `record`, `read_v1` in `proxy_proto.rs`) and its gap (it could not see the `/metrics` assembler), and its note that `http2.rs`/`http3.rs` do not call the counter directly is correct: both delegate to `serve_http` |
| 4. Hindsight | `hindsight-note --title … --project EQProxy --tags v0.8,ce4,metrics,prometheus,admin` | stored, exit 0 (bank `eqproxy`) |

## Limits (NOT EXECUTED / pending)

- **One platform:** macOS arm64 only. Nothing in the registry is
  platform-specific, but it was not run on Linux/amd64.
- **No Docker/Scout** rebuild in this increment, and no re-pull of a published
  image: CE4 is not part of a release cut yet.
- **Per-server WebSocket/CONNECT tunnels are not attributed:** the tunnel
  branch leaves the h1 engine before the completion point that moves
  `http_requests_proxied`, so `sum(server requests)` equals the proxied
  exchanges and **not** tunnels. The journey proves the accounting for **h1
  only**: h2 and h3 are driven through the same engine and the same completion
  point, but this increment adds no detail assertion to their tests, so their
  attribution is code-level, not measured. gRPC is attributed at its own
  completion sites; no Rust E2E asserts per-server gRPC counts in this slice
  (only the shared path is compiled and exercised by its existing tests), and
  WebSocket has no attribution to test.
- **Latency histograms and per-route bytes** are not part of this slice
  (ADR-0026, pending).
- The budget is **fixed at startup**; changing `max_series` on a reload warns
  and keeps the live budget. Shrinking under live series is deliberately not
  implemented.
