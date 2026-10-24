# v0.7 slice 10 — backend idle-pool sizing and the S-H2-01/02 re-measurement

Language: **English**.

This closes the S-H2-01 defect the first H2 campaign found: at **400 streams in
flight** the keep-alive pool parked only 64 connections per server and
re-dialled the rest, opening **141 155** backend connections (192.85 per 1 000
requests) against HAProxy's 6 106 (1.22), exhausting the ephemeral port range
and answering **7 473 × `502`** — 0.099× HAProxy's throughput. The pool now
sizes its idle cap from the peak concurrency the balancer reports, and the
campaign below re-measures both scenarios on the same host with the new image.

## 1. What changed

| File | Change |
|---|---|
| `eqproxy-net/src/pool.rs` | `Pool::note_in_flight` records the peak exchanges in flight per server, called where a connection is borrowed (pool hit or fresh dial). `checkin` uses `clamp(peak, IDLE_FLOOR_PER_SERVER = 64, IDLE_CEILING_PER_SERVER = 4 096)`. `IDLE_FLOOR/CEILING` replace `MAX_IDLE_PER_SERVER`; 60 s expiry unchanged. |
| `eqproxy-net/src/balancer.rs` | `ActiveGuard::in_flight()` exposes the exchanges the B-H5 slot counts on the guarded server. |
| `eqproxy-net/src/proxy.rs` | Both borrow paths report the in-flight count to the pool (pool checkout and a successful dial; h2 pipes are not pooled and are skipped). |
| `eqproxy-net/tests/e2e_http2.rs` | New `pool_sizing_keeps_a_400_stream_burst_without_churn`: real h2 client (4 connections × 100 streams) against a real keep-alive h1 origin that holds every request while a wave is open, so the 400 exchanges are concurrent by construction and not by scheduling luck (`start_keepalive_origin(hold)`); two waves. |
| `docs/adr/0015-backend-idle-pool-sizing.md` | Decision, options and consequences. |
| `SPEC.md` §7.6 + project-state table, `CHANGELOG.md` | Documented behaviour. |

## 2. Tests

| Check | Command | Result |
|---|---|---|
| Pool unit tests | `cargo test -p eqproxy-net --lib pool` | **7 passed**: the existing roundtrip/floor/stale/pending-bytes/keying ones plus `idle_cap_follows_the_peak_in_flight` (400 in flight keeps 400) and `idle_cap_never_exceeds_the_ceiling` |
| Dataplane E2E | `cargo test -p eqproxy-net --test e2e_http2` | **7 passed**, including the new 400-stream test: wave 1 dials exactly **400** (empty pool), wave 2 dials **0**, reuses **400**, `discarded = 0`, and the origin accepts no new connection during wave 2 |
| Red check | same test with the cap forced back to the fixed 64 (`let cap = self.floor`) | **fails** at `wave 2 must not dial`: **736** dials against **400**, i.e. the 336 the fixed pool dropped, so the test detects the defect rather than passing by construction |
| Stability | `cargo test -p eqproxy-net --test e2e_http2` ×6 and `cargo test -p eqproxy-net --test e2e_http2 pool_sizing` ×8 | 6/6 and 8/8 green. The first version of the test measured 400 concurrent exchanges only when the machine scheduled it that way (wave 1 parked between 110 and 300 connections) and failed ~1 run in 3; the held origin removed that dependence — this is a fix to the test's measurement, not to its assertions |
| Suite | `cargo test --workspace` | **424 passed, 0 failed, 2 ignored**, 28 result lines, exit 0 |
| Lints | `cargo fmt --all -- --check` + `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |

## 3. Artifact under test

| Item | Value |
|---|---|
| Image | `eqproxy-bench:v07c`, id `934f8a46f7a9c60d` (the tag was later re-pointed to the h3 close build, `cbdbd07a05c4`; the build cited here is no longer on the host — the measurements are reproducible from the run directories under [`v07-h2-bench/`](v07-h2-bench/), and the same tree rebuilds them) |
| Binary sha256 | `7ef8a754ebf03e4917194e791916b25a21d640a5e98851fe3109583132776042` |
| HAProxy | `haproxy:3.4.6` (id `e273915691a8eab3`) |
| Generator | `load.go` (golang.org/x/net/http2), sha256 `711baf20…`; probe `9f36912c…` |
| Host | netcup-bench, Linux 6.8.0-147-generic x86_64, 8 vCPU, 16 GiB; start load 0.71 (S-H2-01) and 0.79 (S-H2-02) |
| Campaigns | S-H2-01 `run-20261023T215728Z`, S-H2-02 `run-20261023T220349Z` — one scenario per campaign, as the first campaign established |

Both products use the same TLS 1.3 certificate, ALPN `h2`, HTTP/1.1 keep-alive
origin and container topology as in
[`v07-h2-bench.md`](v07-h2-bench.md) §3; nothing in the configuration or the
generator changed between the two campaigns except the proxy image.

## 4. S-H2-01 — HTTP/2 multiplexed, 1 KiB, 400 streams in flight

| Metric | EQProxy (adaptive pool) | HAProxy 3.4.6 | Ratio | Previous EQProxy (fixed 64) |
|---|---|---|---|---|
| Throughput | **40 872.0 req/s** (40 240.5 – 42 144.4) | 55 064.1 req/s (47 784.2 – 61 571.9) | **0.742** | 5 704.0 req/s (0.099×) |
| Bandwidth | 39.91 MiB/s | 53.77 MiB/s | 0.742 | 5.53 MiB/s |
| p50 latency | 9.21 ms | 6.71 ms | 1.37× higher | 46.84 ms |
| p95 latency | 17.58 ms | 14.13 ms | 1.24× higher | 191.87 ms |
| p99 latency | 22.51 ms | 18.60 ms | 1.21× higher | 470.39 ms |
| CPU | 315.9 % (313.7 – 318.2) | 212.0 % (208.4 – 213.7) | 1.49× | 665.4 % |
| Peak memory | 83.77 MiB | 39.00 MiB | 2.15× | 87.25 MiB |
| Backend connections opened | **2 021** (0.55 / 1 000 req) | 5 127 (1.03 / 1 000 req) | 0.39× | 141 155 (192.85 / 1 000 req) |
| Responses | 3 706 403 × `200`, **0 errors** | 4 983 840 × `200`, 0 errors | — | 731 939 × `200`, 7 473 × `502` |
| Generator CPU | 196.4 % | 247.8 % | — | 46.8 % |

Connection churn is gone: 0.55 backend connections per 1 000 requests against
the previous 192.85 (−99.7 %), and no `502`. EQProxy is still **Worse** on this
scenario (0.742× throughput, 1.24–1.37× higher latency, 1.49× CPU), but the
gap moved from "fails the scenario" to a measured margin. Memory peak is
slightly below the previous 87.25 MiB despite four times the concurrency.

## 5. S-H2-02 — HTTP/2 large payload, 1 MiB, 32 streams in flight

| Metric | EQProxy | HAProxy 3.4.6 | Ratio | Previous EQProxy |
|---|---|---|---|---|
| Throughput | **1 504.3 MiB/s** (1 291.5 – 1 545.2) | 1 391.7 MiB/s (1 100.9 – 1 624.9) | **1.081** | 1 490.1 MiB/s (0.975×) |
| p50 latency | 20.84 ms | 22.56 ms | 1.08× lower | 21.08 ms |
| p95 latency | 34.07 ms | 36.73 ms | 1.08× lower | 34.15 ms |
| p99 latency | 40.85 ms | 44.18 ms | 1.08× lower | 40.83 ms |
| CPU | 298.8 % | 240.5 % | 1.24× | 297.2 % |
| Peak memory | 159.96 MiB | 50.00 MiB | 3.20× | 179.84 MiB |
| Backend connections opened | 152 (1.14 / 1 000 req) | 440 (3.51 / 1 000 req) | 0.35× | 155 (1.16 / 1 000 req) |
| Responses | 133 030 × `200`, 0 errors | 125 256 × `200`, 0 errors | — | 133 321 × `200`, 0 errors |

S-H2-02 is **Better** on throughput and latency (1.08×) and still **Worse** on
CPU (1.24×) and memory (3.2×); the change is neutral for 32 streams, as
expected — the defect only appeared beyond 64 concurrent exchanges.

Classification (BENCHMARK_PLAN §1.5): S-H2-01 **Worse** (0.742×, improved from
0.099×); S-H2-02 **Better** on the primary metric, with the CPU/memory cost
disclosed.

## 6. Audits

- **Veyra Proof**: `veyra audit . --profile standard` → **ACCEPTED**, exit
  **0**, evidence `.veyra/evidence/20261023T225628Z/` (profile `standard`,
  305 s of tools). `rustfmt`, `cargo check`, `clippy`, `cargo test`,
  `cargo-audit`, `anti-theater`, `nextest`, `llvm-cov`, `cargo-deny`,
  `cargo-machete` and `veyra-e2e` all **OK**, no problems.
  Not executed, reported as such: `dylint` (no configuration/libraries) and
  `cargo-semver-checks` (no registry baseline for unpublished crates).
  `cargo-geiger` **INCONCLUSIVE**: the scan completed but reported coverage
  warnings in 4 runs, so the unsafe counts are a lower bound, not a pass.
  Two earlier runs of the same tree are kept, not hidden:
  `.veyra/evidence/20261023T220938Z` **REJECTED** (`cargo-test`:
  `a_goaway_drains_in_flight_streams_and_the_next_exchange_dials_a_fresh_one`
  — the pre-existing h2 flake in §7) and `.veyra/evidence/20261023T224907Z`
  **REJECTED** (`cargo-geiger` could not read
  `eqproxy-net/tests/zz_probe_goaway.rs`, a temporary diagnostic file that
  had already been deleted; `cargo clean -p eqproxy-net` removed its stale
  artifact and the rerun above is the accepted one).
- **Rust Audit**: `python3.13 rust_audit.py scan . --format md --out report
  --fail-on high` → exit **1**, **253 findings** (3 critical, 26 high,
  180 medium, 44 low) in `report/rust-audit-20261024-005047.md` and
  `report/not-executed-2026-10-24.md`. The increment adds **one low finding**
  in the new test (`R02`, two assertions against the literals 400/800 — which
  is exactly the specification being asserted) and inherits the existing
  `R08` medium ones for `Instant::now` in the pool tests (the real clock is
  the unit under test there). **No finding lands on `note_in_flight`, the
  clamp, `ActiveGuard::in_flight` or the two borrow paths.** The criticals
  were reviewed and are pre-existing heuristics: `R12` on a high-entropy
  literal in `ws.rs` (a fixture, not a secret), two `R18d` ("impossible"
  `thiserror = "2"`, which exists, and `eqproxy_core`, a workspace path
  dependency), plus `R18c` "`http`/`h2` do not exist" near-miss false
  positives and `R20` typosquat heuristics on `md-5`/`h2`.
- **EvoForge**: **NOT EXECUTED**, and it will not run again. EvoForge left
  the audit process on 2026-10-24 (see the audit stack in `AGENTS.md`): its
  slice eval ran a condensed copy of the code and could not prove anything
  about the real programme the suite had not already proved. This slice never
  submitted an eval; it is reported as missing, not as a pass. The leg that
  replaces it is CodeGraph Rust, added to the process in the same decision.

## 7. Pending and limitations (not claimed)

- **S-H2-01 is still a loss.** 0.742× is a large, measured gap; this slice
  removes the connection churn and the `502`s, it does not close the
  per-request cost. The next lever is the h1⇄h2 translation cost per stream
  (one duplex pipe and two tasks per exchange), not the pool.
- **One host, one topology** (loopback bridge, origin and generator in
  containers on an 8-vCPU machine): the numbers are not comparable to a
  multi-machine setup and the generator/proxy/origin share the CPU.
- **The pool cap follows a process-lifetime peak per server.** A burst leaves
  the cap high until restart; idle sockets expire after 60 s, so the steady
  state footprint follows the live count, but the cap itself does not decay.
  Above 4 096 concurrent exchanges per server the previous churn behaviour
  returns; no test or campaign exercises that bound.
- **No adaptive shrink** and no metric exporting the current cap; only the
  unit tests and the E2E observe it.
- The campaign was **not** repeated on arm64; the first campaign's arm64 H1
  numbers are unrelated and no arm64 S-H2 claim is made.
- A combined S-H2-01+S-H2-02 campaign was not run (the first campaign showed
  the ordering contaminates the second scenario); each is published from its
  own campaign, from an idle host.
- **A pre-existing flake in the h2 backend path was observed twice** while
  running the whole workspace suite: `a_goaway_drains_in_flight_streams_and_the_next_exchange_dials_a_fresh_one`
  (`eqproxy-net/tests/e2e_backend_h2.rs`) answered **502 / "HTTP/2 protocol
  error"** when a new exchange lost the race with the peer's GOAWAY. It did
  not reproduce in 10 isolated runs of that test, in 40 runs under CPU load,
  or in the 6 whole-workspace runs after the new pool test was made
  deterministic, so **it is not fixed here** and this slice does not claim to
  have fixed it. Diagnosis so far, from the h2 0.4.20 sources and a probe: a
  `send_request` issued after the peer's GOAWAY has been processed returns
  `GoAway(NO_ERROR, Remote)` — which the session maps to a replay on a fresh
  session — so the observed failure is on a different branch (a stream the
  peer resets while draining, or the replay's dial/enter). Locating the exact
  branch is pending; the h2 backend code itself is unchanged by this slice.
- The E2E's origin holds every request while a wave is open. That makes the
  400 exchanges deterministic, but it models a slow origin, not an Internet
  latency mix; the campaign (§4, §5) is what covers the real traffic shape.

## 8. Reproduction

```bash
# tests
cargo test -p eqproxy-net --lib pool
cargo test -p eqproxy-net --test e2e_http2 pool_sizing
cargo test --workspace

# image
docker build -f docker/Dockerfile -t eqproxy-bench:v07c .

# campaigns (one scenario at a time, on an idle host)
python3 scripts/evidence/v07-h2-bench/run.py --reps 5 --scenarios S-H2-01 \
  --eq-image eqproxy-bench:v07c --load-binary <linux/amd64 load> \
  --probe-binary <linux/amd64 probe>
python3 scripts/evidence/v07-h2-bench/run.py --reps 5 --scenarios S-H2-02 \
  --eq-image eqproxy-bench:v07c --load-binary <load> --probe-binary <probe>
```

Raw data: [`run-20261023T215728Z/`](v07-h2-bench/run-20261023T215728Z/)
(S-H2-01) and [`run-20261023T220349Z/`](v07-h2-bench/run-20261023T220349Z/)
(S-H2-02) — `report.json`, `raw/` (10 runs each), `logs/`, `configs/`,
`certs/`, `run.log`.
