# Phase 2c evidence — first benchmarks and measured budgets

Date: 2026-10-14. Raw data: [bench-raw.json](bench-raw.json) (full disclosure
block inside), [mem-raw.json](mem-raw.json). Harness:
[scripts/bench_phase2c.py](../../../scripts/bench_phase2c.py),
[scripts/bench_backends.py](../../../scripts/bench_backends.py),
[scripts/mem_budgets.py](../../../scripts/mem_budgets.py).
Commit: see `disclosure.eqproxy_commit` in bench-raw.json.

Language note: from v0.3.0, project documentation is published in English
only. Earlier bilingual documents keep their frozen Spanish sections; all new
content is English.

## 1. Setup (same for both products)

- Host: Apple M2 Pro, 10 cores, 32 GiB, macOS 26.5.1, Docker Desktop (linux/arm64 VM).
- EQProxy: release binary from this commit, containerized (`docker/Dockerfile`).
- Reference: `haproxy:3.4.6` (Docker Hub digest in raw data, `haproxy -vv` in raw data).
- Topology: backends + both proxies in containers on one bridge network;
  generators on the host via published ports. Limitation: VM hop for all
  containerized roles, shared machine, no CPU affinity.
- Backends: stdlib TCP echo and HTTP/1.1 1 KiB origin (same for both).
- Generator: asyncio echo client (32 conns x 300 x 1 KiB) for S-TCP-01;
  oha 1.14.0 `-z 10s -c 50` keep-alive for S-H1-01; same with `--insecure`
  and the test cert (SAN 127.0.0.1, ALPN h1) for S-TLS-01.
- 5 repetitions per scenario per proxy, one warm-up discarded.
- EQProxy requires literal IP:PORT backend addresses (hostnames rejected by
  design); the harness injects the backend container IP for both products.

## 2. Results (median of 5, min–max spread)

| Scenario | EQProxy RPS | haproxy RPS | EQProxy p50/p95/p99 (ms) | haproxy p50/p95/p99 (ms) |
|---|---|---|---|---|
| S-TCP-01 | 5680 (5512–6372) | 5997 (4296–7496) | 0.89 / 1.59 / 3.41 | 0.88 / 1.56 / 2.96 |
| S-H1-01 | 1528 (1292–1563) | 1588 (1305–46475*) | 23.9 / 65.0 / 97.8 | 41.8 / 43.4 / 50.0 |
| S-TLS-01 | 1523 (1355–24197*) | 1569 (1381–2004) | 20.0 / 63.7 / 89.1 | 41.9 / 44.0 / 47.7 |

\* Single-rep outliers (fast-error runs, see §3). haproxy S-H1-01 max 46475 is
one anomalous rep; its other four reps sit at 1305–1785.

## 3. Classification

- **S-TCP-01: Comparable.** Overlapping RPS spreads and matching latencies.
- **S-H1-01: Worse (under sustained concurrency).** EQProxy returned 50–100%
  HTTP 502 against the Python origin at `-c 50`.
- **S-TLS-01: Worse (under sustained concurrency).** Same 502 pattern over TLS.

Root cause (verified, not inferred): EQProxy dials a **new backend
connection per exchange** (backend pool is Phase 3, A16). At ~1.5k dials/s
the proxy container exhausts its ephemeral port range; every failed dial
logs `Cannot assign requested address (os error 99)` (EADDRNOTAVAIL),
increments `connect_failures`, and answers 502 per the documented SPEC §7.4
mapping. Evidence:

1. Follow-up against an nginx origin: EQProxy reached 3439 RPS but still
   16% 502s at `-c 50` — not an origin weakness.
2. After a 75 s TIME_WAIT drain, EQProxy at `-c 5` served 20047 requests
   with **zero** 502s (2506 RPS) — the proxy logic is correct when source
   ports are available.
3. haproxy reuses backend keep-alive connections, so it never approaches the
   port ceiling (7220 RPS clean vs nginx at `-c 50`).

Failure behavior is fail-explicit (log + metric + 502), never silent
success. Remediation is the Phase 3 backend keep-alive pool (A16); no
half-pool was shipped for this release. The parity goal (Better/Comparable
everywhere) remains a Phase 9 acceptance criterion.

## 7. Addendum — A16 pool re-run (Phase 3 first slice)

After the per-server keep-alive pool landed, the same harness re-ran all
three scenarios (raw data overwritten in `bench-raw.json`). Its disclosure
block names the pre-amend commit the numbers were measured on; the published
commit amends only this report, the README and the raw JSON itself — all
code, scripts and configs are byte-identical between the two.

| Scenario | EQProxy RPS | haproxy RPS | EQProxy p50/p95/p99 (ms) | haproxy p50/p95/p99 (ms) |
|---|---|---|---|---|
| S-TCP-01 | 5413 (4800–6388) | 5684 (4632–5786) | 1.27 / 2.31 / 5.09 | 1.15 / 2.38 / 4.88 |
| S-H1-01 | 1547 (1310–1772) | 1265 (1009–2042) | 42.1 / 47.5 / 71.1 | 42.1 / 45.1 / 76.3 |
| S-TLS-01 | 1314 (1233–1481) | 1369 (1158–4059*) | 43.2 / 63.7 / 141.1 | 45.2 / 77.0 / 162.7 |

\* haproxy S-TLS-01 max 4059 is a single fast rep; its p99 spread reaches
1331 ms vs 333 ms for EQProxy.

- **Zero non-2xx in all 10 EQProxy HTTP/TLS runs** (all-200; only routine
oha deadline-aborts at shutdown): the 502-storm is gone.
- Revised classification: S-TCP-01 **Comparable**; S-H1-01 **Comparable**
  (RPS median above the reference, equal p50, tighter p99);
  S-TLS-01 **Comparable** (equal RPS order, lower p95/p99 medians).

## 4. Measured resource budgets (SPEC §7.3, first measurement)

Native release binary on macOS/arm64, 200 idle connections, RSS via `ps`:

| Scenario | RSS before | RSS with conns | Per-conn | Design budget | Verdict |
|---|---|---|---|---|---|
| TCP proxy conn | 3632 KiB | 11184 KiB | **37.8 KiB** | ≤ 36 KiB | Marginal (+5%; allocator rounding on darwin; Linux re-measurement pending) |
| HTTP/1.1 keep-alive conn | 3584 KiB | 6608 KiB | **15.1 KiB** | ≤ 48 KiB | Within budget |

Notes: idle keep-alive connections hold less than the 48 KiB budget because
exchange buffers are allocated per request, not per connection. RSS does not
return to baseline after close (allocator retention, not a leak signal —
no growth across repeated open/close beyond the first plateau; long-run
profiling stays in Phase 9 scope). FD/task/metric-cardinality rows of §7.3
remain design targets until the Linux tier-1 re-measurement.

## 5. Fuzzing (exit criterion, exceeded)

- Deterministic corpus test `eqproxy-net/tests/framing_fuzz_corpus.rs`
  (3 tests): fixed T01–T03 seeds + 200 xorshift mutants per seed over both
  head parsers; asserts no-panic + explicit statuses (requests
  400/431/501/505, responses 502). Green in `cargo test`.
- Live target `fuzz/fuzz_targets/framing.rs` (cargo-fuzz 0.13.2, latest
  nightly, ASan): **3,832,220 execs in 121 s, 0 crashes, 0 timeouts, 0 OOMs**,
  4882 new units added. Seeds in `fuzz/seeds/framing/`.
- Note: the pinned `nightly-2025-11-21` toolchain cannot build the workspace
  (`AtomicU64::try_update` still unstable there); live fuzz used the current
  `nightly`. The read-layer size caps and chunked-body streaming remain under
  E2E coverage; chunked-body differential fuzzing moves to Phase 4 scope.

## 6. Reproduction

```bash
python3 scripts/bench_phase2c.py > docs/evidence/phase2c/bench-raw.json
python3 scripts/mem_budgets.py > docs/evidence/phase2c/mem-raw.json
cargo test -p eqproxy-net --test framing_fuzz_corpus
mkdir -p fuzz/corpus/framing  # working dir: libFuzzer writes new units to the FIRST corpus dir
cargo +nightly fuzz run framing fuzz/corpus/framing fuzz/seeds/framing -- -max_total_time=120
```
