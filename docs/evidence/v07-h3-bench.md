# v0.7 gate — S-H3-01 / S-H3-02: HTTP/3 benchmark vs HAProxy 3.4.6

> **Follow-up (2026-10-23):** the per-request cost reported here was profiled
> and fixed in [`v07-h3-profile.md`](v07-h3-profile.md). A new 5×2 campaign
> ([`run-20261023T181822Z`](v07-h3-bench/run-20261023T181822Z/report.json))
> measured S-H3-01 at **32 941.3 vs 49 279.1 req/s (0.668×, was 0.341×)** and
> S-H3-02 at 0.707× (unchanged), with peak memory now 44.93 MiB vs HAProxy's
> 32.55 MiB. The tables below are the original measurement and are kept as
> published.

## 1. Objective

Execute the two HTTP/3 scenarios of `BENCHMARK_PLAN.md` §3 with **H3 active
on both products** and publish raw data:

- **S-H3-01** — HTTP/3 (QUIC), 1 KiB payload: throughput, latency, CPU and
  memory.
- **S-H3-02** — HTTP/3 massive handshake (0-RTT on/off documented):
  handshakes/s and CPU.

This closes the H3 half of the v0.7 acceptance item *“Escenarios S-H2-01/02 y
S-H3-01/02 comparados con HAProxy 3.4.6 con H3 activo en ambos (o clasificados
«Not comparable» con razón)”*. It is a **measurement, not a promise**: the
result is what the numbers say, including a loss.

## 2. Artifact under test

| | |
|---|---|
| Product | `eqproxy 0.6.3`, image `eqproxy-bench:v07` (id `3e8ef9479fc3`, built from the uncommitted v0.7 working tree on `b93883e`) |
| EQProxy binary SHA-256 | `412feb8e8ce2556fc89eae39beb77ed4c212101e2344c2e0a9dba9e70b8a2ed1` (extracted from the image, not from the host) |
| Reference | `haproxy:3.4.6`, image id `e273915691a8`, build `HAProxy 3.4.6-56332c5 2026/09/28`, `USE_QUIC=1`, OpenSSL 3.5.7, `-vv` in `report.json` |
| Generator | `docs/evidence/v07-h3-bench/load.go`, quic-go **0.64.1** (own QUIC/h3/QPACK), Go 1.26.2, static binary SHA-256 `f02af496…`, QPACK `0.6.0` |
| Counter probe | `docs/evidence/v07-h3-bench/probe/main.go`, static binary SHA-256 `bb546e7e…` |
| TLS certificate | `eqproxy-net/tests/fixtures/cert.pem`, SHA-256 `0c6cab2e…`, CN=localhost, SAN `DNS:localhost` + IP `127.0.0.1` |
| Evidence host | `netcup-bench`: Linux 6.8.0-147-generic, x86_64, AMD EPYC 9645 (8 vCPU exposed), 15.6 GiB RAM, Docker 29.6.1 |
| Raw data | [`run-20261023T134656Z/`](v07-h3-bench/run-20261023T134656Z/) — `report.json`, `raw/` (20 runs), `logs/` (gzipped), `configs/`, `certs/`, `run.log` |

The first attempt was made on the macOS workstation and **discarded**: a
parasitic build from an unrelated project pushed the host load average to
~40, which invalidates the “no parasitic load” control (§5.4 of the plan).
No number from that attempt is used.

## 3. Method

### 3.1 Scenarios (BENCHMARK_PLAN §3)

| ID | Load | Measured |
|---|---|---|
| S-H3-01 | 8 QUIC connections × 8 concurrent h3 request streams (64 in flight), GET `/`, 3 s warm-up + **15 s** measured, closed-loop | req/s, per-request latency p50/p95/p99, CPU, peak memory |
| S-H3-02 | **16 concurrent fresh QUIC handshakes**, no session resumption, no 0-RTT, 2 s warm-up + **10 s** measured | handshakes/s, handshake latency p50/p95/p99, CPU, peak memory |

Five repetitions per cell, alternating which product runs first (odd reps
EQProxy→HAProxy, even reps HAProxy→EQProxy). Medians are reported with the
full min–max range; the best run is never cherry-picked.

### 3.2 Topology and equivalence

One Linux host. Origin, both proxies and the generator are containers on one
bridge network; nothing traverses a host port or a user-space UDP forwarder.

- **Same origin**: `load -mode origin`, one fixed 1 KiB body with
  `content-length`, HTTP/1.1 keep-alive, no TLS, no logging.
- **Same certificate** (TLS 1.3, ALPN `h3`), **same port** 19443, same 30 s
  idle timeout, same congestion controller (`cubic`: quinn's default for
  EQProxy, `quic-cc-algo cubic` for HAProxy), no compression, no rules, no
  health checks, `maxconn` 20000 in both.
- **Configurations published verbatim** in
  [`run-20261023T134656Z/configs/`](v07-h3-bench/run-20261023T134656Z/configs/):
  EQProxy TOML and HAProxy cfg.
- HAProxy 3.4.6 needs a dedicated `bind quic4@:19443` for QUIC (its TCP bind
  stays for h2/http1.1 and carries no traffic here). EQProxy serves TCP and
  UDP from the same listener.
- Architectural difference, declared: **EQProxy translates every h3 request
  into one HTTP/1.1 exchange through its engine** (ADR-0013); HAProxy forwards
  from its QUIC frontend natively. Both terminate TLS/h3 and speak HTTP/1.1 to
  the same origin.

### 3.3 Measurement

- **Latency** is measured per request by the generator, from just before the
  request is written until the body is fully read (1 KiB validated), all
  samples kept, percentiles computed from the sorted samples. It is
  **closed-loop and not coordinated-omission corrected**; no h3-capable
  generator with CO correction was available, and that limitation is carried
  into the verdict.
- **CPU and memory** come from the container's own cgroup v2
  (`cpu.stat usage_usec`, `memory.peak`), read before and after each run by
  the probe binary. CPU % is the delta divided by the run wall time
  (100 % = one core); the interval includes container start/stop (~0.5 s of
  idle), a ≤ 3 % dilution.
- **Generator headroom** is reported by the generator itself (own
  `getrusage`) and calibrated against a local h3 sink of the same binary.
- Every run must have `errors = 0`, `sanity = ok` (TLS verified against the
  fixture CA, status 200, exactly 1024 bytes); a failed run aborts the
  campaign instead of being averaged in.

## 4. Results

Medians of 5 runs; ranges in parentheses. All 20 runs: **0 errors**, **all
responses 200 with a 1024-byte body**.

### S-H3-01 — HTTP/3, 1 KiB, 64 streams in flight

| Metric | EQProxy | HAProxy 3.4.6 | Ratio |
|---|---|---|---|
| Throughput | **16 838.6 req/s** (12 192.8 – 18 237.3) | **49 323.8 req/s** (44 470.4 – 51 734.5) | 0.341 (EQ/HA) |
| p50 latency | 3.58 ms | 1.06 ms | 3.38× higher |
| p95 latency | 6.50 ms | 3.03 ms | 2.14× higher |
| p99 latency | 8.57 ms | 4.30 ms | 1.99× higher |
| CPU (one core = 100 %) | 351.0 % (344.4 – 354.8) | 198.5 % (185.1 – 204.9) | 1.77× (EQ/HA) |
| CPU per request (derived) | 208 µs | 40 µs | 5.2× |
| Peak memory (cgroup) | **9.23 MiB** | 32.71 MiB | 0.28× (EQ/HA) |
| Origin CPU during the run | 99.8 % | 153.9 % | — |
| Generator CPU | 164.2 % | 298.5 % | — |

Per-repetition throughput: EQProxy `12 192.8 / 15 409.9 / 16 838.6 /
18 000.1 / 18 237.3`; HAProxy `45 303.9 / 44 470.4 / 49 323.8 / 49 663.9 /
51 734.5`. Both products improve as the host warms after the image build;
the medians are compared, the trend is disclosed.

### S-H3-02 — HTTP/3 massive handshake, 16 concurrent dials

| Metric | EQProxy | HAProxy 3.4.6 | Ratio |
|---|---|---|---|
| Handshakes/s | **1 209.3** (1 159.4 – 1 241.0) | **1 637.4** (1 619.1 – 1 719.1) | 0.739 (EQ/HA) |
| Handshake p50 | 13.02 ms | 8.76 ms | 1.49× higher |
| Handshake p95 | 20.45 ms | 16.13 ms | 1.27× higher |
| Handshake p99 | 24.88 ms | 20.25 ms | 1.23× higher |
| CPU | 115.3 % (114.9 – 116.1) | 199.4 % (198.9 – 202.8) | 0.58× (EQ/HA) |
| CPU per handshake (derived) | 0.95 ms | 1.22 ms | 0.78× (EQ/HA) |
| Peak memory | **15.28 MiB** | 36.54 MiB | 0.42× (EQ/HA) |
| Generator CPU | 188.3 % | 252.1 % | — |

### Generator calibration (local h3 sink, same binary)

| Calibration | Result | Generator CPU | Sink CPU |
|---|---|---|---|
| `load` 8×8 streams, 10 s | 31 235.0 req/s | 262.5 % | 279.8 % |
| `handshake` 16 dials, 10 s | 1 185.3 hs/s | 201.8 % | 329.7 % |

The sink (quic-go h3 server) saturates before the client in both cases, so
these are **floors, not ceilings**: HAProxy reached 49 324 req/s and
1 637 hs/s, above both sink figures, which proves the client was not capped
at those values. The generator used at most 3.0 of the 8 vCPUs (298.5 % of
one core) during the measured runs.

## 5. Verdict (BENCHMARK_PLAN §1.5 classification)

**EQProxy is Worse than HAProxy 3.4.6 on both HTTP/3 scenarios.**

- **S-H3-01 — Worse.** 0.341× the throughput, 3.38× the p50 and 1.99× the p99
  latency, 1.77× the CPU while doing a third of the work (5.2× CPU per
  request). The only favourable metric is memory: 9.23 vs 32.71 MiB peak.
- **S-H3-02 — Worse.** 0.739× the handshakes/s and 1.49× the p50 handshake
  latency, with **less** total CPU (115 % vs 199 % of one core) because the
  path is single-core bound; CPU per handshake is 0.78×. Memory is again
  lower (15.28 vs 36.54 MiB).

The differences are far outside the observed run-to-run spread (for example,
EQProxy's best S-H3-01 run, 18 237 req/s, is still 2.7× below HAProxy's worst,
44 470 req/s). This is **not** a “Comparable” result and it is not classified
as such.

Context, not excuse: the same product beat HAProxy on HTTP/1.1 in v0.6
(S-H1-04 1.14× amd64 / 1.15× arm64, S-H1-05 4.51× / 1.30×, evidence in
`v06-bench/` and `v06-bench-arm64/`). The loss measured here is specific to
the **HTTP/3 path**, on a different host and scenario; the two campaigns are
not directly comparable.

## 6. Observations (what the measured data shows)

1. **Per-request cost of the h3→h1 translation.** EQProxy spends 208 µs of
   CPU per proxied request at 1 KiB, HAProxy 40 µs. The h3 path opens one
   `tokio::io::duplex` pipe of `PIPE_BUFFER = 64 KiB` per exchange and spawns
   two tasks per request (`eqproxy-net/src/http3.rs:59`, `:236`, `:240`,
   `:258`) before handing it to the HTTP/1.1 engine; HAProxy keeps the QUIC
   stream inside its native HTX pipeline. The arithmetic is measured; *which*
   of those costs dominates is **not** profiled in this campaign (no
   flamegraph was taken) — it is a hypothesis for the next increment, not a
   conclusion.
2. **Handshake path is single-core bound in EQProxy.** Its CPU barely moves
   (114.9–116.1 % of one core) while HAProxy scales to ~2 cores at 1 637
   hs/s. In the discarding arm64 pilots (not part of this campaign) its
   handshake throughput was flat at 8, 16 and 32 concurrent dials with the
   same ~110 % CPU, which points at one core. The QUIC accept loop polls
   `endpoint.accept()` from one task (`http3.rs:72-83`), so handshake
   completion serialises there.
3. **Log flood on peer-initiated close — fixed and re-measured.** EQProxy
   wrote one `WARN [h3] HTTP/3 connection error … ApplicationClose: 0x0` per
   closed connection: **13 859–15 123 lines per 10 s handshake run** (one per
   handshake), against two `NOTICE` lines for the whole HAProxy run, and
   counted those normal session ends as protocol errors. The close is now
   classified (`H3_NO_ERROR` / application code `0` is clean) and the
   S-H3-02 before/after campaign measures the removal: **15 227 → 26 WARN
   lines** and **1.67 MiB → 5.08 KiB** of log per run at the same offered
   load, with no throughput change beyond host drift (the HAProxy control
   moved −4.4 % between the two clean campaigns). Details, raw data and the
   limits of that claim in [`v07-h3-close.md`](v07-h3-close.md).
4. **Memory is consistently lower in EQProxy** (9–15 MiB vs 33–37 MiB peak),
   consistent with its smaller per-connection state.

## 7. Integrity checks

- `report.json` is the only source of the tables; it was produced by the
  harness, not edited.
- Medians were **recomputed independently** from the 20 `raw/*.json` files
  with a separate script; every value matches `report.json` exactly.
- Every run reports `errors = 0`, `sanity = "ok"`, and status `200` only; the
  generator validates TLS against the fixture CA and the 1 KiB body length.
- The origin and sink are in the same network and their CPU is measured with
  the same probe as the proxies.
- The campaign ran on an **idle** host (load average 0.24 at start after the
  image build decayed); the earlier contaminated attempt on the macOS host is
  not part of the evidence.
- `logs/*.log.gz` are the full container stdout/stderr, gzipped after the run
  (the harness writes plain text); nothing was filtered.

## 8. Checks run

| Command | Result |
|---|---|
| `gofmt -l docs/evidence/v07-h3-bench` | clean |
| `go vet ./...` in `v07-h3-bench` | exit 0 |
| `GOOS=linux GOARCH=amd64 go build` (`load`, `probe`) | exit 0, static ELF x86-64 |
| `python3 -m py_compile docs/evidence/v07-h3-bench/run.py` | exit 0 |
| `python3 docs/evidence/v07-h3-bench/run.py --reps 5 --load-binary … --probe-binary …` | exit 0, 20/20 valid runs, report written |
| medians recomputation from `raw/` | exact match |
| `cargo fmt --all --check` | clean |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean |
| `cargo test --workspace` | 414 passed, 0 failed, 2 ignored (no Rust source changed in this slice) |
| `veyra audit . --profile standard` | **ACCEPTED**, exit 0, `.veyra/evidence/20261023T140219Z/` (rustfmt, check, clippy, test, nextest, llvm-cov, deny, machete and `veyra-e2e` OK; geiger INCONCLUSIVE by its own coverage warning, dylint/semver-checks SKIPPED for lack of config/baseline — nothing disabled) |
| Rust Audit `scan . --format terminal,md,json,sarif --fail-on high` | exit 1: 251 findings (3 critical / 25 high / 180 medium / 43 low), the same set triaged in `v07-http3.md`. No Rust source changed in this slice; the tool does not scan the Go/Python harness, which is covered by `gofmt`/`go vet`/`py_compile` and by the campaign run itself |
| EvoForge `mcp_submit_eval` (std-only slice of the h3/h2→h1 translation) | first attempt **F = 0.0** (4/4 tests passed but clippy rejected `Result<_, ()>` in the replica, exit 101); after mirroring the refusal as `Option`, **F = 1.0**, 4/4 tests, clippy clean, exit 0, trace `0fe8a7cf-0a53-459c-918f-3ca896104ab3`. The slice is a condensed replica for the sandbox, not a substitute for the E2E evidence above |

## 9. Limits and NOT EXECUTED

- **One host, components share 8 vCPUs.** During S-H3-01 the generator
  (~3 cores), both proxies (~2/3.5), the origin (~1–1.5) and kernel softirq
  contend; spot checks showed a 1-minute load average of ~12. Absolute
  throughput is therefore host-limited in both directions; the comparison is
  valid because both products run under the identical topology and the
  direction of the gap is larger than any plausible contention effect.
- **Closed-loop generator, no coordinated-omission correction.** Latencies are
  not CO-corrected; p99 values are optimistic for both products.
- **0-RTT off** for both (the client does not attempt it; EQProxy does not
  implement it, ADR-0013). Session resumption is off (fresh handshake each
  dial). HAProxy's 0-RTT capability was not exercised, so no 0-RTT claim is
  made in either direction.
- **Single architecture (amd64).** The arm64 evidence host was unreachable at
  run time; the campaign was not replicated there. **NOT EXECUTED**.
- **Only S-H3-01/S-H3-02.** S-H2-01/S-H2-02 remain pending; the roadmap gate
  item is not complete with this document alone.
- **No profiler in this campaign.** The diagnosis in §6 is arithmetic from
  measured CPU plus code structure. **NOT EXECUTED** here: CPU profile of the
  h3 path — it was executed afterwards, on the same artifact, in
  [`v07-h3-profile.md`](v07-h3-profile.md).
- **Sink calibration is not a ceiling** (the quic-go server saturates first);
  see §4.
- Not measured: p99.9, TLS handshake CPU split, 1 MiB payload, packet loss,
  different `idle_timeout`/stream limits, browsers or `curl` as clients.

## 10. Reproduce

```bash
# generator and probe are committed next to this file (go.mod/go.sum pinned)
cd docs/evidence/v07-h3-bench
gofmt -l . && go vet ./... && go list -m all > go-modules.txt

# on an idle Linux evidence host with Docker and the two images:
#   docker build -f docker/Dockerfile -t eqproxy-bench:v07 .
#   docker pull haproxy:3.4.6
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags=-s -o bin/load .
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags=-s -o bin/probe ./probe
python3 run.py --reps 5 --load-binary bin/load --probe-binary bin/probe
```

The script builds the generator image, creates the network and containers,
runs the calibration and the 20 measured runs, writes `run-<UTC>/` and
removes the containers. The result of the campaign above is
[`run-20261023T134656Z/report.json`](v07-h3-bench/run-20261023T134656Z/report.json).
