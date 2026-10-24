# v0.7 gate — S-H2-01 / S-H2-02: HTTP/2 benchmark vs HAProxy 3.4.6

> **Superseded (2026-10-23):** the 64-slot backend pool measured here was
> replaced by adaptive sizing and both scenarios were re-measured on the same
> host with the new image (`eqproxy-bench:v07c`). S-H2-01 went from **5 704.0
> to 40 872.0 req/s (0.099× → 0.742×)**, with backend connections per 1 000
> requests from **192.85 to 0.55** and the **7 473 × `502` gone**; S-H2-02 went
> from 0.975× to **1.081×**. See
> [`v07-h2-pool-sizing.md`](v07-h2-pool-sizing.md). The tables below are the
> first measurement and are kept as published.

## 1. Objective

Execute the two HTTP/2 scenarios of `BENCHMARK_PLAN.md` §3 with **HTTP/2
active on both products** and publish raw data:

- **S-H2-01** — HTTP/2 multiplexed (100 streams per connection), 1 KiB
  payload: throughput, latency, CPU and memory.
- **S-H2-02** — HTTP/2 large payload (1 MiB): throughput and CPU.

This closes the H2 half of the v0.7 acceptance item *“Escenarios S-H2-01/02 y
S-H3-01/02 comparados con HAProxy 3.4.6 con H3 activo en ambos (o clasificados
«Not comparable» con razón)”*. It is a **measurement, not a promise**: the
result is what the numbers say, and one of the two scenarios loses badly.

## 2. Artifact under test

| | |
|---|---|
| Product | `eqproxy 0.6.3`, image `eqproxy-bench:v07h2` (id `af9e57c5ed53e2a8`, built from the v0.7 working tree on `b93883e`, uncommitted) |
| EQProxy binary SHA-256 | `b4db9260ef34a2b8a87d3d8550f115913224eda12d6da49c4bd242aa8f97aa3c` (extracted from the image, not from the host) |
| Reference | `haproxy:3.4.6`, image id `e273915691a8`, build `HAProxy 3.4.6-56332c5 2026/09/28`, OpenSSL 3.5.7, `-vv` in `report.json` |
| Generator | `docs/evidence/v07-h2-bench/load.go`, `golang.org/x/net/http2` **0.42.0**, Go 1.26.2, static ELF, SHA-256 `d29516bc…` |
| Counter probe | `docs/evidence/v07-h2-bench/probe/main.go`, SHA-256 `c0c2f77d…` |
| TLS certificate | `eqproxy-net/tests/fixtures/cert.pem`, SHA-256 `0c6cab2ee3…`, CN=localhost, SAN `DNS:localhost` + IP `127.0.0.1` |
| Evidence host | `netcup-bench`: Linux 6.8.0-147-generic, x86_64, AMD EPYC 9645 (8 vCPU exposed), 15.6 GiB RAM, Docker 29.6.1, `ip_local_port_range = 32768 60999` (28 232 ports) |
| S-H2-01 raw data | [`run-20261023T200316Z/`](v07-h2-bench/run-20261023T200316Z/) — `report.json`, `raw/` (10 runs), `logs/`, `configs/`, `certs/`, `run.log` |
| S-H2-02 raw data | [`run-20261023T201003Z/`](v07-h2-bench/run-20261023T201003Z/) — same layout, 10 runs |

## 3. Method

### 3.1 Scenarios (BENCHMARK_PLAN §3)

| ID | Load | Measured |
|---|---|---|
| S-H2-01 | **4 TLS connections × 100 concurrent h2 streams** (400 in flight), `GET /1024`, 3 s warm-up + **15 s** measured, closed-loop | req/s, per-request p50/p95/p99, CPU, peak memory, backend connections opened |
| S-H2-02 | **4 connections × 8 streams** (32 in flight), `GET /1048576` (1 MiB), 3 s + **15 s** | MiB/s and req/s, latency, CPU, peak memory, backend connections |

Five repetitions per cell, alternating which product runs first (odd reps
EQProxy→HAProxy, even reps HAProxy→EQProxy). Medians with the full min–max
range; the best run is never cherry-picked.

**Each scenario was run as its own campaign.** A combined campaign was
executed first and its second half was **discarded as contaminated**: the
S-H2-01 EQProxy cell makes the proxy open ~28 000 backend connections per
repetition (§6.1), which leaves the host's port space and conntrack in a
different state; in that combined campaign the HAProxy S-H2-02 cell fell to
**1 125.7–1 673.1 MiB/s, median 1 223.5** — against 1 529.0 in the published
campaign; three of its five repetitions were below 1 250) and made EQProxy
look 1.25× faster. No number from that ordering is used. The two
published campaigns each start from an **idle** host: load average 0.27
(S-H2-01) and 0.38 (S-H2-02) at start; the per-run load averages rise to
6.6–14.5 because the measurement itself saturates the 8 vCPUs, and they are
recorded in every `raw/*.json`.

### 3.2 Topology and equivalence

One Linux host. Origin, both proxies and the generator are containers on one
bridge network; nothing traverses a published host port.

- **Same origin**: `load -mode origin`, path-addressed bodies with
  `content-length`, HTTP/1.1 keep-alive, no TLS, no logging.
- **Same certificate**, TLS 1.3, **ALPN `h2` forced in both**, same port
  19443, same 30 s idle timeout, `maxconn 20000` in both, no compression, no
  rules, no health checks.
- **Configurations published verbatim** in each run's `configs/`: EQProxy
  TOML (`alpn = ["h2", "http/1.1"]`) and HAProxy cfg
  (`bind :19443 ssl crt /certs/haproxy.pem alpn h2,http/1.1`).
- Declared architectural difference: **EQProxy translates every h2 stream
  into one HTTP/1.1 exchange through its engine** (ADR-0006), opening a
  backend connection per concurrent stream; HAProxy forwards natively over
  HTX. Both speak HTTP/1.1 to the same origin.
- Both products' h2 limit is ≥ 100 streams: EQProxy advertises
  `MAX_CONCURRENT_STREAMS = 128`; HAProxy's default
  `tune.h2.max-concurrent-streams` is 100, so the client's 100 per connection
  never queues on the server's setting in either product.

### 3.3 Measurement

- **Latency** is measured per request by the generator, from just before the
  request is written until the body is fully read and its length (plus
  `HTTP/2.0`) validated; every sample is kept and the percentiles come from
  the sorted samples. It is **closed-loop and not coordinated-omission
  corrected**; no h2-capable generator with CO correction was available, and
  the limitation travels with the verdict.
- **CPU and memory** come from each container's own cgroup v2
  (`cpu.stat usage_usec`, `memory.peak`), read before and after each run by a
  static probe mounted into the scratch EQProxy image. CPU % is the delta
  over the run wall time (100 % = one core), so it includes ~0.5 s of
  container start/stop (a ≤ 3 % dilution).
- **Backend connections** are counted on the peer: the origin's
  `/proc/net/snmp` `Tcp: PassiveOpens` delta per run. The origin initiates
  nothing, so this is exactly the number of connections the proxy opened.
  The proxy itself is not instrumented for this figure.
- **Generator headroom** is calibrated before each campaign against a local
  h2 sink (a real TLS/ALPN h2 server running the same binary), and the
  generator reports its own CPU.
- Every run must have `sanity = ok` and `proto = HTTP/2.0`, otherwise the
  campaign aborts. A run with client errors is **recorded, flagged
  `valid: false` and published**, never deleted: those errors are product
  behaviour under the scenario load (they are 502s, not harness failures).

## 4. Results

Medians of 5 runs; ranges in parentheses. Every run used `HTTP/2.0` and
passed the generator's sanity check (TLS verified against the fixture CA,
status 200, exact body size).

### S-H2-01 — HTTP/2 multiplexed, 1 KiB, 400 streams in flight

| Metric | EQProxy | HAProxy 3.4.6 | Ratio |
|---|---|---|---|
| Throughput | **5 704.0 req/s** (5 244.6 – 6 010.2) | **57 453.2 req/s** (53 574.8 – 58 614.4) | **0.099** (EQ/HA) |
| Bandwidth | 5.53 MiB/s | 56.11 MiB/s | 0.099 |
| p50 latency | 46.84 ms | 6.45 ms | 7.26× higher |
| p95 latency | 191.87 ms | 13.40 ms | 14.32× higher |
| p99 latency | 470.39 ms (max 598.42) | 17.85 ms (max 18.58) | 26.35× higher |
| CPU (one core = 100 %) | 665.4 % (658.7 – 667.6) | 211.0 % (210.3 – 212.4) | 3.15× (EQ/HA) |
| CPU per request (derived) | 1 166 µs | 37 µs | 31.8× |
| Peak memory (cgroup) | **87.25 MiB** | 39.16 MiB | 2.23× (EQ/HA) |
| Backend connections opened | **141 155** (28 231 per run) | 6 106 (797 – 1 880 per run) | 23.7× |
| Backend connections per 1 000 requests | **192.85** | 1.22 | 158× |
| Responses | 731 939 × `200`, **7 473 × `502`** | 5 017 486 × `200`, 0 errors | **1.01 % failures in EQProxy** |
| Origin CPU during the run | 52.0 % | 191.5 % | — |
| Generator CPU | 46.8 % | 247.3 % | — |

Per-repetition throughput — EQProxy `6 010.2 / 5 704.0 / 5 676.4 / 5 869.8 /
5 244.6`; HAProxy `57 453.2 / 58 614.4 / 58 061.1 / 55 299.4 / 53 574.8`.
Per-repetition 502s in EQProxy: `1 716 / 2 749 / 207 / 1 727 / 1 074`.

The generator used under half a core in the EQProxy cell and ~2.5 cores in
the HAProxy cell, against a calibrated ceiling of 86 514 req/s (§4.3), so the
client was not the limit in either cell.

### S-H2-02 — HTTP/2 large payload, 1 MiB, 32 streams in flight

| Metric | EQProxy | HAProxy 3.4.6 | Ratio |
|---|---|---|---|
| Throughput | **1 490.1 MiB/s** (1 346.6 – 1 545.3) | **1 529.0 MiB/s** (1 204.4 – 1 632.5) | 0.975 (EQ/HA) |
| p50 latency | 21.08 ms | 21.56 ms | 1.02× lower in EQProxy |
| p95 latency | 34.15 ms | 31.32 ms | 1.09× higher |
| p99 latency | 40.83 ms (max 44.50) | 35.21 ms (max 40.73) | 1.16× higher |
| CPU | 297.2 % (294.6 – 301.2) | 237.5 % (195.4 – 246.8) | 1.25× (EQ/HA) |
| CPU per MiB (derived) | 1.99 ms | 1.55 ms | 1.28× |
| Peak memory (cgroup) | **179.84 MiB** | 51.86 MiB | 3.47× (EQ/HA) |
| Backend connections opened | 155 (1.16 / 1 000 req) | 474 (3.52 / 1 000 req) | 0.33× |
| Responses | 133 321 × `200`, 0 errors | 134 658 × `200`, 0 errors | — |
| Origin CPU during the run | 63.7 % | 61.4 % | — |
| Generator CPU | 338.5 % | 369.5 % | — |

Per-repetition throughput — EQProxy `1 346.6 / 1 490.1 / 1 428.7 / 1 533.5 /
1 545.3`; HAProxy `1 632.5 / 1 529.0 / 1 496.9 / 1 619.7 / 1 204.4`.

### 4.3 Generator calibration (local h2 sink, same binary)

| Calibration (campaign) | Result | Generator CPU | Sink CPU |
|---|---|---|---|
| 4×100 streams, 1 KiB (S-H2-01 campaign) | 86 514.7 req/s | 329.3 % | 292.5 % |
| 4×8 streams, 1 MiB (S-H2-01 campaign) | 1 590.5 MiB/s | 356.1 % | 320.6 % |
| 4×100 streams, 1 KiB (S-H2-02 campaign) | 79 579.6 req/s | 331.8 % | 292.3 % |
| 4×8 streams, 1 MiB (S-H2-02 campaign) | 1 555.9 MiB/s | 358.7 % | 319.1 % |

The 1 KiB sink was not a ceiling (HAProxy reached 57 453 req/s with the
client at 247 % of one core). The **1 MiB calibration is close to the
measured S-H2-02 numbers and the client ran at 338–370 % of one core**: the
S-H2-02 cells are compressed by the generator/origin pair, so its
throughput/latency comparison can distinguish a large regression but not a
2.5 % difference. This is stated with the verdict, not hidden behind it.

## 5. Verdict (BENCHMARK_PLAN §1.5 classification)

**S-H2-01 — EQProxy is Worse, and it also fails the scenario.** 0.099× the
throughput, 7.26× the p50 and 26.35× the p99 latency, 3.15× the CPU while
doing a tenth of the work (31.8× CPU per request), 2.23× the peak memory and
**1.01 % of requests answered `502`** (7 473 of 739 412). No favourable
metric. EQProxy's best run (6 010 req/s) is 8.9× below HAProxy's worst
(53 575 req/s): the spread within each product does not come close to the
gap, so this is not a noise artefact.

**S-H2-02 — Comparable on throughput and p50, Worse on the rest.** 0.975×
throughput and 1.02× better p50 are inside a cell that the generator itself
compresses (client at 3.4–3.7 of 8 vCPUs, calibration at 1 590 MiB/s), so no
win is claimed; p99 is 1.16× higher, CPU 1.25× and peak memory 3.47×. Under
the plan's rule (*“Better or Comparable on all the metrics”*) the scenario is
**Worse**, with the throughput/latency difference declared *not
distinguishable* from the harness ceiling.

Context, not excuse: the same product beat HAProxy on HTTP/1.1 in v0.6
(S-H1-04 1.14× amd64, S-H1-05 4.51×, evidence in `v06-bench/` and
`v06-bench-arm64/`) and its HTTP/3 path measured 0.668× after ADR-0014
(`v07-h3-bench.md`). The H2 loss is specific to the **h2 termination path
plus backend-pool behaviour under high stream concurrency**, and §6 shows
which part is which.

## 6. Diagnosis (measured, not inferred)

### 6.1 Backend connection churn explains the S-H2-01 collapse

The harness counts the origin's accepted connections. In S-H2-01 EQProxy opens
**192.85 backend connections per 1 000 requests** where HAProxy opens 1.22,
and every one of its five runs stops at **exactly 28 231** opened connections
— the host's ephemeral port range is `32768 60999`, i.e. **28 232 ports**. The
proxy is dialling until the port space is exhausted; the `502`s are its
`connect_failures` (`EADDRNOTAVAIL`), and the 60 s `TIME_WAIT` keeps the
space full for the rest of the run.

A concurrency sweep on the same host and image (4 connections × N streams,
1 KiB, 10 s, no campaign record — diagnostic only) localises the threshold:

| Streams/conn | In flight | EQProxy req/s | EQProxy µs CPU/req | EQProxy backend conns / 1k req | HAProxy req/s | HAProxy conns / 1k req |
|---|---|---|---|---|---|---|
| 1 | 4 | 12 036 | 152 | — | 18 345 | — |
| 8 | 32 | 31 523 | 107 | **0.1** | 50 189 | 0.4 |
| 16 | 64 | 31 883 | 111 | — | 41 417 | — |
| 32 | 128 | 15 554 | 407 | **96.3** | 52 852 | 0.5 |
| 64 | 256 | 5 495 | 1 569 | — | 41 482 | — |
| 100 | 400 | 2 344 | 3 962 | **201.3** | 49 957 | 1.1 |

EQProxy's backend idle pool is bounded at `MAX_IDLE_PER_SERVER = 64`
(`eqproxy-net/src/pool.rs:30`). Once the streams in flight exceed that bound,
connections returned while the pool is full are **closed** and the next
stream dials again: the per-request CPU jumps from 107 µs to 407 µs between
64 and 128 streams in flight, throughput falls instead of rising (31.5k →
15.5k → 5.5k → 2.3k req/s), and the dial failures start. The churn is not an
artifact of the origin: the same origin holds 400 HAProxy connections with
1.1 opens per 1 000 requests.

Every 502 has a matching line in the proxy's own log —
`ERROR [h2] could not connect to 172.21.0.2:9000 (peer …): Address not
available (os error 99)` — and the per-repetition counts match the generator
**exactly**: 1 716 / 2 749 / 207 / 1 727 / 1 074 dial errors for 1 716 /
2 749 / 207 / 1 727 / 1 074 client-side 502s. That is 7 473 error lines in
five 18 s runs: the failure is also a **log flood** (one line per refused
dial, same class as the h3 `ApplicationClose` noise in `v07-h3-bench.md` §6)
and the logging itself is inside the measured CPU.

A **diagnostic build** (the same source with only
`MAX_IDLE_PER_SERVER = 4096`; not shipped, not the artifact above) was
measured to confirm the cause rather than assume it:

| Diagnostic build, 4 conns | EQProxy req/s | Backend conns opened | Conns / 1k req | Errors |
|---|---|---|---|---|
| 32 streams, 1 KiB | 41 451 | 128 | 0.3 | 0 |
| 100 streams, 1 KiB | 37 396 | 400 | 0.9 | 0 |
| 100 streams, 1 MiB | 1 317 MiB/s | 396 | 25.4 | 0 |

With the bound above the working set the churn disappears, all 400 streams
are served over 400 stable connections, and the `502`s vanish. The product
build measured in §4 keeps the bound at 64; **the fix is not part of this
increment** (it changes a production default and needs its own decision,
test and ADR — see §11).

### 6.2 The h2→h1 translation itself costs ~2.7× HAProxy's CPU

Below the churn threshold (32 streams in flight, 1 KiB) EQProxy reaches
31 523 req/s at 107 µs CPU per request against HAProxy's 50 189 req/s at
38.9 µs: **0.63× throughput at 2.75× the CPU per request**. That is the
baseline cost of one `tokio::io::duplex` pipe of `PIPE_BUFFER = 64 KiB`, two
spawned tasks and a full h1 exchange per h2 stream (ADR-0006), and it is the
same order as the cost measured for the h3 path before ADR-0014. It is a
second, smaller gap that the churn has been hiding.

### 6.3 Memory

Peak memory is higher in EQProxy in both scenarios: 87.25 vs 39.16 MiB
(S-H2-01, where the concurrent dial/close churn also holds sockets) and
179.84 vs 51.86 MiB (S-H2-02, 32 concurrent 1 MiB exchanges). The 1 MiB
figure is ~3.5× the reference and is a product limitation, not a measurement
artifact: it comes from the per-stream pipe plus the in-flight body copy, and
it should be profiled before any memory claim is made.

## 7. Integrity checks

- `report.json` is the only source of the tables; it was produced by the
  harness and not edited.
- Every median in §4 was **recomputed independently** from the 20 `raw/*.json`
  files with a separate script; all values match exactly (throughput,
  p50/p95/p99, CPU, peak memory).
- Every run reports `proto = "HTTP/2.0"` and `sanity = "ok"`; the generator
  validates TLS against the fixture CA, the status and the exact body length
  (1 KiB / 1 MiB).
- The 502s are the product's own responses (body length 0, counted from the
  generator's status histogram), not generator-side errors, and they are
  matched **one-to-one** by EQProxy's `could not connect … Address not
  available (os error 99)` log lines in all five runs (§6.1). In the
  diagnostic run whose EQProxy counters were readable, `connect_failures`
  also equalled the client's errors exactly (428 = 428). The campaign's own
  per-interval counters were not readable (the metrics line reports a fresh
  interval), so the per-run failure count is the generator's plus the
  matching log lines.
- `logs/` holds the full container stdout/stderr of every run, unfiltered.
- The §6 diagnostic experiments are labelled as diagnostics: they ran the
  same host, image and harness but are **not** part of the published
  campaign, and the 4096 build is not the artifact under test.

## 8. Checks run

| Command | Result |
|---|---|
| `gofmt -l docs/evidence/v07-h2-bench` | clean (no output) |
| `go vet ./...` in `v07-h2-bench` | exit 0 |
| `python3 -m py_compile docs/evidence/v07-h2-bench/run.py` | exit 0 |
| `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build` (`load`, `probe`) | exit 0, static ELF x86-64 |
| `python3 docs/evidence/v07-h2-bench/run.py --reps 5 --scenarios S-H2-01 …` | exit 0, 10 runs, `run-20261023T200316Z` |
| `python3 docs/evidence/v07-h2-bench/run.py --reps 5 --scenarios S-H2-02 …` | exit 0, 10 runs, `run-20261023T201003Z` |
| median recomputation from `raw/` | exact match (all fields) |
| `cargo fmt --all --check` | exit 0 |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | exit 0 |
| `cargo test --workspace` | **414 passed, 0 failed** (no Rust source changed in this slice) |
| `veyra audit . --profile standard` | **ACCEPTED**, exit 0, evidence `.veyra/evidence/20261023T200021Z/` — rustfmt, check, clippy, test, nextest, llvm-cov, audit, deny, machete, anti-theater and `veyra-e2e` OK; `cargo-geiger` INCONCLUSIVE by its own coverage warning; dylint and semver-checks SKIPPED (no config/baseline) — nothing disabled |
| Rust Audit `scan . --format terminal,md,json,sarif --fail-on high` | exit 1: **248 findings (3 critical / 25 high / 177 medium / 43 low)**, the same critical/high set triaged in `v07-http3.md`; no Rust source changed in this slice |
| EvoForge `mcp_submit_eval` (std-only slice of the h2→h1 request translation, 4 tests) | **F = 1.0**, 4/4 tests, clippy clean, exit 0, trace `f0737ae7-a7a7-430b-9e4a-aafd7fca7dcc`. The slice is a condensed replica for the sandbox, not a substitute for §4 |

## 9. Limits and NOT EXECUTED

- **One host, components share 8 vCPUs.** The generator, both proxies, the
  origin and kernel softirq contend; per-run load averages are published
  (6.6–14.5 during the runs). Both products run under the identical topology
  and the direction of the S-H2-01 gap is far larger than any plausible
  contention effect. S-H2-02 is explicitly **ceiling-limited** (§4.3).
- **Closed-loop generator, no coordinated-omission correction.** p99 values
  are optimistic for both products.
- **Only 2 repetitions of the h2 configuration**: S-H2-01 with 4×100 and
  S-H2-02 with 4×8. Other stream counts, connection counts and payload sizes
  are not part of the published campaign (the §6 sweep is diagnostic).
- **Single architecture (amd64).** Not replicated on arm64. **NOT EXECUTED**.
- **No profiler / no flamegraph** in this campaign; §6 is arithmetic from
  measured CPU plus the origin's connection counters plus the diagnostic
  build. A CPU profile of the h2 path is **NOT EXECUTED** here.
- **The 4096-bound build is a diagnostic**, not a proposed default: it is not
  shipped, not benchmarked as a product and not a claim about the fix's cost.
- Not measured: TLS handshake CPU split, h2c (cleartext) frontends, backend
  h2 multiplexing (`ADR-0008`) in this scenario, packet loss, browsers or
  `curl` as clients, HTTP/2 priority/flow-control stress.

## 10. Reproduce

```bash
# generator and probe are committed next to this file (go.mod/go.sum pinned)
cd docs/evidence/v07-h2-bench
gofmt -l . && go vet ./... && go list -m all > go-modules.txt

# on an idle Linux evidence host with Docker:
#   docker build -f docker/Dockerfile -t eqproxy-bench:v07h2 .
#   docker pull haproxy:3.4.6
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags=-s -o load .
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags=-s -o probe ./probe

# one campaign per scenario, each starting from an idle host:
python3 run.py --reps 5 --scenarios S-H2-01 \
  --eq-image eqproxy-bench:v07h2 --load-binary ./load --probe-binary ./probe
python3 run.py --reps 5 --scenarios S-H2-02 \
  --eq-image eqproxy-bench:v07h2 --load-binary ./load --probe-binary ./probe
```

Each campaign writes `run-<UTC>/` with `report.json`, one JSON per run
(`raw/`), the exact configs, the certificate, the container logs and
`run.log`; the tables above are read from `report.json` and were re-derived
from `raw/`.

## 11. Next increment (not done here)

1. **Size the backend idle pool against the workload** instead of a fixed 64
   (`eqproxy-net/src/pool.rs`): make it explicit/configurable, bound it by
   the listener's `maxconn` or by a documented per-backend setting, keep the
   fail-closed checkin contract, and add a test that a 400-stream h2 load
   does not churn backend connections. Then repeat this campaign; the
   diagnostic build suggests S-H2-01 moves from 5.7k to a 30–40k req/s class,
   which still leaves the translation cost of §6.2 to address.
2. **Profile the h2→h1 translation** (pipe per stream, two tasks, 16 KiB
   body chunks) as ADR-0014 did for h3.
