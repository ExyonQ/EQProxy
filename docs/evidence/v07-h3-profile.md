# v0.7 — HTTP/3 per-request cost: profile, fix and S-H3-01 re-run

## 1. Objective

S-H3-01 (`v07-h3-bench.md` §4) measured EQProxy at **0.341× HAProxy 3.4.6**
(16 838.6 vs 49 323.8 req/s) with **5.2× the CPU per request**. That document
left the cause unprofiled. This increment profiles the real HTTP/3 path of the
shipped artifact, fixes the measured per-request cost and **re-runs S-H3-01
(and S-H3-02) with the same harness, criteria and generator**.

It is not a promise of parity: the re-measured verdict is reported in §8,
including the metric that got worse.

## 2. Artifacts under test

| | |
|---|---|
| Profiled artifact | image `eqproxy-bench:v07` (id `3e8ef9479fc3`), binary SHA-256 `412feb8e8ce2556fc89eae39beb77ed4c212101e2344c2e0a9dba9e70b8a2ed1` |
| Profiling build | same working tree, `CARGO_PROFILE_RELEASE_DEBUG=1` (opt-level 3, DWARF kept), built natively on the evidence host in `rust:1.97-alpine`; image `eqproxy-prof:v07` (id `af84008da04d`) |
| Fixed artifact | image `eqproxy-bench:v07b` (id `3bca2612e90d3f74`), binary SHA-256 `b4db9260ef34a2b8a87d3d8550f115913224eda12d6da49c4bd242aa8f97aa3c`, built by the unchanged `docker/Dockerfile` (`cargo build --release --locked`, musl, scratch) |
| Reference | `haproxy:3.4.6`, image id `e273915691a8`, `USE_QUIC=1`, OpenSSL 3.5.7 |
| Generator | `load.go`, quic-go 0.64.1, binary SHA-256 `f02af496e1951f59…` (unchanged from the first campaign) |
| Probe | `probe/main.go`, SHA-256 `bb546e7e235850a9…` |
| Evidence host | `netcup-bench`: Linux 6.8.0-147, x86_64, AMD EPYC 9645 (8 vCPU), 15.6 GiB, Docker 29.6.1 |
| Raw data | [`v07-h3-profile/`](v07-h3-profile/): `perf-flat-before.txt`, `perf-flat-after-mimalloc.txt`, `profile-modules.txt`, `alloc-count-after.txt`, `syscalls-strace.txt`, the A/B run JSONs; campaign [`v07-h3-bench/run-20261023T181822Z/`](v07-h3-bench/run-20261023T181822Z/report.json) |

The profiling build differs from the shipped one only by `debug = 1`; it runs
the same optimized code. Perf sampling adds overhead (the profiled run
measured 10 498.7 req/s instead of ~19 000), so **no throughput number is
taken from a profiled run**; only the relative attribution is.

## 3. Method

1. **CPU profile**: `perf record -F 1997 --call-graph dwarf,8192 -p <pid>` on
   the container's host PID, 14 s, while the standard S-H3-01 load (8
   connections × 8 streams, 1 KiB, 2 s warm-up + 12 s) ran. Frames resolved
   with `perf report` against the unstripped binary (`nm` table, 32 392
   symbols); kernel frames resolved from `/proc/kallsyms`.
2. **Allocation budget**: a measurement-only build (not shipped) installs a
   `GlobalAlloc` wrapper around the system allocator that counts `alloc`,
   `alloc_zeroed`, `realloc` and `dealloc`, and prints cumulative counters
   every 2 s. Allocation count and bytes per request are the delta over the
   measured window divided by the generator's request count.
3. **Syscall shape**: `strace -c -f` on the process for 18 s of load. The
   ptrace overhead collapses throughput (3 876 req/s), so the table is used
   as a **shape** (which syscalls dominate the process), never as a rate.
4. **A/B of the fix**: the same 12 s S-H3-01 load, same host, alternating
   builds, CPU from the container's cgroup v2 `cpu.stat`, p50/p99 from the
   generator.
5. **Re-measurement**: the unmodified harness, 5 repetitions per product,
   alternating order, both scenarios, all 20 runs validated (`errors = 0`,
   `sanity = ok`, status 200 only).

## 4. Profile of the pre-fix artifact

Self time, 129 714 samples (`perf-flat-before.txt`):

| # | Symbol | Self | What it is |
|---|---|---|---|
| 1 | `__lock` | 5.66 % | musl malloc group lock, spin |
| 2 | `__libc_free` | 4.75 % | musl free |
| 3 | `__pv_queued_spin_lock_slowpath` | 4.29 % | kernel lock, reached from `futex_wake` |
| 4 | `memcpy` | 4.03 % | copies (pipe, QUIC, kernel) |
| 5 | `asm_sysvec_call_function` | 3.13 % | IPIs (TLB/CPU sync) |
| 6 | `asm_sysvec_call_function_single` | 2.88 % | IPIs |
| 7 | `asm_sysvec_apic_timer_interrupt` | 2.79 % | timer IRQs |
| 8 | `__unlock` | 2.61 % | malloc unlock → `__wake` |
| 9 | `__libc_malloc_impl` | 2.49 % | musl malloc |
| 10 | `_raw_spin_lock` | 2.44 % | kernel spin lock |
| 11 | `__raw_callee_save___pv_queued_spin_unlock` | 2.03 % | kernel unlock |
| 12 | `futex_wake` | 1.97 % | waking blocked threads |
| 13 | `smp_call_function_many_cond` | 1.22 % | IPI sender |
| 14 | `alloc_slot` | 1.12 % | musl mallocng |
| 15 | `calloc` | 0.98 % | zeroed allocation |
| 16 | `__seccomp_filter` | 0.81 % | Docker seccomp on every syscall |

Aggregated: **allocator self time ≈ 18 %**, and the kernel path it drives
(spinlock slowpath + raw locks + unlock + `futex_wake`) adds ≈ 11 %, i.e.
**~29 % of all CPU in allocating and waking**. `40.16 %` of samples have
`entry_SYSCALL_64_after_hwframe` in their stack (inclusive), consistent with
a path that allocates inside many short syscall-bound steps.

The call tree shows the mechanism: `__unlock` has `__wake` as a child in
18.85 % of samples and `futex_wake` in 8.07 % — frees are not local to the
thread that allocated, so musl's lock hands off and wakes waiters.

Allocation budget, pre-fix build, 12 s S-H3-01 window (18 815 req/s):

| Metric | Value |
|---|---|
| Allocations per request | **108** |
| Bytes allocated per request | 34 KiB |
| Bytes zeroed per request | 44 KiB |
| Free calls per request | ~98 (rest still live) |

`strace -c` shape (76 207 requests, throughput degraded by ptrace):
`futex` 1 837 164, `sendmsg` 43 471, `munmap` 16 795, `mmap` 16 797,
`epoll_pwait` 5 473, `write` 664. The `futex` mass and the `mmap/munmap`
pairs are the allocator, not application I/O.

The h1 engine and the translation functions are **not** the hot spot: the
engine's `serve_http` appears at 0.53 % self, `exchange` at 0.52 %. Removing
application-level work alone could not have moved the 0.341×.

## 5. What was changed

Two independent fixes, each measured separately.

### 5.1 Global allocator — mimalloc 0.1.52 (ADR-0014)

`eqproxy-cli/Cargo.toml` adds `mimalloc = { version = "0.1",
default-features = false }`; `eqproxy-cli/src/main.rs` installs
`#[global_allocator] static GLOBAL: mimalloc::MiMalloc` with the reasoning
inline. mimalloc keeps per-thread free lists: the 108 allocations/request stop
contending on one lock and cross-thread frees stop waking waiters. No
`unsafe` is written in this repository (the trait impl lives in the crate).

Isolated A/B (same source, allocator only), 12 s:

| Build | Throughput | p50 | Errors |
|---|---|---|---|
| musl malloc | 18 815.0 req/s | 3.00 ms | 0 |
| mimalloc | **26 190.0 req/s** (+39 %) | **2.15 ms** | 0 |

### 5.2 HTTP/3 translation (`eqproxy-net/src/http3.rs`)

1. **Body-less requests relay inline.** When the request head carried
   END_STREAM nothing else can arrive from the client, so the h1 answer is
   read and written to the h3 stream in the stream task itself — no relay
   task, no bounded command channel, no timer per step. The `Sink` enum routes
   the same `relay_inner` logic either to the channel (request body still
   streaming) or directly to the stream. Requests with a body keep the two-task
   design unchanged.
2. **Exact-size chunk buffers.** `read_bytes` reads into a `BytesMut` of the
   chunk's own size and `freeze()`s it: a 1 KiB response allocates 1 KiB
   (previously a 16 KiB zeroed `vec![]` plus a second full copy into `Bytes`).
   `Bytes::copy_from_slice` and the 16 KiB `DATA_CHUNK` scratch buffer are gone
   from the response path.
3. **Pipe 64 KiB → 16 KiB.** One head plus one DATA chunk fit; the larger pipe
   only allocated more per exchange.

After the change the same probe counts **111 allocations/request, 32.6 KiB
allocated, 32.8 KiB zeroed** (`alloc-count-after.txt`): the zeroed bytes fell
by 11 KiB/request and the copies by one per chunk, while the allocation
*count* is unchanged because most of the 111 come from quinn, h3 and the h1
engine, not from the translation.

### 5.3 Combined A/B

Both builds, same host, same 12 s load, back to back:

| Build | Throughput | p50 | p99 | CPU | CPU/request | Errors |
|---|---|---|---|---|---|---|
| `v07` (before) | 18 403.7 req/s | 3.26 ms | 8.06 ms | 352 % | 205 µs | 0 |
| `v07b` (after) | **32 587.4 req/s** | **1.73 ms** | **5.22 ms** | **271 %** | **88 µs** | 0 |

+77 % throughput, −47 % p50, −57 % CPU per request. Raw JSONs:
`ab-v07-old.json`, `ab-v07b-new.json`.

## 6. Re-measurement — S-H3-01 / S-H3-02

`python3 run.py --reps 5 --load-binary bin/load --probe-binary bin/probe
--eq-image eqproxy-bench:v07b` → [`run-20261023T181822Z`](v07-h3-bench/run-20261023T181822Z/report.json).
Host load at start: 0.59 (1 min), 2.50 (5 min) — the 5/15-minute averages
still carried the image build; both products ran under the same condition and
the order alternated. **All 20 runs: 0 errors, every response 200 with a
1 024-byte body.**

### S-H3-01 — HTTP/3, 1 KiB, 64 streams in flight

| Metric | EQProxy `v07b` | HAProxy 3.4.6 | Ratio |
|---|---|---|---|
| Throughput | **32 941.3 req/s** (28 878.3 – 36 142.6) | **49 279.1 req/s** (47 710.6 – 51 015.3) | 0.668 (was 0.341) |
| p50 | 1.69 ms | 1.05 ms | 1.61× higher (was 3.38×) |
| p95 | 3.90 ms | 3.06 ms | 1.27× higher |
| p99 | 5.42 ms | 4.39 ms | 1.23× higher (was 1.99×) |
| CPU | 268.7 % | 197.8 % | 1.36× (was 1.77×) |
| CPU per request (derived) | **81.6 µs** | 40.1 µs | 2.03× (was 5.2×) |
| Peak memory | 44.93 MiB | **32.55 MiB** | **1.38× worse (was 0.28×)** |
| Origin CPU / generator CPU | 138.1 % / 227.2 % | 154.6 % / 300.0 % | — |

Per repetition, EQProxy: `32 941.3 / 28 878.3 / 30 680.6 / 35 052.9 /
36 142.6`; HAProxy: `47 710.6 / 48 837.9 / 50 448.1 / 49 279.1 / 51 015.3`.
The spread is larger than before (the host was still settling from the image
build) but no EQProxy run reaches the HAProxy minimum.

### S-H3-02 — HTTP/3 massive handshake, 16 concurrent dials (supplementary)

| Metric | EQProxy `v07b` | HAProxy 3.4.6 | Ratio |
|---|---|---|---|
| Handshakes/s | 1 298.3 (1 239.0 – 1 349.7) | 1 835.2 (1 680.1 – 1 885.5) | 0.707 (was 0.739) |
| p50 | 12.20 ms | 7.82 ms | 1.56× higher (was 1.49×) |
| CPU | 113.6 % | 205.6 % | 0.553× |
| Peak memory | 58.27 MiB | **37.24 MiB** | 1.56× worse |

The handshake path is untouched by this increment and remains single-core
bound; 0.707 vs 0.739 is within the drift between the two campaigns (the host
was also faster overall: HAProxy 1 835 vs 1 637 hs/s). **No improvement is
claimed for S-H3-02.**

## 7. Generator calibration

Local quic-go h3 sink, same binary: 45 250.5 req/s (generator 268 % of one
core) and 1 465.4 handshakes/s. HAProxy reached 49 279 req/s, above the sink
figure, so the generator was not the ceiling.

## 8. Honest verdict

**Still Worse on both scenarios, substantially closer on S-H3-01.**

- S-H3-01: **0.341× → 0.668×** throughput; CPU per request **205 µs → 82 µs
  (−60 %)**; p50 3.38× → 1.61× behind; p99 1.99× → 1.23× behind.
- The remaining gap is no longer allocator lock contention: with mimalloc the
  flat profile is led by `memcpy` (7.7 %), `mi_free` (2.6 %),
  `_mi_page_free_collect` (2.6 %) and `_mi_page_malloc_zero` (2.0 %), i.e.
  copies and the allocator's own bookkeeping, with quinn/h3 protocol work and
  the h1 round trip behind them (`perf-flat-after-mimalloc.txt`).
- **Memory regressed and is now the losing metric**: 44.93 MiB vs HAProxy's
  32.55 MiB (previously 9.23 MiB). mimalloc keeps per-thread heaps; the
  trade-off is disclosed rather than hidden, and it is the one number that
  moved in the wrong direction.
- S-H3-02 is **not** improved and is reported as such.
- By the `BENCHMARK_PLAN` §1.5 classification this is **Worse**, not
  Comparable: the medians differ by 33 % and every EQProxy run is below every
  HAProxy run.

## 9. Limits and NOT EXECUTED

- **One host, components share 8 vCPUs**, and this campaign started 30 s after
  the image build finished (1-minute load 0.59, 5-minute 2.50). Absolute
  numbers are host-limited; the comparison is valid because both products ran
  under the same conditions, alternating.
- **Perf profiling distorts absolute throughput** (10 498 req/s under DWARF
  sampling); only the relative distribution is used.
- **Allocation counts come from a measurement-only build** (counting global
  allocator, not shipped). It adds atomic increments per allocation; counts
  are exact, timings from that build are not used.
- `strace -c` numbers are a shape, not a rate (ptrace collapses throughput).
- **Closed-loop generator, no coordinated-omission correction**; p99 is
  optimistic for both products.
- **Single architecture (amd64)**. arm64 not run: **NOT EXECUTED**.
- **0-RTT and session resumption** not exercised in either direction.
- **S-H2-01/S-H2-02** were measured later on 2026-10-23 and then re-measured
  after the backend-pool fix: S-H2-01 0.742×, S-H2-02 1.081×, both with zero
  `502`s ([v07-h2-pool-sizing.md](v07-h2-pool-sizing.md)). No figure from the
  HTTP/3 runs is reused there.
- `perf` data files (~100 MB) are **not** committed; the text reports and the
  exact reproducer are.

## 10. Checks run

| Command | Result |
|---|---|
| `cargo fmt --all --check` | clean |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean |
| `cargo test --workspace` | **414 passed, 0 failed, 2 ignored** (HTTP/3 E2E 7/7; no test changed) |
| E2E S-H3-01/S-H3-02 campaign | 20/20 valid runs, 0 errors, only status 200 |
| `veyra audit . --profile standard` | run 1 **REJECTED** (exit 1): `cargo-llvm-cov` failed because `interim_1xx_is_forwarded_and_never_desyncs_keepalive` hit its 5 s receive timeout under instrumentation. Diagnosis: the same test passes twice in isolation under `cargo llvm-cov` (and in the uninstrumented suite), so it is a parallel-load flake of the coverage run, not a code path touched here. Run 2 **ACCEPTED**, exit 0, `.veyra/evidence/20261023T184725Z/` (geiger INCONCLUSIVE by its own coverage warning, dylint/semver-checks SKIPPED for lack of config/baseline as before; nothing disabled) |
| Rust Audit `scan . --format … --fail-on high` | exit 1: **248 findings (3 critical / 25 high / 177 medium / 43 low)**, the same classes triaged in `v07-http3.md`; `http3.rs` carries 7 medium `let _ =`/`.ok()` discards (the codebase's existing pattern in those branches), no new high or critical. Report `report/rust-audit-20261023-205556.json` |
| EvoForge `mcp_submit_eval` | first attempt **F = 0.0**: 5/5 tests passed but clippy rejected `Result<_, ()>` in the sandbox replica; after mirroring the real code's typed error, **F = 1.0**, 5/5 tests, clippy clean, exit 0, trace `1ab6fdad-71bd-4a51-9ff5-455ce9d81e64`. Condensed replica of the relay/sink contract, not a substitute for the campaign |
| Hindsight note | stored in bank `eqproxy` (see §11) |

## 11. Memory close-out (Hindsight)

Note stored in the project's own bank `eqproxy` (`status: completed`), memory
ids `25704ac5-125d-42eb-b88d-e3454a8561ce`, `08d16349-725e-4a60-ad67-c3712d4f439c`,
`83708000-dd55-47bd-ab17-519518c3189f`, `1fc55989-7795-4ebc-9c57-768faf54ce13`.

## 12. Reproduce

```bash
# profiling build (same code, DWARF kept)
docker run --rm -v "$PWD:/src" -w /src -e CARGO_PROFILE_RELEASE_DEBUG=1 \
  rust:1.97-alpine sh -c 'apk add --no-cache musl-dev cmake make gcc g++ perl \
  linux-headers && cargo build --release --locked -p eqproxy-cli'

# profile (on the evidence host, container already running)
perf record -F 1997 --call-graph dwarf,8192 -o perf.data -p "$(docker inspect -f '{{.State.Pid}}' eq) " -- sleep 14
perf report --stdio --no-children -g none --sort symbol -i perf.data

# allocation budget: measurement-only `GlobalAlloc` wrapper, then
docker run ... -mode load -url https://eq:19443/ -cacert /certs/cert.pem \
  -conns 8 -streams 8 -warmup 2s -duration 12s

# campaign
cd docs/evidence/v07-h3-bench
python3 run.py --reps 5 --load-binary bin/load --probe-binary bin/probe \
  --eq-image eqproxy-bench:v07b
```
