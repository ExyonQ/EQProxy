# v0.7 — h3 clean-close classification: E2E and S-H3-02 before/after

Language: **English**.

The HTTP/3 campaign in [`v07-h3-bench.md`](v07-h3-bench.md) §8 disclosed a
confounder it could not remove: EQProxy wrote one
`WARN [h3] HTTP/3 connection error … ApplicationClose: 0x0` line for **every
connection a client closed cleanly**, so a handshake-heavy scenario flooded
the log and counted normal session ends as protocol errors. This increment
classifies the close (RFC 9114 §8.1 `H3_NO_ERROR`, or QUIC application code
`0`, is a normal end), verifies it on the release binary with an independent
client, and measures S-H3-02 before and after on the evidence host.

The measurement's verdict is **not** "the fix made it faster": the handshake
rate moved +6.4 % between the two clean campaigns while the HAProxy control
moved −4.4 % on the same scenario, so the throughput change is inside the
drift. What the data does establish is the size of what the fix removed —
**15 227 → 26 WARN lines** per 10 s run, **1.67 MiB → 5.08 KiB** of log — at
the same offered load.

## 1. What changed

| File | Change |
|---|---|
| `eqproxy-net/src/http3.rs` | `classify_h3_close` decides with the QUIC close reason (kept next to the h3 connection): `H3_NO_ERROR` or application code `0` counts `h3_clean_closes` and logs nothing; any other end (protocol code, transport error, stateless reset, timeout) counts `h3_connection_errors` and logs one `WARN` with the cause. Applied to both ends: the h3 handshake builder and `h3_connection.accept()`. |
| `eqproxy-core/src/metrics.rs` | `h3_clean_closes` counter; the periodic line reads `h3[clean_closes=N connection_errors=M]`. |
| `eqproxy-net/src/http3.rs` (tests) | Unit tests one close code at a time: `H3_NO_ERROR`, code `0`, code `0x0100`, and a protocol code, a transport error and a missing reason all stay errors; the two operator lines are asserted verbatim. |
| `eqproxy-net/tests/e2e_http3.rs` | Dataplane E2E: clean closes are counted clean and leave no `WARN`, a protocol-error close is still an error. |

The QUIC handshake itself is a **different** path: a client that aborts the
QUIC connection before the h3 handshake exists is still
`tls_handshake_failures` and still logs
`WARN [h3] failed QUIC handshake …`, because no h3 session was there to close.

## 2. Artifacts under test

| | |
|---|---|
| Functional check binary | `target/release/eqproxy`, SHA-256 `a902bce9e8ab0e50f4063e2bf757fa12f76f1e2d2e46f08456aa5c9b35f33059` |
| Before image | `eqproxy-bench:v07c-pre`, id `07e7753a7df4926c`, built 2026-10-24T00:07:12Z; binary SHA-256 `c02f2938985823099cd2300425bff2912c41def532ed3e66d708c4e8c33b6000` |
| After image | `eqproxy-bench:v07c`, id `cbdbd07a05c40b65`, built 2026-10-24T00:04:34Z; binary SHA-256 `b8fae6d85b8bc0ee8ad041fe4e0c596f5968ca9727748824713143d10931d6ff` |
| Version | `eqproxy 0.6.3`, both images |
| Reference | `haproxy:3.4.6`, id `e273915691a8` |
| Generator | `load.go`, quic-go 0.64.1, SHA-256 `f02af496e1951f598d6048c3d31926d1ea2a6995ce2cdb6765251840d142eade` |
| Probe | `probe/main.go`, SHA-256 `bb546e7e235850a919620ba984d3eed6f49ed01902bb75858dd192318b4da864` |
| Evidence host | `netcup-bench`: Linux 6.8.0-147-generic, x86_64, AMD EPYC 9645 (8 vCPU exposed), 15.6 GiB, Docker 29.6.1 |
| Raw data | `run-20261024T001018Z` (pre), `run-20261024T002632Z` (post), plus the two campaigns §6 excludes — all under [`v07-h3-bench/`](v07-h3-bench/) — and the functional run in [`v07-h3-close/`](v07-h3-close/) |

Both benchmark images are **amd64 builds made on `netcup-bench` from one
source tree** — the repository working tree at 2026-10-24T00:0xZ. The only
difference between them is §3. Two earlier artifacts carried the same tags and
are **not** the ones measured here: the macOS arm64 images (`26baca13a64a`
for `v07c-pre`, `3ec381edc46b` for `v07c`), and the netcup image the H2 pool
campaign cites as `v07c` (`934f8a46f7a9`, no longer on the host — see
[`v07-h2-pool-sizing.md`](v07-h2-pool-sizing.md) §3).

## 3. The exact difference between the two images

The before image is the after tree with the classification disabled, so the
A/B isolates it and nothing else:

```diff
--- eqproxy-net/src/http3.rs (after)
+++ eqproxy-net/src/http3.rs (before)
     ) {
+    // PRE-FIX BUILD (measurement only): the clean-close classification is
+    // disabled, so every ended session counts as an error and logs one line --
+    // the behaviour the S-H3-02 campaign measured before the fix.
         let reason = quic.close_reason();
-        if is_normal_h3_close(err.is_h3_no_error(), reason.as_ref()) {
-            metrics.h3_clean_closes.fetch_add(1, Ordering::Relaxed);
-            return;
-        }
         metrics.h3_connection_errors.fetch_add(1, Ordering::Relaxed);
```

`is_normal_h3_close` stays compiled (`#[allow(dead_code)]`) so the unit tests
that pin its behaviour keep compiling; the shipped image still builds through
the unchanged `docker/Dockerfile` (`cargo build --release --locked`, musl,
scratch).

## 4. Functional check on the release binary

`python3 docs/evidence/v07-h3-close/run.py` with `aioquic` 1.2.0 as the client
(independent QUIC + h3 + QPACK stack), against `a902bce9…`:

| Step | Close | Result |
|---|---|---|
| `clean_close_after_request` | application code `0` | `200`, body `hello from origin`, **0 WARN** |
| `h3_no_error_close` | `H3_NO_ERROR` (`0x0100`) | **0 WARN** |
| `protocol_error_close` | `H3_GENERAL_PROTOCOL_ERROR` (`0x101`) | exactly **1 WARN**, the real error, quoted below |
| `served_after_closes` | — | `200`, body `hello from origin` |

Final counters: `h3[clean_closes=3 connection_errors=1]`, `client[accepted=4
completed=4 protocol_errors=0]`, proxy exit 0. Raw output:
[`v07-h3-close/run-20261023T204312Z/summary.txt`](v07-h3-close/run-20261023T204312Z/summary.txt)
and `results.json` next to it.

```
WARN [h3] HTTP/3 connection error (peer 127.0.0.1:50404): Remote error: \
ApplicationClose: H3_GENERAL_PROTOCOL_ERROR [closed by peer: protocol error (code 257)]
```

The earlier `run-20261023T204259Z` in the same directory stopped after startup
and produced no results; it is kept as the aborted attempt, not as evidence.

## 5. S-H3-02 — before and after, clean pair

Same harness, same generator binary, same topology, 5 repetitions per product,
order alternated per repetition, one scenario pair per campaign. Campaign
start load (1-minute average) 0.28 (before) and 0.13 (after).

| Metric (median of 5) | Before (`v07c-pre`) | After (`v07c`) | Change |
|---|---|---|---|
| Handshakes/s | **1 251.5** (1 230.3 – 1 409.7) | **1 331.7** (1 251.8 – 1 430.0) | +6.4 % |
| Handshake p50 | 12.56 ms | 11.95 ms | −4.9 % |
| Handshake p95 | 20.34 ms | 18.60 ms | −8.6 % |
| Handshake p99 | 24.57 ms | 22.44 ms | −8.7 % |
| Proxy CPU | 113.5 % of one core | 112.1 % | −1.2 % |
| Proxy peak memory | 57.79 MiB | 57.71 MiB | −0.1 % |
| **WARN lines per run** | **15 227** | **26** | **−99.83 %** |
| **Log written per run** | **1.67 MiB** | **5.08 KiB** | **−99.70 %** |
| WARN per 1 000 handshakes | **1 206.0** | **2.0** | −99.83 % |
| Log bytes per 1 000 handshakes | **138 873** | **391** | −99.72 % |
| Ratio vs HAProxy (same campaign) | 0.691 | 0.768 | — |

Per run (`raw/S-H3-02-eqproxy-rep*.json` and `logs/…`):

| Before | hs/s | p50 | p99 | CPU | peak MiB | WARN | log KiB |
|---|---|---|---|---|---|---|---|
| rep1 | 1 230.3 | 12.85 | 24.57 | 113.5 | 57.09 | 14 758 | 1 659.7 |
| rep2 | 1 409.7 | 11.31 | 21.57 | 112.5 | 60.64 | 16 981 | 1 909.9 |
| rep3 | 1 237.1 | 12.56 | 26.78 | 114.1 | 58.46 | 15 135 | 1 702.0 |
| rep4 | 1 251.5 | 12.62 | 24.81 | 114.2 | 54.07 | 15 227 | 1 712.3 |
| rep5 | 1 358.9 | 11.70 | 22.17 | 113.2 | 57.79 | 16 139 | 1 814.4 |

| After | hs/s | p50 | p99 | CPU | peak MiB | WARN | log KiB |
|---|---|---|---|---|---|---|---|
| rep1 | 1 331.7 | 11.95 | 22.98 | 111.6 | 54.76 | 27 | 5.2 |
| rep2 | 1 251.8 | 12.62 | 24.86 | 112.8 | 57.71 | 33 | 6.2 |
| rep3 | 1 411.1 | 11.28 | 21.91 | 111.8 | 58.95 | 25 | 4.9 |
| rep4 | 1 430.0 | 11.14 | 21.36 | 112.1 | 59.20 | 21 | 4.3 |
| rep5 | 1 323.9 | 12.00 | 22.44 | 112.8 | 56.09 | 26 | 5.1 |

Every one of the 20 runs is valid (`errors = 0`, `sanity = ok`, status 200
only); the harness raises rather than record an invalid measurement.

### What the 26 remaining lines are

All of them are `WARN [h3] failed QUIC handshake … aborted by peer: the
application or application protocol caused the connection to be closed during
the handshake` — the client's closed-loop dials that gave up before the QUIC
handshake completed. No h3 session existed, so the h3 classification does not
apply; they stay a handshake failure and a log line. Before the fix the same
shape was there **on top of** the flood:

| Message (sum of 5 runs, before) | Count |
|---|---|
| `failed HTTP/3 handshake … ApplicationClose: 0x0` | 77 094 |
| `HTTP/3 connection error … ApplicationClose: 0x0` | 1 003 |
| `failed QUIC handshake … aborted by peer` | 143 |

After: 132 `failed QUIC handshake` and nothing else.

## 6. Why +6.4 % is not claimed as a speedup

The control in each campaign is HAProxy on the same host, measured in the same
repetition order. Between the two clean campaigns it moved **−4.4 %** on
S-H3-02 (1 812.0 → 1 733.0 hs/s) and **+1.1 %** on S-H3-01 (56 040 →
56 673 req/s). The two EQProxy ranges overlap (1 230–1 410 before,
1 252–1 430 after, and the before campaign's best run, 1 409.7, beats the
after campaign's median). So the honest reading is: **no throughput effect
attributable to the fix beyond host drift**, measured at the same offered
load — and the campaign still places EQProxy at 0.69–0.77× HAProxy on this
scenario, unchanged from [`v07-h3-profile.md`](v07-h3-profile.md).

Two further campaigns were run and are reported, not used:

| Campaign | Start load | EQProxy S-H3-02 median | HAProxy control | Why it is not in the verdict |
|---|---|---|---|---|
| `run-20261024T001614Z` | 7.00 | 1 328.7 hs/s (0.721) | 1 842.3 | Started while the previous campaign's load average was still decaying (§7); its median agrees with the clean after-run, so it does not contradict anything |
| `run-20261024T003532Z` | 0.28 | 989.5 hs/s (0.610) | 1 621.4 | The host degraded mid-campaign: from repetition 3 the **HAProxy control** itself fell from 1 899.1 to 1 417.5 and then 972.3 hs/s, so the campaign measures the host, not the image |

## 7. Method notes and disclosures

- The unchanged `run.py` runs **both** scenarios in one campaign; S-H3-01 is
  therefore measured alongside and serves as the second drift control. The
  question of this document is S-H3-02.
- One harness change was made before these campaigns: the `topology`
  disclosure string was hard-coded to "one macOS host; Docker Desktop VM
  (10 vCPU, 8 GiB)", which the two earlier **netcup** campaigns
  (`run-20261023T134656Z`, `run-20261023T181822Z`) therefore carry
  incorrectly. It now derives from `host_info()` (uname, CPU model, CPUs,
  Docker limits). No measurement, threshold or scenario was touched.
- Generator headroom on this host, measured against a local h3 sink in the
  same campaign: `handshake_c16` **1 558.1** hs/s (before) and **1 589.7**
  hs/s (after) at ~199 % of one core. The best EQProxy run in each campaign
  comes within about 10 % of its own calibration (1 409.7 of 1 558.1 and
  1 430.0 of 1 589.7 hs/s), so a large unexplained gain could not have shown
  even before the HAProxy control is consulted — the second reason the
  throughput claim stays at "inside the drift".
- Log volume is measured on the bytes Docker captured from the proxy's stdout
  and stderr, exactly the stream an operator's log pipeline receives. The
  `logs/*.log.gz` artifacts are that stream gzipped for storage, as in the
  earlier campaigns in this directory; the byte counts and WARN counts in §5
  are the uncompressed stream (the resummariser reads both forms).

## 8. Exact commands

```bash
# source tree -> evidence host (source only; the images are built there)
rsync -a --exclude target --exclude .git --exclude .codegraph --exclude .veyra \
  --exclude report ./ netcup-bench:/root/eqproxy-h3-src/
scp /tmp/h3bench-amd64/{load,probe} netcup-bench:/root/h3bench-bin/

# after image
ssh netcup-bench 'cd /root/eqproxy-h3-src && docker build -f docker/Dockerfile \
  -t eqproxy-bench:v07c .'
# before image = the same tree with §3 applied, in /root/eqproxy-h3-pre
ssh netcup-bench 'cd /root/eqproxy-h3-pre && docker build -f docker/Dockerfile \
  -t eqproxy-bench:v07c-pre .'

# two campaigns per image, each preceded by a wait for 1-minute load < 0.30
ssh netcup-bench 'cd /root/eqproxy-h3-src && python3 \
  docs/evidence/v07-h3-bench/run.py --reps 5 --eq-image eqproxy-bench:v07c-pre \
  --load-binary /root/h3bench-bin/load --probe-binary /root/h3bench-bin/probe'
ssh netcup-bench 'cd /root/eqproxy-h3-src && python3 \
  docs/evidence/v07-h3-bench/run.py --reps 5 --eq-image eqproxy-bench:v07c \
  --load-binary /root/h3bench-bin/load --probe-binary /root/h3bench-bin/probe'

# the tables above, from the run directories only
python3 docs/evidence/v07-h3-bench/summarize-close-ab.py \
  run-20261024T001018Z run-20261024T002632Z \
  run-20261024T001614Z run-20261024T003532Z
```

## 9. Limits and NOT EXECUTED

- **One host, one topology.** 8 vCPU, everything on one bridge network, no
  host port publishing; the generator and both proxies share the CPUs. No
  multi-host, no NIC, no kernel-tuned comparison.
- **Closed-loop generator, no coordinated-omission correction**, and the
  handshake calibration (1 558–1 590 hs/s) is only ~1.2× the result, so this
  scenario cannot resolve a larger speedup.
- **Throughput is not attributed to the fix** (§6). What is attributed is the
  log and error-accounting change, which is deterministic and was checked on
  every one of the 20 runs.
- **h3 counters at the end of a run are not in the campaign logs**: the proxy
  prints `METRICS` every 30 s by default and each run lasts 12 s, so the
  captured line is the startup one. The counters are proven by the functional
  run (§4, `h3[clean_closes=3 connection_errors=1]`), not by the benchmark.
- **Not re-measured:** S-H2-01/02 against these images, Docker Scout, the
  release gate. `S-H3-01` is re-measured only as a control and is published in
  the run directories, not promoted here.
