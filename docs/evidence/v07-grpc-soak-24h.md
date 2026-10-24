# v0.7 gate — gRPC bidi 24-hour soak

Language: **English**. Evidence for the version gate box «gRPC bidi estable
24 h en soak». Collected on the same host and artifact as
[slice 7](v07-grpc.md).

## 1. Status

<!-- soak:verdict:start -->
**PASS — the full window completed, closed 2026-10-23T23:09:55Z.** 86400.0 s of 86400.0 s, 4267 messages, 0 broken streams, 0 failed probes, final grpc-status OK, p50 0.99 ms / p99 17.44 ms / max 413.41 ms, proxy RSS 3568 KiB, binary sha256 `0672763af6afad189cd24fa6f30673b2bd3a02f3d90c467cffc23f79daab6dd6`.

Raw artifacts (`checkpoint.jsonl`, `events.jsonl`, `proxy.log`, `final.json`) are the evidence; this line only transcribes them.
<!-- soak:verdict:end -->

| State | Meaning |
|---|---|
| RUNNING | the process is alive and `checkpoint.jsonl` keeps growing; no verdict |
| PASS | `final.json` with `verdict: PASS`: full 86 400 s, 0 broken streams, 0 failed probes, final `grpc-status: OK` |
| FAIL | `final.json` with `verdict: FAIL` and the reason (broken stream, failed probe, proxy exit, early end) |

A run that is stopped, suspended with the machine, or that loses a stream
writes that event and ends as **FAIL**; it is never rounded up to a pass.

## 2. Artifact under test

| Item | Value |
|---|---|
| Binary | `target/release/eqproxy`, sha256 `0672763af6afad189cd24fa6f30673b2bd3a02f3d90c467cffc23f79daab6dd6` (`cargo build --release -p eqproxy-cli`) |
| Real gRPC stack | `grpcio` 1.66.1 / `grpc-c` 43.0.0, Python 3.9.6 |
| Host | macOS 26.5.1 arm64, loopback |
| Harness | `scripts/evidence/v07-grpc/soak.py` (maintainer-local, not published) |
| Final evidence | [`v07-grpc/soak-24h/`](v07-grpc/soak-24h/): `meta.json`, `checkpoint.jsonl`, `events.jsonl`, `proxy.log`, `runner.log`, `soak.pid`, `watch.pid`/`watch.log` (the automatic close-out), plus `final.json`, `verdict.md` and `verdict.json` written at close |
| Design | [ADR-0011](../adr/0011-grpc-http2-passthrough.md) |

## 3. What the run does

The origin is a genuine `grpcio` TLS server (ALPN h2, fixture certificate);
the client is `grpcio` over h2c to the release binary, which talks TLS/h2 to
the origin with `alpn = ["h2"]`, `idle_timeout = 120s` and no
`max_stream_duration` cap. One bidirectional stream stays open for the whole
24 h:

- one message every **20 s** (`tick-N`), and the echo is required before the
  next one — a missed echo is recorded as a broken stream, never retried
  silently;
- every **60 s** a **separate** short stream (`probe-N`) proves the proxy
  still accepts new streams while the long one is in flight;
- every **60 s** a checkpoint with the message count, drops, probe results,
  RTT p50/p99/max and the proxy's RSS, fsynced to `checkpoint.jsonl`;
- the proxy runs with `--metrics-interval 1h`, so `proxy.log` collects 25
  real metric snapshots (one at startup, one per hour: `grpc[streams=…
  errors=…]`, connections, timeouts) that expose a leak or a slow resource
  drift over the day.

## 4. Harness validation before the real run

The harness was not trusted on inspection: it was executed end to end with
real traffic first, and it completed and produced verdicts on its own.

| Run | Command | Result |
|---|---|---|
| Harness check | `soak.py --hours 0.03 --interval 2 --probe 10 --checkpoint 10 --outdir /tmp/soak-selftest` | **PASS**, 108.0 s, 53 messages, 10 probes OK, 0 drops, final status OK, p50 1.03 ms |
| After the RSS fix | `--hours 0.012 --interval 2 --probe 5` | **PASS**, 43.8 s, 21 messages, 7 probes OK, proxy RSS 8 608 KiB recorded |
| Detached mode | `--hours 0.03 … --detach` | the process reparents to PID 1, survives the launching shell, writes the 108 s run's `final.json` (PASS, 51 messages, 17 probes, final status OK, RSS 7 408 KiB) |

The three numbers above are from `/tmp` run directories, not from the 24-hour
gate; they validate the instrument, they are not the gate.

## 5. Final evidence (written by the soak and its close-out)

The first and the last checkpoints, verbatim from
[`v07-grpc/soak-24h/checkpoint.jsonl`](v07-grpc/soak-24h/checkpoint.jsonl):

```json
{"at": "2026-10-22T23:10:36Z", "drops": 0, "elapsed_seconds": 60.3, "last_rtt_ms": 0.81, "max_rtt_ms": 64.42, "messages": 4, "p50_rtt_ms": 1.75, "p99_rtt_ms": 64.42, "probes_failed": 0, "probes_ok": 1, "proxy_alive": true, "proxy_rss_kb": 7104, "remaining_seconds": 86339.7}
{"at": "2026-10-23T23:08:51Z", "drops": 0, "elapsed_seconds": 86355.2, "last_rtt_ms": 1.15, "max_rtt_ms": 413.41, "messages": 4265, "p50_rtt_ms": 0.99, "p99_rtt_ms": 17.44, "probes_failed": 0, "probes_ok": 1420, "proxy_alive": true, "proxy_rss_kb": 3936, "remaining_seconds": 44.8}
{"final": {"binary_sha256": "0672763af6afad189cd24fa6f30673b2bd3a02f3d90c467cffc23f79daab6dd6", "drops": 0, "duration_seconds": 86400.0, "elapsed_seconds": 86400.0, "final_stream_status": "OK", "finished_at": "2026-10-23T23:09:36Z", "interval_seconds": 20.0, "last_rtt_ms": 1.08, "max_rtt_ms": 413.41, "messages": 4267, "p50_rtt_ms": 0.99, "p99_rtt_ms": 17.44, "probes_failed": 0, "probes_ok": 1420, "proxy_rss_kb": 3568, "reason": "", "started_at": "2026-10-22T23:09:36Z", "verdict": "PASS"}}
```

The run's own close-out, verbatim from
[`v07-grpc/soak-24h/final.json`](v07-grpc/soak-24h/final.json) (written by the
soak at the end of the window) and
[`verdict.json`](v07-grpc/soak-24h/verdict.json) (written by `--close`):

```json
{"binary_sha256": "0672763af6afad189cd24fa6f30673b2bd3a02f3d90c467cffc23f79daab6dd6",
 "drops": 0, "duration_seconds": 86400.0, "elapsed_seconds": 86400.0,
 "final_stream_status": "OK", "finished_at": "2026-10-23T23:09:36Z",
 "interval_seconds": 20.0, "last_rtt_ms": 1.08, "max_rtt_ms": 413.41,
 "messages": 4267, "p50_rtt_ms": 0.99, "p99_rtt_ms": 17.44,
 "probes_failed": 0, "probes_ok": 1420, "proxy_rss_kb": 3568,
 "reason": "", "started_at": "2026-10-22T23:09:36Z", "verdict": "PASS"}
```

```json
{"binary_sha256": "0672763af6afad189cd24fa6f30673b2bd3a02f3d90c467cffc23f79daab6dd6",
 "closed_at": "2026-10-23T23:09:55Z", "elapsed_seconds": 86400.0,
 "reason": "", "verdict": "PASS"}
```

`events.jsonl` contains **only** the `started` record (proxy pid 13015) for
the whole day: no broken stream, no failed probe, no proxy exit. The file is
append-only and is the primary evidence; this page transcribes it.

`proxy.log` holds 25 metric snapshots (`--metrics-interval 1h`): the last one
reads `grpc[streams=1421 errors=0]`, `backend[connect_failures=0
tls_failures=0 discarded=0 reused=1420 opened=1 proxied=1420]`,
`network[idle_timeouts=0]` and `client[accepted=2 active=1 completed=1]` —
one backend h2 session served the whole day, no leak and no error counter
moved. `watch.log` records the automatic close-out: `PASS: criterion met`,
then `wrote verdict.md, verdict.json, v07-grpc-soak-24h.md, Roadmap 0.7.md,
SPEC.md, CHANGELOG.md`.

## 6. Exact commands

Launch (already executed; the shell returns immediately and the run lives in
its own session, with `caffeinate -i -w <soak pid>` keeping the machine awake
for exactly as long as the soak):

```bash
python3 scripts/evidence/v07-grpc/soak.py --hours 24 --interval 20 \
  --probe 60 --checkpoint 60 \
  --outdir docs/evidence/v07-grpc/soak-24h --detach
```

Close the gate (this is what `--close` did here on 2026-10-23T23:09:55Z; it
refuses to write anything while `final.json` is missing, and refuses PASS when
the fields do not prove it):

```bash
python3 scripts/evidence/v07-grpc/soak.py --close docs/evidence/v07-grpc/soak-24h
```

`--close` is the only writer of a verdict: it validates `final.json` against
its own fields (full duration, 0 drops, 0 failed probes, final `grpc-status:
OK`, same binary hash as `meta.json`), writes `verdict.md` and `verdict.json`
into the run directory, replaces the block between the `soak:verdict` markers
on this page, and checks the gate box **only** on PASS. Exit codes: `0` PASS
closed, `1` FAIL closed (box stays unchecked), `3` no verdict yet — nothing
written, `4` `final.json` contradicts itself — nothing written, `5` verdict
written but the gate line was not found. Re-running it is idempotent (same
`closed_at`, same bytes).

The same close also replaces the marked gate sentence in `SPEC.md` (inline,
so the table row stays one line) and the gate paragraph in `CHANGELOG.md`.
`--watch` performs that close by itself when `final.json` appears:

```bash
python3 scripts/evidence/v07-grpc/soak.py --watch docs/evidence/v07-grpc/soak-24h --detach
```

It waits for the verdict, refuses to write anything if the soak process
disappeared without one (exit 2), and otherwise runs the same validation and
patches described above. The detach writes `watch.pid` and `watch.log` in the
run directory.

Inspect at any time:

```bash
python3 scripts/evidence/v07-grpc/soak.py --summarize docs/evidence/v07-grpc/soak-24h
tail -n 3 docs/evidence/v07-grpc/soak-24h/checkpoint.jsonl
```

`--summarize` after the close (its own output, complete table in the run):

```text
# gRPC bidi soak

- started: 2026-10-22T23:09:36Z
- duration: 24.0 h
- interval: 20.0 s, probe: 60.0 s
- binary: `/Volumes/Lexar/Cursor/EQProxy/target/release/eqproxy` sha256 `0672763af6afad189cd24fa6f30673b2bd3a02f3d90c467cffc23f79daab6dd6`
- proxy pid: 13015, soak pid: 13011
- host: macOS-26.5.1-arm64-arm-64bit, python 3.9.6, grpcio 1.66.1
...
| 82599.6 | 4079 | 0 | 1358/0 | 0.98 | 17.44 | 413.41 | 4048 |
| 86175.0 | 4256 | 0 | 1417/0 | 0.98 | 17.01 | 413.41 | 4144 |

**Verdict: PASS** — no failures
```

Stop (records a FAIL with the elapsed time, never a pass):

```bash
kill "$(cat docs/evidence/v07-grpc/soak-24h/soak.pid)"
```

## 7. What the 24 h run proved, and what it did not

Proved, now that it ended PASS: one bidirectional gRPC stream stayed open for
24 h through the release binary, with **4 267** request/echo pairs completed
(one every 20 s of the window — the harness counts the pairs it actually
completed, not the nominal 4 320 slots), **1 420** separate short streams
accepted while the long one was in flight, **0** broken streams, **0** failed
probes, no proxy exit, one backend h2 session for the whole day and an RSS
sampled every minute that peaked at **7 216 KiB** and ended at **3 568 KiB**
(no upward drift: the last quarter of the checkpoints sits at 3 856–4 432
KiB, below the early peak).

Will **not** prove: throughput or latency under load (the numbers are one
loopback message per 20 s, not a benchmark), behaviour under CPU or memory
pressure, multi-host or cross-datacenter paths, Docker/Scout gates, or the
S-H2/S-H3 scenarios against HAProxy 3.4.6.

## 8. Limits and NOT EXECUTED

- The 24-hour verdict: **PASS**, closed 2026-10-23T23:09:55Z by `--close`
  (the automatic `--watch`), which also checked the gate box in `SPEC.md`
  and replaced the gate paragraph in `CHANGELOG.md`. The verdict is a
  transcription of `final.json` + `verdict.json`, not an independent
  measurement: it proves what §7 lists, and nothing about load.
- The machine must stay awake and connected; `caffeinate -i` prevents idle
  sleep, not a lid close or a manual sleep. Any suspension appears as a
  broken stream and a FAIL, and would have to be re-run.
- Docker image and Docker Scout on both architectures: **NOT EXECUTED**.
- S-H2/S-H3 scenarios against HAProxy 3.4.6: **NOT EXECUTED**.
- The 25 metric snapshots in `proxy.log` are the day's resource drift
  evidence, not a benchmark: they show one backend session (`opened=1`,
  `reused=1420`, `connect_failures=0`), `network[idle_timeouts=0]` and
  `grpc[errors=0]` from the first minute to the last, so nothing leaked in
  the counters the soak could see. Counters outside those (99th-percentile
  tables, per-rule timings) were not sampled.
- **Veyra Proof and Rust Audit were not re-executed for this page** (EvoForge
  is no longer part of the audit process). The soaked binary
  `0672763a…ab6dd6` is the one recorded as audited in
  [v07-grpc.md](v07-grpc.md) §7 — ACCEPTED verdict in
  `.veyra/evidence/20261022T223646Z/`, 396-test run, with no Rust source
  changed between that audit and the launch. The tree has moved on since:
  **19** `.rs` files are newer than the soak start and the current
  `target/release/eqproxy` is `a902bce9…`, so today's ACCEPTED run
  (`.veyra/evidence/20261023T233411Z/`) and today's Rust Audit describe the
  **current tree, not the binary that was soaked**. Re-running the toolchain
  while the soak was measuring would only have loaded the host; nothing here
  is reported as a new audit pass.
