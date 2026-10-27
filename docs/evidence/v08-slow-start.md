# v0.8 — the slow-start journey: the flake repaired, not tolerated

Language: **English**. Subject: `run_slow_start_ramps_the_recovered_server_up`
in [`eqproxy-cli/tests/cli_e2e.rs`](../../eqproxy-cli/tests/cli_e2e.rs), which
failed once on 2026-10-27 with `unexpected origin body ""` — the same flake
recorded at v0.6.1 ("helper timeout under a parallel suite"). This increment
removes the two couplings that produced it instead of re-running until green.

Tree under test: `main` at `ae3d950` (v0.8.0 + this increment). Toolchain
1.99.1 (`rust-toolchain.toml`, added by the same commit; see
[v08-toolchain-pin](v08-toolchain-pin.md)). Local host macOS 26.5.1 arm64;
Linux runs on the Netcup amd64 host of [v08-linux-e2e-admin](v08-linux-e2e-admin.md).

## 1. What the flake actually was

The journey configured its health checks with

```
interval = "150ms"
timeout  = "100ms"     # the probe's budget
fall     = 1           # one failed probe marks the server DOWN
```

A probe that exceeds `timeout` counts as a failure. The journey's own origins
run on the same machine as the whole suite, so under load a healthy origin's
probe can take longer than 100 ms; with `fall = 1` the healthy origin is
marked DOWN, and while the intentionally-down server was still out of
rotation the dataplane answered its built-in "no server available"
(`503 service unavailable`, `content-length: 0`). The harness read bodies:
the empty body surfaced as `unexpected origin body ""`, which named neither
the cause nor the response — the 503 was invisible.

Reproduced deterministically before touching the test
([`scripts/evidence/v08-slow-start/probe.py`](../../scripts/evidence/v08-slow-start/probe.py),
local-only harness; it runs from the repository root against the workspace's
debug `eqproxy` — `target/debug/eqproxy` unless `EQPROXY_BIN` overrides it).
A healthy origin whose `/healthz` stalls 300 ms, changing **only** the
check's timeout:

```console
$ python3.13 scripts/evidence/v08-slow-start/probe.py
```

| scenario | health timeout | 20 sequential requests through the proxy |
|---|---|---|
| `old-100ms` | `100ms` | 20 × `503 service unavailable`, body `""` |
| `repaired-1s` | `1s` | 20 × `200 OK`, body `a` |

Raw run: [`docs/evidence/v08-slow-start/raw/run-20261027T201309Z/`](v08-slow-start/raw/run-20261027T201309Z/)
(`result.json`, `eqproxy-old-100ms.toml`, `eqproxy-repaired-1s.toml`; the
earlier attempt `run-20261027T201239Z/` holds only the first config — its
harness mishandled the origin's address and died before `result.json`. The
probe now also silences the broken pipe a cancelled probe produces: the
proxy timing out a probe is the mechanism under test, not an error).

## 2. The repair (commit `ae3d950`)

1. **The probe budget no longer races the machine**: `timeout = "1s"`. B's
   intentional failure is a *status mismatch* (500, `expect_status = "200"`),
   which no timeout can absorb — the check still drops B on its first probe,
   and 1 s is ten times the 100 ms a dead origin needs.
2. **The ramp window is observed, not timed**: the old phase 2 slept 300 ms
   and then counted 10 requests, which coupled the assertion to *when the
   health checker's tick lands* (it fires every 150 ms; under load it can be
   late, and the window then measured the wrong moment). The window now opens
   at **B's first byte of traffic** seen through the dataplane — the first
   `b` body — with a 20 s deadline that fails loudly if the recovered server
   never takes traffic. The assertion itself is unchanged
   (`early.1 < 5`): the recovered server gets less than its fair share during
   the ramp, and phase 3 still requires the exact 5:5 end state.
3. **A failure now names the proxy's answer**: `marker_response()` returns the
   raw response alongside the body, and the panic reads
   `unexpected origin body "": the proxy answered "HTTP/1.1 503 service
   unavailable..."` instead of a bare `""`.

## 3. Verification runs

All local runs used the pinned toolchain
(`cargo 1.99.1`, `1.99.1-aarch64-apple-darwin (overridden by
rust-toolchain.toml)`).

- **Isolated, 8 consecutive runs** —
  [`run-20261027T202812Z/local-slow-start-8x.txt`](v08-slow-start/raw/run-20261027T202812Z/local-slow-start-8x.txt):
  8 × `test result: ok. 1 passed`, 0 failures.
- **The whole `cli_e2e` target under CPU load** (the condition the flake was
  reported under: 4 `yes` spin loops on a 10-core host) —
  [`run-20261027T202812Z/cli-e2e-loaded.txt`](v08-slow-start/raw/run-20261027T202812Z/cli-e2e-loaded.txt):
  `test result: ok. 78 passed; 0 failed`, exit 0.
- **Linux (Netcup amd64, kernel 6.8.0-147, pinned 1.99.1), 3 consecutive
  runs** — section D of
  [`v08-linux-e2e-admin/raw/netcup-session.txt`](v08-linux-e2e-admin/raw/netcup-session.txt):
  3 × `test result: ok. 1 passed` (1.47 s / 1.25 s / 1.25 s).

## 4. Audit legs (this increment)

- **Veyra Proof** — `veyra audit . --profile standard`: **ACCEPTED**, exit 0,
  evidence [`.veyra/evidence/20261027T202634Z/`](../../.veyra/evidence/20261027T202634Z/)
  (local-only). `rustfmt`, `cargo-check`, `clippy`, `cargo-test`, `nextest`
  (558/558, 2 miri-gated skipped), `llvm-cov`, `cargo-deny`, `cargo-audit`,
  `machete` and `veyra-e2e` (17 scenarios, 17 passed) are OK. `dylint` and
  `semver-checks` are **SKIPPED** by the tool's own policy (no lint
  configuration to run; no registry baseline to diff) and `geiger` is
  **INCONCLUSIVE** (its scan reports coverage warnings, so its unsafe counts
  are a lower bound); none of the three is counted as a pass.
- **Rust Audit** — `python3.13 <checkout>/scripts/rust_audit.py scan . --format
  md --out report --fail-on high`: exit 0, report
  `report/rust-audit-20261027-212600.md` (local-only): critical 0, high 0,
  medium 240, low 85 — the same counts as the pre-increment run
  (`rust-audit-20261027-014526.md`), so this increment adds no finding at
  medium or above.
- **CodeGraph Rust** — the index was rebuilt after the last edit
  (`codegraph-rust index . --stats-json`, `--batch-size 16`): 62 files,
  61 510 lines, 7 024 nodes, 12 280 edges, `graph_complete: true`,
  `vector_index_ready: true`, `index_ms: 915 056` (≈ 15 min). `agent impact`
  (“what breaks if the slow-start ramp window changes”) returned the ramp
  contract (`with_options`, `eff_weight`) and named this very journey as an
  affected test; `agent context` located `eff_weight`
  ([`balancer.rs:782-799`](../../eqproxy-net/src/balancer.rs#L782-L799)) and
  the restart on the down→up transition
  ([`balancer.rs:819-823`](../../eqproxy-net/src/balancer.rs#L819-L823)).
  Every `file:line` used here was re-checked in the source — the clamp
  `[1, full]` at 782-798, the restart inside the `!up && rises >= rise`
  branch at 819-825, the unit tests at 1068 and 1120, the journeys at
  `e2e_balancer.rs:411` and `cli_e2e.rs:3249`. CodeGraph is a map: the ramp
  behaviour above is proven by the tests, not by the graph.
- **Hindsight** — note stored (exit 0) in the project's own bank:
  *“EQProxy: flake de slow start reparado y toolchain fijada (main
  ae3d950)”*.

## 5. Limits

- The flake was **load-induced and rare**; these runs do not "prove" it can
  never happen again in any environment. What is removed is the *mechanism*:
  a probe budget below a plausible scheduling delay, and an assertion timed
  against a tick instead of against observed traffic. The deterministic probe
  above is the mechanism's reproduction, not the flake itself.
- The 78-test loaded pass is **one** pass (plus the audit leg below), not a
  stress campaign; the load is four spinners, not a saturation harness.
- B's ramp window still ends where the ramp ends: the load run is the only
  evidence that the 2 s window and 10 requests still fit under load — a
  slower host (e.g. CI's 2-core runner) is exercised by CI itself.
- Nothing here is a throughput or latency measurement; the timings quoted
  (1.47 s / 1.25 s) are the harness's own report of one test.
