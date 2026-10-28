# v0.8 — a scheduling hiccup no longer marks a healthy origin down

Language: **English**. Commits `1b2db9b` (the probes) and the one that carries
this page (the counter race the first one exposed in CI). Six journeys of
`cli_e2e` checked their origin every 150 ms with
`timeout = "100ms"` and `fall = 1`: a probe that did not answer inside
100 ms — because the machine was busy running the rest of the suite, not
because the origin was sick — flipped it to DOWN. The next client request
then met the built-in `503 service unavailable`, an **empty body**, and the
journey failed on `expected a pool member, got ""` although the proxy had done
nothing wrong. It is the flake recorded on 2026-10-27 and reproduced under
load here.

## 1. The change

The seven probe timeouts ([`cli_e2e.rs`](../../eqproxy-cli/tests/cli_e2e.rs))
now say `"1s"`, and the shared origin's doc comment
([`cli_e2e.rs:3065`](../../eqproxy-cli/tests/cli_e2e.rs#L3065)) states the
invariant so the next journey copies it:

```
/// Every journey that runs this origin configures its health check with
/// `timeout = "1s"`, not the 100 ms a *dead* origin would need: the probe
/// shares the machine with the whole suite, and at 100 ms a scheduling
/// hiccup marked the **healthy** origin down (`fall = 1`); the requests then
/// met the built-in `503 service unavailable` with an empty body — the
/// `expected a pool member, got ""` flake recorded on 2026-10-27. The
/// intended failure in these journeys is a status mismatch (`500`), which no
/// timeout can absorb, so the longer timeout takes nothing from the
/// assertion.
```

| Journey | Sites |
|---|---|
| `run_slow_start_ramps_the_recovered_server_up` | [`3290`](../../eqproxy-cli/tests/cli_e2e.rs#L3290) |
| `run_backup_server_covers_a_failed_primary_and_returns_on_recovery` | [`3435`](../../eqproxy-cli/tests/cli_e2e.rs#L3435) |
| `run_priority_ladder_fails_over_between_backups_and_back` | [`3586`](../../eqproxy-cli/tests/cli_e2e.rs#L3586) |
| `run_all_backups_spreads_traffic_across_the_backup_pool` | [`3721`](../../eqproxy-cli/tests/cli_e2e.rs#L3721) |
| `run_document_put_flips_the_backup_pool_live` | [`3946`](../../eqproxy-cli/tests/cli_e2e.rs#L3946), [`4009`](../../eqproxy-cli/tests/cli_e2e.rs#L4009) |
| `run_panel_applies_a_table_and_drains_a_server` | [`4295`](../../eqproxy-cli/tests/cli_e2e.rs#L4295), [`4411`](../../eqproxy-cli/tests/cli_e2e.rs#L4411) |

No assertion changed, no retry or tolerance knob was added, and the origin
still answers in microseconds: the 1 s is headroom for the *machine*, not a
new behaviour of the proxy. The failure each journey asserts — a `500` from a
sick origin, a down primary that fails over, a backup pool that takes over —
is untouched by the timeout, because none of them depends on the probe
firing early.

### 1.1 The last sub-second probe, one increment later

`run_http_check_interops_with_keep_alive_origin`
([`4649`](../../eqproxy-cli/tests/cli_e2e.rs#L4649)) was the one journey still on
a 150 ms probe with `fall = 1`. It now says `"1s"` as well
([`4665`](../../eqproxy-cli/tests/cli_e2e.rs#L4665)), and the origin it runs —
`start_keepalive_origin`, not the balancer origin — carries the same invariant
in its own doc comment ([`4596`](../../eqproxy-cli/tests/cli_e2e.rs#L4596)), so
the next journey that reuses it inherits the rule without reading this page.
No assertion changed.

A longer timeout can hide the very defect this journey exists for (a checker
that reads a keep-alive response to EOF), so the change was checked against
that defect directly. The production checker was temporarily patched back to
reading the body to EOF, the journey run three times, and the file restored
byte-for-byte (`sha256 146a3542…`, `git diff -- eqproxy-net/src/health.rs`
empty). It failed **3/3**:

```
[rep 1] exit=101
    panicked at eqproxy-cli/tests/cli_e2e.rs:4699:9:
    assertion `left == right` failed: the server must stay UP after check cycle 2
[rep 2] exit=101  … check cycle 2
[rep 3] exit=101  … check cycle 2
```

The broken checker marks the origin DOWN when its first probe times out
(≈1.1 s), and the journey's second round meets the empty `503` — the same
symptom one second later, not a scenario the longer timeout absorbs.

With the real checker: 15/15 repetitions under eight CPU spinners on the same
machine (load average 218–233; four foreign 200 %-CPU test binaries from
another project were also running, so this is heavier than the 2026-10-27
flake), and the whole target green.

```
[rep 15] exit=0 5s load={ 231.73 218.88 212.82 } :: test result: ok. 1 passed; 0 failed … finished in 3.20s
fail=0/15

$ cargo test -p eqproxy-cli --test cli_e2e
test result: ok. 78 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 4.80s

$ cargo fmt --all -- --check                               # exit 0
```

Raw: [`keepalive-probe-1s.txt`](v08-health-probe-robust/raw/20261028T145002Z/keepalive-probe-1s.txt),
[`keepalive-1s-under-load.txt`](v08-health-probe-robust/raw/20261028T145002Z/keepalive-1s-under-load.txt),
[`keepalive-1s-negative-control.txt`](v08-health-probe-robust/raw/20261028T145002Z/keepalive-1s-negative-control.txt)
and [`local-full-target.txt`](v08-health-probe-robust/raw/20261028T145002Z/local-full-target.txt).
The journey was run once more after the final doc-comment edit of the same
file (`1 passed`, 2.89 s):
[`keepalive-post-edit.txt`](v08-health-probe-robust/raw/20261028T145002Z/keepalive-post-edit.txt).

## 2. Local verification (macOS arm64, uid 501)

```
$ cargo fmt --all --check                                     # exit 0
$ cargo test -p eqproxy-cli --test cli_e2e
test result: ok. 78 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 4.57s
```

Raw: [`v08-health-probe-robust/raw/20261028T015824Z/local-targets.txt`](v08-health-probe-robust/raw/20261028T015824Z/local-targets.txt).

The whole target was already run with the seven probes at 1 s and the six
journeys were then repeated three times each with six CPU spinners on the same
10-CPU machine (load average 171–194 during the run), the scenario the flake
needed:

```
[rep 3] run_backup_server_covers      :: exit=0 :: 1 passed; 0 failed ... finished in 1.51s
[rep 3] run_priority_ladder           :: exit=0 :: 1 passed; 0 failed ... finished in 1.92s
[rep 3] run_all_backups               :: exit=0 :: 1 passed; 0 failed ... finished in 2.27s
[rep 3] run_document_put             :: exit=0 :: 1 passed; 0 failed ... finished in 2.24s
[rep 3] run_panel_applies             :: exit=0 :: 1 passed; 0 failed ... finished in 1.55s
fail=0
```

Raw: [`.../20261028T014415Z/local-under-load.txt`](v08-health-probe-robust/raw/20261028T014415Z/local-under-load.txt)
and the full target of that tree at
[`.../20261028T014415Z/local-full-target.txt`](v08-health-probe-robust/raw/20261028T014415Z/local-full-target.txt)
(78 passed).

## 3. The counter race CI found in the same run

The first push of the probe repair (`1b2db9b`) failed its **root** tier, in a
test the repair does not touch:
[run 40616967835](https://github.com/ExyonQ/EQProxy/actions/runs/40616967835)
— `linux-tier1`, `evidence-test-citations` and both native `admin-unix-acl`
legs green, `suite-as-root` red at

```
thread 'keep_alive_reuses_a_single_backend_connection' panicked at eqproxy-net/tests/e2e_pool.rs:192:5:
  left: 4
 right: 5
```

`http_requests_proxied` is incremented when the exchange **finishes** on the
proxy side ([`http1.rs:2523`](../../eqproxy-net/src/http1.rs#L2523)), while the
journey reads only the response head. Sampling the counter once, right after
reading the last head, races the proxy's bookkeeping: a correct proxy can
still be at 4 when the test looks. The repair adds a wait on the *same*
counter, with no assertion relaxed
([`e2e_pool.rs:176`](../../eqproxy-net/tests/e2e_pool.rs#L176)):

```rust
async fn wait_for_proxied(metrics: &Metrics, want: u64) {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        if metrics.snapshot().http_requests_proxied == want {
            return;
        }
        assert!(tokio::time::Instant::now() < deadline,
            "the proxy never counted {want} proxied requests");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
```

and the journey calls it before reading the snapshot
([`e2e_pool.rs:207`](../../eqproxy-net/tests/e2e_pool.rs#L207)). The final
values it asserts are unchanged (`proxied == 5`, one backend connection,
`N-1` reuses); the timeout makes a genuinely stuck proxy fail with a named
message instead of hanging.

Verification: the target, then twenty repetitions under six CPU spinners.

```
$ cargo test -p eqproxy-net --test e2e_pool
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s

# x20 with 6 spinners, load averages 169-196
failing reps: 0/20
```

Raw: [`.../20261028T015824Z/local-targets.txt`](v08-health-probe-robust/raw/20261028T015824Z/local-targets.txt)
and [`.../20261028T015619Z/e2e-pool-under-load.txt`](v08-health-probe-robust/raw/20261028T015619Z/e2e-pool-under-load.txt).

## 4. CI on this tree

Commit `16c80a5`, run
[40618301936](https://github.com/ExyonQ/EQProxy/actions/runs/40618301936) —
**all five jobs success**:

| Job | Conclusion |
|---|---|
| Linux x86_64 (tier-1) | success |
| Suite as root (uid-gated skips declared) | success |
| Evidence test citations | success |
| Admin socket ACL E2E (native amd64) | success |
| Admin socket ACL E2E (native arm64) | success |

The root tier — the one that failed on `1b2db9b` — ran the repaired test in
its log:

```
2026-10-28T02:02:53.4380179Z test keep_alive_reuses_a_single_backend_connection ... ok
```

## 5. Limits and NOT EXECUTED

- **macOS arm64 only, locally.** The root tier (`uid 0`) exists only in CI;
  the local runs are uid 501. The failing run is cited as the observation,
  and the fix's verification under root is the CI run of §4.
- **The race, not a proof of its absence.** 20/20 repetitions under load show
  the repair does not fail where the sample-only version did once; they do
  not measure a probability. The source-level reason (increment at exchange
  end) is what makes the old sample wrong by construction.
- `backend_connections_opened`/`reused` are incremented at the same point and
  the sibling journeys sample them after the last head too. None has been
  observed failing; this increment only repaired the counter that failed and
  the probe timeouts that were asked for. They are candidates, not fixes.
- The four sibling probes named in §6.2 are verified but **not** repaired:
  the request covered the `cli_e2e` sites. They are the next candidates, not
  a claim that the rest of the suite is flake-free.
- The negative control of §1.1 is a **local, temporary** patch to
  `eqproxy-net/src/health.rs`, restored byte-for-byte and never committed; the
  shipped tree has no `_want` arm and `git diff` on that file is empty.
- This follow-up is published as `ce77c5a`; its CI run
  [40722095133](https://github.com/ExyonQ/EQProxy/actions/runs/40722095133)
  came back 4/5, with `suite-as-root` failing on a test the commit does not
  touch. §7 diagnoses it (descriptors under `sudo`, not the proxy), and the
  fix `2749ec0` ran green in
  [40723747985](https://github.com/ExyonQ/EQProxy/actions/runs/40723747985)
  (**5/5**, 559 passed per tier). Docker image and Scout gate remain
  untouched by this follow-up (**NOT EXECUTED**).

## 6. Audit legs

### 6.1 The probe and counter increment (commits `1b2db9b`, `16c80a5`, `19c7be2`)

- **Veyra Proof** — `veyra audit . --profile standard`: **ACCEPTED**, exit 0,
  evidence `.veyra/evidence/20261028T020048Z/`. OK: `rustfmt`, `cargo check`,
  `clippy -D warnings`, `cargo test --locked --workspace` (558 passed, 0
  failed, 2 ignored over 30 targets), `cargo-audit`, `veyra-anti-theater`,
  `nextest`, `llvm-cov`, `deny`, `machete`, `veyra-e2e`. SKIPPED: `dylint`
  (no lint configuration in the workspace) and `cargo-semver-checks` (no
  registry baseline for unpublished crates). INCONCLUSIVE: `cargo-geiger`
  (coverage warnings in 4 runs; unsafe counts are a lower bound, not a pass).
- **Rust Audit** — `python3.13 <rust-ai-audit>/scripts/rust_audit.py scan .
  --format md --out report --fail-on high`: exit 0, **0 critical, 0 high**,
  241 medium, 85 low ([report/rust-audit-20261028-030033.md](../../report/rust-audit-20261028-030033.md),
  local-only). The scan names the new helper once,
  `[R08 · medium] e2e_pool.rs:176 wait_for_proxied` — "wall-clock/monotonic
  time read in test": reviewed, heuristic false positive. The clock there is
  a deadline that only bounds the wait and turns a stuck proxy into a named
  failure; no assertion compares timings. Every other finding in the report
  predates this increment.
- **CodeGraph Rust** — index rebuilt after the last source edit: 63 files,
  61 848 lines, 7 043 nodes, 12 441 edges, `graph_complete: true`,
  `vector_index_ready: true`, `index_ms: 850 476` (14.2 min, local Ollama,
  `--batch-size 16`). `agent impact` on `wait_for_proxied` returned one
  caller, `keep_alive_reuses_a_single_backend_connection`, which the source
  confirms ([`e2e_pool.rs:207`](../../eqproxy-net/tests/e2e_pool.rs#L207)); its
  claim that the helper depends on an `eqproxy-config` import is wrong (a
  `#[cfg(test)]` helper in `eqproxy-net/tests/` cannot depend on another
  crate's private module) and is not repeated. `agent context` correctly
  listed the readers of `http_requests_proxied` but could not locate the
  increment and said so; the source does
  ([`http1.rs:2523`](../../eqproxy-net/src/http1.rs#L2523)).
- **Hindsight** — note stored in bank `eqproxy` ("Health probes at 1 s and the
  proxied-counter wait"), memory ids `971ac55a-0ff5-4035-8cf0-5121ccb103e4`
  and `69e208e8-bc53-47c6-8ffa-3a8f8eb7738c`.

### 6.2 This follow-up (uncommitted)

- **Veyra Proof** — `veyra audit . --profile standard`: **ACCEPTED**, exit
  **0** (`VEYRA_EXIT=0`), evidence
  [`.veyra/evidence/20261028T153231Z/`](../../.veyra/evidence/20261028T153231Z/report.md).
  OK: `rustfmt`, `cargo check`, `clippy`, `cargo test` (558 passed, 0 failed,
  2 ignored over 30 targets), `cargo-audit`, `veyra-anti-theater`,
  `cargo-nextest`, `cargo-llvm-cov`, `cargo-deny`, `cargo-machete`,
  `veyra-e2e`. SKIPPED by the tool's own policy: `dylint` (no lint
  configuration in the workspace) and `cargo-semver-checks` (no registry
  baseline). INCONCLUSIVE: `cargo-geiger` (coverage warnings in 4 runs; the
  unsafe counts are a lower bound). An earlier run of the same tree
  (`20261028T145857Z`) reached the same decision and the same 558/0/2; the
  cited one is the second because the first was piped through `tee`, which
  hid its exit status, and a verdict without its code is not evidence.
- **Rust Audit** — `python3.13 <rust-ai-audit>/scripts/rust_audit.py scan .
  --format md --out report --fail-on high` (tool 0.2.7): exit 0, **0
  critical, 0 high**, 241 medium, 85 low
  ([report/rust-audit-20261028-155611.md](../../report/rust-audit-20261028-155611.md),
  local-only). Against the previous scan of the tree
  (`rust-audit-20261028-030033.md`) the finding set is **identical**:
  `added: []`, `removed: []` over the same per-rule/per-file/per-function
  multiset. A probe timeout and two doc comments add no finding, and the
  existing `R08` "wall-clock in test" notices keep their review status
  (deadlines, not timing assertions).
- **CodeGraph Rust** — index rebuilt after the last Rust edit (only
  `cli_e2e.rs` changed, so 62 of 63 files came from cache): 63 files,
  61 855 lines, 7 043 nodes, 12 441 edges, `graph_complete: true`,
  `vector_index_ready: true`, `index_ms` 59 540 (22.4 s, incremental; the
  cold build ran 852 443 ms). `agent impact` on the probe
  timeout placed `check_one` → `http_ok`/`tcp_ok` →
  `report_ok`/`report_fail` at
  [`health.rs:134`](../../eqproxy-net/src/health.rs#L134) and the 1 s default
  at [`schema.rs:91`](../../eqproxy-config/src/schema.rs#L91), both
  confirmed in source; it named the journey at
  [`4649`](../../eqproxy-cli/tests/cli_e2e.rs#L4649), correct. It got one
  line wrong (`e2e_phase2b.rs:436` for a construction that is at
  [`459`](../../eqproxy-net/tests/e2e_phase2b.rs#L459)), and its advice to
  keep `timeout` below `interval` does not apply here: the cycle joins its
  attempts before the next tick
  ([`health.rs:117`](../../eqproxy-net/src/health.rs#L117)), so a 1 s probe
  cannot overlap a cycle, it only delays it — what the negative control of
  §1.1 measures.

  What it found that matters: four library-level tests still build tight
  probes with `fall = 1`, each verified in source and **not** changed —
  [`e2e_resilience.rs:1316`](../../eqproxy-net/tests/e2e_resilience.rs#L1316)
  (the twin of this journey: 100 ms interval, 150 ms timeout),
  [`e2e_resilience.rs:1185`](../../eqproxy-net/tests/e2e_resilience.rs#L1185)
  (80 ms/80 ms),
  [`e2e_balancer.rs:441`](../../eqproxy-net/tests/e2e_balancer.rs#L441)
  (150 ms/100 ms), plus
  [`e2e_phase2b.rs:459`](../../eqproxy-net/tests/e2e_phase2b.rs#L459)
  (80 ms/80 ms, `fall = 2`). Their symptom is a false `is_up`, not an empty
  `503`: same cause, different surface.
- **Hindsight** — note stored in bank `eqproxy` ("Keep-alive journey probe
  raised to 1s (last sub-second cli_e2e probe)"), exit 0, `Memory stored
  successfully`; first memory id `059de630-424c-4249-a8a3-a610e2936440`.

## 7. Publication: the root job's descriptor limit

The change was published as `ce77c5a`. Its CI run
[40722095133](https://github.com/ExyonQ/EQProxy/actions/runs/40722095133)
came back **red in one job**, `suite-as-root`, on a test the commit does not
touch:

```
thread 'pool_sizing_keeps_a_400_stream_burst_without_churn' panicked at eqproxy-net/tests/e2e_http2.rs:712:9:
  left: 502
 right: 200
```

The other four jobs were green, and the unprivileged tier had run the same
test green in the same workflow (`test
pool_sizing_keeps_a_400_stream_burst_without_churn ... ok`, 16:05:02Z). A
`502` is the product's answer when a dial fails, and here the failing dial is
the proxy having no descriptor to open the backend connection — not a pool or
framing defect.

**Cause.** `sudo` runs the suite under PAM's limit set, which on this runner
is lower than the unprivileged shell's. The test keeps both ends of 400
backend exchanges inside one process — 400 origin-accepted sockets plus 400
proxied dials, ~820 descriptors — so a limit below that turns one dial into a
`502`.

**Reproduced locally** (macOS arm64, uid 501), with no product change:

```
# the single test
ulimit -n 800    → FAILED: left 502, right 200 at e2e_http2.rs:712
# the whole target (9 tests, default parallelism)
ulimit -n 512    → FAILED: the same 502
ulimit -n 1024   → ok. 9 passed
```

**Fix.** The root job raises the limit to 65 536 for the whole suite and
asserts it, printing the value it got; a future sudo/PAM policy change fails
with a named message instead of a mystery `502`. No test, assertion or retry
was touched: a `502` when no socket can be opened is correct behaviour, and
the test's contract needs the descriptors.

Run [40723747985](https://github.com/ExyonQ/EQProxy/actions/runs/40723747985)
over that commit (`2749ec0`): **5/5 jobs success**, with the root log showing
both the limit and the test that had failed:

```
root suite fd limit: 65536
test pool_sizing_keeps_a_400_stream_burst_without_churn ... ok
```

Both tiers ran the same 30 targets: **559 passed, 0 failed, 2 ignored**, and
the two declared root skips still print their reason. The journey this
follow-up repaired ran in both tiers
(`test run_http_check_interops_with_keep_alive_origin ... ok`).
