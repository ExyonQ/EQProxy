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

The 150 ms probe of `run_http_check_interops_with_keep_alive_origin`
([`4658`](../../eqproxy-cli/tests/cli_e2e.rs#L4658)) was left as it is: it is a
different journey (a local keep-alive origin cycled many times, no failover)
and was not part of this repair. It is named here as the one remaining
sub-second probe with `fall = 1`.

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
- The 150 ms probe named in §1 is unchanged (out of scope of this repair).
- Docker, Scout and the release artifacts: untouched by this increment
  (**NOT EXECUTED**).

## 6. Audit legs

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
