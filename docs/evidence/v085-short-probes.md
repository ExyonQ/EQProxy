# v0.8.5 — the last five live-origin probes, and a gate so a short one cannot come back

Status: implemented on 2026-10-28 and committed on 2026-10-29.
Scope: §3 (debt) of the v0.8.5 roadmap, first two boxes. Four of the five
sites are the ones [v08-health-probe-robust](v08-health-probe-robust.md) left
verified but **not repaired** (§6.2 and §5): they are library-level tests, and
that increment's request covered the `cli_e2e` sites. The fifth was not in
that inventory: the gate found it once it scanned `#[cfg(test)]` modules in
`src` (§2), and CodeGraph's impact query had pointed at the same file.

## 1. The change: five timeouts, no interval moved

| Test | Site | Before (interval / timeout) | After |
|---|---|---|---|
| `http_expect_check_marks_5xx_server_down` | [`e2e_resilience.rs:1207`](../../eqproxy-net/tests/e2e_resilience.rs#L1207) | 80 ms / 80 ms | 80 ms / **1 s** |
| `http_check_interops_with_keep_alive_origins` | [`e2e_resilience.rs:1340`](../../eqproxy-net/tests/e2e_resilience.rs#L1340) | 100 ms / 150 ms | 100 ms / **1 s** |
| `slow_start_ramps_the_recovered_server_up` | [`e2e_balancer.rs:443`](../../eqproxy-net/tests/e2e_balancer.rs#L443) | 150 ms / 100 ms | 150 ms / **1 s** |
| `healthchecks_e2e` | [`e2e_phase2b.rs:459`](../../eqproxy-net/tests/e2e_phase2b.rs#L459) | 80 ms / 80 ms | 80 ms / **1 s** |
| `check_task_marks_server_down_and_up_again` (unit test) | [`health.rs:472`](../../eqproxy-net/src/health.rs#L472) | 20 ms / 200 ms | 20 ms / **1 s** |

The previous increment's §6.2 cites these calls at `1336` and `1205`; the
comments added here moved them to `1340` and `1207`, and the gate output
below uses the new lines. The same applies to the fifth site: it was at
`health.rs:468` when the gate caught it and at `472` after its comment; the
pre-repair capture keeps the old number.

The fifth site asserts `is_up` 150 ms after starting a probe with `fall = 1`
against a listener that accepts at once; under a 200 ms budget, one
descheduled poll would drop the live server and fail the assertion. Its dead
phase aborts the listener, so the probe sees a refused connect and the 1 s
timeout is never spent. No assertion changed.

The two 50 ms probes of `all_servers_down_returns_503_in_http_mode` and
`all_servers_down_closes_connection_in_tcp_mode`
([`e2e_phase2b.rs:644`](../../eqproxy-net/tests/e2e_phase2b.rs#L644),
[`e2e_phase2b.rs:696`](../../eqproxy-net/tests/e2e_phase2b.rs#L696)) stay as
they were: their origin is a reserved port with no listener, the test asserts
the DOWN, and §2 declares them with that reason.

**Why the interval stays short.** The four journeys observe a state change
within 600–700 ms (`tokio::time::sleep` before the assertion, or `eventually`
with a deadline), and the unit test within 150 ms; `fall = 1` in all of them
except `healthchecks_e2e`, which uses `fall = 2`. Those windows are sized by
the *interval*, which is what each test controls. Moving it to 1 s would make
the assertions fail by construction, and the interval is not the hazard.

**Why the timeout is the hazard.** Every probe here faces an origin that
answers at once: a `500`, a `200` with `ok` on a keep-alive socket, or a
closed port whose `connect(2)` is refused. When the process is descheduled,
the answer waits in the kernel while the check's own deadline runs out; one
failed poll with `fall = 1` marks the server DOWN and the next request meets
the empty `503`. The 1 s is headroom for the machine, not a wait for the
origin: a check that would have returned in microseconds still returns in
microseconds, it only stops being converted into a failure by a scheduling
hiccup. No assertion, retry or tolerance knob changed.

A longer timeout cannot hide a checker that never finishes: the check cycle
joins every attempt before the next tick ([`health.rs:117`](../../eqproxy-net/src/health.rs#L117)),
so a stuck probe delays its cycle instead of overlapping the next one, and the
journey still fails once `fall` counts are reached. The negative control for
that defect (a checker patched to read to EOF) is in §1.1 of the previous
increment: 3/3 failures with the 1 s timeout already in place.

## 2. The gate: `check-short-health-probes.py`

`.github/scripts/check-short-health-probes.py` refuses a suite health check
whose **timeout** is below 1 s unless the site is declared. The shape mirrors
`check-uid-skips.py`: a two-way registry, a `--self-test`, and a verdict read
from text only.

**What it reads.** Every `*.rs` under `eqproxy-*/tests/`, and every
`eqproxy-*/src/**/*.rs` from its last `#[cfg(test)]` line down — a unit test
is part of the same suite, and `health.rs` keeps a live-origin probe in one:

- Rust: `HealthCheck::tcp(<interval>, <timeout>)`, including calls split over
  lines. The two arguments must be `Duration::from_millis(<n>)` or
  `Duration::from_secs(<n>)`; a constant or any other expression is reported
  as **unproven** and rejected, because the gate reads text and cannot
  evaluate code.
- TOML embedded in a Rust string: a `timeout = "<n>ms"` under the nearest
  `[backend.<name>.health_check]` header of the same literal (the form
  `cli_e2e` uses, where the original flake lived).

Production wiring is not a probe literal: `main.rs` builds the check from the
operator's config (`HealthCheck::tcp(hc.interval, hc.timeout)`), before any
`#[cfg(test)]`, so it is not scanned and a config-driven timeout is never
reported as unproven. A probe in a `//` comment is not a probe and is skipped.

Every `src` file of the workspace has at most one `#[cfg(test)]` today
(checked with `grep -c`: none has two), so the anchor delimits the unit-test
module exactly.

**The registry.** `.github/scripts/short-health-probes.txt` holds
`<path>::<test fn>  <reason>`, one per line, exhaustive in both directions:
a sub-second probe not declared fails the gate, and an entry whose test no
longer has one fails too (it rotted). An entry covers every sub-second probe
of that test, so its reason has to say why none of them can mark a healthy
origin DOWN. The two entries are the dead-origin tests above.

**Deliberate difference from the roadmap wording.** The roadmap asked for a
gate that fails on a sub-second timeout "junto a `fall = 1`". The gate does
not parse `fall`: it refuses *any* sub-second timeout, whatever the fall,
unless declared. `fall = 1` is the loudest case, not the only one — with a
short timeout a `fall = 2` probe still turns one hiccup into a failed check,
and the builders these tests use put `fall` and the probe in different
positions of a chained expression, where a textual association would be a
guess. The rule that can be proven from text is the probe budget itself; the
declared dead-origin tests are the ones that need less than 1 s.

**Inventory on this tree**, from the gate's own output
([`gate-self-test-and-tree.txt`](v085-short-probes/raw/gate-self-test-and-tree.txt)):

```
self-test ok: short, multi-line, non-literal, TOML, stale, duplicate and malformed input all rejected
suite health probes: 18 found, 2 sub-second or unproven, 2 declared in short-health-probes.txt
ok: every suite health probe has 1 s of timeout or a declared reason
```

18 sites = 8 Rust constructions + 10 TOML `timeout` keys. The two sub-second
sites are the declared dead-origin probes.

**The fifth site came from this gate.** Once the scan included `src`, the
gate failed on `health.rs` with `timeout is 200 ms`
([`gate-finds-health-rs.txt`](v085-short-probes/raw/gate-finds-health-rs.txt),
captured before the repair and therefore naming `:468`). That was not a
roadmap item; it is the same class, and the fix is the one above.

**The gate both ways.** The negative controls are reproducible with
`scripts/evidence/v085-short-probes/gate-control.sh` (local, as `scripts/` is
excluded from the repository):

- a synthetic tree with one undeclared 80 ms probe exits 1, naming the site
  and the declaration that no longer covers anything
  ([`gate-negative-control.txt`](v085-short-probes/raw/gate-negative-control.txt));
- the test files **and `health.rs`** of `HEAD` — before this increment —
  with only the two dead-origin declarations exit 1 **and name exactly the
  five repaired sites**
  ([`gate-against-head.txt`](v085-short-probes/raw/gate-against-head.txt));
- the working tree exits 0.

**CI.** In `.github/workflows/ci.yml`, job `linux-tier1`, after Clippy:

```yaml
      - name: Self-test the short health-probe gate
        run: python3 .github/scripts/check-short-health-probes.py --self-test

      - name: Health probes have 1 s of timeout
        run: python3 .github/scripts/check-short-health-probes.py
```

The self-test runs first, so a detector that stopped detecting fails before
its verdict is trusted. `ci.yml` parses as YAML and both step names are
present in the `linux-tier1` job (checked with `yaml.safe_load`).

## 3. Local verification (macOS arm64, uid 501)

```
$ cargo fmt --all -- --check                    # exit 0
$ cargo clippy --workspace --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 37.84s   # exit 0
$ python3 .github/scripts/check-short-health-probes.py --self-test          # exit 0
$ python3 .github/scripts/check-short-health-probes.py                      # exit 0
```

The four journeys, one run each before the repetition loop:

```
$ cargo test -q -p eqproxy-net --test e2e_resilience http_expect_check_marks_5xx_server_down -- --exact
test result: ok. 1 passed; 0 failed; ... finished in 0.62s
$ cargo test -q -p eqproxy-net --test e2e_resilience http_check_interops_with_keep_alive_origins -- --exact
test result: ok. 1 passed; 0 failed; ... finished in 0.72s
$ cargo test -q -p eqproxy-net --test e2e_balancer slow_start_ramps_the_recovered_server_up -- --exact
test result: ok. 1 passed; 0 failed; ... finished in 4.50s
$ cargo test -q -p eqproxy-net --test e2e_phase2b healthchecks_e2e -- --exact
test result: ok. 1 passed; 0 failed; ... finished in 1.24s
```

The fifth journey, a unit test, after its edit:

```
$ cargo test -q -p eqproxy-net --lib check_task_marks_server_down_and_up_again
test result: ok. 1 passed; 0 failed; ... finished in 0.31s
$ cargo clippy --workspace --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 35.57s   # exit 0
$ cargo fmt --all -- --check                                             # exit 0
```

The 52 repetitions below were run **before** that test-only edit. The four
integration targets link the library without `cfg(test)`, so the unit-test
module cannot change them; the unit test itself was re-run after the edit,
and the final tree went through fmt, Clippy and a new Veyra pass (§5).

Repetitions via `scripts/evidence/v085-short-probes/repeat.sh`:

| Mode | Runs | Failed | Log |
|---|---|---|---|
| idle | 40 (10 × 4 tests) | 0 | [`repeat-20261028T170739Z-idle.txt`](v085-short-probes/raw/repeat-20261028T170739Z-idle.txt) |
| load, 10 `yes` processes (one per core) | 12 (3 × 4 tests) | 0 | [`repeat-20261028T170940Z-load.txt`](v085-short-probes/raw/repeat-20261028T170940Z-load.txt) |

The load mode saturates every core for the duration of the runs — the
condition under which a 150 ms timeout converts a loopback answer into a
failed check. The load processes are killed by recorded PID; no `yes` process
was left behind (checked with `ps`). The logs carry the git revision, the
`dirty` flag, the core count, the toolchain and the probe timeouts read from
the source, so the run can be tied to this tree.

## 4. Limits and NOT EXECUTED

- **CI is NOT EXECUTED.** The tree is uncommitted and nothing was pushed, so
  the new steps have not run in GitHub Actions. Their commands are the ones
  above, run locally.
- **The root tier is NOT EXECUTED.** It exists only in CI; the local runs are
  uid 501.
- **No control proving the old timeouts fail under this synthetic load.** The
  class was reproduced before, under heavier conditions (load average
  218–233 with foreign test binaries), in §1.1 of
  [v08-health-probe-robust](v08-health-probe-robust.md); here 52/52 green runs
  show the repaired probes do not fail, not a probability that the old ones
  would have.
- **The gate is a suite gate.** It says nothing about the production default
  (`1s`, [`schema.rs`](../../eqproxy-config/src/schema.rs)) or about a value an
  operator writes; it scans `tests/` and `src` from the last `#[cfg(test)]`,
  so a harness under `scripts/evidence/` that deliberately reproduces an old,
  short timeout is out of its reach by design. A unit test placed *before* a
  later `#[cfg(test)]` item would be missed; no `src` file in the tree has
  more than one anchor today.
- **A non-literal timeout is rejected, not accepted.** A future refactor that
  hoists the probe into a constant turns the gate red until it is written as
  a literal or declared; that is the intended fail-closed behaviour, not a
  false positive.
- **Two Veyra instances were started by mistake**: the first launch used a
  shell `&` that outlived its tool call, so a second was started while it was
  still running. Both were stopped by PID and §5 cites one clean pass on the
  final tree (`.veyra/evidence/20261028T174418Z/`); the aborted attempt left only
  `.veyra/evidence/20261028T171240Z/tools/`, no report, and is not cited.
- Docker image and Scout gate are untouched by this increment (**NOT
  EXECUTED**).

## 5. Audit legs

### Veyra Proof (real toolchain)

```
$ veyra audit . --profile standard
Decision: ACCEPTED
Decision reason: All required profile tools executed without blocking findings
exit 0 · evidence .veyra/evidence/20261028T174418Z/ (report.md, report.json, manifest.json)
```

The accepted run is on the **final** tree, after the fifth repair. An earlier
accepted run (`.veyra/evidence/20261028T171508Z/`) predates the `health.rs`
change and is not the one cited.

OK: `rustfmt`, `cargo check`, `clippy`, `cargo test`, `cargo-audit`,
`veyra-anti-theater`, `cargo-nextest`, `cargo-llvm-cov`, `cargo-deny`,
`cargo-machete`, `veyra-e2e`. Times: cargo-test 175.5 s, llvm-cov 129.6 s,
geiger 110.3 s, veyra-e2e 67.5 s, nextest 39.1 s; 540.01 s of 542.62 s wall.
The suite leg is the whole `cargo test`/nextest run, so the four repaired
journeys and the fifth unit test were exercised by the audit as well as by
§3.

- **SKIPPED (named, not counted as OK):** `dylint` — no Dylint configuration
  or lint libraries, and Veyra refuses to invent lints; `cargo-semver-checks`
  — no registry baseline for an unpublished crate. Both are the open decision
  of roadmap §3, not a result of this increment.
- **INCONCLUSIVE:** `cargo-geiger` — the scan completed with coverage warnings
  in 4 runs, so its unsafe counts are a lower bound; Veyra reports it as an
  error, not a pass. The same tool was inconclusive in
  `.veyra/evidence/20261025T211457Z/` (before this increment).

### Rust Audit (static scan)

```
$ python3.13 /Volumes/Lexar/Cursor/rust-ai-audit/scripts/rust_audit.py scan . \
    --format md --out report --fail-on high
wrote report/rust-audit-20261028-185949.md
wrote report/not-executed-2026-10-28.md
exit 0
```

Run on the final tree; an earlier scan of the pre-`health.rs` tree
(`report/rust-audit-20261028-181124.md`) reported the same counts.

Tool 0.2.7, engine sha256 `84b5ba5b…`. Severities: **critical 0, high 0**,
medium 241, low 85, info 0. None of the findings starts at an edited line
(`1207`, `1340`, `443`, `459`, `health.rs:472`: no match); the findings in the
touched files are pre-existing `R08` timing heuristics in test helpers
(`e2e_balancer.rs:224` `eventually`, `e2e_resilience.rs:500`/`987`,
`e2e_phase2b.rs:177`). This increment adds no sleep, clock read or assertion,
so it adds no finding. NOT EXECUTED, as listed by the tool's own report:
`--deep` (mutants/coverage/udeps), `--supply-chain` (audit/deny/vet, guarddog,
osv-scanner), `--miri`, `scan --online` (registry/OSV).

### CodeGraph Rust (structure, not behaviour)

```
$ codegraph-rust index . --stats-json /tmp/cg-index-085-final2.json
64 files, 62 380 lines, 7 062 nodes, 12 772 edges, graph_complete: true,
vector_index_ready: true, errors 0, cached_files 63, index_ms 51 666
$ codegraph-rust agent impact "what changes if the suite health-check timeout moves from 200 ms to 1 s in health.rs unit tests" --format text
$ codegraph-rust agent context "where is the anti-short-probe gate and what does it scan" --format text
```

Raw answers:
[`codegraph-impact.txt`](v085-short-probes/raw/codegraph-impact.txt),
[`codegraph-context.txt`](v085-short-probes/raw/codegraph-context.txt).

The **impact** query is what pointed at `health.rs`'s unit test in the first
place; the source check confirmed the 200 ms literal (at `:468` before the
repair), `fall = 1` and the 150 ms sleep, and the gate then found the same
site on its own once it scanned `#[cfg(test)]` (§2). Its final-index answer
adds the right structural fact: the unit tests have no code dependents, so
the change breaks nothing at compile time; it could not confirm the 200 ms
literal because the index had already been rebuilt after the repair, and it
says so instead of inventing it.

The **context** query described the gate in the source's terms, and every
line it named checks out: `test_sources` at `:110`, `rust_probes` at `:200`,
`toml_probes` at `:232`, `problems` at `:297`, `run` at `:326`, `self_test` at
`:352`, `HealthCheck::tcp` at [`health.rs:89`](../../eqproxy-net/src/health.rs#L89)
and the 1 s production default at `schema.rs:91-93`. Its stated gap — it
could not confirm which workflow invokes the script — is covered here: the
two steps in `.github/workflows/ci.yml` (§2).

One claim from the first round was **not** repeated because the source
contradicts it: it said `run` is "called only from `check_one`" (inverted —
`run` spawns `check_one`, [`health.rs:117`](../../eqproxy-net/src/health.rs#L117)).
CodeGraph is not behavioural proof here; the suite and Veyra are.

### Hindsight (memory close-out)

```
$ ~/.local/bin/hindsight-note --title "v0.8.5 debt: five live-origin probes at 1 s + anti-short-probe gate" \
    --project EQProxy --tags v0.8.5,debt,tests,ci
{"status":"completed","message":"Memory stored successfully","memory_ids":["72a3adfb-…", … ,"095a44e4-…"]}
exit 0
```

Nine memory ids; first `72a3adfb-da3d` — bank `eqproxy`, note with the same
commands, results and limits as this page.

