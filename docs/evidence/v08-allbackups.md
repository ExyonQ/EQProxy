# B7/B8 — backup pooling (`option allbackups`), v0.8

Language: **English**.

**Increment:** the pooling half of parity matrix **B7/B8**, and the last
declared gap of the backup tier. The reference manual (HAProxy 3.4,
`option allbackups`) states:

> "When "option allbackups" is enabled, the load balancing will be performed
> [among all backup servers] … The same load balancing algorithm will be used
> and the servers' weights will be respected. Thus, there will not be any
> priority order between the backup servers anymore."

(Quoted from the official manual page `option allbackups`,
<https://docs.haproxy.org/3.4/configuration.html>; the same two sentences
appear on the 3.0/2.8/2.6/2.4 pages of the same manual returned by the same
lookup. The full page was not rendered here, so the wording is cited as the
manual's own, not paraphrased.)

EQProxy adds `all_backups` (a backend field, `false` by default, standing for
`option allbackups`). With it on, the whole backup tier is one pool: every
operational backup is a candidate, so the algorithm and the `weight`s spread
the load — and, as the reference says, the `priority` ladder of the previous
increment ([v08-priority](v08-priority.md)) no longer orders anything.

Two deviations from the reference, both deliberate and both reported instead
of silently ignored: the reference ignores `priority` when `allbackups` is on
and ignores `allbackups` in a backend with no backup server; EQProxy **refuses
both** as configuration errors (the field path and a fix in the message), so a
configuration never looks applied while doing nothing.

**Binary under test:** `target/release/eqproxy`, `eqproxy 0.7.0`, sha256
`4f15f531f4fbb13f1800151f4f124a79bfa38f5703f2393d6d7cc7b807a45adb`
(`cargo build --release -p eqproxy-cli`). **Host:** macOS 26.5.1 arm64
(Darwin), `python3` 3.9.6. **Date:** 2026-10-26.

**Re-runs (same tree, final binaries):** the journey was repeated against the
release binary of the panel increment, sha256
`47fff1c8cef6193640d3cecbba166b7dbd1f84bf5c5acf392d42b9adb0279c9c` — 15
`PASS`, 0 `FAIL`, `ALL PASS`, raw transcript and configs in
[`raw/run-20261027T003549Z/`](v08-allbackups/raw/run-20261027T003549Z/)
(`python3.13`) — and once before that against `c532bd1c…` in
[`raw/run-20261026T230424Z/`](v08-allbackups/raw/run-20261026T230424Z/), with
the same result. The numbers in this page are from the run cited above and
all three runs agree on every phase.

## What the increment does

```toml
[backend.api]
balance = "roundrobin"        # or "leastconn"
all_backups = true            # HAProxy `option allbackups`
servers = [
  { addr = "10.0.0.1:9000" },
  { addr = "10.0.0.2:9000", weight = 2, backup = true },
  { addr = "10.0.0.3:9000", weight = 1, backup = true },
]
```

- Selection still happens in the one function shared by `roundrobin`,
  `leastconn`, affinity and retries ([balancer.rs:629](eqproxy-net/src/balancer.rs#L629)).
  Primaries (eligible: up, `ready`, `weight > 0`, resolved, not excluded by a
  retry) always outrank the backup tier — the pool is a backup tier, not a
  union with the primaries ([balancer.rs:654](eqproxy-net/src/balancer.rs#L654)).
- With `all_backups = true` the tier predicate admits **every** eligible
  backup ([balancer.rs:429](eqproxy-net/src/balancer.rs#L429)) and the rung
  selection is skipped entirely, so the existing SWRR/leastconn code spreads
  the load by weight inside the pool. Retries, affinity and the drain/`weight
  = 0` rules keep working inside the pool unchanged; with the flag off the
  previous behaviour is untouched (the rung pick runs exactly as before).
- Validation: `priority` + `all_backups` is an error naming
  `backend.api.servers[N].priority`
  ([validate.rs:1469](eqproxy-config/src/validate.rs#L1469)), and
  `all_backups` in a backend with no `backup = true` slot is an error naming
  `backend.api.all_backups` ([validate.rs:1480](eqproxy-config/src/validate.rs#L1480)).
  The public JSON Schema declares the field
  ([schema.rs:1143](eqproxy-config/src/schema.rs#L1143), regenerated
  `eqproxy.schema.json`).
- Observability: `GET /api/v1/status` publishes the live policy per backend
  ([admin.rs:391](eqproxy-net/src/admin.rs#L391),
  [admin.rs:1637](eqproxy-net/src/admin.rs#L1637)), `config explain` prints
  `all_backups=true` when on ([main.rs:1660](eqproxy-cli/src/main.rs#L1660))
  and `config diff` reports the transition
  ([main.rs:505](eqproxy-cli/src/main.rs#L505)).
- The flag survives every balancer rebuild: `with_balance` and
  `with_server_modes` re-apply it
  ([proxy.rs:153](eqproxy-net/src/proxy.rs#L153),
  [proxy.rs:193](eqproxy-net/src/proxy.rs#L193)), and the CLI applies it to
  the real topology ([main.rs:2481](eqproxy-cli/src/main.rs#L2481)). Startup
  and the hot write path build that topology through the same
  `resolve_with` ([main.rs:2426](eqproxy-cli/src/main.rs#L2426) and
  [main.rs:2192](eqproxy-cli/src/main.rs#L2192)), so a document `PUT` or
  `SIGHUP` applies the policy too instead of only a restart.

## Tests in the suite

Unit (`eqproxy-net/src/balancer.rs`): `all_backups_balances_the_whole_tier_by_weight`
(a primary outranks the pool; with the primary down, 2:1 weights split 9 picks
6/3), `all_backups_drops_the_priority_ladder` (two rungs with different
`priority` strictly alternate — no rung owns the tier),
`all_backups_keeps_a_dead_member_out_and_a_retry_skips_the_one_it_tried`
(failed member out of rotation, retry exclusion inside the pool, recovered
member shares again), `all_backups_with_every_member_unusable_is_still_none`
(weight 0 and all-down), `least_conn_spreads_inside_the_backup_pool`,
`affinity_pins_inside_the_backup_pool` (pin kept, next member in configuration
order when the pinned one dies). The eleven earlier B8 cases still pass
unchanged, which is the regression check for the default (flag off).

Config (`eqproxy-config/src/validate.rs`):
`all_backups_balances_the_pool_and_refuses_a_contradiction` — a weighted pool
validates; `priority` + `all_backups` and `all_backups` with no backup slot
(both the `servers` list and the single `server` form) are rejected with their
field paths.

Read plane (`eqproxy-net/src/admin.rs`): `status_marks_backup_servers` now
asserts `all_backups` is `false` on the default backend and `true` on the
same slots built with the pool on.

CLI (`eqproxy-cli/src/main.rs`): `diff_report_names_an_all_backups_change`
asserts `~ backend "api" all_backups: false -> true`.

CLI E2E (`eqproxy-cli/tests/cli_e2e.rs`):
`run_all_backups_spreads_traffic_across_the_backup_pool` walks the real binary
through five phases with three real origins and HTTP health checks
(`fall = 1`, `rise = 1`) asserting **exact** weighted counts (30 requests =
20/10 and 21 = 14/7 under weights 2:1, the pool cycle being 3 requests);
`validate_accepts_a_backup_pool_and_refuses_a_contradiction` proves the three
validation outcomes (pool accepted, ladder refused, empty pool refused) over
`eqproxy config validate` and asserts the error text and exit code 1.

## E2E journey over the release binary

Harness: `scripts/evidence/v08-allbackups/journey.py` (local-only; writes into
`docs/evidence/v08-allbackups/raw/`). Three real origins answer with their own
label; the proxy runs with HTTP health checks (`interval = 200ms`, `fall = 2`,
`rise = 2`) and an admin listener.

```console
$ cargo build --release -p eqproxy-cli
$ shasum -a 256 target/release/eqproxy
4f15f531f4fbb13f1800151f4f124a79bfa38f5703f2393d6d7cc7b807a45adb  target/release/eqproxy
$ python3 scripts/evidence/v08-allbackups/journey.py
binary: /Volumes/Lexar/Cursor/EQProxy/target/release/eqproxy
version: eqproxy 0.7.0
[roundrobin] dataplane 127.0.0.1:54491 · admin 127.0.0.1:54492

[roundrobin] phase 1: primary healthy, pool cold
PASS the primary owns the tier: {'primary': 40}
PASS config explain names the pool policy
PASS read plane answers status: 200
PASS status publishes the live pool policy and the weights: {'all_backups': True, 'slots': {…: (1, False, 0), …: (2, True, 0), …: (1, True, 0)}}

[roundrobin] phase 2: the primary dies, the whole pool serves
PASS the pool takes over: {'backup-low': 1}
PASS the pool splits the load 2:1 by weight: {'backup-high': 20, 'backup-low': 10}

[roundrobin] phase 3: one pool member dies
PASS the survivor takes the whole tier: {'backup-low': 1}
PASS the dead member leaves rotation: {'backup-low': 20}

[roundrobin] phase 4: the member recovers
PASS the recovered member rejoins the pool: {'backup-high': 1}
PASS the pool balances again with the recovered member's share: {'backup-high': 14, 'backup-low': 7}

[roundrobin] phase 5: the primary recovers
PASS the primary outranks the whole pool: {'primary': 1}
PASS the pool is cold again: {'primary': 30}

[roundrobin] phase 6: everything dies
PASS all-down answers an explicit 503: (503, '')

leastconn leg: the same pool under the other algorithm
[leastconn] dataplane 127.0.0.1:54900 · admin 127.0.0.1:54901
PASS [leastconn] the pool serves once the primary is gone: {'backup-low': 1}
PASS [leastconn] the pool splits the load 2:1 by weight: {'backup-high': 20, 'backup-low': 10}

ALL PASS
```

Raw run: [run-20261026T183429Z](v08-allbackups/raw/run-20261026T183429Z/)
(`journey.txt` with the transcript above, both `eqproxy-<balance>.toml` configs
and logs, `explain.txt`, `status.json`).

A previous run of the harness
([run-20261026T183359Z](v08-allbackups/raw/run-20261026T183359Z/)) is kept on
disk and is **not** the accepted one: its wait predicate accepted a `502`
(sent while the balancer had not yet written the dead primary off) as "the
tier moved" and then counted 30 refused requests. The predicate was fixed to
wait for a real pool answer before the accepted run above; the failure was a
harness bug, not a product result, and the config, log and status of that run
are unchanged on disk.

## Checks run

```console
$ cargo fmt --all --check                              → exit 0
$ cargo clippy --workspace --all-targets -- -D warnings → exit 0
$ cargo test --workspace                               → 29 targets, 529 passed, 0 failed (2 ignored)
```

The 529 passed are 10 more than the 519 of the `priority` increment: 6 balancer
unit cases, 1 config validation case, 1 diff case, the `status_marks_backup_servers`
assertions, and the 2 CLI E2E cases.

## Audits

| Leg | Command | Verdict / exit | Evidence |
|---|---|---|---|
| 1. Veyra Proof | `veyra audit . --profile standard` | **ACCEPTED**, exit 0, reason "All required profile tools executed without blocking findings"; OK: rustfmt, cargo check, clippy, cargo test (29 targets / **529 passed** / 0 failed), cargo-audit, veyra-anti-theater, cargo-nextest (**529 tests run: 529 passed, 2 skipped**), cargo-llvm-cov (**88.41 % lines**, 21 343 lines / 2 473 missed; 89.65 % regions, 91.52 % functions), cargo-deny, cargo-machete, veyra-e2e (its scenario suite PASS). SKIPPED `dylint` (no configuration, "refusing to invent lints") and `cargo-semver-checks` (no baseline for unpublished crates); `cargo-geiger` **ERROR / inconclusive** (coverage warnings in 4 runs, unsafe counts a lower bound — not a pass). 421.88 s of 424.26 s wall in tools. Run started 18:38:39Z, i.e. after the last Rust edit; the only edits after it are documentation (this page) | `.veyra/evidence/20261026T183839Z/` (report.md, report.json, per-tool logs) |
| 2. Rust Audit | `python3.13 /Volumes/Lexar/Cursor/rust-ai-audit/scripts/rust_audit.py scan . --format md --out report --fail-on high` (tool 0.2.7) | exit 0; **critical 0, high 0**, medium 228, low 73, info 0 (301 findings). This increment adds exactly two: R08 medium on the new CLI E2E, `cli_e2e.rs:3639` — `Instant::now()` (the wait deadline) and `std::thread::sleep` waiting for the **real** health checker, which is the subject of the test, not a fake assertion; the other 299 are pre-existing and none points at the new balancer, validation, status or diff code | `report/rust-audit-20261026-193906.md`, `report/not-executed-2026-10-26.md` |
| 3. CodeGraph Rust | `codegraph-rust index . --batch-size 16 --stats-json /tmp/cg-index-allbackups.json` (after the last code edit), then `agent context "where is the option allbackups backup pool decided during server selection?"` and `agent impact "what breaks if Balancer::with_all_backups changes or is removed?"` | exit 0; `files: 60`, `lines: 58 358`, `nodes: 6 558`, `edges: 11 680`, `graph_complete: true`, `vector_index_ready: true`, `embedding_status: ready`, `semantic_status: ready`, `errors: 0`, `index_ms: 804 523` (13.4 min; 53 files reused from the cache, no error line this run). The `context` answer matched the source where it pointed: `Balancer::select` `balancer.rs:629`, the tier decision `:654`/`:668`, the flag `:228`, builder `:379`, getter `:387`, `ResolvedBackend::with_all_backups` `proxy.rs:163`, the rebuild preservation `proxy.rs:153`/`:193`, `BackendStatus.all_backups` `admin.rs:391`, the validation test `validate.rs:2373`, the CLI E2E `cli_e2e.rs:3639`, the diff test `main.rs:3299`. Its two **declared gaps** were closed by hand: the config→`ResolvedBackend` wiring it could not establish is `main.rs:2480`, reached through `resolve_with` from startup (`main.rs:2413`) and from the hot write path (`main.rs:2211`). The `impact` answer's "`Balancer::with_all_backups` has no non-test dependents" is a resolution artifact it names itself (the call at `proxy.rs:173` was recorded as a self-edge); the real consumers are the two rebuild helpers, checked in the source. Its ranges (`select` 629–727, `proxy.rs` 156/195) are approximate; the precise lines above are the verified ones | `.codegraph/`, `/tmp/cg-index-allbackups.json` |
| 4. Hindsight | `~/.local/bin/hindsight-note --title "v0.8 option allbackups (backup pool) implemented and E2E" --project EQProxy --tags b8,allbackups,balancer` | stored, exit 0, `{"status":"completed","message":"Memory stored successfully"}`, bank `eqproxy` (nine memory IDs, first `0bb9d747-3930-4e44-bdca-a444bfaa582f`) | `eqproxy` bank |

## Not executed in this increment

- **Docker gate** (image build, the journeys inside the container on both
  architectures, Docker Scout): **NOT EXECUTED** — this increment publishes
  nothing and cuts no release, so the release-time gate it belongs to was not
  opened. No image was built or pushed.
- **The deeper audit legs** (`cargo --deep`: mutants/llvm-cov/udeps,
  `cargo --supply-chain`: audit/deny/vet/guarddog/osv-scanner, `cargo --miri`,
  `scan --online`): **NOT EXECUTED** for this increment; the profile that ran
  is `standard` (leg 1) plus the static scan (leg 2).
- **h2/h3, TCP mode and gRPC re-run**: **NOT EXECUTED** — they share the same
  selection function, and the claim is a code-level one (the flag is read in
  `select`), not a measured one.
- **`commit`/`push`**: **NOT EXECUTED** — not requested; the tree is left
  uncommitted.

## Limitations

- Exercised over HTTP/1.1 with HTTP health checks. h2/h3, TCP mode and gRPC
  share the same selection function and the same flag, but were not re-run for
  it in this increment.
- `all_backups` is backend-wide startup configuration: it is replaced wholesale
  by a document PUT or `SIGHUP` (ADR-0019), and no runtime route flips it.
- Stricter than the reference by decision: pairing it with `priority`, or using
  it with no `backup = true` slot, is refused; HAProxy ignores both silently.
  A configuration that moves from an HAProxy setup would have to drop the
  `priority` values (an EQProxy-only field anyway) when it turns the pool on.
- The pool covers the backup tier only. A backend that mixes weighted primaries
  and backups keeps two tiers: primaries first, the pool when none is eligible.
- `priority` remains an EQProxy extension (`v08-priority`), and the pool makes
  it inert by design rather than by accident: the pair is rejected, so no
  configuration can carry both orders at once.
