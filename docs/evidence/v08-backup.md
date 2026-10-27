# B8 — backup servers (`backup = true`), v0.8

Language: **English**.

**Increment:** parity matrix **B8** — HAProxy `server … backup`, "activated
only when primaries fail", with the primary → backup → primary transition.
Sibling of B7 (weights), whose known-limitations column no longer points at a
missing flag. Semantics recorded in [SPEC §7.5](../SPEC.md#75-tls-balancing-and-health-checks-phase-2b).

**Binary under test:** `target/release/eqproxy`, `eqproxy 0.7.0`,
sha256 `02d86a529c3913756f770d66ed395c345087c676d50a87e8fa5602390dd37e68`
(`cargo build --release -p eqproxy-cli`).
**Host:** macOS arm64 (Darwin), `python3` 3.9.6 (the harness has no 3.10-only
syntax). **Date:** 2026-10-26.

## What the increment does

```toml
[backend.api]
servers = [
  { addr = "10.0.0.1:9000" },
  { addr = "10.0.0.2:9000", backup = true },   # B8: only when no primary is
]                                             # eligible
```

- `backup` is a **per-slot boolean**, parsed and validated with the rest of
  the server table (`servers[0].backup` is named in the error for a non
  boolean), regenerated into `eqproxy.schema.json`.
- The selection function both algorithms (`roundrobin`, `leastconn`) share —
  and which also serves affinity/hash picks — computes one **tier** per
  request: if any primary is eligible, only primaries are candidates;
  otherwise only backups. Eligible means: health `up`, administrative state
  `ready`, `weight > 0`, address resolved and not excluded by a retry. Inside
  the backup tier one rung serves at a time (the first operational backup),
  and a backend whose slots are all backups follows the same ladder. The
  follow-up increment added `priority` to order those rungs
  ([v08-priority](v08-priority.md)).
- No timer and no latch: the moment a primary is eligible again it is chosen
  on the next request, and the backup goes cold with its counters intact.
- `GET /api/v1/status` reports `backup` for every slot, so the read plane
  names the role instead of leaving an operator to infer it from traffic.

## Tests in the suite

Unit (`eqproxy-net/src/balancer.rs`, seven cases): idle backup while a
primary is eligible, failover when every primary is down and return on
recovery, drained and `weight = 0` primaries handing over to the backup,
retry exclusion of the primary using the backup, affinity never pinning to a
backup while a primary is up, an all-backups backend serving its first
operational rung, and `leastconn` never using the backup while a primary is
eligible.

Config (`eqproxy-config/src/validate.rs`): `backup_servers_parse_and_validate_without_weakening_the_list`
— mixed list with weights parses, the address list itself is untouched, and
`backup = "yes"` is rejected with the field path.

CLI E2E (`eqproxy-cli/tests/cli_e2e.rs::run_backup_server_covers_a_failed_primary_and_returns_on_recovery`):
a primary and a backup as real origins with HTTP health checks; the backup
stays idle while the primary is healthy, takes over when it fails, and the
primary takes the traffic back after recovery.

Read plane (`eqproxy-net/src/admin.rs::status_marks_backup_servers`): the
status JSON carries `backup: false` for a primary slot and `true` for the
backup slot.

Operator surfaces (`eqproxy-cli/src/main.rs::diff_report_names_a_server_turning_backup`):
`config diff` prints the transition as
`[127.0.0.1:9000(1)] -> [127.0.0.1:9000(1,backup)]`, so the flag is visible
before a reload, not only in the status plane.

## E2E journey over the release binary

Harness: `scripts/evidence/v08-backup/journey.py` (local-only, `scripts/` is
excluded from the repository; it writes its raw run into
`docs/evidence/v08-backup/raw/`). Three real HTTP origins answer with their
own label, two configured as primaries and one as a backup; the binary runs
with HTTP health checks (`interval = 200ms`, `fall = 2`, `rise = 2`) and an
admin listener with both tokens.

```console
$ cargo build --release -p eqproxy-cli
$ shasum -a 256 target/release/eqproxy
02d86a529c3913756f770d66ed395c345087c676d50a87e8fa5602390dd37e68  target/release/eqproxy
$ python3 scripts/evidence/v08-backup/journey.py
binary: /Volumes/Lexar/Cursor/EQProxy/target/release/eqproxy
version: eqproxy 0.7.0
dataplane 127.0.0.1:49671 · admin 127.0.0.1:49672

phase 1: two primaries healthy, backup configured
PASS both primaries answered: {'primary-b': 20, 'primary-a': 20}
PASS the backup is idle: 0
PASS read plane answers status: 200
PASS status marks exactly the backup slot: {'127.0.0.1:49668': False, '127.0.0.1:49669': False, '127.0.0.1:49670': True}

phase 2: both primaries die
PASS traffic fails over to the backup: {'backup-c': 1}
PASS every request lands on the backup: {'backup-c': 30}

phase 3: primary-a recovers
PASS traffic returns to the primary and leaves the backup: {'primary-a': 1}
PASS the recovered primary serves alone: {'primary-a': 30}

phase 4: everything dies
PASS all-down answers an explicit 503: (503, '')

ALL PASS
```

The same journey was re-run after the `priority` ladder landed (single backup,
so the expected result is unchanged): sha256
`11eed39f06b4ea63694be6a7a1cabfbc8dfbdebdf2532f43cc4dadb067003b8b`,
`ALL PASS`, raw run
[run-20261026T005143Z](v08-backup/raw/run-20261026T005143Z/).

The first run's own files are
[raw/run-20261026T000510Z/eqproxy.toml](v08-backup/raw/run-20261026T000510Z/eqproxy.toml)
and [its log](v08-backup/raw/run-20261026T000510Z/eqproxy.log). The final
`METRICS` line of that log closes the journey: `accepted=112 completed=112`,
`backend[proxied=107 connect_failures=3]`, `proxy[no_server=2]` — 40 requests
in phase 1, 31 in phase 2 (one probe), 31 in phase 3 and 2 all-down probes,
with the three refused connects being the dead primaries in phase 2 and the
dead backup in phase 4.

## Checks run

```console
$ cargo fmt --all --check                            → exit 0
$ cargo clippy --workspace --all-targets -- -D warnings → exit 0
$ cargo test --workspace                             → 29 targets, 512 passed, 0 failed
```

The one failure this increment hit in a full run was
`run_writes_combined_lines_when_configured`, which asserted a hardcoded
`[25/Oct/` stamp and therefore failed on 2026-10-26. The assertion was
replaced by a shape check of the real UTC stamp (`DD/Mon/YYYY:HH:MM:SS
+0000`, month in the calendar list), which tests the same contract without
owning a calendar day; no other test was weakened.

## Audits

| Leg | Command | Verdict / exit | Evidence |
|---|---|---|---|
| 1. Veyra Proof | `veyra audit . --profile standard` | **ACCEPTED**, exit 0; `cargo-test` 29 targets / 512 passed / 0 failed, `nextest` 512/512 (2 skipped), `llvm-cov` 89.53 % lines (31 690 lines, 3 318 missed). SKIPPED `dylint` (no configuration) and `cargo-semver-checks` (no published baseline); `cargo-geiger` INCONCLUSIVE (coverage warnings in 4 runs, unsafe counts a lower bound) | `.veyra/evidence/20261026T001855Z/` |
| 2. Rust Audit | `python3.13 /Volumes/Lexar/Cursor/rust-ai-audit/scripts/rust_audit.py scan . --format md --out report --fail-on high` (tool 0.2.7) | exit 0; **critical 0, high 0**, medium 224, low 73, info 0. The two findings on this increment are R08 on the new CLI E2E: `std::thread::sleep` and `Instant::now` waiting for the real health checker — timing dependence that is the test's subject (it waits for `fall`/`rise`), not a fake assertion | `report/rust-audit-20261026-010915.md`, `report/not-executed-2026-10-26.md` |
| 3. CodeGraph Rust | `codegraph-rust index . --batch-size 16 --stats-json /tmp/cg-index-b8.json`, then `agent impact "what breaks if Balancer::select changes?"` and `agent context "where is the backup server tier handled in selection?"` | exit 0; `files: 60`, `lines: 57 280`, `nodes: 6 448`, `edges: 11 486`, `graph_complete: true`, `vector_index_ready: true`, `errors: 0`, `index_ms: 104 316`. The two answers were checked against the source: `Balancer::select` at `eqproxy-net/src/balancer.rs:588`, the tier comment and predicate at `balancer.rs:603–609`, the four pick wrappers at `520/530/549/562`, `pick_server` at `proxy.rs:1955`, `status_marks_backup_servers` at `admin.rs:2028` and the diff test at `main.rs:3243` all match. Impacts named by the tool that could not be confirmed as calls (`any`, `usable`, `options`…) were discarded as name collisions, as the tool itself warned | `.codegraph/`, `/tmp/cg-index-b8.json` |
| 4. Hindsight | `hindsight-note --title "v0.8 B8 backup servers implemented and E2E" --project EQProxy --tags b8,backup,balancer` | stored, exit 0, bank `eqproxy` (memory IDs `00027f02…`, `f8c30180…`, …) | `eqproxy` bank |

## Limitations

- State at the time of this increment: one backup rung at a time, matching
  the reference default; `option allbackups` (all backups concurrently,
  load-balanced) was not implemented yet, so backup weights had no effect.
  Two follow-up increments closed that: `priority` ordering
  ([v08-priority](v08-priority.md)) and the pool itself, `all_backups = true`
  ([v08-allbackups](v08-allbackups.md)).
- An all-backups backend follows the same ladder (the reference behaves the
  same); it is not rejected and generates no configuration warning.
- Behaviour was exercised over HTTP/1.1 with HTTP health checks; h2/h3, TCP
  mode and gRPC share the same balancer selection but were not re-run
  separately for this flag.
- `backup` is startup configuration; like the rest of a backend it is
  replaced wholesale by a document PUT or by `SIGHUP` (ADR-0019), and there
  is no runtime route that flips a slot's tier.
