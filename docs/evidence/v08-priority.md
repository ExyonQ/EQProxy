# B7/B8 — backup failover ladder (`priority`), v0.8

Language: **English**.

**Increment:** the `priority` half of parity matrix **B7** and the failover
order of **B8**. The reference manual (HAProxy 3.4.0, `doc/configuration.txt`,
`server` keyword `backup`) says:

> "By default, only the first operational backup server is used, unless the
> "allbackups" option is set in the backend."

and has **no** numeric `priority` keyword on `server` lines. EQProxy therefore
does two things in this slice:

1. brings the backup tier in line with the reference default — **one
   operational backup rung at a time** (the earlier B8 slice load-balanced
   across every eligible backup, which is `option allbackups` semantics and is
   not implemented);
2. adds `priority` (0..=255) as a documented **EQProxy extension** to order
   those rungs, higher first.

**Binary under test:** `target/release/eqproxy`, `eqproxy 0.7.0`, sha256
`11eed39f06b4ea63694be6a7a1cabfbc8dfbdebdf2532f43cc4dadb067003b8b`
(`cargo build --release -p eqproxy-cli`). **Host:** macOS arm64 (Darwin),
`python3` 3.9.6. **Date:** 2026-10-26.

## What the increment does

```toml
[backend.api]
servers = [
  { addr = "10.0.0.1:9000" },
  { addr = "10.0.0.2:9000", backup = true, priority = 10 },  # first rung
  { addr = "10.0.0.3:9000", backup = true, priority = 5 },   # next rung
]
```

- Selection still happens in the one function shared by `roundrobin`,
  `leastconn`, affinity and retries. Primaries (eligible: up, `ready`,
  `weight > 0`, resolved, not excluded by a retry) always outrank the ladder.
- Inside the backup tier the rungs are ordered by `priority` descending, ties
  by configuration order, and **only the first eligible rung is a candidate**.
  A higher rung that recovers takes the traffic back on the next request; a
  retry that excluded the top rung falls through to the next one; affinity
  lands on the active rung instead of a cold one.
- `priority` is validated 0..=255 with the field path in the error, and is
  **rejected on a non-backup slot** (`priority is only meaningful on a backup
  server`) instead of being a silent no-op. The public JSON Schema declares
  `minimum: 0` / `maximum: 255`.
- `GET /api/v1/status` publishes `priority` per slot; `config diff` prints
  `addr(weight,backup,priority)` when the rung differs.
- `option allbackups` is not implemented, so weights do not spread load inside
  the backup tier: one rung serves.

## Tests in the suite

Unit (`eqproxy-net/src/balancer.rs`): `priority_orders_the_backup_ladder`
(highest first, ties by declaration order, recovered rung takes over, primary
outranks the ladder), `a_retry_that_excludes_the_top_rung_uses_the_next_backup`,
`affinity_lands_on_the_active_backup_rung`,
`least_conn_uses_only_the_highest_priority_backup`, plus the corrected
`a_backend_of_only_backups_serves_the_first_operational_rung`. The existing
B8 cases (idle backup, failover/recovery, drain and weight 0, retry,
affinity, leastconn) still pass unchanged.

Config (`eqproxy-config/src/validate.rs`):
`priority_orders_backups_and_is_rejected_outside_the_backup_tier` — a valid
ladder parses, `priority = 256` and `priority` on a primary are both rejected
with `backend.api.servers[0].priority`.

Read plane (`eqproxy-net/src/admin.rs`): `status_marks_backup_servers` now
asserts the published rung (`0` on the primary, `10` on the backup).

CLI (`eqproxy-cli/src/main.rs`): `diff_report_names_a_priority_change` asserts
`[127.0.0.1:9000(1,backup)] -> [127.0.0.1:9000(1,backup,10)]`.

CLI E2E (`eqproxy-cli/tests/cli_e2e.rs::run_priority_ladder_fails_over_between_backups_and_back`):
one primary and two real origins as backup rungs with HTTP health checks
(`fall = 1`, `rise = 1`); the test walks primary → high rung → low rung →
high rung → primary and asserts the cold rung receives nothing.

## E2E journey over the release binary

Harness: `scripts/evidence/v08-priority/journey.py` (local-only; writes into
`docs/evidence/v08-priority/raw/`). Three real origins answer with their own
label; the proxy runs with HTTP health checks (`interval = 200ms`,
`fall = 2`, `rise = 2`) and an admin listener.

```console
$ cargo build --release -p eqproxy-cli
$ shasum -a 256 target/release/eqproxy
11eed39f06b4ea63694be6a7a1cabfbc8dfbdebdf2532f43cc4dadb067003b8b  target/release/eqproxy
$ python3 scripts/evidence/v08-priority/journey.py
binary: /Volumes/Lexar/Cursor/EQProxy/target/release/eqproxy
version: eqproxy 0.7.0
dataplane 127.0.0.1:65379 · admin 127.0.0.1:65382

phase 1: primary healthy, two backup rungs configured
PASS the primary owns the tier: {'primary': 40}
PASS read plane answers status: 200
PASS status publishes the backup rungs: {'127.0.0.1:65376': (False, 0), '127.0.0.1:65377': (True, 10), '127.0.0.1:65378': (True, 5)}

phase 2: the primary dies
PASS the high-priority backup takes over: {'backup-high': 1}
PASS only the high rung serves: {'backup-high': 20}

phase 3: the high rung dies
PASS the lower rung takes over: {'backup-low': 1}
PASS only the lower rung serves: {'backup-low': 20}

phase 4: the high rung recovers
PASS the recovered high rung takes the traffic back: {'backup-high': 1}
PASS the lower rung goes cold again: {'backup-high': 20}

phase 5: the primary recovers
PASS the primary outranks the whole ladder: {'primary': 1}
PASS the primary serves alone: {'primary': 30}

phase 6: everything dies
PASS all-down answers an explicit 503: (503, '')

ALL PASS
```

Raw run: [run-20261026T005004Z](v08-priority/raw/run-20261026T005004Z/)
(config and log). Its final `METRICS` line reports
`accepted=149 completed=149`, `backend[proxied=143 connect_failures=3]`,
`proxy[no_server=3]`.

## Checks run

```console
$ cargo fmt --all --check                              → exit 0
$ cargo clippy --workspace --all-targets -- -D warnings → exit 0
$ cargo test --workspace                               → 29 targets, 519 passed, 0 failed
```

## Audits

| Leg | Command | Verdict / exit | Evidence |
|---|---|---|---|
| 1. Veyra Proof | `veyra audit . --profile standard` | **ACCEPTED**, exit 0; `cargo-test` 29 targets / 519 passed / 0 failed, `nextest` 519/519 (2 skipped), `llvm-cov` 89.57 % lines (31 875 lines, 3 324 missed). SKIPPED `dylint` (no configuration) and `cargo-semver-checks` (no baseline); `cargo-geiger` INCONCLUSIVE (coverage warnings in 4 runs, unsafe counts a lower bound) | `.veyra/evidence/20261026T005530Z/` |
| 2. Rust Audit | `python3.13 /Volumes/Lexar/Cursor/rust-ai-audit/scripts/rust_audit.py scan . --format md --out report --fail-on high` (tool 0.2.7) | exit 0; **critical 0, high 0**, medium 226, low 73, info 0. The two new findings are R08 on the new CLI E2E (`std::thread::sleep` + `Instant::now` waiting for the real health checker) — the test's subject, not a fake assertion | `report/rust-audit-20261026-015537.md`, `report/not-executed-2026-10-26.md` |
| 3. CodeGraph Rust | `codegraph-rust index . --batch-size 16 --stats-json /tmp/cg-index-priority.json`, then `agent context "where is backup priority ordering handled?"` and `agent impact "what breaks if ServerConfig::priority changes?"` | exit 0; `files: 60`, `lines: 57 703`, `nodes: 6 491`, `edges: 11 545`, `graph_complete: true`, `vector_index_ready: true`, `errors: 0`, `index_ms: 536 841` (the store logged one post-run `transaction was dropped` line; the stats and both queries still answered — reported, not suppressed). The cited facts were checked in the source: `Balancer::select` at `balancer.rs:602`, the rung pick at `:631`, `ServerConfig.priority` at `schema.rs:337`, validation at `validate.rs:1436/1446`, the tests at `balancer.rs:1445/1518`, `admin.rs:2034`, `main.rs:3263` and `cli_e2e.rs:3505`. The tool's `schema.rs:316-338` / `validate.rs:1434-1445` ranges are approximate; the precise lines above are the verified ones | `.codegraph/`, `/tmp/cg-index-priority.json` |
| 4. Hindsight | `hindsight-note --title "v0.8 backup priority ladder implemented and E2E" --project EQProxy --tags b8,priority,balancer` | stored, exit 0, bank `eqproxy` (memory IDs `7685aa98…`, `637852c1…`, …) | `eqproxy` bank |

## Limitations

- State at the time of this increment: `option allbackups` was not
  implemented, so only one backup rung served and backup `weight` had no
  effect. The pool landed in the follow-up increment
  ([v08-allbackups](v08-allbackups.md)), where `all_backups = true` balances
  every backup by weight and drops this ladder.
- `priority` is an extension, not parity: the reference has no such keyword.
  It is rejected on primaries (silent no-op avoided), fixed at startup, and
  replaced wholesale by a document PUT or `SIGHUP`.
- Behaviour was exercised over HTTP/1.1 with HTTP health checks; h2/h3, TCP
  mode and gRPC share the same selection but were not re-run separately.
- A backend made only of backups follows the ladder and gets no configuration
  warning (same as the reference).
