# B8/Q1 — the backup pool flipped on a running proxy, v0.8

Language: **English**.

**Increment:** `option allbackups` is a backend field, and a running backend is
replaced wholesale by the document write of
[ADR-0019](../adr/0019-hot-config-writes-via-admin-api.md). This page proves
the two compose: the pool is turned on **while the proxy serves**, the whole
backup tier starts balancing from the next pick, a contradicting candidate
changes nothing, and writing the single-primary document back retires the pool
— no restart, no dropped client request.

| Piece | Where |
|---|---|
| A whole `[backend.<name>]` table replaces the live one | [lib.rs:87](eqproxy-config/src/lib.rs#L87) (`parse_backend_table`), [lib.rs:109](eqproxy-config/src/lib.rs#L109) (`parse_table`: the body may be the bare table **or** the complete section) |
| Validation + swap + revision, serialised with `SIGHUP` | [main.rs:2192](eqproxy-cli/src/main.rs#L2192) (`apply_candidate`) |
| The rebuilt balancer keeps the policy | [proxy.rs:163](eqproxy-net/src/proxy.rs#L163) (`with_all_backups`) |
| CLI E2E of the same flip (debug profile) | [cli_e2e.rs:3857](eqproxy-cli/tests/cli_e2e.rs#L3857) (`run_document_put_flips_the_backup_pool_live`) |
| Panel form that drives the same pipeline | [cli_e2e.rs:4206](eqproxy-cli/tests/cli_e2e.rs#L4206) (`run_panel_applies_a_table_and_drains_a_server`), [ADR-0029](../adr/0029-panel-sessions-and-csrf.md) |

## Binary under test

- `target/release/eqproxy`, `eqproxy 0.7.0`, sha256
  `47fff1c8cef6193640d3cecbba166b7dbd1f84bf5c5acf392d42b9adb0279c9c`
  (`cargo build --release -p eqproxy-cli`, final tree of the increment,
  rebuilt with the panel wiring; the journey was also run against the previous
  build `c532bd1c…` in `raw/run-20261026T230428Z/`, same outcome, and the
  quotes below are from this run).
- Host: macOS 26.5.1 arm64 (Darwin), `python3.13`.
- Journey: [`scripts/evidence/v08-flip-live/journey.py`](../../scripts/evidence/v08-flip-live/journey.py)
  (local-only harness), run from the repository root.
- Raw run: [`docs/evidence/v08-flip-live/raw/run-20261027T003553Z/`](v08-flip-live/raw/run-20261027T003553Z/)
  — `journey.txt`, `eqproxy.toml` (the starting document), `eqproxy.log`,
  `status.json`, `metrics.txt`.

## Command

```console
$ python3.13 scripts/evidence/v08-flip-live/journey.py
binary: /Volumes/Lexar/Cursor/EQProxy/target/release/eqproxy
version: eqproxy 0.7.0
sha256: 47fff1c8cef6193640d3cecbba166b7dbd1f84bf5c5acf392d42b9adb0279c9c  target/release/eqproxy
dataplane 127.0.0.1:49732 · admin 127.0.0.1:49735
servers {'a': '127.0.0.1:49729', 'h': '127.0.0.1:49730', 'l': '127.0.0.1:49731'}
```

Exit code **0**, 22 `PASS`, 0 `FAIL`, last line `ALL PASS`.

## What was run

Two clients hammer the proxy for the whole run; the document writes happen
while they do. Every write is conditional (`If-Match`) and carries the
**complete** section, health check included, because a document write replaces
the table.

1. **Before the flip** the running document has one primary and no pool:

   ```
   PASS the primary owns the tier: ['a', 'a', 'a', 'a', 'a', 'a']
   PASS the live document reports one server and no pool: {'all_backups': False, 'servers': [{…}]}
   PASS the starting revision is read: v1
   ```

2. **The pool is written under load** (`v1 → v2`, one commit):

   ```
   PASS the commit is accepted: (200, '{"elapsed_ms":0,…,"revision":"v2",…}')
   PASS the commit is one revision: v2
   PASS the commit is measured under a second: 0
   PASS no client request failed across the flip: {'failed': 0, 'ok': 580}
   PASS clients kept being served: {'ok': 580, 'labels': {'a': 580}}
   ```

   580 requests crossed the flip with zero failures — the claim is "invisible",
   and the counter is the evidence.

3. **The pool the document describes is the pool the dataplane uses**: weights
   and the `backup` flag are in the status JSON, and with the primary failed
   the split is exactly 2:1:

   ```
   PASS the live document is the pool now: {'all_backups': True, 'servers': [{'addr': '127.0.0.1:49729', 'weight': 1, 'backup': False}, {'addr': '127.0.0.1:49730', 'weight': 2, 'backup': True}, {'addr': '127.0.0.1:49731', 'weight': 1, 'backup': True}]}
   PASS the pool serves: (200, 'h')
   PASS the pool splits 2:1 by weight: {'h': 20, 'l': 10}
   ```

4. **A contradicting candidate is refused by the validator, not silently
   applied**, the revision does not move and the pool keeps serving:

   ```
   PASS the contradiction is refused: (400, '{"error":"invalid_config","message":"… field `backend.api.servers[1].priority`: all_backups = true balances every backup at once: no failover ladder is left for `priority` to order …"}')
   PASS the revision did not advance: v2
   PASS the running pool still serves: (200, 'h')
   ```

5. **Retiring the pool** (`v2 → v3`) hands the tier back to the primary and the
   retired members stop receiving traffic:

   ```
   PASS the retirement is accepted: (200, '{"revision":"v3",…}')
   PASS the primary owns the tier again: (200, 'a')
   PASS every request goes to the primary: ['a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a']
   PASS the retired members see no more traffic: {'served': 90, 'before': 90}
   PASS the clients never failed across any flip: {'failed': 0, 'ok': 745}
   ```

   Across all three commits (v1→v2→v3, plus the refused candidate): **745
   client requests, 0 failures** (the count follows how long the load
   generators ran; the older run reported 984 with the same zero failures).

## What this does not prove

- Only HTTP/1.1 data traffic was driven. The flip is a configuration commit, so
  it does not depend on the client protocol — but no h2/h3/WS/TCP traffic was
  run **for this page**.
- The `elapsed_ms` of the commit is `0` on this host: the assertion is
  `< 1000`, the same bound the roadmap sets. It is not a latency measurement.
- The health-check interval is 150 ms and `fall`/`rise` are 1, chosen so the
  journey is quick; a production one is slower to declare a server down.
- Runtime-only, by design (ADR-0019): the file is still the baseline, and the
  next `SIGHUP` replaces what the API wrote.

## Not executed

- **Docker image and Docker Scout**: **NOT EXECUTED** — nothing is published
  here.
- **h2/h3/TCP/gRPC traffic during the flip**: **NOT EXECUTED** for this page.
- **A second architecture**: **NOT EXECUTED** (host-only run, arm64).
