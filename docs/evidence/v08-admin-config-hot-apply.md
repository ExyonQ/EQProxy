# v0.8 — Hot backend and listener configuration (ADR-0019)

Language: **English**. Raw data: [`v08-admin-config-hot-apply/raw/`](v08-admin-config-hot-apply/raw/).

## What was proved

A running `eqproxy` accepts a configuration write on its admin plane and swaps
the dataplane **without dropping a request**, under four concurrent clients:

1. modify the live backend `api` (origin A → B);
2. create a backend `green` (origin C);
3. repoint the live listener `web` to `green` on the same socket;
4. refuse an invalid table (`400`), a stale revision (`412`), a bind conflict
   (`409`, old generation keeps serving) and a writer that read the same
   revision (exactly one `200`, the other `412`);
5. `SIGHUP` restores the file baseline as the next generation;
6. `SIGINT` exits cleanly with code 0.

Traffic counters span every generation (`origin-a`, `origin-b`, `origin-c`),
the failure counter stays at **0**, and every configuration `PUT` answers
`200` only after the dataplane reports a committed swap with `elapsed_ms`
below the roadmap's one-second gate.

## Artifact and environment

- Binary: `target/debug/eqproxy` (Cargo debug profile), sha256
  `f59ed6ba45d9eadacf4c5ff345a0b406ae959a4f543bff15252fedbaddd54a88`.
- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, macOS 15 (Darwin),
  Apple silicon (aarch64).
- Real dependencies: the binary itself, three real HTTP origins (Python
  `ThreadingHTTPServer`), four real HTTP clients, the loopback kernel stack.
  No mock of the proxy, the admin plane, the origins or the transport.
- Build: `cargo build -p eqproxy-cli` (debug, exit 0).

## Commands and results

### Format, lint, suite

```console
$ cargo fmt --all --check
(no output, exit 0)
$ cargo clippy --workspace --all-targets -- -D warnings
Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.31s
(exit 0)
$ cargo test --workspace
...
total summed over the 29 test binaries: 460 passed, 0 failed, 2 ignored
(exit status 0; full log in raw/full-suite.txt)
```

The two ignored tests are the existing miri-only `#[cfg_attr(miri, ignore)]`
cases; they run in a normal `cargo test` and are not part of this slice.

A rejected Veyra run before this one (`20261024T233622Z`, exit 1) failed
`cargo-llvm-cov` because the pre-existing
`run_slow_start_ramps_the_recovered_server_up` E2E assumed a fixed
2.5 s wall-clock ramp: under coverage the health checker marked the origin up
later than its nominal tick, so a 10-request window still saw `6:4`. The test
now polls the same exact `5:5` window (20 s bound) instead of sleeping; the
assertion is unchanged and stricter in what it observes (the split must
actually become exactly fair). The accepted run below executes that test under
llvm-cov, which is the environment that exposed the race.

### Automated E2E (real binary, real sockets)

```console
$ cargo test -p eqproxy-cli --test cli_e2e run_admin_plane -- --nocapture
running 3 tests
run_admin_plane_serves_status_and_metrics_with_a_bearer_token ... ok
run_admin_plane_drains_a_server_with_the_write_token ... ok
run_admin_plane_applies_backend_config_under_traffic ... ok
test result: ok. 3 passed; 0 failed
```

`run_admin_plane_applies_backend_config_under_traffic` starts the binary, four
loader threads and three origins, then asserts:

- `403` with the read token and `428` without `If-Match`;
- backend A→B: `200`, `revision: v2`, `ETag: "v2"`,
  `summary: listeners kept=1 added=0 removed=0`, `elapsed_ms < 1000`, and B
  starts serving;
- a connection opened **before** the swap and kept open: after the swap it
  still answers `origin-a` (its accepted generation), while a fresh
  connection answers `origin-b`;
- stale `If-Match`: `412 precondition_failed` with the current revision;
- new backend `green`: `200`, revision `v3`, reported by `GET /status`;
- listener repointed to `green`: `200`, revision `v4`, kept socket, C serves;
- invalid table (`balance = "random"`): `400 invalid_config`, revision stays
  `v4`;
- listener address already bound by the test: `409 swap_rejected`, status
  unchanged, C still serves;
- `SIGHUP`: revision `v5`, listener back on `api`, origin A serving again;
- two racing writers on `v5`: statuses `[200, 412]`, final revision `v6`;
- zero failed requests, at least 100 requests, and every generation observed;
- `AUDIT` lines with status 200 and no token; clean `SIGINT` (exit 0).

### Independent harness (public HTTP interface)

`scripts/evidence/v08-admin-config-hot-apply/run.py` (local-only; output
published here) drives the same binary with `http.client` and prints raw
evidence: [`raw/manual-run.txt`](v08-admin-config-hot-apply/raw/manual-run.txt).

```console
$ python3.13 scripts/evidence/v08-admin-config-hot-apply/run.py
binary: .../target/debug/eqproxy
sha256: f59ed6ba45d9eadacf4c5ff345a0b406ae959a4f543bff15252fedbaddd54a88
rustc: rustc 1.97.1 (8bab26f4f 2026-07-14)
...
PUT backend api -> B: status=200 roundtrip_ms=1.8
  applied={'elapsed_ms': 0, 'listeners': [{'listen': '127.0.0.1:51635', 'name': 'web'}],
           'revision': 'v2', 'summary': 'listeners kept=1 added=0 removed=0'} etag="v2"
PUT backend green (new): status=200 roundtrip_ms=1.5 applied={... 'revision': 'v3' ...}
PUT listener web -> green: status=200 roundtrip_ms=1.1 applied={... 'revision': 'v4' ...}
PUT backend api invalid table: status=400 ... field `backend.api.balance`: unknown variant `random`
PUT backend api stale If-Match: status=412 body={"error":"precondition_failed","revision":"v4"}
two racing writers on v4: statuses=[200, 412]
status after: revision "v5", listener web -> green, backend api -> A
traffic through every generation: {"failed": 0, "origin-a": 45, "origin-b": 33, "origin-c": 38} total=116
audit lines: 7
exit code: 0
```

The measured configuration round trip on loopback is 1.1–1.8 ms; the
dataplane's own commit is reported below 1 ms (`elapsed_ms: 0`, integer
milliseconds), well inside the one-second acceptance gate. The harness also
proves that the swap is per-connection atomic: none of the 116 requests under
load failed across four generations.

## Audit legs

### 1. Veyra Proof — real toolchain

```console
$ veyra audit . --profile standard
```

- Verdict: **ACCEPTED** — “All required profile tools executed without blocking findings”.
- Exit code: **0** (`report.json` → `decision.exit_code: 0`).
- Evidence: `.veyra/evidence/20261024T235914Z/` (UTC timestamp in the path).
- OK: rustfmt, cargo check, clippy, cargo test, cargo-audit, veyra-anti-theater,
  cargo-nextest, cargo-llvm-cov, cargo-deny, cargo-machete, veyra-e2e.
  `cargo-llvm-cov` passed including the slow-start E2E repaired above;
  `veyra-e2e`: 17 scenarios executed against the real binary, 17 passed.
- The earlier run `20261024T233622Z` was **REJECTED** (exit 1) solely on
  `cargo-llvm-cov`: `run_slow_start_ramps_the_recovered_server_up` saw a
  `6:4` split from a fixed sleep. Diagnosis and the test repair are recorded
  in the suite section; that rejected run stays on disk and is not cited as a
  pass.
- Named non-passes: `cargo-geiger` **INCONCLUSIVE** (4 runs with dependency
  files not scanned/parsed; unsafe counts are a lower bound, not a pass);
  `dylint` **SKIPPED** (no configuration/lint libraries); `cargo-semver-checks`
  **SKIPPED** (no registry baseline for unpublished crates).
- Deeper legs (`cargo --deep`: mutants/udeps; `--supply-chain`: audit/deny/vet
  already partly covered, osv-scanner; `--miri`; `scan --online`) were **NOT
  EXECUTED** by this profile.

### 2. Rust Audit — static scan

```console
$ python3.13 /Volumes/Lexar/Cursor/rust-ai-audit/scripts/rust_audit.py scan . \
    --format md --out report --fail-on high
wrote report/rust-audit-20261025-021419.md
not-executed report: report/not-executed-2026-10-25.md
exit 1
```

- Tool: rust-ai-audit 0.2.6, engine sha256 `e47f704f…5de43`; report is
  local-only (`report/` is excluded).
- Counts: **3 critical / 26 high / 212 medium / 58 low** — identical to the
  previous run (`rust-audit-20261025-010437.md`): the test repair added no
  critical/high finding (the heading set is unchanged).
- **The `--fail-on high` gate is red (exit 1)**, as it was before this slice.
  Every critical/high was reviewed; all are false positives or pre-existing,
  and none is added by this increment’s new code:
  - **R12 critical, `ws.rs:376`**: a long base64 alphabet literal (RFC 6455
    protocol constant), not a secret.
  - **R18d critical, `Cargo.toml:1`**: `thiserror = "2"` exists (the lockfile
    builds and `cargo-deny`/`cargo-audit` pass); **`eqproxy-cli/src/main.rs:27`**:
    `eqproxy_core` is a workspace path crate, not a registry dependency.
  - **R03 high ×12**: the `not_implemented` helper (deliberately returns exit
    code 2; it never fakes success), ten serde `default_*` functions (typed
    defaults, not stubs) and `h3_close_log_line` (log text).
  - **R04 high ×4, `rules.rs` and its corpus**: error-message literals
    containing placeholder words such as `$host`/`$remote_addr`; they are text,
    not data injection.
  - **R09 high ×5**: `.expect` on invariants only (`plan_report` after a
    listener lookup, the rate-limiter mutex, the phase-1 kept entry in
    `BoundProxy::apply`, and the session owner); no untrusted input reaches
    them.
  - **R16 high, `proxy.rs:2322`**: the lock is a `tokio::sync::Mutex` guard
    held across an `.await` on purpose (the HTTP/2 connect gate); the scanner
    reports it as a synchronous lock. It is bounded by `connect_timeout` and is
    the mechanism that makes session reuse hold under concurrency.
  - **R20 high ×4 and R18c high ×2**: `md-5`, `h2`, `http` and `h3` are real,
    widely used crates (three of them are direct protocol dependencies already
    in the lockfile); the typo-squat/near-miss heuristic is wrong for them.
  - Line-number shifts mean four high headings are “new” relative to the
    previous report (`main.rs:751`, `proxy.rs:1551`, `proxy.rs:2322`,
    `main.rs:240`); the code behind them predates this increment. The new
    admin/config code adds only low/medium heuristics (E2E clocks and bounded
    sleeps, `let _ =` on sockets being closed).

### 3. CodeGraph Rust — structure (advisory, verified in source)

```console
$ codegraph-rust index . --stats-json /tmp/cg-admin-final2.json
files: 57, lines: 50994, nodes: 5618, edges: 10133, errors: 0,
cached_files: 56, graph_complete: true, vector_index_ready: true,
index_ms: 949446
```

- Index rebuilt after the last source edit (the slow-start E2E repair); zero
  errors, 56 cached files, 15.8 minutes wall.
- `agent impact "What breaks if ApplyMessage changes?"` located
  `ApplyMessage` at `admin.rs:165-169` and the producer/consumer pair the
  source confirms: `apply_config` builds and sends it (`admin.rs:445-460`),
  `ConfigApplier::run` receives it (`main.rs:1996-2013`) and `handle` reads
  `change`/`if_match` (`main.rs:2015-2052`). The import direction is still
  strictly `eqproxy-cli` → `eqproxy-net` (`main.rs:28`, `lib.rs:30`). The
  query's warning that the graph records only one dependent edge is a limit
  of the graph, not of the source; the call sites above were checked in the
  file.
- `agent context "Where is an admin configuration PUT validated and
  swapped?"` → `put_config` (`admin.rs:898`), `apply_config` (`:445`),
  `ConfigApplier::apply_candidate` (`main.rs:2087`) and the E2E at
  `cli_e2e.rs:6089`. Those spans were checked and are exact; the described
  ordering (route → role → Origin → media type → length → `If-Match` → body
  parse → candidate parse → whole-document check → resolve → swap → revision)
  matches the source. The query itself reported a gap: it could not find the
  `SwapRequest` receiver. The source does: `serve_with_reloads`
  (`proxy.rs:1669`) receives on `reloads` and calls `self.apply(...)`
  (`proxy.rs:1682`), which is `BoundProxy::apply` (`proxy.rs:1466`). This is
  exactly why the leg is advisory — the gap was closed by reading the file,
  not by trusting the answer.
- An earlier query against the previous index claimed `e2e_admin.rs`
  “exercises the 503 branch”; that was **wrong** (those tests never send a
  configuration `PUT`). Recorded here so the claim is not reused.
- CodeGraph is not behaviour evidence; `cargo test`, the E2E and the manual
  harness are.

### 4. Hindsight — memory close-out

`hindsight-note` stored the increment in the project's own bank
(`hindsight[eqproxy]: Memory stored successfully`, exit 0) with the commands
and results above, the binary hash, the rejected/accepted Veyra pair and the
pending release-level checks.

## Limits and unverified conditions

- Configuration writes are **runtime-only**: they are not persisted to the
  TOML file. The next `SIGHUP` replaces them with the file baseline (asserted
  in the E2E). `DELETE` does not exist.
- A table `PUT` replaces the whole table; omitted fields return to their
  defaults. The revision is monotonic per process (`v1`, `v2`, …) and starts
  over at `v1` after a restart; it is not a cross-process identity.
- The admin plane still has no TLS and binds loopback unless
  `allow_remote = true`; its listener and tokens are fixed at startup.
- No RBAC beyond the read/write tokens, no durable audit sink, no panel UI, no
  certificate management.
- Verified on macOS 15 aarch64 with a debug build only. The **Docker image**
  (both architectures, Docker Scout, live journeys in the container) and the
  release binary were **NOT EXECUTED** for this increment — it is an
  unreleased feature slice, not a release.
- The load is four clients on loopback (116 requests in the cited run,
  98–140 across runs); it is real traffic but not a throughput benchmark, and
  no latency percentile is claimed.
