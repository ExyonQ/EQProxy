# v0.8 — Hot reload of the admin socket policy (ADR-0022)

Language: **English**. Raw data: [`v08-admin-unix-reload/raw/`](v08-admin-unix-reload/raw/).

## What was proved

A running `eqproxy` changes the **mode, owning group and `SO_PEERCRED`
allowlist** of its admin Unix socket on `SIGHUP`, without a restart, without
rebinding the listener and without disturbing the dataplane:

1. install `0660` + group + a deny list in one reload: the file becomes
   `660 <uid> <gid>` and the **next** connection from the owner is closed with
   EOF, although the kernel credential did not change;
2. a policy the process cannot write (`unix_socket_gid = 54321` as a
   non-root uid) is rejected as a whole: the socket keeps `660`, the group and
   the previous deny list, nothing is swapped, and `cfg[reload_failures]`
   advances;
3. the reverse reload (`0600`, owner admitted) restores access on the same
   socket;
4. the dataplane answers on the same announced address after every reload and
   `SIGINT` still exits `0` and unlinks the socket.

## Artifact and environment

- Binary: `target/debug/eqproxy` (Cargo debug profile), sha256
  `4029290d73caef034f3e36b34d485cd84e49a4f282d65e43863af2774ac870ff`.
- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, macOS 15 (Darwin 25.5.0),
  Apple silicon (aarch64), uid 501, primary gid 0.
- Real dependencies: the binary itself, one real HTTP origin (Python
  `http.server`), `curl` over the real Unix socket, the loopback kernel stack.
  No mock of the proxy, the admin plane, the origin or the transport.
- Harness: `scripts/evidence/v08-admin-unix-reload/run.sh` (local-only), which
  writes its transcript back into `raw/run.log`. Every number below comes from
  that file or from the logs next to it.

## Commands and results

### Format, lint, suite

```console
$ cargo fmt --all --check
(no output, exit 0)
$ cargo clippy --workspace --all-targets -- -D warnings
Finished `dev` profile [unoptimized + debuginfo] target(s)
(exit 0)
$ cargo test --workspace
...
29 test binaries: 481 passed, 0 failed, 2 ignored
(exit status 0; full log in raw/full-suite.txt)
```

The two ignored tests are the pre-existing miri-only cases.

### Targeted E2E

```console
$ cargo test -p eqproxy-net --test e2e_admin
running 14 tests
... 
test admin_unix_socket_policy_reloads_without_a_restart ... ok
test a_tcp_admin_plane_exposes_no_unix_socket_policy ... ok
test result: ok. 14 passed; 0 failed
```

`admin_unix_socket_policy_reloads_without_a_restart` binds a real Unix socket,
then drives `UnixSocketPolicy::apply` directly: `0600` → `0660` + group (stat
reports `660`, the configured gid and the owner uid), a **list-only** change
(`allow_uids` moves to `uid+1`) closes the next connection with zero bytes,
`0600`/empty list admits the owner again, and `gid = 54321` fails with
`PermissionDenied` while the live policy and the file stay unchanged
(`600`, gid untouched, `200` still served).

`run_admin_plane_reloads_unix_socket_policy_on_sighup` is the CLI journey with
the real binary and three `kill -HUP`s; it asserts the same observable results
plus the rejected-policy log line and a proxied `200` after each step.

### Operator transcript

```console
$ stat -f '%Lp %u %g %HT' .../admin.sock      # after start
600 501 0 Socket
$ curl --unix-socket .../admin.sock .../api/v1/status
exit/http = 0 200
$ curl http://127.0.0.1:<port>/traffic
body = reload-origin

# SIGHUP 1: unix_socket_mode = "0660", unix_socket_gid = 0, allow_uids = [502]
INFO admin socket policy applied: mode 0660, gid 0, 1 allowed uid(s)
INFO config reload applied: listeners kept=1 added=0 removed=0 in 96µs
$ stat -f '%Lp %u %g %HT' .../admin.sock
660 501 0 Socket
$ curl --unix-socket .../admin.sock .../api/v1/status
WARN admin connection refused: unix-socket:uid=501 is not in unix_socket_allow_uids
exit/http = 52 000
$ curl http://127.0.0.1:<port>/traffic
body = reload-origin

# SIGHUP 2: unix_socket_gid = 54321 (not a group this uid belongs to)
ERROR admin unix socket policy cannot be applied: Operation not permitted (os error 1)
$ stat -f '%Lp %u %g %HT' .../admin.sock      # unchanged
660 501 0 Socket
$ curl --unix-socket .../admin.sock .../api/v1/status
WARN admin connection refused: unix-socket:uid=501 is not in unix_socket_allow_uids
exit/http = 52 000

# SIGHUP 3: unix_socket_mode = "0600", allow_uids = [501]
INFO admin socket policy applied: mode 0600, gid unchanged, 1 allowed uid(s)
INFO config reload applied: listeners kept=1 added=0 removed=0 in 47.333µs
$ stat -f '%Lp %u %g %HT' .../admin.sock
600 501 0 Socket
$ curl --unix-socket .../admin.sock .../api/v1/status
exit/http = 0 200
$ curl http://127.0.0.1:<port>/traffic
body = reload-origin

$ kill -INT <pid>; wait
exit=0
socket removed
$ METRICS (final)
cfg[reloads=2 reload_failures=1 last_swap_us=47]
```

The proxy address never changed (the same `127.0.0.1:<port>` served the
`reload-origin` body before, between and after the reloads), and the socket
path stayed the only admin endpoint.

## Audits

| Leg | Tool and command | Result |
|---|---|---|
| 1. Veyra Proof | `veyra audit . --profile standard` | **ACCEPTED**, exit 0, `.veyra/evidence/20261025T122439Z/`. OK: rustfmt, cargo check, clippy, cargo test, cargo-nextest, llvm-cov, cargo-audit, cargo-deny, cargo-machete, veyra-anti-theater, veyra-e2e. SKIPPED: `dylint` (no lint libraries configured), `cargo-semver-checks` (unpublished crates, no baseline). INCONCLUSIVE: `cargo-geiger` (coverage warning in 4 runs; unsafe counts are a lower bound, not a pass) |
| 2. Rust Audit | `python3.13 /Volumes/Lexar/Cursor/rust-ai-audit/scripts/rust_audit.py scan . --format md --out report --fail-on high` (rust-ai-audit 0.2.7) | exit 0: **0 critical, 0 high, 216 medium, 64 low** (`report/rust-audit-20261025-132623.md`, local-only). Same counts as the previous slice; the only finding touching this code is the pre-existing **R16** `bind_unix` blocking-fs-in-async (now `admin.rs:494`), and the reload path adds two syscalls per SIGHUP in the same pattern (accepted: owner-triggered, no request waiting on it). No new high or critical |
| 3. CodeGraph Rust | `codegraph-rust index . --stats-json /tmp/cg-reload-final.json`, then `agent impact` on `UnixSocketPolicy::apply` and `agent context` on the SIGHUP re-apply | 58 files, 53 947 lines, 6 026 nodes, 10 920 edges, `graph_complete: true`, `vector_index_ready: true`, `errors: 0` (last rebuild after this page: 1 318 ms, incremental). Spans **checked in the source**: `UnixSocketPolicy::options:152`, `allow_uids:159`, `apply:177`, `write_file_policy:204`, `AdminHandle::unix_policy:422`, `ConfigApplier::apply_candidate:2151`, `apply_admin_unix_policy:2251`, `restore_admin_unix:2300` |
| 4. Hindsight | `~/.local/bin/hindsight-note --project EQProxy` | note stored, exit 0 (bank `eqproxy`) |
| Docker | image build and journeys | **NOT EXECUTED** in this iteration |

### CodeGraph claims that did not survive the source check

The `agent` answers were useful as a map and wrong on details, so they are
quoted only where verified:

- `apply` was reported at `admin.rs:161`; the function is at **177**
  (`options` 149 → really 152, `allow_uids` 157 → really 159).
- `AdminHandle::unix_policy` was said to be called from `bind_unix`,
  `accept` and `resolve_admin`; the only call site is the applier
  construction at `main.rs:2926`, and `bind_unix` *constructs* the policy
  rather than calling the accessor.
- One impact line cited a non-existent symbol id
  (`admin.rs:442f46a5`) and the claim that the accept path reads
  `options`; the accept loop reads `allow_uids` only (`admin.rs:810`).
- The context answer could not find the SIGHUP subscription and said so; it
  is at `main.rs:2962` (the `SignalKind::hangup()` loop).

## Limits of this run

- **macOS only.** The peer credential comes from `getpeereid`; the Linux
  `SO_PEERCRED` path is the same Tokio call, but it was not executed here.
- **One uid.** The denied case excludes the test uid instead of starting a
  second system user, so the kernel's decision is exercised but two distinct
  uids are not.
- **No Docker image** was built for this slice.
- The endpoint path and the bearer tokens remain startup-only; a reload that
  changes them logs a `WARN` and keeps the old ones.
