# v0.8 — Group-shared admin socket and peer-uid allowlist (B-H14, ADR-0022)

Language: **English**. Raw data: [`v08-admin-unix-group-uid/raw/`](v08-admin-unix-group-uid/raw/).

## What was proved

The Unix admin socket can be shared with a group and restricted to an
explicit uid list, all with the **real binary** and the **real kernel
credential**:

1. `unix_socket_mode = "0660"` + `unix_socket_gid = 20` creates a socket
   whose `stat` is `660 501 20 Socket`: owner `501`, group `20`, mode `0660`.
2. `unix_socket_allow_uids = [501]` (the owner) lets the real client in:
   `GET /api/v1/status` with the bearer token → `200`.
3. `unix_socket_allow_uids = [502]` closes the same client before any HTTP
   byte: `curl --unix-socket` exits `52` (**Empty reply from server**),
   `http_code=000`, and there is no response body. The process log records
   `WARN admin connection refused: unix-socket:uid=501 is not in
   unix_socket_allow_uids`.
4. The dataplane is independent of that refusal: a real proxied request
   still answers `200` with the origin body in both runs.
5. A gid the process cannot assign (`54321` as uid `501`) fails startup with
   `Operation not permitted (os error 1)` and **no socket file is left
   behind**; it does not silently fall back to `0600` or `0660`-with-other-gid.
6. An unsupported mode (`0666`) is refused by validation before binding
   (`exit 1`, `"0666" is not a supported socket mode`, no socket created).
7. `SIGINT` still exits `0` and removes the socket in both runs.

The in-process E2E additionally proves the allowed uid path and the denied
uid path through `AdminHandle` without a second OS user; the CLI E2E runs the
same two configurations as real processes.

## Artifact and environment

- Binary: `target/debug/eqproxy`, sha256
  `084ad05ef784bd309987f380a97d4ba9267a416ced8eb1c0d16a475aa10e8905`.
- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, macOS 15 (Darwin 25.5.0),
  Apple silicon (arm64).
- Real dependencies: the binary, one Python `ThreadingHTTPServer` origin,
  `curl --unix-socket` and `curl` over TCP, the kernel's Unix-socket and TCP
  stacks. No mock of the plane, of `SO_PEERCRED`/`getpeereid`, or of the
  origin.
- Build: `cargo build -p eqproxy-cli` (debug, exit 0).

## Commands and results

### Format, lint, suite

```console
$ cargo fmt --all --check
(no output, exit 0)
$ cargo clippy --workspace --all-targets -- -D warnings
Finished `dev` profile [unoptimized + debuginfo] target(s) in 15.00s
(exit 0)
$ cargo test --workspace
...
total summed over the 29 test binaries: 478 passed, 0 failed, 2 ignored
(exit status 0; full log in raw/full-suite.txt)
```

### Targeted E2E

```console
$ cargo test -p eqproxy-net --test e2e_admin
running 12 tests
admin_unix_socket_group_mode_and_uid_allowlist ... ok
admin_unix_socket_serves_the_same_routes_and_is_owner_only ... ok
admin_unix_socket_refuses_live_sockets_and_replaces_stale_ones ... ok
test result: ok. 12 passed; 0 failed

$ cargo test -p eqproxy-cli --test cli_e2e run_admin_plane
running 5 tests
run_admin_plane_enforces_group_mode_and_uid_allowlist ... ok
run_admin_plane_listens_on_a_unix_socket_and_removes_it_on_shutdown ... ok
run_admin_plane_drains_a_server_with_the_write_token ... ok
run_admin_plane_serves_status_and_metrics_with_a_bearer_token ... ok
run_admin_plane_applies_backend_config_under_traffic ... ok
test result: ok. 5 passed; 0 failed
```

### Manual run (`raw/run.log`)

```console
$ stat -f '%Lp %u %g %HT' allowed.sock
660 501 20 Socket
$ curl --unix-socket allowed.sock -H 'Authorization: Bearer <token>' /api/v1/status
200
$ curl http://127.0.0.1:51183/group-admin
200
group-admin-origin
$ kill -INT <pid>; wait
exit=0
socket removed

$ curl --unix-socket denied.sock -H 'Authorization: Bearer <token>' /api/v1/status
curl: (52) Empty reply from server
http_code=000
$ curl http://127.0.0.1:51189/after-denied-admin
200
WARN admin connection refused: unix-socket:uid=501 is not in unix_socket_allow_uids
exit=0
socket removed

$ eqproxy run --config wrong-gid.toml   # gid 54321 as uid 501
exit=1
error: admin plane cannot bind: Operation not permitted (os error 1)
no socket left behind

$ eqproxy config validate --config broad.toml   # mode 0666
field `admin.unix_socket_mode`: "0666" is not a supported socket mode; use "0600" (owner only) or "0660" (owner and group)
exit=1
no socket created
```

## A rejected run and the test fix

The first Veyra run on this slice (`20261025T112434Z`, exit `1`) failed
`run_admin_plane_enforces_group_mode_and_uid_allowlist` because the test
helper `wait_for_unix_admin` stopped as soon as the socket **file** existed,
a few instructions before the process wrote its announcement line; the
assertion then saw an empty log. The helper now waits for the
`admin listening on unix:` announcement (and asserts the file exists after
it). No assertion was weakened and no production code changed for this: the
run was repeated, rejected evidence left on disk, and the accepted run below
is the one cited.

## Audits

| Leg | Command | Result |
|---|---|---|
| Veyra Proof | `veyra audit . --profile standard` | **ACCEPTED**, exit `0`, `.veyra/evidence/20261025T113346Z/`; `dylint` and `semver-checks` SKIPPED, `cargo-geiger` INCONCLUSIVE |
| Rust Audit | `python3.13 /Volumes/Lexar/Cursor/rust-ai-audit/scripts/rust_audit.py scan . --format md --out report --fail-on high` | exit `0`: **0 critical, 0 high, 216 medium, 64 low** (`report/rust-audit-20261025-123929.md`). The one medium touching this slice is **R16** (`bind_unix` does filesystem I/O in async); reviewed as startup-only, before the accept loop. No new high or critical |
| CodeGraph Rust | `codegraph-rust index . --stats-json /tmp/cg-index-group-final.json` | `files: 58`, `lines: 53 485`, `nodes: 5 957`, `edges: 10 744`, `graph_complete: true`, `vector_index_ready: true`, `errors: 0`, `index_ms: 27 353`. Source-checked: `UnixSocketOptions` at `admin.rs:107`, `bind_unix` at `admin.rs:384`, `peer_allowed` at `admin.rs:664`, `resolve_admin` at `main.rs:1885`. Its validation range `validate.rs:3038-3166` is actually the test block (the checked code is at 100-240), and its `bind_unix:439` is the non-Unix stub, not the Unix implementation; both are flagged here instead of repeated as fact |
| Hindsight | `~/.local/bin/hindsight-note …` | stored, exit `0` (bank `eqproxy`); no secrets |
| Docker | — | **NOT EXECUTED** (no image built) |

## What this does not prove

- **A second OS user**: the tests run as uid `501` and demonstrate the deny
  path by excluding `501` from the allowlist; no test logs in as another uid.
  The credential used is the kernel's real `getpeereid`/`SO_PEERCRED` answer,
  not a fabricated one.
- **Linux**: only macOS was executed. The code path is Tokio's `peer_cred()`;
  Linux uses `SO_PEERCRED` and is expected to behave the same, but it was
  **not run** here.
- **Group names**: only numeric gids are accepted; name resolution needs NSS
  and is not implemented.
- **Live policy changes**: mode, gid and the allowlist are fixed at startup,
  like the tokens; `SIGHUP` does not re-apply them.
- **Root**: a platform administrator can still open the socket; this is not a
  boundary against root.
- **Refusal logging is not rate-limited**: every denied connection writes one
  `WARN` line. The socket mode still limits who can trigger it, but a group
  member can produce log volume.
- **ACLs, abstract sockets, socket activation and pid-level identity** remain
  pending for v0.9.1.
