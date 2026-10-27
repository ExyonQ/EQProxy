# v0.8 — Admin plane on a Unix domain socket (B-H14 first step, ADR-0021)

Language: **English**. Raw data: [`v08-admin-unix-socket/raw/`](v08-admin-unix-socket/raw/).

## What was proved

The administration plane can listen on a **Unix domain socket** instead of a
TCP port, with the same routes, tokens and isolation:

1. `[admin] unix_socket = "admin.sock"` (relative to the configuration file)
   opens a socket instead of a TCP port; the binary announces
   `admin listening on unix:/…/admin.sock`.
2. The socket file is **mode `0600`** (`stat -f '%Lp %HT'` → `600 Socket`).
3. The bearer token still gates every route over the socket: anonymous
   `GET /api/v1/status` → `401`; with the token → `200` and the topology,
   revision and live counters; `/metrics` → `200` with
   `eqproxy_build_info{version="0.7.0"} 1`. The read token cannot write
   (`403`, asserted in the in-process E2E).
4. Proxied traffic is untouched by the admin transport: a real request
   through the dataplane returned `200` and the origin body, and the export
   moved `eqproxy_http_requests_proxied_total` from `0` to `1`.
5. `SIGHUP` reloads the file and keeps the running socket (`200` after the
   reload, revision still present): the endpoint is fixed at startup.
6. `SIGINT` exits `0` and **removes the socket file** the process created.
7. A stale socket left by a crash (bound and closed without unlinking) is
   recognised and replaced: the next start binds, answers `200`, and cleans
   up on shutdown.
8. A **regular file** at the configured path is never deleted: startup exits
   `1` with `exists and is not a socket; refusing to remove it`, and the file
   keeps its contents (`do not delete me`).

The in-process E2E additionally proves that a **live** socket cannot be
stolen (second bind → `AddrInUse`), that the socket is owner-only, and that
the read token is refused on the write route over the Unix transport.

## Artifact and environment

- Binary: `target/debug/eqproxy` (Cargo debug profile), sha256
  `5446390ac4832c7114b28e1bc26d1e2c2125ac059a49c0d48b5f741a12995469`.
- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, macOS 15 (Darwin 25.5.0),
  Apple silicon (arm64).
- Real dependencies: the binary itself, a real HTTP origin (Python
  `ThreadingHTTPServer`), a real HTTP client (`curl --unix-socket` for the
  admin plane, `curl` for the dataplane), the kernel's Unix-socket and TCP
  stacks. No mock of the plane, the origin or the transport.
- Build: `cargo build -p eqproxy-cli` (debug, exit 0).

## Commands and results

### Format, lint, suite

```console
$ cargo fmt --all --check
(no output, exit 0)
$ cargo clippy --workspace --all-targets -- -D warnings
Finished `dev` profile [unoptimized + debuginfo] target(s) in 18.31s
(exit 0)
$ cargo test --workspace
...
total summed over the 29 test binaries: 476 passed, 0 failed, 2 ignored
(exit status 0; full log in raw/full-suite.txt)
```

The two ignored tests are the existing miri-only `#[cfg_attr(miri, ignore)]`
cases, unchanged by this slice. The suite grew by four tests: one validation
unit test, two in-process admin E2E tests and one CLI E2E test with the real
binary.

### Targeted E2E (real sockets)

```console
$ cargo test -p eqproxy-net --test e2e_admin
running 11 tests
...
admin_unix_socket_serves_the_same_routes_and_is_owner_only ... ok
admin_unix_socket_refuses_live_sockets_and_replaces_stale_ones ... ok
test result: ok. 11 passed; 0 failed

$ cargo test -p eqproxy-cli --test cli_e2e run_admin_plane
running 4 tests
run_admin_plane_listens_on_a_unix_socket_and_removes_it_on_shutdown ... ok
run_admin_plane_drains_a_server_with_the_write_token ... ok
run_admin_plane_serves_status_and_metrics_with_a_bearer_token ... ok
run_admin_plane_applies_backend_config_under_traffic ... ok
test result: ok. 4 passed; 0 failed
```

The CLI test is the one that runs the built binary as a process, with a
relative `unix_socket` path in the TOML, a real origin, a real HTTP client and
a real `SIGINT`; it also asserts the file is gone afterwards.

### Manual run (`raw/run.log`)

```console
$ stat -f '%Lp %HT' /tmp/…/admin.sock
600 Socket
$ curl -s -o /dev/null -w '%{http_code}' --unix-socket /tmp/…/admin.sock \
    http://localhost/api/v1/status
401
$ curl ... -H "Authorization: Bearer <token>" .../api/v1/status
200                      # version, revision v1, listener 127.0.0.1:50274
$ curl ... /metrics | grep eqproxy_build_info
eqproxy_build_info{version="0.7.0"} 1
$ curl -s http://127.0.0.1:50274/proxied-through-unix-admin
200                      # body: unix-admin-origin
$ curl ... /metrics | grep eqproxy_http_requests_proxied_total
eqproxy_http_requests_proxied_total 1
$ kill -HUP <pid>; curl .../api/v1/status
200                      # config reload applied, socket kept
$ kill -INT <pid>; wait
exit=0
socket removed
```

Crash recovery and the regular-file refusal are in the same transcript:

```console
$ stat -f '%HT' /tmp/…/admin.sock        # created by bind+close, no listener
Socket
$ eqproxy run --config …                 # replaces the stale socket
bind=ok
$ curl --unix-socket … status
200
stale socket removed

$ printf 'do not delete me' > …/admin.sock
$ eqproxy run --config …
exit=1
error: admin plane cannot bind: …/admin.sock exists and is not a socket; refusing to remove it
$ cat …/admin.sock
do not delete me
```

## Audits

| Leg | Command | Result |
|---|---|---|
| Veyra Proof | `veyra audit . --profile standard` | **ACCEPTED**, exit `0`, evidence `.veyra/evidence/20261025T105134Z/`. `dylint` and `cargo-semver-checks` SKIPPED (no lint config / no registry baseline); `cargo-geiger` INCONCLUSIVE (coverage warnings, not a pass) |
| Rust Audit | `python3.13 /Volumes/Lexar/Cursor/rust-ai-audit/scripts/rust_audit.py scan . --format md --out report --fail-on high` | exit `0`: **0 critical, 0 high, 215 medium, 64 low** (`report/rust-audit-20261025-115642.md`). The 215/64 are the pre-existing pattern classes (test sleeps, `unwrap_or_default` in the HTTP parser, clone counts); the only new medium from this slice is **R16** `bind_unix` blocking filesystem calls inside async. Reviewed: this is the startup path, before the accept loop serves anything, and the calls are `lstat`/`connect`/`remove_file`/`chmod` on one path; the alternative (making the drop-time cleanup async) is not possible. No new high or critical |
| CodeGraph Rust | `codegraph-rust index . --stats-json /tmp/cg-index-v08-unix.json` | `files: 58`, `lines: 52 999`, `nodes: 5 898`, `edges: 10 668`, `graph_complete: true`, `vector_index_ready: true`, `errors: 0`, `index_ms: 52 923`. Checked against the source: `bind_unix` at `admin.rs:354`, `prepare_socket_path` at `admin.rs:410`, `SocketFile` at `admin.rs:439`, `Drop for AdminHandle` at `admin.rs:315`, `resolve_admin` at `main.rs:1885` — all correct. Its claim that `resolve_admin` “calls `run`” is the wrong direction (`run` calls `resolve_admin`); its `bind_unix → bind` cycle is a name-resolution artifact (`UnixListener::bind`). The `agent context` answer also flagged the real short window between `UnixListener::bind` and `chmod 0600`, which is listed under limitations |
| Hindsight | `~/.local/bin/hindsight-note --title … --project EQProxy` | stored, exit `0` (bank `eqproxy`); it contains the same commands and limits, no secrets |
| Docker | — | **NOT EXECUTED**: no image was built or published in this iteration |

## What this does not prove

- **Non-Unix platforms**: the configuration key exists everywhere, but the
  bind path returns `Unsupported`; only macOS was exercised here. Linux is
  the same `tokio::net::UnixListener` path, but it was **not run** in this
  campaign.
- **Path length**: `sun_path` limits (104 bytes on macOS, 108 on Linux) are
  enforced by the OS and fail at bind; no test covers the exact boundary.
- **`SO_PEERCRED` uid**: the audit line records `unix-socket:uid=<uid>`, but
  no test captures an audit line over the Unix transport (the audit sink is
  the process stderr and the in-process tests do not capture it). The uid is
  informational, never an authorization decision.
- **Shared access**: mode `0600` means one uid. Group access (`0660` +
  `chown`), ACLs, SELinux/AppArmor policy, abstract sockets and systemd
  socket activation are future work (B-H14 completion in v0.9.1).
- **Bind → chmod window**: `UnixListener::bind` creates the socket with the
  process umask, and `chmod 0600` happens immediately after, before the
  accept loop is spawned. A local user could enqueue a connection in that
  microsecond window; the bearer token still gates every request, but the
  filesystem mode is not atomic with creation. Making it atomic needs an
  umask trick or a new crate, neither worth it for a startup-only window.
- **Hot changes**: the endpoint, like the tokens, is fixed at startup; a
  `SIGHUP` that edits `unix_socket` keeps the running socket (the reload
  reads the file for the dataplane and the TCP/Unix endpoint is not
  re-bound).
- **Docker**: no image was built in this iteration, so the slice is
  **NOT EXECUTED** in a container.
