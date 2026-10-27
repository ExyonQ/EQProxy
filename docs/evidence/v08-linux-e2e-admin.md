# v0.8 — the Linux-gated admin E2E, compiled and run off-CI

Language: **English**. This page closes the v0.8.0 post-release item 7: the
Linux-gated test in
[`eqproxy-net/tests/e2e_admin.rs`](../../eqproxy-net/tests/e2e_admin.rs) and
the `unix_acl` module it drives are compiled out on macOS, so their
compilation was only ever exercised by CI's `ubuntu-latest` job. The run
below is native Linux from the maintainer's own host, with the pinned
toolchain, so the claim no longer rests on a CI log alone.

## Host and toolchain

- Netcup AMD64 host, Ubuntu 24.04.4 LTS, kernel `6.8.0-147-generic`, 8 vCPU,
  15 GiB. Sessions 1–3 below ran as `root`; the full suite in §4 ran as an
  unprivileged user, and §7 runs the same host both ways (`root` and uid
  10022). The server tree is a source copy without `.git`, so each file's
  `sha256` is the identity of what ran.
- Checkout of `main` at `ae3d950`, synced from the working tree of the same
  contents: `cargo 1.99.1 (5f94df478 2026-08-27)` /
  `rustc 1.99.1 (58cf8f9c3 2026-10-13)` /
  `1.99.1-x86_64-unknown-linux-gnu (overridden by
  '/root/eqproxy-verify/rust-toolchain.toml')` — the pin of
  [v08-toolchain-pin](v08-toolchain-pin.md), resolved by `rustup` on Linux
  exactly as on macOS.
- Raw session: [`v08-linux-e2e-admin/raw/netcup-session.txt`](v08-linux-e2e-admin/raw/netcup-session.txt)
  (sections A–C) and [`.../netcup-e2e-admin-as-root.txt`](v08-linux-e2e-admin/raw/netcup-e2e-admin-as-root.txt)
  (the first, root attempt, kept for §3 below).

## 1. The Linux-gated target, as an unprivileged user (section A)

Session 1 compiled the target; session 2 ran **its** binary as uid 65534:

```console
# session 1
$ cargo test -p eqproxy-net --test e2e_admin          # builds the Linux-only paths
# session 2
$ install -m 755 target/debug/deps/e2e_admin-<hash> /tmp/e2e_admin-nonroot
$ setpriv --reuid=65534 --regid=65534 --clear-groups env TMPDIR=/tmp /tmp/e2e_admin-nonroot --nocapture
```

```
test admin_unix_socket_acl_uids_write_replace_and_clear_the_posix_acl ... ok
test admin_unix_socket_policy_reloads_without_a_restart ... ok
test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.67s
```

The ACL test is the Linux-gated one: it writes and decodes
`system.posix_acl_access` on a live socket, replaces the named user and
clears the attribute — the kernel layout, from a Linux kernel, as uid 65534.
16 of 16 pass, in the binary `cargo test` built in this same checkout.

## 2. The Linux workspace compiles in full (section B)

```console
$ cargo test --workspace --no-run
    ...
  Executable tests/e2e_rules.rs (target/debug/deps/e2e_rules-89c667213476b83d)
  Executable tests/e2e_sni.rs (target/debug/deps/e2e_sni-2255375a9d6d2cec)
  Executable tests/e2e_tcp.rs (target/debug/deps/e2e_tcp-9eedefa99ed4b12a)
  Executable tests/e2e_ws_h2.rs (target/debug/deps/e2e_ws_h2-e2e432dbd0582f4b)
  Executable tests/framing_fuzz_corpus.rs (target/debug/deps/framing_fuzz_corpus-2ba2934a4018159a)
```

Every test target of the workspace, including the ones with Linux-only code
paths, links on Linux with the pinned toolchain.

## 3. What the first, root attempt showed — and why it is kept

Running the target as `root` (the same command, no `setpriv`) gave
`15 passed; 1 failed`: `admin_unix_socket_policy_reloads_without_a_restart`
panics at
[`e2e_admin.rs:1298`](../../eqproxy-net/tests/e2e_admin.rs#L1298) with

```
an unprivileged chown to a foreign group must fail: ()
```

The test *requires* an unprivileged uid: it asserts that `chown(2)` to group
54321 is refused with `PermissionDenied`, and a root process is allowed to do
it. That is an environment prerequisite, not a defect — CI's runners and the
maintainer's macOS account are unprivileged. It is recorded here because a
root user of this repository will hit it, and because the first run would
otherwise look like a Linux failure. §7 is the fix for exactly that: the test
now states the premise itself, so the same root run prints the reason and
passes 16 of 16 instead of failing on it.

## 4. The whole workspace suite, as an unprivileged user (follow-up run)

`cargo test --workspace` — the same command CI's `linux-tier1` job runs —
executed on this host as **uid 10022 (`eqverify`)**, not as root, against the
tree of `main` at `bdaa115` (`sha256` of `eqproxy-cli/tests/cli_e2e.rs`,
`rust-toolchain.toml`, `ci.yml` and `docker/Dockerfile` equal the HEAD
checkout's). The user's `rustup` resolves the pin:
`1.99.1-x86_64-unknown-linux-gnu (overridden by
'/srv/eqproxy-verify/rust-toolchain.toml')`.

```console
$ setpriv --reuid=10022 --regid=10022 --clear-groups env HOME=/home/eqverify \
    bash -c 'cd /srv/eqproxy-verify && export PATH="$HOME/.cargo/bin:$PATH" && cargo test --workspace'
```

```
== started:  2026-10-27T21:03:17Z ==
== finished: 2026-10-27T21:05:40Z ==    CARGO-TEST-EXIT=0
30 targets with a result line  ->  559 passed; 0 failed; 2 ignored
```

The 2 min 23 s include the rebuild cargo demanded after the checkout moved
(the artifacts had been built under `/root`). Full raw log:
[`full-suite-eqverify.txt`](v08-linux-e2e-admin/raw/full-suite-eqverify.txt)
(889 lines); the Linux-gated ACL test (line 605) and the privilege-sensitive
reload (line 610) are both `ok`, and no target printed a failure or a panic.
The total matches the release workflow's Linux figure — 559, one more than
macOS (558) — so that count is now verified outside CI, by a real
unprivileged process on a real Linux kernel.

## 5. The image's Linux binary, built by the pinned builder (section C)

The same session built the release image's builder stage — recorded in full
in [v08-toolchain-pin](v08-toolchain-pin.md) §2, where it belongs.

## 6. Limits and NOT EXECUTED

- The unprivileged leg ran the **compiled test binary** through `setpriv`,
  not `cargo test` as that user: the server's checkout lives under `/root`,
  which uid 65534 cannot traverse. The binary is the artifact cargo built in
  the same session; nothing was rebuilt or patched for the run.
- **The Linux suite no longer rests on CI alone** (§4): `cargo test
  --workspace` as uid 10022, 30 targets, 559 passed, 0 failed, 2 ignored.
  What that does not replace: CI re-runs the suite on GitHub's own runner on
  every push, and the timing-sensitive journeys (health checks, slow start,
  idle timeouts) passed **once** on this host, not as a soak.
- **arm64 Linux: NOT EXECUTED here.** The ACL journey on a native arm64 host
  is CI's `ubuntu-24.04-arm` leg (`.github/workflows/ci.yml`); the Netcup
  host is amd64 only.
- The kernel-level contract (ACL support of the filesystem, `SO_PEERCRED`,
  `connect(2)` enforcement) is exercised against `/tmp` on this host; CI's
  journey exercises `/srv`, `/etc` and `/var/log` as root with `setpriv`.
- **The root runs are single passes on one host** (§7): as root the workspace
  reports 559 passed, 0 failed, 2 ignored, with both premises declared and
  skipped. That is the same suite under a different uid, not a soak, and it
  does not replace CI's unprivileged run, where the two blocks execute.

## 7. Both tests declare their root premise (follow-up)

§3 recorded a prerequisite that lived in a comment *outside* the programme:
the refusal blocks of
[`admin_unix_socket_policy_reloads_without_a_restart`](../../eqproxy-net/tests/e2e_admin.rs#L1218)
and of
[`run_admin_plane_reloads_unix_socket_policy_on_sighup`](../../eqproxy-cli/tests/cli_e2e.rs#L8460)
assert that a `chown(2)`/`chgrp(2)` to group 54321 is refused, which is false
for root. Both now ask their own uid first and, as root, print the reason and
let the rest of the test run
([`e2e_admin.rs:1301`](../../eqproxy-net/tests/e2e_admin.rs#L1301),
[`cli_e2e.rs:8544`](../../eqproxy-cli/tests/cli_e2e.rs#L8544)):

```rust
// An **unprivileged** process is the premise of this block: root is allowed
// to `chown(2)` to a foreign group, so the refusal asserted here does not
// exist for it. A root run therefore declares the block skipped, with the
// reason printed, instead of failing on a premise that is absent;
// the rest of the test keeps running.
if current_ids().0 == 0 {
    eprintln!("SKIP (running as root): ... the reason is intentional, not a missing assertion.");
} else {
    ... the chown(2) refusal, its PermissionDenied kind, the untouched
    mode/group and the file still owned by the group it had ...
}
```

No assertion was deleted or softened: the mode, the group, the restore to
owner-only, the still-refused peer and the final `200` keep running as root,
and the refusal itself keeps running — unskipped — wherever the process is
unprivileged, CI included. Before the change the second test did not merely
fail as root, it **blocked** (`wait_for_stderr` reads lines with no deadline,
and the log line it waits for cannot appear when the reload is *applied*): the
pre-fix source of `4c7a89a` run as root through the `timeout` guard had to be
killed at 90 s, exit `124`, with the socket it was told to refuse left as
`0660 root 54321`
([`prefix-hang-as-root.txt`](v08-linux-e2e-admin/raw/prefix-hang-as-root.txt)).

Runs, all on this host, all with the pinned toolchain, on the tree these edits
produce — `sha256` of `eqproxy-net/tests/e2e_admin.rs` `20b67d56…`,
`eqproxy-cli/tests/cli_e2e.rs` `1714fe9c…`, `rust-toolchain.toml` `1f8615e3…`,
`ci.yml` `1ed217d5…`, equal in the working tree and in the server checkout
(the server copy has no `.git`; the `sha256` is the identity):

| # | Command, as | Result | Raw |
|---|---|---|---|
| R1 | `cargo test -p eqproxy-cli --test cli_e2e run_admin_plane_reloads_unix_socket_policy_on_sighup -- --nocapture`, **uid 10022** | `1 passed; 0 failed`, no skip: the refusal block ran | [cli-e2e-reload-as-eqverify.txt](v08-linux-e2e-admin/raw/cli-e2e-reload-as-eqverify.txt) |
| R2 | the same, **root** | `1 passed; 0 failed`, `SKIP (running as root): …` printed first | [cli-e2e-reload-as-root.txt](v08-linux-e2e-admin/raw/cli-e2e-reload-as-root.txt) |
| R3 | `cargo test -p eqproxy-net --test e2e_admin -- --nocapture`, **root** | `16 passed; 0 failed`, `SKIP (running as root): …` before the reload test's `ok` | [e2e-admin-as-root.txt](v08-linux-e2e-admin/raw/e2e-admin-as-root.txt) |
| R4 | `cargo test --workspace`, **root** | `30 targets` → `559 passed; 0 failed; 2 ignored`, exit `0` | [full-suite-root.txt](v08-linux-e2e-admin/raw/full-suite-root.txt) |
| R5 | `cargo test --workspace`, **uid 10022** | `30 targets` → `559 passed; 0 failed; 2 ignored`, exit `0`, **0 skip lines** | [full-suite-eqverify2.txt](v08-linux-e2e-admin/raw/full-suite-eqverify2.txt), [summary](v08-linux-e2e-admin/raw/full-suite-eqverify2-summary.txt) |

Both totals come from the same arithmetic over each log, not from a summary the
runner prints:

```console
$ grep -oE "[0-9]+ passed; [0-9]+ failed; [0-9]+ ignored" full-suite-root.txt \
    | awk -F'[ ;]+' '{p+=$1; f+=$3; i+=$5} END {print "targets="NR" passed="p" failed="f" ignored="i}'
targets=30 passed=559 failed=0 ignored=2
$ grep -cE "^test result: FAILED" full-suite-root.txt
0
```

The difference between §3 and R3 is the whole point of the change: the first
root run of that target was `15 passed; 1 failed` on a premise root does not
have, kept verbatim as
[netcup-e2e-admin-as-root.txt](v08-linux-e2e-admin/raw/netcup-e2e-admin-as-root.txt),
and the rerun of the fixed tree is `16 passed; 0 failed` twice — as root and as
uid 10022
([e2e-admin-root-vs-eqverify.txt](v08-linux-e2e-admin/raw/e2e-admin-root-vs-eqverify.txt),
16 of 16 in both halves). R5 is the `559` the release workflow's Linux leg
reports, re-measured off CI on the changed tree; R4 shows the same suite does
not look broken under a uid that cannot observe the refusal.

### What the skip does not prove

- It does not prove the refusal on a platform where the process is root: that
  observation is impossible there, which is why it is skipped and named.
- As root, step 2 of the CLI journey is the only part of it that does not run;
  step 1 (mode, group and allowlist applied as a whole on `SIGHUP`) and step 3
  (restore to owner-only) still execute and still assert.
- macOS still compiles the ACL test out (`cfg(target_os = "linux")`), so the
  macOS count stays 558 and the Linux count stays 559; the skips are *inside*
  a test, they do not add or remove one.

### Audit legs of this increment

| Leg | Command | Result |
|---|---|---|
| Veyra Proof | `veyra audit . --profile standard` | **ACCEPTED**, exit `0`, [`.veyra/evidence/20261027T215246Z/`](../../.veyra/evidence/20261027T215246Z/) (local, untracked): 11 tools OK (`rustfmt`, `cargo check`, `clippy`, `cargo test`, `cargo-audit`, `veyra-anti-theater`, `nextest`, `llvm-cov`, `deny`, `machete`, `veyra-e2e`); `dylint` and `semver-checks` **SKIPPED** by the tool's own policy; `cargo-geiger` **INCONCLUSIVE** (coverage warning, a lower bound, not a pass) |
| Rust Audit | `python3.13 /Volumes/Lexar/Cursor/rust-ai-audit/scripts/rust_audit.py scan . --format md --out report --fail-on high` | exit `0`, `report/rust-audit-20261027-225305.md` (local): critical `0`, high `0`, medium `240`, low `85`. No finding names a line this increment touched (`e2e_admin.rs:1295–1330`, `cli_e2e.rs:8535–8570`) |
| CodeGraph Rust | `codegraph-rust index . --stats-json /tmp/cg-index-v08-skip.json`, then `agent impact` and `agent context` | fresh index for this tree: `files: 62`, `lines: 61549`, `nodes: 7026`, `edges: 12282`, `graph_complete: true`, `vector_index_ready: true`, `index_ms: 970922`. **Checked in the source**: the skip is at [`cli_e2e.rs:8544`](../../eqproxy-cli/tests/cli_e2e.rs#L8544) inside `run_admin_plane_reloads_unix_socket_policy_on_sighup` (8460–8605); `wait_for_unix_admin` (:8307) is shared with `run_admin_plane_enforces_group_mode_and_uid_allowlist` (:8367, :8406); `ConfigApplier::restore_admin_unix` ([`main.rs:2397`](../../eqproxy-cli/src/main.rs#L2397)) calls `UnixSocketPolicy::apply` ([`admin.rs:184`](../../eqproxy-net/src/admin.rs#L184)); `peer_allowed` ([`admin.rs:824`](../../eqproxy-net/src/admin.rs#L824)) is the single uid decision point, fail-closed for `uid: None` and `Tcp`. **Not confirmed**: the same answer states the library counterpart `admin_unix_socket_policy_reloads_without_a_restart` “has no root skip” — false, the skip is at [`e2e_admin.rs:1301`](../../eqproxy-net/tests/e2e_admin.rs#L1301); it also could not read the SIGHUP dispatch or the `getsockopt` source of `Peer::Unix { uid }`, and the first `agent impact` attempt errored while Ollama restarted (retried once `/api/tags` answered) |
| Hindsight | `~/.local/bin/hindsight-note` | note left at the close of the increment |
