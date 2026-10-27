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
  unprivileged user.
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
otherwise look like a Linux failure.

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

The increment's audit legs (Veyra Proof, Rust Audit, CodeGraph, Hindsight)
are recorded in [v08-slow-start](v08-slow-start.md) §4.
