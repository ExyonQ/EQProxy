# v0.8 — Named users in the admin socket's POSIX ACL (ADR-0023)

Language: **English**. Raw data: [`v08-admin-unix-acl/raw/`](v08-admin-unix-acl/raw/).

## What was proved

A user who is **not** a member of the socket's group can be admitted to the
admin plane through a named POSIX ACL entry, and the kernel — not the proxy —
decides at `connect`:

- `unix_socket_mode = "0660"`, `unix_socket_gid = 2000`,
  `unix_socket_acl_uids = [2001]` produces `660 1000 2000 socket` and a
  `getfacl` that lists `user:2001:rw-`, `mask::rw-`, `other::---`;
- uid 2001 (`groups=3001`, not in gid 2000) reads `/api/v1/status` → `200`;
- uid 2003 (`groups=2000`, no ACL entry) → `200` (the group path is intact);
- uid 2002 (neither owner, nor group, nor ACL) → `curl` exit **7**, no HTTP;
- after a `SIGHUP` that empties `unix_socket_acl_uids`, `getfacl` no longer
  shows the named user, the mode stays `660`, uid 2001 is refused
  (exit **7**), and the group member and the owner still get `200`;
- `SIGINT` exits `0` and removes the socket.

No `libacl`: the entries are written as the `system.posix_acl_access`
extended attribute in its kernel layout, read back with `getfacl` and, for the
reload, by the crate's own test.

The same journey runs on **native `amd64` and `arm64` runners for every pull
request** and on the candidate image of both architectures before the release
promotes a digest — one published script, three jobs.

## Artifact and environment

- Release image `eqproxy:b-h14-acl`, image id
  `sha256:b326c7558ba5114fecaf90f74853d20ea86ac3ca828835944ab2064b92db7981`, built by
  `docker build -f docker/Dockerfile` (rust:1.97-alpine builder, Wolfi runtime,
  static musl binary, exit 0).
- Binary extracted from the image:
  `c083620edc24e5b755ee4fb674d266bebf398df21f01df75532b27dcd9db3f2c`
  (18 337 456 bytes), `file(1)`: *ELF 64-bit LSB executable, ARM aarch64,
  statically linked*.
- Journey container: `debian:bookworm-slim`, kernel `Linux 7.0.14-linuxkit`,
  `curl` and `acl` installed; uid/gid changes through `setpriv
  --reuid/--regid --clear-groups`.
- The socket lives on the container's **overlayfs**. Docker's `--tmpfs` mount
  on this kernel rejects POSIX ACLs (`setfacl: Operation not supported`), even
  though it is mounted `rw,nosuid,nodev,noexec,relatime`; the overlay carries
  `system.posix_acl_access` and was used instead. That is a property of this
  host, not of the feature.
- Harnesses: `scripts/evidence/v08-admin-unix-acl/run.sh` and
  `e2e-multiarch.sh` (host, local-only: build the image per platform, extract
  the binary, start the container) drive
  [.github/scripts/admin-unix-acl-e2e.sh](../../.github/scripts/admin-unix-acl-e2e.sh)
  (**published**: the release gate and the pull-request job run that same
  file, from this repository, unmodified).
  The transcripts they produce are `raw/run.log`, `raw/e2e-*.log` and
  `raw/ci-*.log`.

## Commands and results

### Format, lint, suite (macOS host)

```console
$ cargo fmt --all --check
(no output, exit 0)
$ cargo clippy --workspace --all-targets -- -D warnings
Finished `dev` profile [unoptimized + debuginfo] target(s)
(exit 0)
$ cargo test --workspace
...
29 test binaries: 485 passed, 0 failed, 2 ignored
(exit status 0; full log in raw/full-suite.txt)
```

The Linux-only ACL test is not compiled on macOS, by design.

### Linux test in the real kernel

```console
$ docker run --rm -v "$PWD:/src" -v eqproxy-acl-target:/src/target \
    rust:1.97-alpine sh -c "apk add --no-cache musl-dev cmake make gcc g++ perl \
    linux-headers acl && cargo test -p eqproxy-net --test e2e_admin \
    admin_unix_socket_acl -- --nocapture"
running 1 test
test admin_unix_socket_acl_uids_write_replace_and_clear_the_posix_acl ... ok
test result: ok. 1 passed; 0 failed
```

It binds a real socket with a named user, compares the attribute bytes with
the canonical encoder output, decodes the tag/uid pair and the mask, replaces
the entry through `UnixSocketPolicy::apply`, then empties the list and asserts
the attribute is **gone** and the mode is unchanged (`raw/full-suite.txt`
records the macOS run; this one is in `raw/linux-test.log`).

### Container journey

```console
$ stat -c '%a %u %g %F' /srv/eqproxy/admin.sock
660 1000 2000 socket
$ getfacl -p /srv/eqproxy/admin.sock
# owner: 1000
# group: 2000
user::rw-
user:2001:rw-
group::rw-
mask::rw-
other::---
$ id   # as 2001
uid=2001 gid=3001 groups=3001
$ id   # as 2003
uid=2003 gid=2000 groups=2000

$ status as owner       1000:2000   -> 0 200
$ status as ACL-only    2001:3001   -> 0 200
$ status as group-only  2003:2000   -> 0 200
$ status as outsider    2002:3002   -> 7 000

# SIGHUP with unix_socket_acl_uids = []
INFO admin socket policy applied: mode 0660, gid 2000, 0 allowed uid(s)
$ getfacl -p /srv/eqproxy/admin.sock
user::rw-
group::rw-
other::---
$ stat -c '%a %u %g' /srv/eqproxy/admin.sock
660 1000 2000

$ status as ACL-only    2001:3001   -> 7 000
$ status as group-only  2003:2000   -> 0 200
$ status as owner       1000:2000   -> 0 200

$ kill -INT <pid>; wait
exit=0
socket removed
cfg[reloads=1 reload_failures=0 last_swap_us=5]
```

`curl` exit 7 is *failed to connect*: the kernel answered `EACCES` before the
proxy accepted anything, which is the whole point of putting the grant in the
file instead of in the peer-credential filter.

### Both architectures, with assertions

The transcript above printed its findings; the journey now **checks** them. It
counts a failure for every observable result that differs from its expectation —
ownership and mode of the socket, the three lines `getfacl` must show, the four
client outcomes, the state after the `SIGHUP`, the shutdown code, the socket's
disappearance and the absence of `ERROR`/`WARN` lines — and exits 1 if any
counting is non-zero: sixteen assertions in all.

`scripts/evidence/v08-admin-unix-acl/e2e-multiarch.sh` runs it once per
published architecture. For each platform it builds `docker/Dockerfile` for
that platform only, extracts the static binary from the resulting image and
runs the journey inside a `debian:bookworm-slim` container of the **same**
platform, so the binary meets the kernel and the emulation it would meet in
production. `uname -m` inside each container, printed in the transcript, names
the machine it really ran on.

| | linux/arm64 | linux/amd64 |
|---|---|---|
| binary sha256 | `2a819ecad85d1d70cd2fe5585e631137f43e81d0c280f0caa55de38b032762b9` | `2c2c92f296a0a2eb7549388c91b42c9b682f6f6858d7a9eb46366d20e3a9bdbb` |
| `file(1)` | ELF 64-bit LSB executable, ARM aarch64, statically linked | ELF 64-bit LSB pie executable, x86-64, static-pie linked |
| machine inside the container | `aarch64` | `x86_64` |
| journey | **PASS**, exit 0, 16 assertions | **PASS**, exit 0, 16 assertions |
| Docker Scout critical/high | **0** (36 packages) | **0** (36 packages) |

Both binaries came out byte-identical in three independent builds of each
platform (three runs of the script, each rebuilding the image), which is what
lets the hashes above stand in for the artifact: `raw/e2e-multiarch.log`,
`raw/e2e-arm64.log`, `raw/e2e-amd64.log`, `raw/scout-arm64.sarif`,
`raw/scout-amd64.sarif`.

`linux/amd64` executes under Docker's QEMU emulation on this Apple-silicon
host. That is a real x86-64 userland and a real kernel on the other side of the
`connect(2)`, but it is not amd64 silicon; the two results agree exactly, which
is expected because the decision is the kernel's permission check on a file
attribute, not arithmetic.

#### The journey is not green by construction

With the ACL naming the **outsider** instead of the ACL-only client
(`ACL_UID=2002`, one run on arm64) the same script fails and says which
observations disagree:

```console
$ docker run --platform linux/arm64 -e ACL_UID=2002 … bash /journey.sh
FAIL ACL user reaches the plane: expected [0 200], got [7 000]
FAIL outsider is refused by the kernel: expected [7 000], got [0 200]
RESULT: 2 assertion(s) failed
(exit 1)
```

`raw/negative-control.log`. The grant follows the uid named in the
configuration, and the test follows the grant.

### The same journey is the release gate

`.github/workflows/release.yml` (job `image`) runs
`.github/scripts/admin-unix-acl-e2e.sh` on both architectures immediately
before *Promote the scanned digest to the release tags*: it pulls the
`-candidate` manifest per platform, extracts `/opt/eqproxy` from it, prints the
binary's sha256, and runs the journey in a `debian:bookworm-slim` container of
that platform. `set -euo pipefail` plus `|| fail` stop the job on the first
mismatch, so the tags cannot end up pointing at a digest whose admin socket
admits the wrong users.

The step was executed locally from its own YAML — extracted with PyYAML —
against a real `registry:2` holding a real OCI index with both platforms. The
only substitution is the registry host (`ghcr.io/exyonq` → `localhost:5051`):

```console
$ GITHUB_WORKSPACE=$PWD GITHUB_REF_NAME=v0.7.0-test bash /tmp/gate-run.sh
==> admin ACL E2E (linux/amd64): binary sha256 2c2c92f296a0a2eb7549388c91b42c9b682f6f6858d7a9eb46366d20e3a9bdbb
RESULT: all assertions passed
==> admin ACL E2E (linux/arm64): binary sha256 2a819ecad85d1d70cd2fe5585e631137f43e81d0c280f0caa55de38b032762b9
RESULT: all assertions passed
(exit 0; the sixteen PASS lines per architecture are in raw/ci-gate-local.log)
```

The failure path, running the same step with the real journey configured to
name the outsider (`ACL_UID=2002`), stops the job at the first architecture:

```console
FAIL ACL user reaches the plane: expected [0 200], got [7 000]
FAIL outsider is refused by the kernel: expected [7 000], got [0 200]
RESULT: 2 assertion(s) failed
release FAILED: admin socket ACL journey on linux/amd64
(exit 1)   raw/ci-gate-failpath.log
```

**NOT EXECUTED: the GitHub Actions run itself.** A workflow run needs a tag
push, and no tag was pushed for this change. What ran is the step's own script,
verbatim, with a real multi-arch index behind it and the same image digests the
gate would pull; the Actions orchestration (checkout, QEMU, artifact upload,
`if: github.ref_type == 'tag'`) is not proven by that.

### The journey also runs on native runners for every pull request

`.github/workflows/ci.yml` adds the job `admin-unix-acl`, a matrix of
`ubuntu-latest` (`amd64`) and `ubuntu-24.04-arm` (`arm64`). The arm64 label is
a GitHub-hosted arm64 runner (generally available, free for public
repositories), so each leg compiles with `cargo build --release --locked -p
eqproxy-cli` and runs the journey on **real silicon of its own
architecture** — no QEMU, and no cross-compiled binary meeting a foreign
kernel.

It runs the same published file the release gate mounts
([.github/scripts/admin-unix-acl-e2e.sh](../../.github/scripts/admin-unix-acl-e2e.sh)),
which now takes the binary from `$EQPROXY_BIN` when set and falls back to
`/opt/eqproxy`: one journey, two jobs, so a pull request cannot be green on a
journey the release does not actually run. The matrix declares both the runner
label and the machine it must report, and the first thing the step does is
compare them:

```bash
host_machine="$(uname -m)"
if [ "$host_machine" != "${{ matrix.machine }}" ]; then
  printf 'FAIL declared %s but the runner is %s: not a native leg\n' … >&2
  exit 1
fi
```

Both `run:` blocks were extracted from `ci.yml` with PyYAML, the `matrix.*`
references substituted for the arm64 leg exactly as Actions would, and executed
in a `linux/arm64` Debian container on this Apple-silicon host — native for
that leg — with a stable Rust toolchain and the real journey
(`raw/ci-native-arm64.log`):

```console
== environment: Linux aarch64, rustc 1.99.1 (58cf8f9c3 2026-10-13)
== step: Build the binary for this runner (run block verbatim)
== step: Admin socket ACL E2E (B-H14) (run block verbatim)
==> admin ACL E2E (native arm64, aarch64): sha256 4ac455adf94cf4cd90d4552005acbc395fd0641dec24c5da624c8cbaa0c31c0a, ELF 64-bit LSB pie executable, ARM aarch64, dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, for GNU/Linux 3.7.0, not stripped
kernel: Linux 7.0.14-linuxkit, machine: aarch64
server binary: /work/target/release/eqproxy
eqproxy version: eqproxy 0.7.0
…16 PASS…
RESULT: all assertions passed
(exit 0)
```

Two controls show the leg is not green by construction (`raw/ci-native-controls.log`).
First the architecture guard, with the same block and `matrix.machine` forced to
the other leg's value while the runner really is `aarch64`:

```console
FAIL declared arm64 but the runner is aarch64: not a native leg
(exit 1, before the journey starts)
```

Then the journey itself, naming the outsider in the ACL (`ACL_UID=2002`):

```console
FAIL ACL user reaches the plane: expected [0 200], got [7 000]
FAIL outsider is refused by the kernel: expected [7 000], got [0 200]
RESULT: 2 assertion(s) failed
(exit 1)
```

**NOT EXECUTED: the Actions run itself, and the `amd64` leg natively.**
A workflow run needs a pull request or a branch push; nothing was pushed. The
`amd64` leg needs amd64 hardware, which this arm64 host does not have — running
it here would be the emulation the job exists to avoid, so it is reported as
unrun rather than approximated. What was exercised is the step's own script on
the architecture this machine is.

## Audits

| Leg | Tool and command | Result |
|---|---|---|
| 1. Veyra Proof | `veyra audit . --profile standard` | **ACCEPTED**, exit 0, `.veyra/evidence/20261025T152443Z/` (656.95 s of tool time; re-run after the `ci.yml` change, on a machine also running this container). OK: rustfmt, cargo check, clippy, cargo test, cargo-nextest, llvm-cov, cargo-audit, cargo-deny, cargo-machete, veyra-anti-theater, veyra-e2e. SKIPPED: `dylint`, `cargo-semver-checks`. INCONCLUSIVE: `cargo-geiger` (coverage warnings in 4 runs; unsafe counts are a lower bound, not a pass) |
| 2. Rust Audit | `python3.13 /Volumes/Lexar/Cursor/rust-ai-audit/scripts/rust_audit.py scan . --format md --out report --fail-on high` (0.2.7, engine sha256 `84b5ba5b…`) | exit 0: **0 critical, 0 high, 216 medium, 64 low** (`report/rust-audit-20261025-163711.md`, local-only) — identical to the previous two accepted runs, which is the expected result: this increment touched no Rust file |
| 3. CodeGraph Rust | `codegraph-rust index . --batch-size 16 --stats-json /tmp/cg-ci.json` (after the last edit), `agent context` on where the admin ACL is written and reloaded | 59 files, 54 402 lines, **6 084 nodes, 10 970 edges**, `graph_complete: true`, `vector_index_ready: true`, `errors: 0`, **680 500 ms** — a full re-embed of all 6 084 entities (an earlier index run was killed at the 10-minute tool timeout, and the vector index had to be rebuilt). Counts identical to the previous index: the workflow and the shell script are outside it. The context answer was accurate on every span checked — `write_file_policy` `admin.rs:212`, `UnixSocketPolicy::apply` `admin.rs:182`, `allow_uids` `admin.rs:164`, `unix_socket_options` `main.rs:1937`, `ConfigApplier::reload` `main.rs:2109`, `set_access` `unix_acl.rs:79` (Linux) and `:95` (stub), `access_blob:52`, `ACCESS_XATTR:31` — all confirmed in the source; it also named two gaps itself (an empty reverse-dependency query on `apply`, and the Linux `setxattr` body it never read) |
| 4. Docker | `docker buildx build --platform linux/{arm64,amd64} --load -f docker/Dockerfile …` + `docker scout cves --only-severity critical,high --format sarif` per image | builds exit 0 on both; Scout exit 0 on both, **0 critical/high, 0 vulnerable packages** (36 packages indexed each; `raw/scout-arm64.sarif`, `raw/scout-amd64.sarif`). The E2E journey ran against the binary of each platform's image (see above) |
| 5. Hindsight | `~/.local/bin/hindsight-note --project EQProxy` | note stored, exit 0 (bank `eqproxy`) |

### CodeGraph claims that did not survive the source check

- `AdminHandle::unix_policy` was reported as called from `bind_unix`, `accept`
  and `run`; the only call sites are the applier construction
  (`main.rs:2928`) and two tests — `bind_unix` constructs the policy, and the
  accept loop reads `allow_uids`, never the accessor.
- The ACL validation block was placed at `validate.rs:273-286`; it starts at
  **251** and ends at 296 (the test really is at 3232).
- The context answer admitted it never read `write_file_policy` or the Linux
  `set_access` body; the spans above were read for this report.
- It correctly noticed there is **no ACL-specific SIGHUP test in the Rust
  suite**: the reload of `unix_socket_acl_uids` is covered by the container
  journey (uid 2001 refused after the HUP), not by `cli_e2e`.
- On the re-index used for the both-architecture step, `agent impact "what
  depends on UnixSocketPolicy::apply"` opened with "Recorded in the graph:
  none" and then
  listed five real call sites itself in the next paragraph, admitting the index
  stores those calls against a different `apply` node. Its `DoctorReport::ok`
  entry is a name-collision artifact it correctly disowned; its claim that
  `AdminHandle::unix_policy` is called from `bind_unix`, the admin `accept` and
  `run` still does not survive the source: the only production caller is
  `main.rs:2928`.

## Limits of this run

- **Linux only.** macOS has no POSIX.1e ACLs; on that platform the field is a
  validation error and the plane refuses to start with it, by design.
- **amd64 runs emulated here.** Both architectures are built and exercised,
  but `linux/amd64` runs under QEMU on this Apple-silicon host; no amd64
  hardware took part. The new CI job is where amd64 runs natively, and its
  `amd64` leg is **NOT EXECUTED** from this machine (see above).
- **The `uname -m` guard compares the matrix with the kernel's report, not
  with the silicon.** A QEMU-emulated x86-64 container also reports `x86_64`,
  so the guard catches a leg that landed on the wrong host (an `arm64` label
  resolving to an x86-64 runner) but cannot detect emulation of a foreign
  architecture. What keeps the new job emulation-free is the two labels, and
  `ubuntu-24.04-arm` is an arm64 runner by definition.
- **The local run of the job happened in a container, not on a runner.** The
  journey's socket therefore sat on overlayfs here, while `/srv` on the
  GitHub runner is ext4; both carry `system.posix_acl_access`, so the
  difference is the filesystem, not the feature.
- **The binary, not the runtime stage, is under test.** The journey runs the
  binary extracted from each platform's image, in a `debian:bookworm-slim`
  container; the Wolfi runtime stage (uid 65532, no `setpriv`, no `acl` tools)
  cannot host the four-uid client plan and is unchanged by this slice.
- **Four synthetic uids.** The clients are real processes with real
  credentials, but they are numeric ids created by `setpriv`, not accounts in
  `/etc/passwd`.
- **No proxied traffic** in this journey: it exercises the admin plane and
  the filesystem, not the dataplane (covered by the other v0.8 evidence).
