# v0.8 — the toolchain pin: CI, release build and image builder on 1.99.1

Language: **English**. Commit `ae3d950`. Before this, both CI jobs and the
release workflow installed `stable` — whatever the runner's rustup resolved
that morning — and a new stable had already turned CI red between two pushes
(a clippy lint, repaired in `7da08df`). The image builder pinned its own
`ARG RUST_VERSION=1.97`, so the "tested" and "shipped" compilers were two
different versions by construction.

## 1. What changed

- **[`rust-toolchain.toml`](../../rust-toolchain.toml)** (new): the single
  source. `channel = "1.99.1"` — the current stable at the time
  (`rustup check`: `stable ... up to date: 1.99.1 (58cf8f9c3 2026-10-13)`) —
  with `profile = "minimal"` and `components = ["rustfmt", "clippy"]`, so a
  fresh `rustup` installs the lint and format tools this repository gates on.
- **`ci.yml`** (both jobs) and **`release.yml`** (darwin build): the install
  step reads the `channel` line out of the file
  (`sed -n 's/^channel = "\(.*\)"/\1/p'`) and installs exactly that; the
  darwin job adds both Apple targets to *that* toolchain.
- **`ci.yml`**, new gate `Docker builder matches the toolchain pin`: reads
  the same line and `ARG RUST_VERSION` from `docker/Dockerfile` and fails the
  job when they differ. Two pins that can drift are not a pin.
- **[`docker/Dockerfile`](../../docker/Dockerfile)**: `ARG RUST_VERSION`
  `1.97` → `1.99.1`, with the reason in a comment.
- **`CONTRIBUTING.md`**: the "CI runs stable" sentence replaced by the pin's
  rule — bump it deliberately, with its verification.

Bump procedure: edit `rust-toolchain.toml`, edit the Dockerfile's `ARG`, and
let CI's gate (and the darwin build's own pin) confirm they match.

## 2. The pinned builder on Linux (Netcup amd64)

`docker buildx build --file docker/Dockerfile --target export` in the
`ae3d950` checkout, section C of
[`v08-linux-e2e-admin/raw/netcup-session.txt`](v08-linux-e2e-admin/raw/netcup-session.txt):

```
#2  [internal] load metadata for docker.io/library/rust:1.99.1-alpine
#4  [builder 1/15] FROM docker.io/library/rust:1.99.1-alpine@sha256:b1d5dd5a22a09404d3e798c0cf051b689077360374eb505fa5bb93c479693d87
...
#19 DONE 178.6s                       # cargo build --release --locked -p eqproxy-cli
#20 [export 1/1] COPY --from=builder /opt/eqproxy /eqproxy
/tmp/eqproxy-export/eqproxy: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked, BuildID[sha1]=3eacbeb0d2505bf3506b4b97bb88e77ea2c17b02, not stripped
eqproxy 0.8.0
```

The `file | grep -Eq 'statically linked|static-pie linked'` gate inside the
Dockerfile passed as part of the build, and the binary the pinned builder
produced **ran on Linux and reported `eqproxy 0.8.0`**.

## 3. Local checks with the pin active (macOS arm64)

```console
$ rustup show active-toolchain
1.99.1-aarch64-apple-darwin (overridden by '<repo>/rust-toolchain.toml')
$ cargo fmt --all -- --check          # OK
$ cargo clippy --workspace --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 33.93s
    clippy exit=0
```

Raw: [`v08-toolchain-pin/raw/local-clippy-1.99.1.txt`](v08-toolchain-pin/raw/local-clippy-1.99.1.txt)
and [`.../netcup-toolchain.txt`](v08-toolchain-pin/raw/netcup-toolchain.txt)
(the Linux host resolving the same pin).

## 4. CI on this commit

On `ae3d950`, green:

- **CI** — run [40578501195](https://github.com/ExyonQ/EQProxy/actions/runs/40578501195):
  `linux-tier1` (the pin install step, the new pin gate, `fmt`,
  `clippy -D warnings`, the whole suite), `evidence-test-citations`, and
  `admin-unix-acl` on both `ubuntu-latest` (amd64) and `ubuntu-24.04-arm`
  (native arm64) — the job whose logs were quoted above relies on the
  install step that now reads the pin.
- **CodeQL** — run [40578500518](https://github.com/ExyonQ/EQProxy/actions/runs/40578500518)
  (“Push on main”), `Analyze (rust)` and `Analyze (actions)`: success.

## 5. Limits and NOT EXECUTED

- **The darwin release job was not executed**: it runs on a `v*` tag. Its
  install step changed in `ae3d950`, and a future release is its first real
  run; until then that job's pin is **NOT EXECUTED**.
- **linux/arm64 image: NOT EXECUTED in this pass.** The export stage was
  built natively for linux/amd64 only; the multi-arch candidate image is
  built by the release workflow.
- **Docker Scout: NOT EXECUTED** — nothing was published in this increment,
  and Scout runs on the candidate digest at release time.
- The pin freezes *surprises*, not *breakage*: a toolchain bump can still
  contain a change that requires code work (as `7da08df` did). What changes
  is that it arrives as a visible, testable bump instead of overnight.
- The base image is pinned by tag (`rust:1.99.1-alpine`), which Docker
  resolves to the digest cited above; a rebuilt image can pick up a new
  Alpine layer, which the release pipeline's Scout gate and E2E re-check.

The increment's audit legs (Veyra Proof, Rust Audit, CodeGraph, Hindsight)
are recorded in [v08-slow-start](v08-slow-start.md) §4.
