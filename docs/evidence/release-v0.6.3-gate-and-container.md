# v0.6.3 — ALPN h2 gate and container state directory

Language: **English**. Evidence for the v0.6.3 patch release, collected on
2026-10-21 (macOS 26 arm64 host, Docker 29.8.2, Rust 1.97.1).

## 1. Objective

Two defects were found while measuring TLS parity
([v0.6.2-tls-parity](v0.6.2-tls-parity/README.md)):

1. `alpn = ["h2"]` on a `mode = "http"` listener passed the configuration gate,
   negotiated h2 on the wire and then failed every request, because the
   dataplane is HTTP/1.1 only.
2. The container had no writable state directory: `config apply` and
   `config rollback` exited 1 with `Permission denied` inside the published
   image.

The release also republishes the four platform binaries and the multi-arch
image so the fixes ship as artifacts, not only as source.

## 2. Changes

| File | Change |
|---|---|
| `eqproxy-config/src/validate.rs` | `unserved_alpn` rejects `h2`/`h2c` for `mode = "http"` listeners and for backend TLS used by such a listener; five unit tests |
| `eqproxy-cli/tests/cli_e2e.rs` | E2E test asserting `config validate` exits 1 with field, cause and fix |
| `eqproxy-net/src/maps.rs` | test race fixed: the map publishes data before the reload counter increments, so the test waits for both (assertion unchanged: exactly one reload) |
| `eqproxy-cli/src/main.rs`, `eqproxy-cli/tests/cli_e2e.rs` | generated reports are written through `emit_report`, which treats a closed pipe as success; E2E test pipes `config explain` into `head` and requires no panic |
| `docker/Dockerfile` | runtime stage ships `/var/lib/eqproxy` owned by 65532, `ENV EQPROXY_STATE_DIR=/var/lib/eqproxy`, `EXPOSE 8443` |
| `.github/workflows/release.yml` | image E2E now also proves `alpn = ["h2"]` is rejected and `config apply` writes state on both architectures |
| `docs/docker-hub-readme.md` | stale `0.6.1` tags, wrong uid (65534 → 65532), state directory/volume, withdrawn musl-vs-"glibc" claim |
| `Cargo.toml`, `CHANGELOG.md`, `README.md` | version 0.6.3 |

`mode = "tcp"` listeners keep any ALPN value: they relay bytes without parsing
them, so an h2 hint there is a legitimate tunnel, not the HTTP/1.1 trap.

## 3. Before / after

### 3.1 Gate

Published v0.6.2 binary (`eqproxy-darwin-arm64`, sha256
`7e2f792f5eace1c261e5d93d24b920be859994a60a5e5a7e8835e71336a20fe5`)
accepts the configuration:

```
$ ./eqproxy-darwin-arm64 config validate --config h2.toml
config OK: 1 listener(s), 1 backend(s) in h2.toml        # exit 0
```

The same file on the v0.6.3 build:

```
$ ./eqproxy config validate --config h2.toml
configuration error in h2.toml:2 — field `listener.web.tls.alpn`: ALPN protocol "h2" cannot be served: mode = "http" speaks HTTP/1.1 only, so the handshake would succeed and every request would then fail (no HTTP/2 dataplane yet)
  example: alpn = ["http/1.1"]
invalid config: 1 error(s) in h2.toml                    # exit 1
```

`alpn = ["http/1.1"]` in the same file is accepted (`config OK`, exit 0).

On the wire, the published v0.6.2 image (`ghcr.io/exyonq/eqproxy:0.6.2`)
serving that configuration, from a Debian 12 client:

```
$ curl --http2 -sk -o /dev/null -w 'code=%{http_code} http=%{http_version}\n' https://eq62h2:8443/
code=000 http=0        # curl exit 52
```

The handshake succeeded (`ALPN h2`) and the request died: exactly the trap the
gate now closes. v0.6.3 never starts a listener from that file.

### 3.2 Container state directory

v0.6.2 image, read-only config mount:

```
$ docker run --rm -v .../eqproxy.toml:/etc/eqproxy/eqproxy.toml:ro \
    ghcr.io/exyonq/eqproxy:0.6.2 config apply --config /etc/eqproxy/eqproxy.toml
error: cannot use state in .eqproxy: Permission denied (os error 13)
  (check permissions or set EQPROXY_STATE_DIR=<path>)      # exit 1
```

v0.6.3 image (`eqproxy-local:0.6.3`, arm64, `sha256:a891f510…`):

```
$ docker run --rm -v .../c.toml:/c.toml:ro eqproxy-local:0.6.3 config apply --config /c.toml
applied: /c.toml -> /var/lib/eqproxy/current.toml (no previous configuration)
plan: 1 listener(s), 1 backend(s) — nothing started (dry run)    # exit 0
```

## 4. Verification (commands and results)

| Check | Command | Result |
|---|---|---|
| Format | `cargo fmt --all --check` | clean |
| Clippy | `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| Tests | `cargo test --workspace` | **334 passed, 0 failed** across 23 suites, exit 0 |
| Unit gate tests | `cargo test -p eqproxy-config --lib` | 48 passed |
| E2E gate test | `cargo test -p eqproxy-cli --test cli_e2e validate_rejects_h2_alpn_on_an_http_listener_with_a_fix` | 1 passed |
| Veyra Proof | `veyra audit . --profile standard` | **ACCEPTED**, exit 0, `.veyra/evidence/20261021T161320Z/` (final tree; `20261021T133249Z` is the earlier accepted run before the EPIPE fix) |
| Rust Audit | `rust_audit.py scan . --format terminal,md,json --fail-on high` | exit 1 (190 static findings, 2 critical / 16 high, triaged below); none in the files changed here |
| EvoForge | `mcp_submit_eval` on the gate slice | **F = 1.0**, 3/3 sandbox tests pass, trace `56043e4f-e523-4bee-a63a-3a1771a8456c` |

Veyra detail: `llvm-cov`, `cargo-test`, `nextest`, `cargo-deny`,
`cargo-machete`, `audit`, `anti-theater` and `veyra-e2e` OK; `dylint` and
`semver-checks` skipped (no lint set; unpublished crates have no baseline);
`cargo-geiger` inconclusive (4 runs with unparsed dependency files, reported as
a lower bound, not a pass).

The first veyra run of this increment was **REJECTED** (exit 1,
`.veyra/evidence/20261021T132629Z/`): `llvm-cov` failed because
`maps::tests::watcher_keeps_last_good_data_when_the_file_disappears` asserted
`map_reloads == 1` the instant the new data became visible, while the watcher
increments the counter after publishing the map. Instrumented builds lose that
race. The test now waits for both conditions up to the same 5 s deadline and
still asserts exactly one reload; the rerun is the ACCEPTED entry above.

Rust Audit triage (unchanged from earlier releases, no suppression): the two
critical items are `thiserror = "2"` (major 2 exists) and the workspace crate
`eqproxy_core` matching a "generic name" heuristic; the high items are
`md-5` (the published crate name), `default_*` serde helpers that return
constants by design, error-message strings read as "placeholders", and three
`.expect(` calls at startup that abort with a message. No finding points at
`unserved_alpn`, `http_mode_user`, the new tests or the Dockerfile.

Container journeys on `eqproxy-local:0.6.3` (arm64, 15.8 MB):

| Journey | Result |
|---|---|
| `--version` | `eqproxy 0.6.3`, exit 0 |
| `config validate` (good config) | `config OK: 1 listener(s), 1 backend(s)`, exit 0 |
| `config validate` with `alpn = ["h2"]` | exit 1 with field, cause and `example: alpn = ["http/1.1"]` |
| TLS termination, live traffic | `HTTP 200` |
| `config apply` (default state dir) | exit 0, writes `/var/lib/eqproxy/current.toml` |
| `config apply` twice + `config rollback` in a named volume | exit 0, backup `0001-…`, `rolled back: current restored from …` |
| `SIGHUP` under traffic | `INFO config reload applied: listeners kept=1 added=0 removed=0` |
| `config explain \| head -1` | first line printed, exit 0, no `Broken pipe` panic (before: panic) |

## 5. Publication (2026-10-21T17:17Z)

Release: <https://github.com/ExyonQ/EQProxy/releases/tag/v0.6.3>, tag
`v0.6.3` at commit `bc74d50`, run 39633772504 (all jobs success).

**Assets:** `eqproxy-darwin-arm64`, `eqproxy-darwin-amd64`,
`eqproxy-linux-arm64`, `eqproxy-linux-amd64`, `SHA256SUMS.txt`, the four
CycloneDX SBOMs and `SCOUT-0.6.3-linux-amd64.md` / `…-arm64.md`. All four
binaries pass `shasum -a 256 -c SHA256SUMS.txt` on this host.

**Images:** `ghcr.io/exyonq/eqproxy:0.6.3`, `docker.io/exyonq/eqproxy:0.6.3`,
`ghcr.io/exyonq/eqproxy:latest` and `docker.io/exyonq/eqproxy:latest` all
resolve to the scanned index
`sha256:559504b5cd5513073af61ec3761f3e5c6d2f1f51749e15c36130fbdf7997fedb`
(sha256 of each raw manifest checked byte for byte).

**Release CI on the candidate, per architecture:** version, validate happy
path, `alpn = ["h2"]` rejected (exit 1 with cause and fix), `config apply`
writes state, live traffic `200` (`linux/amd64` and `linux/arm64`).

**Re-check of the published artifacts from this host:** `eqproxy 0.6.3` on
darwin arm64, darwin amd64 (Rosetta) and both Linux binaries inside Debian
12; h2 exits 1 with the gate message on all four; `config explain | head`
exits 0 without a panic; the published arm64 image serves TLS with `200` and
runs `config apply` (exit 0); the Docker Hub `amd64` image reports 0.6.3.

**Post-publication re-check is now a pipeline step, not a manual habit.**
`Re-pull the published image and replay the journeys` was added to the release
workflow after this release: it pulls `:<version>` from GHCR and Docker Hub on
`linux/amd64` and `linux/arm64`, asserts the pulled image's `RepoDigests`
contain the scanned index, and runs `--version`, the h2 rejection, `config apply`
and live traffic. The exact script was extracted from the workflow and run on
this host against the published v0.6.3 images: 4/4 combinations passed, and a
wrong index made it fail at the digest assertion. It cannot run during v0.6.3
itself (the tag predates it), so for this release the four combinations were
executed by hand with the same commands — the pipeline enforcement is
**NOT EXECUTED in CI** until the next tag.

**Attempts that did not publish:** two earlier runs of this tag failed and
nothing was released from them — `a6f4521` (the new image check piped
`config apply` into `grep -q`, so `pipefail` failed on SIGPIPE while the
candidate image passed the same journey locally) and `3c6eef5` (the darwin
E2E piped `config explain` into `grep -q` and the binary panicked on EPIPE,
which is the product bug fixed in `bc74d50`). GitHub Actions reported
"partially degraded service" during the window and delivered the tag event
late and three times; two duplicate release runs were cancelled, one
completed.

## 6. Limits of this evidence

- The local image build and its journeys ran on **linux/arm64** (this host).
  `linux/amd64` is exercised by the release workflow before the tag is promoted
  (§5 records the result).
- `tcp`-mode ALPN is deliberately not restricted; no wire test covers an h2
  tunnel through a `tcp` listener.
- A read-only-rootfs container still needs a volume on `/var/lib/eqproxy` for
  `config apply`; that is documented, not automated.
- Ports below 1024 remain unavailable to uid 65532; the Docker Hub page now
  says so instead of leaving it implicit.
