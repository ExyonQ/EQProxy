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
| Tests | `cargo test --workspace` | **333 passed, 0 failed** across 23 suites, exit 0 |
| Unit gate tests | `cargo test -p eqproxy-config --lib` | 48 passed |
| E2E gate test | `cargo test -p eqproxy-cli --test cli_e2e validate_rejects_h2_alpn_on_an_http_listener_with_a_fix` | 1 passed |
| Veyra Proof | `veyra audit . --profile standard` | **ACCEPTED**, exit 0, `.veyra/evidence/20261021T133249Z/` |
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

## 5. Publication

Filled in after the tag build: release assets, checksums, image digests and the
post-publication re-check of the same journeys on the published artifacts.

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
