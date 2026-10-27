# v0.8 — the pinned builder on both architectures, and Docker Scout off-cycle

Language: **English**. Raw data:
[`v08-release/raw/20261027T225140Z-builder-pin/`](v08-release/raw/20261027T225140Z-builder-pin/).

**What this closes:** the two items [v08-toolchain-pin](v08-toolchain-pin.md) §5
left as NOT EXECUTED once the pin landed — the `linux/arm64` image built by the
pinned builder (only the amd64 `export` stage had been), and Docker Scout on
those images — without waiting for the next release tag. It is **not** a
publication: nothing was pushed, tagged or released, and both images are local.

| Piece | Where |
|---|---|
| Image definition | [docker/Dockerfile](../../docker/Dockerfile) — `ARG RUST_VERSION=1.99.1`, Wolfi runtime pinned by index digest |
| Tree under test | `c93cdb6` (main after v0.8.0; the workspace version is still `0.8.0`) |
| Container E2E harness (local-only) | [`scripts/evidence/v08-release/container-e2e.sh`](../../scripts/evidence/v08-release/container-e2e.sh) |
| Transcripts and Scout reports | [raw/20261027T225140Z-builder-pin/](v08-release/raw/20261027T225140Z-builder-pin/) |

## The two images

| Platform | Built where | Image manifest | Manifest list (the local tag) | Size (bytes) | Builder base |
|---|---|---|---|---|---|
| linux/arm64 | this macOS arm64 host, Docker 29.8.2 / `buildx` 0.37.2 (native) | `sha256:086866c8…be10c341` | `sha256:d1f7342c…66ec67c37` | 50 509 179 | `rust:1.99.1-alpine@sha256:b1d5dd5a…693d87` |
| linux/amd64 | Netcup Ubuntu 24.04 **amd64**, Docker 29.6.1 / `buildx` 0.35.0 (native) | `sha256:93feff30…d6a797e8` | `sha256:3277ef25…030d0952` | 15 379 606 | `rust:1.99.1-alpine@sha256:b1d5dd5a…693d87` |

Both declare the pin the same way: [docker/Dockerfile:25](../../docker/Dockerfile#L25)
is `ARG RUST_VERSION=1.99.1`, [rust-toolchain.toml](../../rust-toolchain.toml)
says `channel = "1.99.1"`, and CI's `Docker builder matches the toolchain pin`
gate fails the job when they drift. Both logs show the **same builder base
digest** (the alpine image v08-toolchain-pin §2 quoted for amd64) and the same
runtime base pin, `cgr.dev/chainguard/wolfi-base:latest@sha256:360896efb075…ee2923a7`.

### linux/arm64, built on this host (native)

```console
$ docker buildx build --pull --file docker/Dockerfile --platform linux/arm64 \
    --provenance=mode=max --sbom=true --tag eqproxy-pin:0.8.0-arm64 --load .
#5  [internal] load metadata for cgr.dev/chainguard/wolfi-base:latest@sha256:360896efb075…ee2923a7
#6  [internal] load metadata for docker.io/library/rust:1.99.1-alpine
#25 [builder 15/15] RUN cargo build --release --locked -p eqproxy-cli \
      && cp target/release/eqproxy /opt/eqproxy \
      && file /opt/eqproxy | grep -Eq 'statically linked|static-pie linked'
#25 554.5     Finished `release` profile [optimized] target(s) in 9m 13s
#28 [linux/arm64] generating sbom using docker.io/docker/buildkit-syft-scanner:stable-1
#29 exporting manifest sha256:086866c872ce99a91a68d77f0248c852022eed2704440725eb2299a3be10c341 done
#29 exporting manifest list sha256:d1f7342cc1462cba9c8882fc7ee84035e90a93fede5dbf319dbf96566ec67c37 done
ARM64-BUILD-EXIT=0
```

The Dockerfile's own gate — `file … | grep -Eq 'statically linked|static-pie
linked'`, which refuses a dynamically linked binary — passed as part of that
build, on arm64. Full 24 788-byte log: `build-arm64.txt`.

### linux/amd64, built on the Netcup host (native)

```console
$ docker buildx build --pull --file docker/Dockerfile --platform linux/amd64 \
    --provenance=mode=max --sbom=true --tag eqproxy-pin:0.8.0-amd64 --load .
#23 165.4     Finished `release` profile [optimized] target(s) in 2m 45s
#26 [linux/amd64] generating sbom using docker.io/docker/buildkit-syft-scanner:stable-1
#27 exporting manifest sha256:93feff308130732253a3801fa9d0cad58f44aeefe41f77b414f3232bd6a797e8 done
#27 exporting config sha256:dfd37492039b4b288875c2f6f804dde1ba9cf72ad084ac2e0799e1775bfd64cc done
AMD64-BUILD-EXIT=0
```

The first run's tail is `build-amd64-netcup.txt`. The **re-run** with the log
kept whole (`build-amd64-netcup-full.txt`, cache warm) resolves the two bases
by digest —

```
#6  [runtime 1/3] FROM cgr.dev/chainguard/wolfi-base:latest@sha256:360896efb075…ee2923a7
#7  [builder  1/15] FROM docker.io/library/rust:1.99.1-alpine@sha256:b1d5dd5a…693d87
```

— and exports the **same image manifest** `93feff308130…` and the same config
`dfd37492…` as the first run: the image content is identical. Its manifest
*list* digest differs (`3277ef25…` → `e76fd237…`) because the provenance
attestation carries the build timestamps, not because the image changed. The
tar that travelled to the Mac (`docker save`, 15 314 045 bytes,
`sha256:9998aa4e…`) was loaded as `sha256:3277ef25…` and is what Scout and the
amd64 container E2E below examined.

## The binary, executed natively on amd64

Not a build-only claim: the image ran on the Linux amd64 host it was built on.

```console
$ docker run --rm eqproxy-pin:0.8.0-amd64 --version
eqproxy 0.8.0
$ printf <valid config> | docker run --rm -i eqproxy-pin:0.8.0-amd64 config validate --config /dev/stdin
config OK: 1 listener(s), 1 backend(s) in /dev/stdin
$ printf <config naming an unknown backend> | docker run --rm -i eqproxy-pin:0.8.0-amd64 config validate --config /dev/stdin
configuration error in /dev/stdin:2 — field `listener.web.backend`: backend "nope" does not exist
  example: backend = "nope" requires a [backend.nope] section with server = "127.0.0.1:9000"
invalid config: 1 error(s) in /dev/stdin
bad-config-exit=1
```

The invalid document is the boundary case: the image refuses it, explains the
field and exits `1` — it is not a placeholder answer.

## Docker Scout: 0 critical, 0 high on both

```console
$ docker scout cves --only-severity critical,high --exit-code -o raw/…/scout-arm64.md eqproxy-pin:0.8.0-arm64
    ✓ SBOM obtained from attestation, 69 packages found
    ✓ Provenance obtained from attestation
    ✓ No vulnerable package detected
SCOUT-ARM64-EXIT=0
$ docker scout cves --only-severity critical,high --exit-code -o raw/…/scout-amd64.md eqproxy-pin:0.8.0-amd64
    ✓ SBOM obtained from attestation, 69 packages found
    ✓ Provenance obtained from attestation
    ✓ No vulnerable package detected
SCOUT-AMD64-EXIT=0
```

Both reports read `0C 0H 0M 0L` and `69 packages`:

| Report | Platform | Image digest | Vulnerabilities | Base |
|---|---|---|---|---|
| `scout-arm64.md` | linux/arm64 | `086866c872ce` | `0C 0H 0M 0L` | `cgr.dev/chainguard/wolfi-base:latest` `15ae92e2d465` |
| `scout-amd64.md` | linux/amd64 | `93feff308130` | `0C 0H 0M 0L` | `cgr.dev/chainguard/wolfi-base:latest` `8e250f5e2803` |

The per-architecture digests Scout names are the arm64 and amd64 manifests
*inside* the pinned index `360896ef…`; both build logs load that index. The
arm64 report also carries the provenance link to
`https://github.com/ExyonQ/EQProxy/blob/c93cdb647c91c920ac202cbcb21ef35a71723eea`,
so the scanned bytes are traceable to the tree. Scout CLI **1.25.0** (the
version the release workflow pins), advisory DB as of the run.

## Container E2E: 20 checks per architecture, all passing

```console
$ scripts/evidence/v08-release/container-e2e.sh eqproxy-pin:0.8.0-arm64 linux/arm64 20261027T225140Z-builder-pin
container E2E linux/arm64: 20 PASS, 0 FAIL
ALL PASS
E2E-ARM64-EXIT=0
$ scripts/evidence/v08-release/container-e2e.sh eqproxy-pin:0.8.0-amd64 linux/amd64 20261027T225140Z-builder-pin
container E2E linux/amd64: 20 PASS, 0 FAIL
ALL PASS
E2E-AMD64-EXIT=0
```

What the harness does is described in [v08-release](v08-release.md) §"Container
E2E"; the checks are the same ones: `--version`, `config validate`, live
proxied traffic from two real `nginx:alpine` backends, the admin plane
(`/api/v1/status` with the read token, `revision=v1`, both servers `ready`), the
panel (login page, `HttpOnly`/`SameSite=Strict`/`Path=/panel` session, dashboard
naming the container servers) and a drain from the API that the dataplane
honours for ten requests before `ready` returns the backend. Transcripts:
`container-e2e-linux-arm64.txt`, `container-e2e-linux-amd64.txt`, with
`status-container.json`, `status-after-drain.json`, `login-page.html`,
`dashboard.html` and the two TOMLs beside them.

- **arm64** ran natively on this host.
- **amd64** ran through the host's x86-64 emulation: the transcript records
  Docker's `WARNING: The requested image's platform (linux/amd64) does not
  match the detected host platform …` where the harness starts the two
  long-running containers without `--platform` (lines 12 and 16), and the first
  check's `--version` is the amd64 image's own answer. The build and the binary
  checks above, by contrast, were native Linux amd64.

## Limits and NOT EXECUTED

- **Still not the release candidate.** The gate that binds a release is the
  scan of the pushed `-candidate` **index digest**, which runs only on the tag
  ([release.yml:533](../../.github/workflows/release.yml#L533)); this page
  proves the same Dockerfile, the same pinned bases and the same tree build,
  run, pass and scan off-cycle, on both architectures.
- **The arm64 release image is built by the workflow's arm runner**, not on
  this Mac: same Dockerfile and same base digests, different host. The Mac
  build is the native arm64 datapoint available before that runner runs.
- **Scout ran on single-arch local images**, one per platform; the multi-arch
  index is scanned per platform at release time.
- **The amd64 image was scanned after `docker save` / `docker load`**; the
  loaded manifest list digest is the one the server produced, and the re-run
  reproduced the image manifest and config digests exactly.
- **The images are local tags** (`eqproxy-pin:0.8.0-{arm64,amd64}`); they were
  not pushed, and no registry digest exists for them.
- **A new advisory can change the verdict** without any change here: the
  reports are bound to the Scout CLI, the advisory DB and the run date above.
- **`--sbom=true --provenance=mode=max` with `--load`** keeps the attestations
  in the local store (Scout read both), but the Docker exporter is not a
  registry: the attestations of a pushed index are produced again by the
  release job.

## One audit-leg failure, diagnosed (not hidden)

The first Veyra run of this increment came back **REJECTED**, exit `1`, reason
`Tool error(s): llvm-cov`; that evidence is left on disk at
`.veyra/evidence/20261027T230034Z/`. Its `tools/llvm-cov/stderr.log` names the
test:

```
FAIL [   0.904s] ( 37/558) eqproxy-cli::cli_e2e run_all_backups_spreads_traffic_across_the_backup_pool
  all_backups phase 2 (pool): high=20 low=10 primary=11
  panicked at eqproxy-cli/tests/cli_e2e.rs:3744:26:
  expected a pool member, got ""
```

Nothing in this increment touches that journey (this change is `docs/` only),
and the same target passes **78/78** under
`cargo nextest run -p eqproxy-cli --test cli_e2e` on this tree
([raw/nextest-cli-e2e.txt](v08-builder-pin-both-arch/raw/nextest-cli-e2e.txt)).
What produced the empty body is observable:

1. **Where the empty body comes from.** A `503` with no body is the
   `write_no_server(…, 503, "service unavailable")` path —
   [`http1.rs:2005`](../../eqproxy-net/src/http1.rs#L2005) — i.e. *no eligible
   server*: the product's fail-closed answer, not a wrong pool member.
2. **How the pool can be empty while the survivor's dataplane is fine.** The
   local-only harness [`all-backups-probe.py`](../../scripts/evidence/v08-builder-pin/all-backups-probe.py)
   replays the journey against the real binary: primary down, `h` down, `l`
   healthy but answering `/healthz` 300 ms late — past the `timeout = "100ms"`
   of its probe, with `fall = 1`. Deterministic result
   ([raw/allbackups-probe-deterministic.txt](v08-builder-pin-both-arch/raw/allbackups-probe-deterministic.txt)):
   the client gets
   `HTTP/1.1 503 service unavailable` with an empty body and the admin plane
   reports all three `healthy=False` — exactly the `""` the assertion trips on.
3. **Under load it happens by itself.** With CPU burners on the same host the
   same harness hit it with no artificial delay
   ([raw/allbackups-probe-under-load.txt](v08-builder-pin-both-arch/raw/allbackups-probe-under-load.txt)):
   `phase 2: high=20 low=9` — one of
   30 round-robin answers was the empty `503` — and in the next phase a `503`
   on the first request while `/api/v1/status`, asked straight after, already
   had the survivor back at `healthy=True`: the probe recovered inside a 150 ms
   tick before the query could see it.
4. **The trigger was mine.** I launched Veyra and the Rust Audit scan in
   parallel, on a host already at load average ≈ 400 from another project.
   Under that oversubscription a 100 ms probe to a local Python origin times
   out, `fall = 1` drops the member, and the tier can be empty for a tick.

What this does **not** claim: five further load passes (40–80 requests each,
12 burners — `raw/allbackups-probe-load-attempt{1..5}.txt`) found no further
hit, so the frequency is unknown; the 20 ms
watcher never recorded a surviving member's `healthy=False` tick, so step 3
rests on the deterministic mechanism of step 2 plus the product's own state,
not on a captured down-tick. And it is a load-sensitive *journey*, not a
functional defect found here: step 2 shows the dataplane would have served `l`
correctly had its probe been answered in time. It is listed under "Pending"
below rather than papered over.

### Audit legs of this increment

| Leg | Command | Result |
|---|---|---|
| Veyra Proof (re-run **alone**, the one cited) | `veyra audit . --profile standard` | **ACCEPTED**, exit `0`, `.veyra/evidence/20261027T232435Z/` (local, untracked): 11 tools OK — including `cargo-llvm-cov` (232.6 s) and `cargo-test`; `dylint` and `semver-checks` **SKIPPED** by the tool's own policy; `cargo-geiger` **INCONCLUSIVE**, not a pass |
| — the same leg, first run, launched in parallel with the Rust Audit scan | `veyra audit . --profile standard` | **REJECTED**, exit `1`: `cargo-llvm-cov` exit `100` on the `all_backups` journey above; the run stays at `.veyra/evidence/20261027T230034Z/` and is not cited as a pass |
| Rust Audit | `python3.13 /Volumes/Lexar/Cursor/rust-ai-audit/scripts/rust_audit.py scan . --format md --out report --fail-on high` | exit `0`, `report/rust-audit-20261028-000048.md` (local): critical `0`, high `0`, medium `240`, low `85` — the same profile as the previous increment, and no finding names a file this one touched (only `docs/` changed) |
| CodeGraph Rust | `codegraph-rust index .` / `agent impact` / `agent context` | **NOT EXECUTED for this increment**, and not counted as a pass: this change touches `docs/` only, so the index already on disk (built in this session from the same code — 62 files, 61 549 lines, 7 026 nodes, 12 282 edges, `graph_complete: true`) answers the same graph, and there is no changed symbol for `impact`/`context` to explain. The previous increment's queries and their source-checked findings are in [v08-linux-e2e-admin](v08-linux-e2e-admin.md) §7 |
| Hindsight | `~/.local/bin/hindsight-note` | note left at the close of the increment |

### The leg, re-run alone

```console
$ veyra audit . --profile standard
- Decision: ACCEPTED
- Decision reason: All required profile tools executed without blocking findings
Evidence written to: .veyra/evidence/20261027T232435Z
VEYRA-ALONE-EXIT=0
```

Same tree, same commit candidate, no other heavy job running: `cargo-llvm-cov`
finishes (232.6 s) where the parallel run's instrumented `nextest` failed one
journey. The rejected run is not deleted and not counted; the accepted one is
the cited verdict.

### Pending (this increment does not fix it)

- **The journeys' 100 ms probe timeout is load-sensitive.** Seven places in
  [`eqproxy-cli/tests/cli_e2e.rs`](../../eqproxy-cli/tests/cli_e2e.rs) build a
  health check with `timeout = "100ms"` and `fall = 1`, and any of them can see
  the empty `503` (fail-closed: no eligible server) when the machine is
  oversubscribed — the `all_backups` journey is simply the one that tripped
  first. The honest repair is its own increment and its own justification:
  either the journeys stop asserting a service level the loaded host cannot
  guarantee, or the probe's timing is isolated from it — and whatever the fix,
  the assertions about *which* member serves stay exactly as strict.
- **Nothing here ran under `llvm-cov` again.** The re-run of the leg below is
  the clean run of the tree; the instrumented condition that tripped the first
  one is documented, not reproduced on demand.
