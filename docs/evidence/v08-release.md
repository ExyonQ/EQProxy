# v0.8.0 — the image gate before publication, v0.8

Language: **English**.

**What this page answers:** whether the `0.8.0` image is fit to be published —
the same Dockerfile and pinned base the release workflow builds, scanned by
Docker Scout on **both** architectures and exercised end to end inside the
image, plus the release-binary journeys on the 0.8.0 build. It is the local
counterpart of the workflow's `image` job, **not** a publication: nothing was
pushed, tagged or released here.

| Piece | Where |
|---|---|
| Image definition (builder `rust:1.97-alpine`, Wolfi runtime) | [docker/Dockerfile](../../docker/Dockerfile) |
| Pinned base (index digest, ADR-0016) | [docker/Dockerfile:71](../../docker/Dockerfile#L71) |
| Container E2E harness (local-only) | [`scripts/evidence/v08-release/container-e2e.sh`](../../scripts/evidence/v08-release/container-e2e.sh) |
| Scout reports and transcripts | [`docs/evidence/v08-release/raw/20261027T011607Z/`](v08-release/raw/20261027T011607Z/) |
| CI gate that repeats this on the pushed candidate | [.github/workflows/release.yml:533](../../.github/workflows/release.yml#L533) |

## Images under test

Both were built from the **0.8.0 tree** (workspace version bumped, crate pins
and `Cargo.lock` agreeing) with:

```console
$ docker buildx build --pull --file docker/Dockerfile --platform linux/amd64 \
    --provenance=mode=max --sbom=true --tag eqproxy-release:0.8.0-amd64 --load .
$ docker buildx build --pull --file docker/Dockerfile --platform linux/arm64 \
    --provenance=mode=max --sbom=true --tag eqproxy-release:0.8.0-arm64 --load .
```

| Platform | Image ID | Suffix digest (Scout) | Local size |
|---|---|---|---|
| linux/amd64 | `sha256:32130c25d367…e6e8177` | `sha256:8686145b1282…2a5579f` | 55.7 MB |
| linux/arm64 | `sha256:0735c5b17f23…aa9d0c0` | `sha256:019ce9532861…42ff5fa` | 50.8 MB |

- Base: `cgr.dev/chainguard/wolfi-base:latest@sha256:360896efb075…ee2923a7`
  (the same pin CI builds from), 69 packages, reported 15 MB / 14 MB.
- Host: macOS 26.5.1 arm64, Docker 29.8.2, buildx 0.37.2, Scout CLI
  **v1.25.0** (the version the workflow pins), `amd64` executed through the
  host's x86-64 emulation.
- The binary inside both images is `eqproxy 0.8.0`, static musl, built with
  `cargo build --release --locked` under the image's `file` gate.

## Docker Scout gate: 0 critical, 0 high on both architectures

```console
$ docker scout cves --only-severity critical,high --exit-code eqproxy-release:0.8.0-amd64
   vulnerabilities │    0C     0H     0M     0L
 Base image        │  cgr.dev/chainguard/wolfi-base:latest
## Packages and Vulnerabilities
  No vulnerable packages detected
# exit 0
$ docker scout cves --only-severity critical,high --exit-code eqproxy-release:0.8.0-arm64
   vulnerabilities │    0C     0H     0M     0L
   packages        │ 69
# exit 0
```

Both runs also wrote the markdown report CI ships next to the release
(`raw/…/scout-amd64.md`, `raw/…/scout-arm64.md`). **The gate is met** on the
images built here; the one that will bind the release is the scan of the
pushed `-candidate` **index digest**, which runs only on the tag (see
"Not executed").

## Container E2E: 20 checks per architecture, all passing

```console
$ scripts/evidence/v08-release/container-e2e.sh eqproxy-release:0.8.0-amd64 linux/amd64 20261027T011607Z
container E2E linux/amd64: 20 PASS, 0 FAIL
ALL PASS
$ scripts/evidence/v08-release/container-e2e.sh eqproxy-release:0.8.0-arm64 linux/arm64 20261027T011607Z
container E2E linux/arm64: 20 PASS, 0 FAIL
ALL PASS
```

What the harness does, all against real containers and real sockets:

1. **CLI inside the image** — `--version` is `eqproxy 0.8.0`, and
   `config validate --config /dev/stdin` accepts a minimal document
   (`config OK: 1 listener(s), 1 backend(s)`).
2. **Live proxied traffic** — two `nginx:alpine` containers as servers on a
   dedicated docker network, the image as the proxy mapped to the host; the
   response is a real backend 200 with the nginx body (not a placeholder).
3. **Administration plane** — `GET /api/v1/status` with the read token lists
   both servers `ready` at revision `v1`; the 14-byte token of the first
   attempt was refused at startup (`admin.token is 14 bytes; use at least
   16`), which is how that attempt failed.
4. **Panel** — anonymous `GET /panel` is the login page (`Log in`) with the
   no-script CSP; `POST /panel/login` returns `303` with an `HttpOnly`,
   `SameSite=Strict`, `Path=/panel` cookie that never echoes the token; the
   write session renders the dashboard naming both container servers.
5. **Drain from the admin API** — the write token drains one backend (`200`,
   `status` then says `drain`), the dataplane keeps answering from the other
   backend for ten requests, and `{"state":"ready"}` returns it. Every write
   leaves its `AUDIT` line in the container log.

The transcripts are `raw/…/container-e2e-linux-amd64.txt` and
`container-e2e-linux-arm64.txt`; `status-container.json`,
`status-after-drain.json`, `login-page.html`, `dashboard.html` and the two
TOMLs the run used are next to them.

### Two harness failures that are part of the record

- `run-20261027T011435Z` — the first attempt used tokens shorter than  the product's 16-byte minimum, so the admin plane refused to start and 15 checks
  cascaded. That is the **product validating**, not a product bug; the harness
  now uses 22-byte tokens.
- `raw/20261027T011539Z/` — the intermediate after the token fix: 19 PASS and
  one wrong needle (the login page says `Log in`, not `Sign in`), fixed before
  the cited run.
- `raw/…/container-e2e-linux-arm64.attempt1.txt` — the arm64 attempt could not
  create its docker subnet (`Pool overlaps with other one on this address
  space`); the harness moved to `10.88.0.0/24` / `10.89.0.0/24` and reports a
  network failure explicitly instead of cascading.

## The 0.8.0 binary on the host

- `target/release/eqproxy`, `eqproxy 0.8.0`, sha256
  `d337f474b7942587964d2b29e7048d5030c7f5bb72e1895e4efe2500894465e1`.
- The panel journey of [v08-panel](v08-panel.md) re-run against it:
  **42 PASS, 0 FAIL, `ALL PASS`**
  ([`run-20261027T012157Z`](v08-panel/raw/run-20261027T012157Z/)).
- `cargo test --workspace` on the 0.8.0 tree: on this macOS host **30
  targets, 558 passed, 0 failed, 2 ignored** (the miri-gated cases); the
  release workflow runs the same suite on the Linux tier-1 runner and counts
  **559 passed, 0 failed** (one test is Linux-only).

## Not executed in this run

- **Pushing the `0.8.0-candidate` manifest and scanning the published index
  digest**: **NOT EXECUTED** — it needs the tag and the registry credentials,
  and it is the CI gate that actually binds the release
  ([release.yml:533](../../.github/workflows/release.yml#L533)). The scans here
  cover the same Dockerfile, base pin and `0.8.0` binaries, built locally.
- **Promotion by digest, `:0.8.0` and `:latest` tags, Docker Hub mirror,
  Docker Hub page, GitHub release, `SHA256SUMS.txt`**: **NOT EXECUTED** —
  nothing was published.
- **The darwin/linux prebuilt binaries** (`release.yml` jobs `darwin` and
  `linux`): **NOT EXECUTED** locally; the container E2E covers the Linux
  artifact on both architectures, and the darwin artifacts are built and
  exercised by CI on its runners.
- **Docker Scout on a multi-arch index** (one scan per platform against the
  same manifest list): **NOT EXECUTED**; each image was scanned as a
  single-arch local image.

## Limitations

- The local images are **not byte-identical** to the ones CI will push (build
  metadata, provenance attestations and layer ordering differ); the dependency
  graph, base pin and binary are the same, and CI repeats the gate on the
  exact candidate digests.
- The amd64 run executes under the host's x86-64 emulation; timings from it
  mean nothing, only behaviour does.
- One backend type (`nginx:alpine`) and HTTP/1.1 live traffic: the protocol
  matrix (h2/h3/gRPC/WS) has its own pages; the image does not change it.
- No container was run as a non-root user test beyond the image's own
  `USER 65532`; the panel's TLS story on the admin plane is out of scope
  (ADR-0017).

## Publication run — 2026-10-27

The tree was committed as `b550e33`, tagged `v0.8.0` (annotated, Doken) and
pushed at 13:33Z. [`release.yml`](../../.github/workflows/release.yml) run
[40513029637](https://github.com/ExyonQ/EQProxy/actions/runs/40513029637)
finished **success** in 2 h 03 m (13:33:18Z → 15:36:23Z) with all six jobs
green: `guard`, `darwin`, `linux`, `image`, `release`, `Docker Hub page`.

### Gate on the pushed artifact (not a local image)

| What | Result |
|---|---|
| Candidate index | `ghcr.io/exyonq/eqproxy:0.8.0-candidate@sha256:f3bf57b3…48a0` |
| Scout `linux/amd64` | **0C 0H 0M 0L**, 69 packages, "no vulnerable packages detected", exit 0 |
| Scout `linux/arm64` | same result, from the same attestation SBOM |
| Scout CLI / base | 1.25.0 (the workflow pin) / `wolfi-base` `360896efb075` |
| Image E2E on the candidate | `--version`, `validate` (h2 ALPN accepted, h3-on-TCP rejected), `config apply`, live traffic — both architectures |
| Promotion | tags `0.8.0` **and** `latest` → the scanned index, GHCR and Docker Hub |

Read back after the promotion with `imagetools inspect`: the index
`sha256:f3bf57b3…48a0` is what both registries serve for `0.8.0` and `latest`,
with per-architecture manifests amd64 `sha256:8e977cbc…32d2` and arm64
`sha256:c7b59632…56d7` — the same two manifests CI had re-pulled and
exercised from both registries.

### Release assets

`eqproxy-darwin-amd64|arm64`, `eqproxy-linux-amd64|arm64`, the source
tarball, four CycloneDX SBOMs, the two Scout reports and `SHA256SUMS.txt`,
published (not draft, not prerelease) at 15:35:59Z.

## Post-publication verification (maintainer machine, macOS 26.5.1 arm64)

Independent of CI, against the **published** artifacts:

```console
$ shasum -a 256 eqproxy-darwin-arm64 eqproxy-linux-amd64
77ef032a40e3f9beef6e73d5c5ceb1cc4ae0ed6291506eae795d46f4fd8879f7  eqproxy-darwin-arm64   # == SHA256SUMS.txt
befca49ccf4e8421d063d9393024fc945a397e93c36944cee426aca5c2b12fa1  eqproxy-linux-amd64    # == SHA256SUMS.txt
$ ./eqproxy-darwin-arm64 --version
eqproxy 0.8.0
```

- **Binary journey** against the published darwin binary
  ([transcript](v08-release/raw/binary-published-20261027T164405Z/journey.txt),
  harness in `scripts/evidence/v08-release/journey-published.sh`, local-only):
  `config validate`, live traffic reaching both origins,
  `PUT /api/v1/backends/api/servers/…/state` with `{"state":"drain"}` → 200,
  status reporting `drain`, **10/10** requests to the surviving origin, back to
  `ready` and traffic to both again, plus the `AUDIT` line for the admin write —
  9 `PASS`, `ALL PASS`, exit 0. A first
  attempt reused one secret as `token` and `write_token`; the product refused
  it ("one secret per privilege level") and the harness was fixed — the
  refusal is the documented boundary, not a bug.
- **Container E2E against the published Docker Hub tag**
  ([`container-e2e.sh`](../../scripts/evidence/v08-release/container-e2e.sh)):
  **20 PASS / 0 FAIL** on `linux/arm64` (`push-20261027T154430Z`, transcript in
  [raw/push-20261027T154430Z](v08-release/raw/push-20261027T154430Z/)) and
  **20 PASS / 0 FAIL** on `linux/amd64` (`push-amd-20261027T154441Z`, same
  directory layout). Both runs cover `--version`, `config validate`, live
  traffic through two nginx origins, the admin status, the panel login and
  drain, and the return to `ready`.
- **Scout on the published tag**: `docker scout cves --only-severity
  critical,high --exit-code --platform linux/{amd64,arm64}
  exyonq/eqproxy:0.8.0` → exit 0 on both, "No vulnerable packages detected".
- **Source tarball**: 2242 entries, none under `ROADMAP EQPROXY/`,
  `SERVIDORES.md`, `.dockerignore` or `scripts/`.

### What remains unverified after publication

- The **differential corpus** against HAProxy/nginx and the benchmark pages
  are separate campaigns; publishing the image does not re-run them.
- Protocol matrix beyond HTTP/1.1 live traffic (h2/h3/gRPC/WS) has its own
  pages and its own evidence; the container runs here prove the image, not the
  protocol matrix.
- CodeGraph was **not re-indexed** after the docs-only commits that closed the
  increment: the Rust structure is unchanged, and an index is not a test run.
