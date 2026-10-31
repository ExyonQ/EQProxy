# v0.8.5 — image gate before publication (Docker Scout + container E2E, both architectures)

Language: **English**.

**What this page answers:** whether the `0.8.5` image is fit to be published —
the same Dockerfile, pinned base and toolchain the release workflow builds,
scanned by Docker Scout on **both** architectures and exercised end to end
inside the image. It is the local counterpart of the workflow's `image` job,
**not** a publication: nothing was tagged, pushed or released.

| Piece | Where |
|---|---|
| Image definition (builder `rust:1.99.1-alpine`, Wolfi runtime) | [docker/Dockerfile](../../docker/Dockerfile) |
| Pinned base (index digest, ADR-0016) | [docker/Dockerfile:74](../../docker/Dockerfile#L74) |
| Container E2E harness (maintainer-local) | `scripts/evidence/v08-release/container-e2e.sh` |
| Scout reports and transcripts | [`raw/20261031T000218Z/`](v085-release-gate/raw/20261031T000218Z/) |
| Pipeline that repeats this on the pushed candidate | [.github/workflows/release.yml:611](../../.github/workflows/release.yml#L611) |

## Images under test

Both were built from the **0.8.5 tree** (workspace version bumped, crate pins
and `Cargo.lock` agreeing) with:

```console
$ docker buildx build --pull --file docker/Dockerfile --platform linux/amd64 \
    --provenance=mode=max --sbom=true --tag eqproxy-release:0.8.5-amd64 --load .
$ docker buildx build --pull --file docker/Dockerfile --platform linux/arm64 \
    --provenance=mode=max --sbom=true --tag eqproxy-release:0.8.5-arm64 --load .
```

| Platform | Image ID | Digest (Scout) | Size | Build |
|---|---|---|---|---|
| linux/amd64 | `4d0d9f07368f` | `sha256:af5431d4541816ecfb7923a83e76079cd25e7d79c76e26a84b10d4d7ecabbb8a` | 76.8 MB | emulated x86-64, ~31 min |
| linux/arm64 | `b167f66d87dd` | `sha256:f783747c199763eae402a46e9e5c898250f2ef6927e01c8915432fda31c4c98c` | 67.6 MB | native, ~27 min |

- Builder: `docker.io/library/rust:1.99.1-alpine`, resolved from
  `ARG RUST_VERSION=1.99.1`. The compile line inside the build is
  `cargo build --release --locked -p eqproxy-cli` followed by the `file` gate
  that refuses anything not `statically linked|static-pie linked`
  ([docker/Dockerfile:25](../../docker/Dockerfile#L25),
  [docker/Dockerfile](../../docker/Dockerfile) builder step 15/15).
- Runtime base: `cgr.dev/chainguard/wolfi-base:latest@sha256:360896efb0753a5701c48f860e17130c205eae5a264797aa3e7ea126ee2923a7`,
  the pin in the Dockerfile; the build log shows that exact digest being
  resolved, so `--pull` did not drift the base.
- Host: macOS 26.5.1 arm64, Docker 29.8.2, buildx 0.37.2, Scout CLI
  **v1.25.0** (the version the workflow pins).
- The binary inside both images reports `eqproxy 0.8.5`
  ([`raw/…/container-e2e-linux-amd64.txt`](v085-release-gate/raw/20261031T000218Z/container-e2e-linux-amd64.txt)
  line 8 and the arm64 twin).

The local release binaries were built by the pinned compiler as well:
`rustc 1.99.1 (58cf8f9c3 2026-10-13)`, `cargo build --workspace --release`
exit 0, `target/release/eqproxy --version` → `eqproxy 0.8.5`
(sha256 `78e68ea91c8c82f0a81b58e1d77f91161a7e7389854a3707d9e123b452c8a574`,
macOS arm64 Mach-O — a host artifact, not a release one).

## Docker Scout gate: 0 critical, 0 high on both architectures

```console
$ docker scout cves --only-severity critical,high --exit-code eqproxy-release:0.8.5-amd64
   vulnerabilities │    0C     0H     0M     0L
   packages        │ 69
 Base image        │  cgr.dev/chainguard/wolfi-base:latest
## Packages and Vulnerabilities
  No vulnerable packages detected
# exit 0
$ docker scout cves --only-severity critical,high --exit-code eqproxy-release:0.8.5-arm64
   vulnerabilities │    0C     0H     0M     0L
   packages        │ 69
 Base image        │  cgr.dev/chainguard/wolfi-base:latest
## Packages and Vulnerabilities
  No vulnerable packages detected
# exit 0
```

Both runs also wrote the markdown report the release job ships next to the
release: [`raw/…/scout-amd64.md`](v085-release-gate/raw/20261031T000218Z/scout-amd64.md)
and [`raw/…/scout-arm64.md`](v085-release-gate/raw/20261031T000218Z/scout-arm64.md).

**The gate is met** on the images built here. The scan that will bind the
release is the one over the **pushed `0.8.5-candidate` index digest**, which
only exists on a tag run — see "Not executed".

## Container E2E: 20 checks per architecture, all passing

```console
$ scripts/evidence/v08-release/container-e2e.sh eqproxy-release:0.8.5-amd64 linux/amd64 20261031T000218Z
container E2E linux/amd64: 20 PASS, 0 FAIL
ALL PASS
$ scripts/evidence/v08-release/container-e2e.sh eqproxy-release:0.8.5-arm64 linux/arm64 20261031T000218Z
container E2E linux/arm64: 20 PASS, 0 FAIL
ALL PASS
```

Against real containers and real sockets, on each architecture: `--version`
reports the release version; `config validate` accepts a minimal document and
rejects an invalid one; the proxy serves live HTTP traffic whose body comes
from a real nginx origin behind it; `/api/v1/status` answers with the read
token and lists both backend servers as `ready`; the panel answers an
anonymous login page, exchanges the token for a `HttpOnly`, `SameSite=Strict`,
`/panel`-scoped session cookie, renders the dashboard with the container
servers, drains a backend through `PUT …/state`, serves from the remaining one
and returns it to `ready` — with the admin audit log written for each write.

## Not executed

- **Tag `v0.8.5`, push, and the scan of the pushed index digest**: the
  publication steps need the owner's authorization. What is verified here is
  the same Dockerfile and pin, built locally.
- **Digest promotion, the Docker Hub mirror and the re-pull of the published
  tags**: they do not exist until the `image` job has pushed the candidate.
- **Checksums and the source tarball of the release**: produced by the
  `release` job on the tag commit, not by this run.

The procedure that closes those is [docs/release-0.8.5.md](../release-0.8.5.md)
§4–§5.

## Reproduce

```console
$ cargo build --workspace --release && ./target/release/eqproxy --version   # eqproxy 0.8.5
$ docker buildx build --pull --file docker/Dockerfile --platform linux/arm64 \
    --provenance=mode=max --sbom=true --tag eqproxy-release:0.8.5-arm64 --load .
$ docker buildx build --pull --file docker/Dockerfile --platform linux/amd64 \
    --provenance=mode=max --sbom=true --tag eqproxy-release:0.8.5-amd64 --load .
$ docker scout cves --only-severity critical,high --exit-code eqproxy-release:0.8.5-arm64
$ docker scout cves --only-severity critical,high --exit-code eqproxy-release:0.8.5-amd64
$ scripts/evidence/v08-release/container-e2e.sh eqproxy-release:0.8.5-arm64 linux/arm64
$ scripts/evidence/v08-release/container-e2e.sh eqproxy-release:0.8.5-amd64 linux/amd64
```
