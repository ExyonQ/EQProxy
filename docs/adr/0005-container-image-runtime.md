# ADR-0005: Container image runtime

Language: **English**.

- State: **Accepted** (2026-10-20, owner request: scan the image with Docker
  Scout before publishing, after the v0.6.0 images showed findings on Docker
  Hub) · **Superseded in part** by
  [ADR-0016](0016-wolfi-runtime-base.md) (2026-10-24): the runtime base is
  Wolfi; the static-musl binary, the unprivileged `65532` user, the writable
  state directory and the 0-critical/high Scout gate stand unchanged
- Date: 2026-10-20
- Related: [ADR-0001](0001-production-platform.md) (support tiers),
  [ADR-0004](0004-network-stack-and-crate-layout.md) (rustls/aws-lc-rs)

## Context

The published image used `debian:bookworm-slim` as its runtime: the release
binary (glibc), the CA bundle copied from the system store, and one
`apt-get install ca-certificates`. Docker Scout on the v0.6.1 candidate
reported **4 critical + 13 high** vulnerabilities and flagged 367 packages
as copyleft. Every finding came from the base distribution, not from
EQProxy: `perl` (4 critical, fixable in a newer `deb12u4`), `util-linux`
(8 high, no fix), `openssl` (1 high, no fix) and `zlib` (1 high, no fix).
An operator reading that report cannot tell our bugs from Debian's, and
patching waits on Debian rebuilds we do not control.

The alternatives were measured against the same scanner, on the same host
(macOS aarch64, Docker 29.8.2, buildx 0.37.2, Docker Scout CLI 1.25.0):

| Option | Packages | Scout (critical/high) | Size (local) |
|---|---|---|---|
| `debian:bookworm-slim` + CA bundle (current) | 129 | 4C / 13H | 164 MB |
| `debian:trixie-slim` (recommended tag) | 15 fewer | 0C / 1H (unfixed) | ~150 MB |
| **static musl binary on `scratch`** | **0** | **0C / 0H / 0M / 0L** | **15.8 MB** |

## Decision

The **published image** runs a **statically linked musl** binary on
`scratch`. The image contains exactly two files: `/opt/eqproxy` and
`/etc/ssl/certs/ca-certificates.crt` (used only when an operator points
`ca_file` at the system store; the default verification uses the
compiled-in Mozilla roots). It runs as `65532:65532`, with no shell, no
package manager and no distribution packages.

The builder stage is `rust:1.97-alpine` (musl target by default) and fails
the build if `file` no longer reports the binary as statically linked — a
dynamic binary would not run on `scratch`, so the guarantee is enforced,
not documented.

Released **binaries** (GitHub Releases) stay glibc-built, exactly as
ADR-0001 declares, so the tier-1 platform and its performance claims are
unchanged.

## Evidence

- Docker Scout on the previous runtime: `4C 13H` in 4 packages, all Debian
  (`docker scout cves --only-severity critical,high local://eqproxy:0.6.1-local`).
- Docker Scout on the new image: `0C 0H 0M 0L`, 0 packages, policies
  "Default non-root user", "No copyleft licenses", "No fixable critical or
  high vulnerabilities" and "No high-profile vulnerabilities" all met.
- Functional E2E through the container: `--version` (`eqproxy 0.6.1`),
  `config validate` through stdin, and live proxied traffic (`200` from a
  real nginx backend behind the container).
- **Both architectures, not only amd64** (2026-10-20): a retro-check of the
  published v0.6.1 image gave `0C 0H 0M 0L` on `linux/amd64`
  (`sha256:f1b1ff07…`, 4.6 MB) and on `linux/arm64` (`sha256:517945df…`,
  4.3 MB), 0 packages each. The pipeline now enforces what was checked by
  hand: it builds the multi-arch index once under a `-candidate` tag, scans
  both platforms, runs E2E on both, and promotes that digest to
  `<version>`/`:latest`; the release job depends on it and receives the two
  Scout reports as assets. Evidence:
  `docs/evidence/release-v0.6.1-scout-both-arch.md`.

## Consequences

- **Security surface**: no OS package in the published artifact, so the
  scanner has nothing to inherit; future findings would point at what we
  actually ship.
- **Operational cost**: no shell and no `docker exec … sh` for debugging.
  Operators debug with `docker logs`, the metrics endpoint and the CLI
  subcommands, which is what the container contract already promised;
  anyone needing a shell should use the release binaries or their own
  base image.
- **Support tier**: the container is a musl build, i.e. ADR-0001 tier 2.
  It is functionally verified (unit, E2E through the image, live traffic)
  but **not** covered by the benchmark claims — those were measured on
  glibc x86_64 and remain tier 1. This is stated in the release evidence
  rather than presented as equivalent.
- **Supply chain**: builds push provenance (`mode=max`) and an SPDX SBOM;
  the workflow fails if Scout finds any critical/high vulnerability.
- **Not verified here**: arm64 containers run under QEMU emulation on the
  amd64 runner; the E2E journeys and Scout scan prove the artifact, not
  native arm64 speed (the benchmark evidence covers arm64 separately).
  Registry-side policy evaluation (`docker scout policy`, the Docker Hub
  health score) is not part of the gate; only `cves --only-severity
  critical,high --exit-code` is.
