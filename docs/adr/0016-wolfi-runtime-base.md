# ADR-0016: Wolfi as the image runtime base

Language: **English**.

- State: **Accepted** (2026-10-24, owner request: ship the v0.7.0 image on
  Wolfi, with Docker Scout at 0 critical/0 high before publishing)
- Date: 2026-10-24
- Supersedes in part: [ADR-0005](0005-container-image-runtime.md) (the
  `scratch` runtime base; the static-musl binary, the unprivileged user, the
  writable state directory and the Scout gate stand unchanged)
- Related: [ADR-0001](0001-production-platform.md) (support tiers),
  [ADR-0004](0004-network-stack-and-crate-layout.md) (rustls/aws-lc-rs)

## Context

[ADR-0005](0005-container-image-runtime.md) replaced the
`debian:bookworm-slim` runtime (Scout: 4 critical + 13 high, all inherited
from the base) with a statically linked musl binary on `scratch`: 0 packages,
0C / 0H / 0M / 0L, no shell and nothing to patch. That image shipped through
v0.6.3.

The owner asked for v0.7.0 to run on **Wolfi**
(`cgr.dev/chainguard/wolfi-base`), the minimal glibc distro built for
containers. The trade-off is explicit: Wolfi adds packages (and therefore
Scout findings to keep at zero) in exchange for a real distro underneath —
a shell for `docker exec`, `apk` for operators who extend the image, a CA
bundle maintained by the distro, and a base that is rebuilt upstream instead
of pinned to a hand-assembled file list.

## Decision

The **published image** uses `cgr.dev/chainguard/wolfi-base` as its runtime
stage, pinned by **index digest**
`sha256:360896efb0753a5701c48f860e17130c205eae5a264797aa3e7ea126ee2923a7`
(the `:latest` tag is resolved to that digest at build time; bumping it is a
deliberate commit).

Unchanged from ADR-0005:

- the release binary stays a **statically linked musl** executable — the
  `file` gate in the Dockerfile fails the build if that stops being true, and
  the `export` stage still feeds the published `eqproxy-linux-<arch>`
  artifacts;
- it runs as uid/gid **65532** (Wolfi's `nonroot`), with
  `/var/lib/eqproxy` writable for `config apply`/`rollback`;
- the default verification roots are the compiled-in Mozilla roots; the
  distro CA bundle only matters when an operator points `ca_file` at it;
- the release gate is **0 critical / 0 high** from Docker Scout on both
  architectures before the candidate digest is promoted.

The base digest is the only new thing to keep current: a CVE fix in Wolfi
means bumping that digest and re-running the gate.

## Evidence (measured locally, 2026-10-24)

Host: macOS aarch64, Docker 29.8.2, buildx 0.37.2, Docker Scout CLI.
Built with `docker buildx build --platform linux/<arch> --load`.

| | linux/arm64 | linux/amd64 |
|---|---|---|
| Image size (Scout) | 13 MB | 15 MB |
| Packages (Scout) | 36 | 36 |
| Scout critical / high / medium / low | **0 / 0 / 0 / 0** | **0 / 0 / 0 / 0** |
| `eqproxy --version` | `eqproxy 0.7.0` | `eqproxy 0.7.0` |
| `config validate` (happy path) | OK | OK |
| Gate accepts `alpn = ["h2"]` on an http listener | yes | yes |
| Gate rejects `alpn = ["h3"]` on the TCP table | yes (exit 1) | yes (exit 1) |
| `config apply` writes state | yes | yes |
| Live proxied traffic (nginx origin) | HTTP 200 | HTTP 200 |
| h2c (`curl --http2-prior-knowledge`) | HTTP/2 | HTTP/2 |

The arm64 image unpacks to 47.96 MB (`docker image inspect`); the local
containerd store reports a different figure for the emulated amd64 build, so
the table quotes the size Docker Scout reports for each architecture.

The real gate is the release workflow, which repeats these journeys on the
pushed candidate manifest, scans each architecture and only then promotes the
scanned digest.

## Consequences

- The Docker Hub page and README no longer claim “0 packages / no OS”; they
  state the Wolfi base, its package count and the Scout result that the
  release gate enforces.
- Image size grows from the `scratch` image's ~13 MB to ~48 MB unpacked.
- Base updates are a digest bump plus a re-scan, not a `FROM` tag drift.
- `docker exec … sh` now works, which is the operational reason for the
  change; it also means the image has a shell attack surface it did not have
  before, mitigated by running as 65532 and by the Scout gate.

## Alternatives considered

1. **Keep `scratch`** (ADR-0005). Strictly smaller surface and 0 packages;
   rejected by the owner for this release.
2. **`cgr.dev/chainguard/static`.** Distroless static base: closer to
   `scratch` (no shell), so it does not deliver the debuggability the change
   is for.
3. **A general-purpose distro (Debian slim).** Measured in ADR-0005: 4C/13H
   inherited from the base; rejected there and still rejected.
