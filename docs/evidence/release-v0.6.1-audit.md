# Evidence — release v0.6.1 (and the container security fix)

Date: 2026-10-20. Host: macOS aarch64 (darwin 25.x), Rust
`1.97.1-aarch64-apple-darwin`, Docker 29.8.2 / buildx 0.37.2, Docker Scout
CLI 1.25.0. Workspace: `/Volumes/Lexar/Cursor/EQProxy`.

This release closes the four items v0.6.0 had postponed (multi-certificate
SNI, `hash_policy` + `request_mirror`, the B-E4 equivalence table, the public
JSON Schema) **and** fixes the published container image, whose Docker Hub
scan showed vulnerabilities inherited from the Debian base.

## 1. What the release contains

| Item | Where |
|---|---|
| `[[listener.*.tls.certs]]` (SNI multi-certificate) | `eqproxy-net/src/tls.rs`, `eqproxy-config/src/schema.rs` |
| `hash_policy` / `request_mirror` | `eqproxy-net/src/proxy.rs`, `eqproxy-net/src/mirror.rs`, `eqproxy-net/src/http1.rs` |
| Public JSON Schema (`eqproxy config schema`) | `eqproxy-config/src/schema.rs`, `eqproxy.schema.json` |
| B-E4 filter equivalence table | `docs/equivalences.md` |
| Image runtime: static musl on `scratch` | `docker/Dockerfile`, `docs/adr/0005-container-image-runtime.md` |
| Publish gate: Docker Scout + `--pull` + provenance/SBOM | `.github/workflows/release.yml` |

Two defects found while verifying (both fixed, neither hidden):

1. **Image build was broken by the schema increment.** `eqproxy-config`
   embeds `eqproxy.schema.json` with `include_str!`, but the Dockerfile never
   copied it: `cargo build` inside the image failed with
   `couldn't read eqproxy-config/src/../../eqproxy.schema.json`. The v0.6.1
   image could not have been built at all.
2. **A coverage-only test failure was a harness timeout, not a product bug.**
   `cargo llvm-cov` (through veyra) failed
   `run_slow_start_ramps_the_recovered_server_up` with
   `unexpected origin body ""`. The helper read the response with a 5 s
   timeout and swallowed the error (`let _ = read_to_end`), so an instrumented
   binary under a fully parallel suite surfaced as a routing mismatch. The
   timeout is now 30 s and a response without a complete head fails with the
   bytes read, instead of being counted as an origin body. The assertions of
   the test are unchanged.

## 2. Rust checks (final tree)

Commands and results, all run in `/Volumes/Lexar/Cursor/EQProxy`:

| Command | Result |
|---|---|
| `cargo fmt --check` | exit 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | exit 0, 0 warnings |
| `cargo test --workspace` | exit 0 — **23 suites, 327 passed, 0 failed, 2 ignored** (the two Docker-gated harnesses) |
| `veyra audit . --profile standard` | **ACCEPTED**, exit 0 — `.veyra/evidence/20261020T164627Z` (llvm-cov OK, geiger INCONCLUSIVE; dylint and semver-checks skipped: no config / no baseline) |
| Rust Audit `scan . --format terminal,md,json,sarif --fail-on high` | exit **1** — 190 findings: 2 critical, 16 high, 142 medium, 30 low. Unchanged by this increment; the R03/R14 hits in `eqproxy-config/src/schema.rs` are serde `#[serde(default = "…")]` constant helpers and one `to_spec` clone set, and R08 hits are wall-clock waits in tests. Report: `report/rust-audit-20261020-185731.json` |
| EvoForge `mcp_submit_eval` (SNI name grammar + resolver preference slice) | **F=1.0**, exit 0, 3 tests passed, clippy pass, trace `2d08e32f-21c7-469c-ace7-361f77bb2ad8`; host proof first: `cargo test -p eqproxy-net --lib tls` → 8 passed |

Coverage-only rerun of the flaky test after the fix (instrumented build):
`cargo nextest run -p eqproxy-cli --test cli_e2e --target-dir target/llvm-cov-target`
→ **51/51 passed**.

## 3. Container image: before and after

Built locally with
`docker buildx build --pull -f docker/Dockerfile --platform linux/arm64 …`.

| | v0.6.0 runtime (`debian:bookworm-slim`) | v0.6.1 runtime (`scratch` + static musl) |
|---|---|---|
| `docker scout cves --only-severity critical,high` | **4 critical + 13 high** in perl, util-linux, openssl, zlib | **0 / 0** — "No vulnerable packages detected" |
| Packages visible to the scanner | 129 | **0** |
| Local image size | 164 MB | **15.8 MB** |
| `docker scout quickview` health | C (56 %), 4/7 policies | **A (100 %), 7/7 policies** |
| Copyleft policy | 367 packages flagged | 0 |
| Attestations | missing | provenance `mode=max` + SPDX SBOM (verified in the manifest) |

The 13 high/critical findings of the old image were **all** Debian packages
(`Fixed version: not fixed` for most of them), so patching them was not in our
hands; the change removes the surface instead.

Verified on the exact artifact pushed to a local registry
(`localhost:5050/eqproxy:0.6.1-attest`, index digest
`sha256:187c65dedb4c50f61e303d595ef6c5f9b661fda914aa3975595bce87ec79cfd8`,
arm64 manifest `sha256:3308db56…`, attestation manifest `sha256:6c3fa1ed…`):

- `docker scout cves --only-severity critical,high --exit-code local://…` →
  **exit 0**, the exact command the release workflow now runs before pushing.
- `docker run --rm … --version` → `eqproxy 0.6.1`.
- `config validate --config /dev/stdin` → `config OK: 1 listener(s), 1 backend(s)`.
- Live traffic: nginx:alpine backend on a private docker network, EQProxy in
  the scratch image in front of it → `HTTP 200` on `/`, with
  `INFO listener web listening on 0.0.0.0:18082` in its log.
- `docker inspect` → `user=65532:65532`, entrypoint `/opt/eqproxy`.

## 4. Commands not executed (declared)

- **`linux/amd64` image build locally**: not emulated on this host; CI builds
  and E2E-verifies `linux/amd64` for every release (it always did). The
  arm64 build was verified here.
- **The two Docker-gated harnesses** (`differential`, `migration`): not
  re-run; this increment does not touch routing/TLS. Their last real runs are
  in the v0.6.0 evidence (23/23 and 65/65).
- **dylint / cargo-semver-checks**: no configuration / no registry baseline
  (veyra reports them as skipped, not as passing).
- **`cargo-geiger`**: INCONCLUSIVE (coverage warnings in 4 runs), reported as
  such, not as a pass.

## 5. Publication (verified against the published artifacts)

Workflow run **39469628305** (tag `v0.6.1`): every job green — guard, darwin
binaries, linux binaries + SBOM, multi-arch image (build, Scout gate, E2E,
push, Docker Hub mirror), GitHub release.

An earlier run of the same tag (**39465112082**) failed in the image job:
`ERROR: failed to build: docker exporter does not currently support exporting
manifest lists` — `--provenance/--sbom` together with `--load`. It had already
published the GitHub release (9 assets) but no image. The workflow was fixed
(attestations only on the pushed manifest; Scout gate runs on the publishing
path with the Docker Hub login it needs; the release step refreshes an existing
release), the tag was re-pointed to that commit and the run above is the one
that published.

Artifacts checked after publication, not during:

| Check | Result |
|---|---|
| `docker buildx imagetools inspect ghcr.io/exyonq/eqproxy:0.6.1` | index `sha256:ae15bb0f3651c9a76dd5be7b592ae007839ad46883a7c57756c52c2dcd4c4418`, platforms `linux/amd64` + `linux/arm64` + **2 attestation manifests** |
| `docker buildx imagetools inspect exyonq/eqproxy:0.6.1` | **same index digest** (Docker Hub mirrors the verified manifest) |
| `ghcr.io/exyonq/eqproxy:latest` | same digest (no prerelease re-pointing) |
| `docker pull` + `docker run … --version` | `eqproxy 0.6.1`, `user=65532:65532`, 15.8 MB |
| `docker scout cves --only-severity critical,high --exit-code local://ghcr.io/exyonq/eqproxy:0.6.1` | **exit 0**, 0 packages, no vulnerable packages |
| `docker scout quickview` on the published image | **7/7 policies met** (non-root, copyleft, fixable critical/high, high-profile, outdated base, unapproved base, **attestations**) |
| `gh release download v0.6.1` + `shasum -a 256 -c SHA256SUMS.txt` | `eqproxy-linux-arm64: OK` |
| released binary run in `debian:bookworm-slim` (linux/arm64) | `eqproxy 0.6.1`, `config validate` → `config OK`, `config schema --output` reproduces the repository schema byte for byte |

The CI image job also ran the Scout gate itself (`Docker Scout gate
(critical/high must be zero): success`) and the live-traffic E2E on the
exact image it pushed.

## 6. Known limitations of the new runtime

- The published **container** is a musl build (ADR-0001 tier 2): functionally
  verified, **not** covered by the benchmark claims, which stay on glibc
  x86_64 (ADR-0005).
- No shell in the image: `docker exec … sh` is not available by design;
  diagnostics go through `docker logs`, METRICS and the CLI.
- The Scout "no outdated base images" policy is time-sensitive: it passes
  because the build runs with `--pull`; a cached build would flag the recorded
  digest later. That is why `--pull` is part of every build in the workflow.
