# Release audit — GitHub release v0.5.0

Audit date: 2026-10-18. Auditor: maintainer tooling (read-only against the
published release; the only post-publication change is the notes sync recorded
in section 3). Scope: published assets, `SHA256SUMS.txt`, release notes vs
`CHANGELOG.md`, full E2E execution of each binary on its target platform, the
container image (E2E + filesystem leak scan), documentation/asset hygiene
(no tooling or local-path leakage), and the toolchain audits (Veyra Proof,
EvoForge slice eval).

## 1. Release facts

- Tag `v0.5.0` -> commit `44a1861` ("docs: record the 24h soak gate PASS");
  tag present on `origin`, lightweight (same style as `v0.4.4`/`v0.4.5`).
- Published 2026-10-18T15:52:30Z; not a draft, not a prerelease; name `v0.5.0`.
- 9 assets, all state `uploaded`:
  `eqproxy-darwin-amd64`, `eqproxy-darwin-arm64`, `eqproxy-linux-amd64`,
  `eqproxy-linux-arm64`, `SHA256SUMS.txt`, and 4 CycloneDX SBOMs
  (`eqproxy-{cli,config,core,net}.cdx.json`).

## 2. Checksums and byte identity

Commands (run from a clean download of every asset):

```sh
gh release download v0.5.0 --repo ExyonQ/EQProxy --dir /tmp/rel-assets
cd /tmp/rel-assets && shasum -a 256 -c SHA256SUMS.txt   # macOS
```

Results:

- `shasum -c SHA256SUMS.txt` -> 4/4 **OK**, exit 0.
- All **8** binary + SBOM assets are **byte-identical** (`cmp`) to the
  artifacts produced by the release workflow run `39142467707`
  (`gh run download` of `dist-darwin/`, `dist-linux/`, `sbom/`), so the
  pre-publish E2E gate of the pipeline (section 4) covers the published
  bytes exactly.
- All **9** assets match the `digest` (SHA-256) field of the GitHub release
  API — computed hash == API digest for every asset, including
  `SHA256SUMS.txt` itself.

## 3. Release notes vs CHANGELOG

- The notes are the full `CHANGELOG.md`, per the project convention.
- **Post-publication sync (2026-10-18, documented here on purpose):** the
  notes were updated once after publication to match the docs-review commit:
  release date corrected to 2026-10-18, the measured 24h soak gate result
  added, and a `Fixed` entry for the release-pipeline E2E backend. The source
  tarball of tag `v0.5.0` carries the pre-sync `CHANGELOG.md`; the notes are
  the authoritative narrative. No asset was touched (section 2 proves the
  digests before and after).
- `SHA256SUMS.txt` covers only the 4 binaries (the 4 SBOMs are covered by
  the API digests) — same minor gap flagged in the v0.4.5 audit.

## 4. Execution per target platform (full E2E, not just `--version`)

Each published binary was executed through the release pipeline's own E2E
contract (`verify_cli` + `verify_live_native` from `scripts/release.sh`):
`--version`, `config validate` happy path, `config validate` missing-file
error (exit 1, actionable message), `config explain` (simulation only),
`config diff` (identical inputs), `config apply`/`rollback` (offline versioned
state, idempotence), `doctor` pre-flight (PASS, bind probe) and **live
proxied traffic** through the running binary against a real backend
(raw-socket backend returning the expected body).

| Artifact | Platform | Checksum | E2E contract | Live traffic | Exit |
|---|---|---|---|---|---|
| `eqproxy-darwin-arm64` | macOS arm64 (native) | OK | 8/8 journeys | OK | 0 |
| `eqproxy-darwin-amd64` | macOS arm64 via Rosetta 2 (not native Intel) | OK | 8/8 journeys | OK | 0 |
| `eqproxy-linux-amd64` | netcup-bench, x86_64 Ubuntu 24.04 | OK | 8/8 journeys | OK | 0 |
| `eqproxy-linux-arm64` | oracle-quasar, aarch64 Ubuntu 24.04 | OK | 8/8 journeys | OK | 0 |

All four report `eqproxy 0.5.0`. Binaries were fetched with the release
download API and verified against `SHA256SUMS.txt` before execution.

## 5. Container image

Built from the tag tree (`docker buildx build --file docker/Dockerfile
--tag eqproxy-audit:0.5.0 --load .`, Docker 29.8.2) and verified with the
pipeline's `scripts/release.sh verify-image eqproxy-audit:0.5.0`:

- `--version` -> `eqproxy 0.5.0` (inside the container).
- `config validate` happy path -> `config OK`, exit 0.
- **Live proxied traffic through the container** -> expected body, exit 0.
  Overall `verify-image` exit code: **0**.Filesystem leak scan (`docker export` of a created container, full stream
grep for the IDE/tooling name and absolute home/workspace paths): **no local
paths and no tooling references**. The 38 case-insensitive matches of the
scanned term are false positives: Rust standard-library type symbols in the
binary (inherent to every Rust build) and terminfo/glibc/database/systemd
strings of the base image userland (terminal capability names, database
iteration APIs). Labels/ENV carry no paths.

**Registry status (resolved 2026-10-18):** `ghcr.io/exyonq/eqproxy:0.5.0`
is published as a multi-arch manifest (`sha256:a7b691ec…`) with
`linux/amd64` and `linux/arm64` (plus the two buildkit attestation
manifests). The first workflow attempt failed at the push step with
`denied: permission_denied: write_package`: the package had been created
by a manual push during v0.4.x and never granted the repository write
access, so the workflow `GITHUB_TOKEN` could not push to it (documented
GitHub behavior for pre-existing, manually created packages). After the
package-level "Actions access" grant, `gh run rerun 39142467707 --failed`
re-ran the image job (the push step succeeded; the dry-run step stayed
skipped) and both published variants were pulled and executed through the
documented install path (`docker run --rm …:0.5.0 --version` per platform)
— `eqproxy 0.5.0` each.

## 6. Documentation and asset hygiene

- Sweep for tooling and local-path leakage (IDE/editor names, absolute
  home-directory and workspace-volume paths) across tracked docs, scripts,
  workflows, release assets, notes and the image filesystem:
  - One leak found and fixed post-tag: `docs/evidence/phase2c/mem-raw.json`
    embedded the absolute build path in a metadata field; now a
    workspace-relative path. (Fix lives on `main`, after the tag; the
    published assets were never affected.)
  - Assets, notes and binaries: clean (the scanned term appears in binaries
    only as Rust standard-library type symbols, see section 5).
  - This document itself quotes none of the scanned literals.
  - Local-only material (`.veyra/`, `.evoforge/`, `.agents/`, IDE dirs) is
    excluded via `.git/info/exclude` and cannot be committed.

## 7. Toolchain audits

- **Veyra Proof** (`veyra audit . --profile standard`, veyra 0.7.0):
  **Decision ACCEPTED**, exit code 0, evidence
  `.veyra/evidence/20261018T171614Z/`. OK: rustfmt, cargo-check, clippy,
  cargo-test (181 passed / 0 failed), cargo-audit (no advisories),
  veyra-anti-theater (1 informational, VT013), nextest, llvm-cov, cargo-deny,
  machete, veyra-e2e (17/17 scenarios). INCONCLUSIVE: cargo-geiger (the
  documented coverage gap with the manual `unsafe` inventory in `repo.md`).
  SKIPPED (with reason): dylint (no lint libraries configured),
  semver-checks (unpublished crates, no registry baseline).
- **EvoForge slice eval** (`mcp_submit_eval`, real slice of
  `eqproxy-core/src/expectation.rs`): **F = 1.0**, `compiles: true`,
  `clippy_pass: true`, sandbox ran **2 real tests** (0 failed),
  `trace_id c21208a8-be20-4b08-8587-5b29313a4d9d`. Host proofs ran first:
  `cargo test --workspace` -> 181 passed, 0 failed.

## 8. Findings

1. **PASS** — published artifacts, checksums, API digests, notes and the
   pipeline output are internally consistent; the 4 binaries pass the full
   E2E contract on their real target platforms and the image passes
   `verify-image` including live traffic.
2. **Resolved (2026-10-18):** the GHCR image push needed a package-level
   "Actions access" grant (no API and no pipeline change can substitute
   it); after the grant, the same workflow job pushed the verified
   multi-arch artifact (section 5).
3. Minor: `SHA256SUMS.txt` covers only the binaries (unchanged from
   v0.4.5; suggestion to include the SBOMs stands).
4. Minor: the release notes were synced once post-publication (section 3);
   the tagged source tree carries the pre-sync changelog text.

## 9. Limitations

- `eqproxy-darwin-amd64` ran under Rosetta 2, not on native Intel hardware.
- The local image audit is single-arch (local build); the multi-arch
  manifest is produced and verified inside the release workflow and both
  published variants were smoke-executed per platform (section 5).
- Miri/cargo-geiger/dylint/semver-checks statuses are as reported by Veyra
  Proof (section 7) — INCONCLUSIVE/SKIPPED where the tool cannot decide.

## 10. Reproducibility

```sh
gh release view v0.5.0 --repo ExyonQ/EQProxy --json tagName,name,publishedAt,isDraft,isPrerelease,assets
gh release download v0.5.0 --repo ExyonQ/EQProxy --dir /tmp/rel-assets
cd /tmp/rel-assets && shasum -a 256 -c SHA256SUMS.txt
gh run download 39142467707 --repo ExyonQ/EQProxy --dir /tmp/run-artifacts   # then cmp per asset
# per platform, from the release pipeline's own contract:
bash -c 'source <(sed -n "1,330p" scripts/release.sh); verify_cli native <bin>; verify_live_native <bin>'
docker buildx build --file docker/Dockerfile --tag eqproxy-audit:0.5.0 --load .
./scripts/release.sh verify-image eqproxy-audit:0.5.0
veyra audit . --profile standard
cargo test --workspace
```
