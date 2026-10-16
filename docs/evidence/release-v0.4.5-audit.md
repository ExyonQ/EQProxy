# Release audit — GitHub release v0.4.5

Audit date: 2026-10-16. Auditor: maintainer tooling (read-only; nothing was
re-uploaded or modified). Scope: published assets, `SHA256SUMS.txt`, release
notes vs `CHANGELOG.md`, and execution of each binary on its target platform.

**Post-audit note (2026-10-16):** the repository history was later rewritten
to purge `ROADMAP.md` (owner decision), so commit SHAs changed and the tag
`v0.4.5` now points at a rewritten commit. The release assets, `SHA256SUMS.txt`
and all digests verified below are unaffected (the audit proves the published
bytes; only the git SHAs moved).

## 1. Release facts

- Tag `v0.4.5` -> commit `b376d8b` ("SBOM 0.4.5 matching the v0.4.5 release
  artifacts"); tag present on `origin`.
- Published 2026-10-15T19:49:14Z; not a draft, not a prerelease; name `v0.4.5`.
- 9 assets, all state `uploaded`:
  `eqproxy-darwin-amd64`, `eqproxy-darwin-arm64`, `eqproxy-linux-amd64`,
  `eqproxy-linux-arm64`, `SHA256SUMS.txt`, and 4 CycloneDX SBOMs
  (`eqproxy-{cli,config,core,net}.cdx.json`).

## 2. Checksums

Commands (run from a clean download of every asset):

```sh
gh release download v0.4.5 --repo ExyonQ/EQProxy --dir /tmp/eqp045-audit
cd /tmp/eqp045-audit && shasum -a 256 -c SHA256SUMS.txt   # macOS
```

Results:

- `shasum -c SHA256SUMS.txt` -> 4/4 **OK**, exit 0.
- Published `SHA256SUMS.txt` is byte-identical to `dist/SHA256SUMS.txt` from
  the release pipeline run (`diff` empty).
- All 4 downloaded binaries are **byte-identical** to the `dist/` artifacts
  (`cmp` identical each), so the release.sh E2E gate (version, validate
  ok/invalid, explain, diff, live proxied traffic per artifact, executed
  before checksums are written) covers the published bytes exactly.
- All **9** assets match the `digest` (SHA-256) field of the GitHub release
  API — computed hash == API digest for every asset, including `SHA256SUMS.txt`
  itself.

## 3. Release notes vs CHANGELOG

- The notes are the full `CHANGELOG.md` as of the release. The `[v0.4.5]`
  section is **identical** to the one in `CHANGELOG.md` (36 lines each,
  empty `diff`).
- The `[Unreleased]` heading in the notes is empty (2 lines) — correct at
  release time. The current working-tree `CHANGELOG.md` `[Unreleased]`
  (27 lines, hot reload work) is correctly not part of the published notes.
- Cosmetic observation: the notes include the entire version history and an
  empty `[Unreleased]` heading; trimming to the released section would read
  better. Not a defect.

## 4. Execution per target platform

| Artifact | Platform | Checksum | `--version` | Exit |
|---|---|---|---|---|
| `eqproxy-darwin-arm64` | macOS arm64 (native) | OK | `eqproxy 0.4.5` | 0 |
| `eqproxy-darwin-amd64` | macOS arm64 via Rosetta 2 (not native Intel) | OK | `eqproxy 0.4.5` | 0 |
| `eqproxy-linux-amd64` | netcup-bench, x86_64 Ubuntu 24.04.4 | OK | `eqproxy 0.4.5` | 0 |
| `eqproxy-linux-arm64` | oracle-quasar, aarch64 Ubuntu 24.04.4 | OK | `eqproxy 0.4.5` | 0 |

Linux artifacts were fetched on the servers with the README install URLs
(`https://github.com/ExyonQ/EQProxy/releases/download/v0.4.5/...`) and
verified against the downloaded `SHA256SUMS.txt` with `sha256sum -c`
before execution — the documented operator install path works as written.

## 5. SBOM drift (informational)

Local `sbom/*.cdx.json` differ from the published ones **only in metadata**
(`timestamp`, `serialNumber`): the full `components` arrays (including
hashes and purls) and every other field are byte-equal per file (cli 70,
config 19, core 13, net 39 entries) and the bom version field is `0.4.5` in
both (deep JSON comparison, 2026-10-16). Cause: the local SBOMs were regenerated
after the release (0.4.6 preparation). The published SBOMs are the
authoritative ones for v0.4.5 and their integrity is anchored by the GitHub
API digests (section 2).

## 6. Findings

1. **PASS** — artifacts, checksums and notes are internally consistent and
   match the locally verified pipeline output byte for byte.
2. Minor: `SHA256SUMS.txt` covers only the 4 binaries; the 4 SBOM assets are
   not listed there (they are covered by GitHub API digests). Suggestion:
   include the SBOMs in `SHA256SUMS.txt` from v0.4.6 onward.
3. Minor: release notes carry the whole changelog (cosmetic; see section 3).

## 7. Limitations

- `eqproxy-darwin-amd64` ran under Rosetta 2, not on native Intel hardware.
- Execution checks are `--version` level; deeper behavior of the published
  bytes is covered indirectly by the release.sh E2E gate (version, validate
  ok/invalid, explain, diff and live proxied traffic per artifact) plus the
  byte-identity proof in section 2. The workspace suite of the released
  commit was 144 tests green (ninth-slice delivery record); the later 151
  count belongs to the unreleased hot-reload work.

## 8. Reproducibility

```sh
gh release view v0.4.5 --repo ExyonQ/EQProxy --json tagName,name,publishedAt,isDraft,isPrerelease,assets
gh release download v0.4.5 --repo ExyonQ/EQProxy --dir /tmp/eqp045-audit
shasum -a 256 -c SHA256SUMS.txt                    # in the download dir
cmp <bin> dist/<bin>                                # per binary
gh release view v0.4.5 --repo ExyonQ/EQProxy --json body -q .body
diff <(awk '/^## \[v0\.4\.5\]/{f=1} /^## \[v0\.4\.4\]/{f=0} f' notes.md) \
     <(awk '/^## \[v0\.4\.5\]/{f=1} /^## \[v0\.4\.4\]/{f=0} f' CHANGELOG.md)
ssh netcup-bench   'curl -sSLO .../v0.4.5/eqproxy-linux-amd64; ...; ./eqproxy-linux-amd64 --version'
ssh oracle-quasar  'curl -sSLO .../v0.4.5/eqproxy-linux-arm64; ...; ./eqproxy-linux-arm64 --version'
```
