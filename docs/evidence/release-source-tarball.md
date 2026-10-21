# Source tarball as a released asset, checksummed

Language: **English**. Evidence for the release-pipeline change of 2026-10-21
(macOS 26 arm64 host, Git 2.39.5, Docker 29.8.2 not involved in this change,
Rust 1.97.1). Commit `048b5ca`.

## 1. Objective

The release page shipped four binaries, `SHA256SUMS.txt`, four CycloneDX SBOMs
and the Docker Scout reports of both image architectures, but no sources. The
only source archive a user could get was the GitHub auto-generated one, which
carries no line in `SHA256SUMS.txt`: whoever wanted to build or audit an
artifact had to trust a download the release itself does not vouch for.

The pipeline now exports the tagged commit to
`eqproxy-<version>-src.tar.gz`, verifies the export, and adds its digest to
`SHA256SUMS.txt` **without touching the four existing lines**.

## 2. Changes

| File | Change |
|---|---|
| `.github/workflows/release.yml` | the release job split "assemble" from "checksum"; new step exports and verifies the tarball; `SHA256SUMS.txt` appends the tarball line and is self-checked with `-c` before upload; the Scout requirement is scoped to tag runs (found by the dry run, §3.6) |
| `README.md` | the asset list names the source tarball and how to build it |
| `CHANGELOG.md` | Unreleased entry describing the asset and its guarantees |

Design decisions:

- **`git archive` of the released commit, not a copy of the workspace.** Only
  tracked files travel, so the maintainer-local material (`ROADMAP EQPROXY/`,
  `SERVIDORES.md`, `.dockerignore`, `scripts/`) cannot leak into a published
  asset, and nothing untracked on a runner can either. The commit archived is
  `$GITHUB_SHA`, printed in the log, so the asset is traceable to its tree.
- **Appending, never rewriting.** The four binary lines are produced by the
  same `sha256sum`/`shasum` call as before, byte-identical; the tarball line is
  appended, so every checksum a v0.6.x reader already verifies still holds.
- **Verified before it is an asset.** No local-only path, `Cargo.toml` +
  `Cargo.lock` present, every `[workspace] members` entry present, and the
  exported `Cargo.toml` declares the released version. Then `-c` on the whole
  sums file and an exact line count, so a partially written file cannot ship.

## 3. Verification

### 3.1 The step scripts executed against the real repository

The three `run:` blocks were extracted from the YAML itself and executed
verbatim (`bash -euo pipefail`) in a clean `git worktree` of the released
commit — a checkout with no local-only files, like the CI runner. `collect/`
was populated with four throwaway binaries and two Scout reports so the
assemble step runs its real checks.

```
$ python3 /tmp/relcheck-run.py /tmp/relcheck     # steps 1-3 from the YAML
==> dist/eqproxy-0.6.3-src.tar.gz: 1376 entries, 813224 bytes, version 0.6.3
==> writing SHA256SUMS (only after every artifact passed)
eqproxy-darwin-amd64: OK
eqproxy-darwin-arm64: OK
eqproxy-linux-amd64: OK
eqproxy-linux-arm64: OK
eqproxy-0.6.3-src.tar.gz: OK
e4fd20bae1429102ba5302386cef8fdfdd5427ae652d0632c745e9d513d14cdc  eqproxy-darwin-amd64
6f911d2de60428a93488926f088ede2fcb95d4c46f43280a5b4966ddd31691d7  eqproxy-darwin-arm64
00996587d059d70f709291c4e5f716fa0f381d04b827c219354144d7cfe1b977  eqproxy-linux-amd64
1ae90a0a9f06ca6e3eb970790c4ecb2e41618d1afd5d7d01b8e99c6fcb5adff7  eqproxy-linux-arm64
2f8696fb526598dd2dc97706baeb880d8b49873e8e714b9149c24848386175d3  eqproxy-0.6.3-src.tar.gz
STEP_EXIT=0 (x3)
```

(The binary digests above belong to the throwaway files used to exercise the
step, not to released binaries.)

### 3.2 "Without breaking the existing ones" is a diff, not a claim

The pre-change step was taken from `git show HEAD:.github/workflows/release.yml`
and run on the same four files; its output was compared with the first four
lines of the new file:

```
$ bash /tmp/orig-step.sh          # original assemble+sums step
original assemble step exit=0
$ head -4 /tmp/new-sums.txt | diff - dist/SHA256SUMS.txt
IDENTICAL: the four binary lines are byte-for-byte what the old step wrote
```

### 3.3 The export is exactly the tagged tree

```
$ git ls-tree -r --name-only HEAD | sort > /tmp/git-tree.txt
$ tar -tzf dist/eqproxy-0.6.3-src.tar.gz | sed 's|^eqproxy-0.6.3/||' \
    | grep -v '/$' | grep -v '^$' | sort > /tmp/tar-tree.txt
$ diff /tmp/git-tree.txt /tmp/tar-tree.txt
IDENTICAL: 1328 tracked files, no extras, no omissions
```

Re-exporting the same commit produced the same digest twice
(`2f8696fb…`), so `--clobber` on a tag re-run refreshes the asset with an
unchanged checksum instead of churning it.

### 3.4 The asset is usable: build from it, run it

```
$ tar -xzf dist/eqproxy-0.6.3-src.tar.gz -C /tmp/srctree
$ cd /tmp/srctree/eqproxy-0.6.3 && cargo build --locked -p eqproxy-cli
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 49.93s
$ ./target/debug/eqproxy --version
eqproxy 0.6.3
```

The consumer journey from the README, with only the tarball downloaded:

```
$ shasum -a 256 -c SHA256SUMS.txt --ignore-missing
eqproxy-0.6.3-src.tar.gz: OK                                    # exit 0
$ printf 'x' >> eqproxy-0.6.3-src.tar.gz
$ shasum -a 256 -c SHA256SUMS.txt --ignore-missing
eqproxy-0.6.3-src.tar.gz: FAILED                                # exit 1
```

### 3.5 Negative controls (the assertions are not decorative)

Each control is the real step script, run against a throwaway git repository:

| Scenario | Result |
|---|---|
| `scripts/`, `ROADMAP EQPROXY/`, `SERVIDORES.md` and `.dockerignore` tracked in the exported commit | `source tarball contains the local-only path ROADMAP EQPROXY/`, exit 1. Without the gate that archive carried 5 such entries (`tar -tzf … | grep -c`), i.e. they would have been published |
| a `[workspace] members` entry deleted from the tree | `source tarball is missing the workspace member eqproxy-cli`, exit 1 |
| tag `v0.6.4` with `Cargo.toml` at 0.6.3 | `tag v0.6.4 does not match Cargo.toml 0.6.3`, exit 1 |

### 3.6 Real CI execution, and what the first attempt found

The new steps were exercised in a `workflow_dispatch` dry run: no tag, so no
release and no registry push, but the darwin, linux and image jobs build and
E2E-verify the real artifacts those steps then handle.

**Attempt 1 — run
[39647699303](https://github.com/ExyonQ/EQProxy/actions/runs/39647699303) at
`048b5ca`, conclusion `failure` at "Assemble dist/ (only after both builds
verified)":**

```
missing Scout report for linux/amd64
##[error]Process completed with exit code 1.
```

The Scout requirement was unconditional, but the image job only scans a
registry reference and a branch pushes none — so a dry run could never reach
the checksum steps, contradicting the workflow header ("a manual run exercises
the whole pipeline as a dry run"). Fixed in `4e95b09`: the requirement applies
where it protects something, a tag run. Both directions were re-run locally:
tag without reports `missing Scout report for linux/amd64`, exit 1; branch run
assembles, exports and checksums, exit 0.

**Attempt 2 — run
[39658861318](https://github.com/ExyonQ/EQProxy/actions/runs/39658861318) at
`4e95b09`, conclusion `success`, all five jobs green.** The release job log:

```
dry run: no Scout reports expected (nothing is scanned or published)
==> exporting 4e95b09 as dist/eqproxy-0.6.3-src.tar.gz
==> dist/eqproxy-0.6.3-src.tar.gz: 1376 entries, 814938 bytes, version 0.6.3
==> writing SHA256SUMS (only after every artifact passed)
eqproxy-darwin-amd64: OK
eqproxy-darwin-arm64: OK
eqproxy-linux-amd64: OK
eqproxy-linux-arm64: OK
eqproxy-0.6.3-src.tar.gz: OK
10e3e61c18f6a3d47202df9461dc9d8f0b3bcd3eab78a12bf76c2bc65da27f05  eqproxy-darwin-amd64
30ec6a0bd5ed9b574c2a4638105439aae75e570d3a22e24689209e6bce373192  eqproxy-darwin-arm64
b96c377082d6fa7797863913a4bd79f95f048f7ff82e10e7b21d5835911fdbde  eqproxy-linux-amd64
57b435e41aa17f2973471f4079a439f6a410c505a6b637599ed8be5da4740c8d  eqproxy-linux-arm64
9d17d3e4c3c2177f5f0ac7a7ee00b3c7be6828b379f83f6906485f12b7cf3cb0  eqproxy-0.6.3-src.tar.gz
```

Those are the four binaries the darwin and linux jobs built and E2E-verified in
that run, so the appended line is a checksum over a real export of `4e95b09`,
not over a fixture. `sha256sum -c` covered all five entries before upload.

## 4. Pending

- **The published asset does not exist yet.** v0.6.3 was released before this
  change, so its release page has four binaries and no source tarball. The
  first release that ships the asset is the next tag; only that run proves the
  upload (`gh release upload --clobber`) and the asset-as-downloaded digest.
  What the dry run proves is the export, its assertions and the sums file; the
  upload path itself is unchanged code that has run on every release so far,
  but a dry run does not execute it.
- **Cross-platform digest stability is verified on one git version.** The
  re-export test ran with macOS Git 2.39.5; git's tgz writer is expected to be
  deterministic, but a git upgrade on the runner that changed the archive
  bytes would only change the tarball's checksum line (the four binary lines
  stay put), which the release job would publish consistently.
- The tarball is the workspace tree, so `fuzz/` targets are included; no
  vendored crates are shipped (`cargo build --locked` fetches from the
  registry, as the build from the asset above did).
