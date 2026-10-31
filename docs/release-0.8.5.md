# v0.8.5 — publication checklist and artifact gate

Language: **English**.

**What this page answers:** what must be true before the `v0.8.5` tag is
pushed, what the pipeline does with it, and how the published artifacts are
verified afterwards.It is a procedure, and it has been executed for `v0.8.5`: the local gates of
§2 were run on the cut commit (`fmt`, `clippy`, the suite, the release build,
the citation and probe gates with their self-tests); the `guard` job supplied
the two `uid-skips` verdicts from its own suite transcripts; §4 and §5 were
completed on 2026-10-31 (tag `v0.8.5`, release run
[41165822327](https://github.com/ExyonQ/EQProxy/actions/runs/41165822327),
2 h 58 min, six jobs green). The artifact gate is recorded with its digests,
Scout readings, checksums and re-pull transcripts in
[v085-published](evidence/v085-published.md).

- Version: **0.8.5** (`Cargo.toml` `[workspace.package] version`).
- Release notes: [CHANGELOG.md](../CHANGELOG.md) section `## [v0.8.5] — 2026-10-31`,
  extracted automatically by the `release` job.
- Pipeline: [.github/workflows/release.yml](../.github/workflows/release.yml).

## 1. The cut commit

One commit, and nothing else in it:

| File | Change | Why |
|---|---|---|
| `Cargo.toml` | `version = "0.8.5"` in `[workspace.package]` | single source of truth: the tag gate, the image tag, the release notes and the SBOM all read it |
| `eqproxy-net/Cargo.toml`, `eqproxy-config/Cargo.toml`, `eqproxy-cli/Cargo.toml` | `version = "0.8.5"` on the path dependencies | a stale pin fails to resolve against the workspace version |
| `Cargo.lock` | the four `eqproxy*` entries at `0.8.5` | the release builds with `--locked` |
| `fuzz/Cargo.lock` | the four `eqproxy*` entries at `0.8.5` | the fuzz workspace has its own lockfile and is not built by CI |
| `CHANGELOG.md` | `## [Unreleased] — v0.8.5` becomes `## [v0.8.5] — 2026-10-31` | the release job refuses to publish without a section for the version |

Regenerate the lockfiles with `cargo metadata` (it rewrites the entries and
leaves the rest of the resolution alone when the lockfile is in sync), never
by hand; if the lockfile was already behind its manifest the diff carries that
catch-up too, so read it:

```console
$ cargo metadata --format-version 1 > /dev/null
$ cargo metadata --manifest-path fuzz/Cargo.toml --format-version 1 > /dev/null
$ grep -A1 '^name = "eqproxy-core"' Cargo.lock
name = "eqproxy-core"
version = "0.8.5"
```

If the release slips, the date in the CHANGELOG heading is corrected in the
same commit as the tag, because it becomes the release-notes heading.

## 2. Local gates before the tag

Every one of these must be green on the cut commit. They are the same checks
the `guard` job repeats on the tag commit, and none of them is replaced by CI
having been green on an earlier push.

```console
$ cargo fmt --all -- --check
$ cargo clippy --workspace --all-targets -- -D warnings
$ cargo test --workspace
$ cargo build --workspace --release
$ python3 .github/scripts/check-evidence-test-citations.py --self-test
$ python3 .github/scripts/check-evidence-test-citations.py
$ python3 .github/scripts/check-short-health-probes.py --self-test
$ python3 .github/scripts/check-short-health-probes.py
$ python3 .github/scripts/check-uid-skips.py --self-test
```

The `uid-skips` verdict reads a transcript, not the source: it runs on the two
suite runs the `guard` job performs (`--nocapture`, unprivileged then as
`root`, `--user-log` / `--root-log`), so the only honest local result is its
`--self-test` until those two logs exist.

Version invariants the pipeline enforces, checkable before pushing:

```console
$ sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1        # 0.8.5
$ sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml          # 1.99.1
$ grep '^ARG RUST_VERSION' docker/Dockerfile                       # 1.99.1, must match
$ grep -n '^## \[v0.8.5\]' CHANGELOG.md                            # the release-notes section
```

`ci.yml` fails on a toolchain/`ARG RUST_VERSION` mismatch, and the `guard` job
fails on `v$VER != $GITHUB_REF_NAME`.

The image half of the gate was already run on this tree without publishing:
both architectures built from this Dockerfile and the pinned base, Docker
Scout **0 critical / 0 high** on each, and 20/20 container checks per
architecture — [v085-release-gate](evidence/v085-release-gate.md). The scan
that binds the release is still the one over the pushed digest (§5).

## 3. The commit itself

The commit must not carry material the repository does not publish, and it
must not carry AI or bot attribution ([CONTRIBUTING.md](../CONTRIBUTING.md)
authorship policy). Before pushing the tag:

```console
$ git log <base>..HEAD --format=%b | grep -iE '^co-authored-by:'
$ git log <base>..HEAD --format=%s,b | grep -iE 'generated with|co-authored-by'
```

Both must return nothing. Inspect the outgoing diff for maintainer-local files
as well; a build context or an archive that absorbed one is not fixed by a
later commit.

## 4. Tag and push

```console
$ git tag -a v0.8.5 -F release-notes-v0.8.5.md      # the notes of the CHANGELOG section
$ git push origin v0.8.5
```

A `v*` tag runs the whole pipeline; a manual `workflow_dispatch` runs it as a
dry run where release creation and registry pushes stay off.

| Job | What it proves |
|---|---|
| `guard` | both suite tiers on the tag commit (`--nocapture`, unprivileged and `root`), the three gate self-tests and verdicts, and `v$VERSION == $GITHUB_REF_NAME` |
| `darwin`, `linux` | the binaries build with the pinned toolchain and pass their E2E journeys (real CLI, live proxied traffic) before any checksum exists |
| `image` | builds and pushes the `0.8.5-candidate` index, records its digest, runs **Docker Scout on both architectures with `--exit-code` and `--only-severity critical,high`**, replays the version/config/live-traffic and admin-ACL journeys inside the image, then promotes the *scanned digest* to `:0.8.5` and `:latest` (GHCR) and mirrors it to Docker Hub |
| `release` | assembles `dist/` only after both builds verified, exports and checks the source tarball of the released commit, writes and re-checks `SHA256SUMS.txt`, and creates the GitHub release with the notes, SBOM and Scout reports |

Nothing is published by a job whose verification failed: the registry push and
the release creation are gated on the earlier jobs, and the promotion copies a
digest that was scanned, not a rebuild.

## 5. After publication — the artifact gate

This is the gate that closes the version. It ran after the tag run finished
(2026-10-31) and every line returned its expected result; the outputs are in
[v085-published](evidence/v085-published.md). Every line is a check with its
expected result.

```console
$ gh run list --workflow release.yml --limit 1        # the tag run: success, every job
$ sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1   # 0.8.5 == tag v0.8.5
$ gh release view v0.8.5                             # assets: 4 binaries, src tarball, SHA256SUMS, SBOM, 2 Scout reports
$ gh release download v0.8.5 --pattern 'eqproxy-*' --dir /tmp/rel && cd /tmp/rel && \
    (command -v sha256sum >/dev/null && sha256sum -c SHA256SUMS || shasum -a 256 -c SHA256SUMS)   # the workflow writes it with the same fallback
$ docker pull ghcr.io/exyonq/eqproxy:0.8.5 && docker run --rm ghcr.io/exyonq/eqproxy:0.8.5 --version   # eqproxy 0.8.5
$ docker scout cves --only-severity critical,high --exit-code ghcr.io/exyonq/eqproxy:0.8.5   # 0C 0H, exit 0
$ docker buildx imagetools inspect ghcr.io/exyonq/eqproxy:0.8.5 \
    --format '{{json .Manifest}}' | jq -r '.manifests[].platform.architecture'   # amd64 and arm64
$ docker buildx imagetools inspect ghcr.io/exyonq/eqproxy:0.8.5 \
    --format '{{.Manifest.Digest}}'                                              # == the scanned candidate digest
```

- The digest check is the one that matters: `:0.8.5`, `:latest` and the Docker
  Hub mirror must carry **exactly** the index digest the Scout gate scanned
  (the `image` job prints it and re-verifies it before finishing).
- Both architectures are re-pulled and replayed by the pipeline itself; repeat
  one journey by hand on the published tag (credential-free: `--version`,
  `config validate` and one proxied request) to confirm the public artifact,
  not the local build.
- Then, in a follow-up commit, update what describes the published state:
  `README.md` (status line, install URLs, image tags) and
  `docs/docker-hub-readme.md`. They are not part of the cut commit on purpose:
  until the tag run succeeds they would claim a release that does not exist.
- Record the run id, the digests, the Scout reports and the re-pull transcript
  under `docs/evidence/`, so the version is reproducible from the repository
  alone.

## 6. If the tag run fails

- **A `guard`/build/E2E job failed:** nothing was published. Fix it in a new
  commit; the tag is not reused, because a second tag on the same version
  publishes artifacts that were never built from one commit. Bump the patch
  version instead (`0.8.6`) or, if the tag never left the machine, delete it
  before pushing.
- **The version pin or the notes extraction failed:** the mismatch is real
  (tag ≠ `Cargo.toml`, or no `## [v0.8.5]` section); fix the commit.
- **The image job failed before promotion:** the `-candidate` tag may exist but
  `:0.8.5` and `:latest` were not touched; the release job depends on the image
  job, so no release exists either.
- **The release job failed after the registry promotion:** the images are
  public and the GitHub release is missing. Do not re-tag: finish the release
  from the same commit with a re-run of the failed job, and verify the digests
  again before declaring the version published.
