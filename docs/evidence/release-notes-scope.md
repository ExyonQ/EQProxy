# Release notes carry only their own version

Language: **English**. Evidence for the release-pipeline change of 2026-10-21
(commit `b993dc5`). Host: macOS 26 arm64, `gh` authenticated as the
maintainer.

## 1. Objective

`gh release create/edit --notes-file CHANGELOG.md` published the whole
changelog as the body of every release. The v0.6.3 page was 45 201 characters
long and listed v0.1.0, v0.2.0 … v0.6.2 under the notes of a patch release, so
a reader looking for "what changed in 0.6.3" had to scroll past every previous
version.

## 2. Change

| File | Change |
|---|---|
| `.github/workflows/release.yml` | new step `Extract the release notes for this version`; both `gh release create` and `gh release edit` take `--notes-file release-notes.md` |
| `CHANGELOG.md` | Unreleased entry describing the scope change |

Rules the step enforces:

- the version comes from `Cargo.toml`; on a tag run it must equal the tag;
- the section is found by its heading (`## [v0.6.3] — 2026-10-21`, also
  `## 0.6.3` and prerelease names such as `0.6.0-alpha`) and runs to the next
  top-level `## ` heading, so `### Fixed`/`### Changed` stay inside;
- the heading is rewritten as `## EQProxy v<version> — <date>` (date omitted
  when the changelog has none) instead of the bracketed changelog form;
- a missing section fails the release (`CHANGELOG.md has no section for
  <version>`) rather than publishing an empty or stale body.

## 3. Verification

### 3.1 The step, executed verbatim against the real changelog

The `run:` block was extracted from the workflow and executed with
`bash -euo pipefail` in a directory holding the repository's `Cargo.toml` and
`CHANGELOG.md`:

```
$ GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v0.6.3 bash /tmp/step-notes.sh
==> release-notes.md: 61 lines for v0.6.3
## EQProxy v0.6.3 — 2026-10-21

Patch release closing the two defects found while measuring TLS parity: a
configuration that asked for HTTP/2 could pass the gate and then fail every
STEP_EXIT=0
```

The file has exactly one top-level heading:

```
$ grep -nE '^## ' release-notes.md
1:## EQProxy v0.6.3 — 2026-10-21
```

and no section of an earlier release. The remaining mentions of `v0.6.1` /
`v0.6.2` inside it are prose of the v0.6.3 section (the erratum and the parity
report it references), not headings.

### 3.2 Negative controls

| Scenario | Result |
|---|---|
| `9.9.9` with no such section | `CHANGELOG.md has no section for 9.9.9`, exit 1 |
| tag `v9.9.9` with `Cargo.toml` at 0.6.3 | `tag v9.9.9 does not match Cargo.toml 0.6.3`, exit 1 |
| prerelease `0.6.0-alpha` | `## EQProxy v0.6.0-alpha — 2026-10-19`, 202 lines, exit 0 |

### 3.3 The published v0.6.3 page, corrected through the same interface

```
$ gh release view v0.6.3 --json body --jq '.body | length'
45201            # before: the whole changelog
$ gh release edit v0.6.3 --notes-file /tmp/release-notes-v0.6.3.md
$ gh release view v0.6.3 --json body --jq '.body | length'
3678             # after: the v0.6.3 section
$ gh release view v0.6.3 --json body --jq '.body' | grep -cE '^## \[v0\.'
0
```

The body now starts with `## EQProxy v0.6.3 — 2026-10-21`. The section is
identical at the `v0.6.3` tag and at `HEAD`, so the corrected page describes
the released commit and not a later edit.

### 3.4 Real CI execution

`workflow_dispatch` run
[39673034463](https://github.com/ExyonQ/EQProxy/actions/runs/39673034463) on
`main` at `b993dc5`, conclusion `success`, all five jobs green. The release job
log for the new step (ubuntu-latest, so this also proves `python3` exists and
runs on the runner image):

```
==> release-notes.md: 61 lines for v0.6.3
## EQProxy v0.6.3 — 2026-10-21

Patch release closing the two defects found while measuring TLS parity: a
configuration that asked for HTTP/2 could pass the gate and then fail every
```

The rest of the release job in the same run printed the five checksum lines
(`eqproxy-0.6.3-src.tar.gz: OK` included), so the notes step did not disturb
the tarball or the sums.

## 4. Pending

- **Earlier release pages keep the whole changelog.** They were published
  before this change and are left as they are: rewriting v0.1.0 … v0.6.2 would
  edit historical records without being asked. The next tag is the first one
  produced by the new step.
- A dry run proves the extraction; the two `gh` calls that consume
  `release-notes.md` are tag-only (the release step is gated on
  `github.ref_type == 'tag'`), so their CI path is first executed by the next
  tag. The same command line was run here against the real v0.6.3 release
  (`gh release edit --notes-file …`), which is the strongest evidence available
  before that tag.
