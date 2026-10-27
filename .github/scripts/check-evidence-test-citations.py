#!/usr/bin/env python3
"""Reject `docs/evidence` citations of tests that do not exist.

The evidence documents are the proof that a release was exercised, and they
cite tests by name. A name that no longer exists (or never did) turns the
proof into a claim: the reader cannot run what the document points at. This
gate reads the Rust tree that ships in the same commit and refuses a document
that cites a test-shaped identifier the tree does not define.

What counts as a citation
-------------------------
Only prose is read (fenced code blocks are skipped: the run transcripts there
are recorded output, including tests that existed at the time). A backticked
token is checked when both hold:

* its shape is a Rust test name: lowercase snake_case, at least 10 characters
  and at least two underscores (`setup`, `maxconn`, hashes, paths and command
  lines are not candidates), and
* it appears under a section whose heading talks about tests, a suite,
  journeys, E2E or verification, or on a line that names a test target
  (`<crate>/tests/<file>.rs`).

Such a token must exist as an identifier somewhere in the workspace's Rust
sources. This is deliberately looser than "#[test] function": sections also
name helpers the tests use (`wait_for_unix_admin`), and failing those would
force rewording accurate evidence. Identifiers that exist but are not a
`#[test]` function are reported as notes, not failures.

Historical names
----------------
Some documents correctly record a name that no longer exists: a test renamed
in a later slice, a v0.7 name superseded by a decision, an identifier removed
with its validation rule. Those live in
`.github/scripts/evidence-test-citations-allow.txt`, one `token  reason` per
line. An entry without a reason, a duplicated token or an entry no document
uses is an error: the list cannot rot into a blanket exemption. A new
hallucinated name added there would be visible in review as prose that has to
argue for it.

What this gate does not prove
-----------------------------
It proves the identifier exists, not that the test passes or that the document
described it correctly — a hallucinated name that coincides with an unrelated
identifier or config key passes. It reads `docs/evidence/**/*.md` only (the
`raw/` run transcripts are recorded output, not citations) and the workspace
crates listed in `Cargo.toml`.

Usage
-----
    python3 .github/scripts/check-evidence-test-citations.py
    python3 .github/scripts/check-evidence-test-citations.py --self-test

Exit status is 0 when the tree is clean and 1 when a citation is dangling, the
allowlist is malformed/stale, or the workspace cannot be read.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_DIR = ROOT / "docs" / "evidence"
ALLOWLIST = ROOT / ".github" / "scripts" / "evidence-test-citations-allow.txt"

TEST_ATTR = re.compile(r"^#\[\s*(?:tokio::)?test\b")
FN_DECL = re.compile(r"\b(?:async\s+)?fn\s+([a-z_][a-z0-9_]*)")
BACKTICK = re.compile(r"`([^`\n]+)`")
TEST_SHAPED = re.compile(r"^[a-z][a-z0-9_]{9,}$")
HEX = re.compile(r"^[0-9a-f]{8,}$")
HEADING = re.compile(r"^(#{1,6})\s+(.*)")
FENCE = re.compile(r"^\s*```")
TEST_SECTION = re.compile(
    r"\b(?:test|tests|suite|journeys?|e2e|verification|checks)\b", re.IGNORECASE
)
TEST_TARGET = re.compile(r"\b[A-Za-z0-9_.-]+/tests/[A-Za-z0-9_.-]+\.rs\b")


@dataclass
class Tree:
    identifiers: set[str] = field(default_factory=set)
    tests: dict[str, str] = field(default_factory=dict)
    files: int = 0


@dataclass
class Scan:
    candidates: int = 0
    dangling: list[tuple[str, int, str]] = field(default_factory=list)
    notes: list[tuple[str, int, str]] = field(default_factory=list)


def workspace_members() -> list[Path]:
    cargo = ROOT / "Cargo.toml"
    try:
        text = cargo.read_text(encoding="utf-8")
    except OSError as err:
        raise SystemExit(f"cannot read {cargo}: {err}")
    block = re.search(r"^members\s*=\s*\[(.*?)\]", text, re.DOTALL | re.MULTILINE)
    if not block:
        raise SystemExit(f"no workspace members in {cargo}")
    members = re.findall(r'"([^"]+)"', block.group(1))
    if not members:
        raise SystemExit(f"empty workspace members in {cargo}")
    return [ROOT / member for member in members]


def read_tree() -> Tree:
    tree = Tree()
    for member in workspace_members():
        if not member.is_dir():
            raise SystemExit(f"workspace member not found: {member}")
        for source in sorted(member.rglob("*.rs")):
            tree.files += 1
            lines = source.read_text(encoding="utf-8").splitlines()
            tree.identifiers.update(
                re.findall(r"[A-Za-z_][A-Za-z0-9_]*", "\n".join(lines))
            )
            for index, line in enumerate(lines):
                if not TEST_ATTR.match(line.strip()):
                    continue
                # The attribute is not always adjacent to the fn: a
                # `#[cfg_attr(miri, ignore)]` line can sit in between.
                for lookahead in lines[index + 1 : index + 6]:
                    match = FN_DECL.search(lookahead)
                    if match:
                        tree.tests.setdefault(
                            match.group(1), str(source.relative_to(ROOT))
                        )
                        break
    return tree


def read_allowlist() -> dict[str, str]:
    allowed: dict[str, str] = {}
    if not ALLOWLIST.exists():
        raise SystemExit(
            f"allowlist missing: {ALLOWLIST.relative_to(ROOT)} "
            "(create it empty if no historical name is cited)"
        )
    for number, raw in enumerate(
        ALLOWLIST.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"\s{2,}|\t+", line, maxsplit=1)
        if len(parts) != 2 or not parts[1].strip():
            raise SystemExit(
                f"{ALLOWLIST.relative_to(ROOT)}:{number}: "
                "expected `token  reason` (two spaces or a tab before the reason)"
            )
        token, reason = parts[0].strip(), parts[1].strip()
        if token in allowed:
            raise SystemExit(
                f"{ALLOWLIST.relative_to(ROOT)}:{number}: duplicate entry `{token}`"
            )
        if not TEST_SHAPED.match(token):
            raise SystemExit(
                f"{ALLOWLIST.relative_to(ROOT)}:{number}: `{token}` is not "
                "test-shaped; it would never be checked"
            )
        allowed[token] = reason
    return allowed


def test_shaped(token: str) -> bool:
    return bool(
        TEST_SHAPED.match(token)
        and not HEX.match(token)
        and token.count("_") >= 2
    )


def scan_markdown(
    text: str,
    relative: str,
    identifiers: set[str],
    tests: dict[str, str],
    allowed: dict[str, str],
    used: set[str],
) -> Scan:
    scan = Scan()
    in_test_section = False
    in_fence = False
    for number, line in enumerate(text.splitlines(), start=1):
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        heading = HEADING.match(line)
        if heading:
            in_test_section = bool(TEST_SECTION.search(heading.group(2)))
            continue
        if in_fence:
            continue
        cites_target = bool(TEST_TARGET.search(line))
        if not in_test_section and not cites_target:
            continue
        for token in BACKTICK.findall(line):
            if token.endswith(".rs") or not test_shaped(token):
                continue
            scan.candidates += 1
            if token in identifiers:
                if token not in tests:
                    scan.notes.append((relative, number, token))
                continue
            if token in allowed:
                used.add(token)
                continue
            scan.dangling.append((relative, number, token))
    return scan


def gather_documents() -> list[Path]:
    if not EVIDENCE_DIR.is_dir():
        raise SystemExit(f"evidence directory not found: {EVIDENCE_DIR}")
    return sorted(EVIDENCE_DIR.rglob("*.md"))


def run() -> int:
    tree = read_tree()
    allowed = read_allowlist()
    documents = gather_documents()

    candidates = 0
    dangling: list[tuple[str, int, str]] = []
    notes: list[tuple[str, int, str]] = []
    used: set[str] = set()
    for document in documents:
        result = scan_markdown(
            document.read_text(encoding="utf-8"),
            str(document.relative_to(ROOT)),
            tree.identifiers,
            tree.tests,
            allowed,
            used,
        )
        candidates += result.candidates
        dangling.extend(result.dangling)
        notes.extend(result.notes)

    print(
        f"evidence citations: {len(documents)} documents, {candidates} cited "
        f"identifiers, {len(tree.tests)} #[test] functions in {tree.files} files"
    )
    for document, number, token in notes:
        print(f"note: {document}:{number}: `{token}` exists but is not a #[test] function")
    for token, reason in sorted(allowed.items()):
        if token not in used:
            print(f"stale allowlist entry: `{token}` ({reason}) is cited by no document")
    if dangling:
        print("dangling test citations:")
        for document, number, token in dangling:
            print(f"  {document}:{number}: `{token}` does not exist in the Rust tree")
        print(
            "Fix the citation or, if the name is historical, record it with its "
            "reason in .github/scripts/evidence-test-citations-allow.txt"
        )
        return 1
    if any(token not in used for token in allowed):
        return 1
    print("ok: every cited test-shaped identifier exists in the Rust tree")
    return 0


def self_test() -> int:
    """Prove the detector still detects, without touching the checkout."""
    identifiers = {"a_real_test_that_exists", "wait_for_unix_admin"}
    tests = {"a_real_test_that_exists": "self/good.rs"}
    good = """
## Test suite

| Test | Asserts |
|---|---|
| `a_real_test_that_exists` | something |
| `wait_for_unix_admin` | a helper the tests use |
"""
    bad = """
## Test suite

| Test | Asserts |
|---|---|
| `a_test_that_never_existed` | something |
"""
    allowed_use: set[str] = set()
    ok = scan_markdown(good, "self/good.md", identifiers, tests, {}, allowed_use)
    ko = scan_markdown(bad, "self/bad.md", identifiers, tests, {}, allowed_use)
    failures = []
    if ok.dangling:
        failures.append(f"false positive: {ok.dangling}")
    if len(ok.notes) != 1:
        failures.append(f"expected one helper note, got {ok.notes}")
    if [token for _, _, token in ko.dangling] != ["a_test_that_never_existed"]:
        failures.append(f"missed the dangling citation: {ko.dangling}")
    fenced = "## Test suite\n\n```console\n$ cargo test\nfoo_that_never_existed ... ok\n```\n"
    if scan_markdown(fenced, "self/fenced.md", identifiers, tests, {}, allowed_use).dangling:
        failures.append("fenced run output must not be read as a citation")
    historical = "## Test suite\n\n`a_test_that_never_existed` (renamed)\n"
    allowed = {"a_test_that_never_existed": "renamed in self-test"}
    waived = scan_markdown(
        historical, "self/historical.md", identifiers, tests, allowed, allowed_use
    )
    if waived.dangling or "a_test_that_never_existed" not in allowed_use:
        failures.append(f"allowlisted historical name was not applied: {waived.dangling}")
    if failures:
        for failure in failures:
            print(f"self-test FAILED: {failure}")
        return 1
    print("self-test ok: dangling citation detected, real and helper names accepted")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="exercise the detector against synthetic input and exit",
    )
    args = parser.parse_args()
    return self_test() if args.self_test else run()


if __name__ == "__main__":
    sys.exit(main())
