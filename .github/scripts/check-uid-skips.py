#!/usr/bin/env python3
"""Count the uid-gated skips of a suite run and refuse the undeclared ones.

Two blocks of the test suite only hold for an **unprivileged** uid: each
asserts that `chown(2)` to a foreign group is refused, which root is allowed
to perform. Run as uid 0 they print

    SKIP (running as root): <reason>

and carry on. The declaration exists so a root run reports a premise that is
absent instead of failing on it — or instead of hanging on a line that can
never arrive, which is what happened in `cli_e2e` on 2026-10-27: the step
waited inside `read_line` for a refusal the reload, applied for root, never
wrote, and only a 90 s guard ended the run. A skip is therefore allowed, but
only while it is declared; this gate turns "a new uid-gated skip nobody wrote
down" and "a declaration that stopped printing" into a red build.

What a run must look like
-------------------------
The log is a `cargo test` transcript captured with `--nocapture`, so the
`eprintln!` of a skip reaches the log instead of being swallowed for a
passing test. This gate reads the log only: it does not run the suite, and a
root log whose markers never appear because they were captured invisibly is
rejected as unproven, never accepted.

Declarations
------------
`.github/scripts/uid-skips.txt` holds them, one `<count>  <the whole log
line>` per entry (two spaces or a tab before the line), with the reason
verbatim. The registry is exhaustive in both directions:

* as **root** (`--root-log`): every `SKIP (running as root): ` line printed
  must be declared, the counts must match, and every declared entry must have
  been printed — a block that stopped skipping, or a reason that was
  reworded, fails until the registry is updated with it.
* as an **unprivileged** user (`--user-log`): none of these lines may appear.
  In an unprivileged run the block must actually run; a skip there would be
  hiding it.

What this gate does not prove
-----------------------------
That the unprivileged block asserted what it claims (the suite run in the
same job does that), and that a skip declared from memory matches a real
program: it compares observed log lines, in text, with the registry. It also
cannot see a uid-gated block that skips *without* printing the marker; the
root run itself covers that class the blunt way, by failing or hanging where
the job's step timeout turns it red.

Usage
-----
    python3 .github/scripts/check-uid-skips.py --user-log /tmp/suite-user.log
    python3 .github/scripts/check-uid-skips.py --root-log  /tmp/suite-root.log
    python3 .github/scripts/check-uid-skips.py --self-test

Exit status is 0 when the log obeys its side of the contract and 1 when it
does not, when the registry is malformed or empty, or when the log is missing
or is not a `cargo test` transcript.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / ".github" / "scripts" / "uid-skips.txt"

# The exact marker both declarations print: a line that starts with it is a
# uid-gated skip, and nothing else is.
MARKER = "SKIP (running as root): "

# A cargo test transcript always carries at least one per-target result line.
RESULT_LINE = re.compile(r"^test result: ")

# `<count>` and the whole log line are separated by two spaces or a tab; the
# reasons themselves only use single spaces.
SEPARATOR = re.compile(r"\s{2,}|\t+")


def parse_registry(text: str) -> Counter:
    declared: Counter = Counter()
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = SEPARATOR.split(line, maxsplit=1)
        if len(parts) != 2:
            raise SystemExit(
                f"uid-skips.txt:{number}: expected `<count>  <log line>` "
                "(two spaces or a tab before the line)"
            )
        raw_count, log_line = parts[0].strip(), parts[1].strip()
        if not raw_count.isdigit() or int(raw_count) < 1:
            raise SystemExit(
                f"uid-skips.txt:{number}: `{raw_count}` is not a positive count"
            )
        if log_line in declared:
            raise SystemExit(f"uid-skips.txt:{number}: duplicate entry `{log_line}`")
        if not log_line.startswith(MARKER) or len(log_line) <= len(MARKER):
            raise SystemExit(
                f"uid-skips.txt:{number}: the entry must be a whole "
                f"`{MARKER}<reason>` line"
            )
        declared[log_line] = int(raw_count)
    if not declared:
        raise SystemExit("uid-skips.txt declares nothing")
    return declared


def read_registry() -> Counter:
    if not REGISTRY.is_file():
        raise SystemExit(f"registry missing: {REGISTRY}")
    return parse_registry(REGISTRY.read_text(encoding="utf-8"))


def read_log(path: str) -> str:
    log = Path(path)
    if not log.is_file():
        raise SystemExit(f"log missing: {log}")
    text = log.read_text(encoding="utf-8", errors="replace")
    if not any(RESULT_LINE.match(line) for line in text.splitlines()):
        raise SystemExit(
            f"{log}: no `test result:` line: this is not a cargo test transcript"
        )
    return text


def skips(text: str) -> Counter:
    return Counter(
        line.rstrip("\r") for line in text.splitlines() if line.startswith(MARKER)
    )


def root_problems(declared: Counter, observed: Counter) -> list:
    problems = []
    for line, count in sorted(observed.items()):
        want = declared.get(line, 0)
        if want == 0:
            problems.append(f"undeclared uid-gated skip ({count}x): {line}")
        elif count != want:
            problems.append(f"declared {want}x but printed {count}x: {line}")
    for line, count in sorted(declared.items()):
        if line not in observed:
            problems.append(f"declared {count}x but never printed: {line}")
    return problems


def user_problems(observed: Counter) -> list:
    return [f"printed in an unprivileged run: {line}" for line in sorted(observed)]


def run_root(path: str) -> int:
    declared = read_registry()
    observed = skips(read_log(path))
    print(
        f"uid-gated skips as root: {sum(observed.values())} printed, "
        f"{sum(declared.values())} declared in {REGISTRY.name}"
    )
    problems = root_problems(declared, observed)
    if problems:
        print("uid-gated skip contract violated:")
        for problem in problems:
            print(f"  {problem}")
        print(
            "A new skip is declared in .github/scripts/uid-skips.txt with its "
            "reason; an entry the run no longer prints is removed together "
            "with the block that stopped printing it."
        )
        return 1
    print("ok: every uid-gated skip of the root run is declared, with its reason")
    return 0


def run_user(path: str) -> int:
    observed = skips(read_log(path))
    print(f"uid-gated skips in an unprivileged run: {sum(observed.values())} printed")
    problems = user_problems(observed)
    if problems:
        for problem in problems:
            print(f"  {problem}")
        print(
            "In an unprivileged run the block must run: a root-only skip "
            "branch was taken with the wrong uid."
        )
        return 1
    print("ok: the unprivileged run printed no uid-gated skip")
    return 0


def self_test() -> int:
    """Prove the detector still detects, without running the suite."""
    reasons = [
        MARKER + "the first declared block is skipped as root",
        MARKER + "the second declared block is skipped as root",
    ]
    declared = Counter({reasons[0]: 1, reasons[1]: 1})
    clean = "running 3 tests\n" + "\n".join(reasons) + "\ntest result: ok. 3 passed\n"
    failures = []
    if root_problems(declared, skips(clean)):
        failures.append("a declared root log was rejected")
    if not user_problems(skips(clean)):
        failures.append("a skip in an unprivileged run was accepted")
    if user_problems(skips("test result: ok. 3 passed\n")):
        failures.append("a clean unprivileged log was rejected")
    extra = clean + MARKER + "an undeclared block\n"
    if not root_problems(declared, skips(extra)):
        failures.append("an undeclared skip was accepted")
    missing = "running 1 test\n" + reasons[0] + "\ntest result: ok. 1 passed\n"
    if not root_problems(declared, skips(missing)):
        failures.append("a declaration that stopped printing was accepted")
    twice = clean + reasons[0] + "\n"
    if not root_problems(declared, skips(twice)):
        failures.append("a count that grew was accepted")
    malformed = [
        "1 " + reasons[0],  # no count separator
        "x  " + reasons[0],  # the count is not a number
        "1  " + reasons[0] + "\n1  " + reasons[0],  # duplicate entry
        "1  " + MARKER,  # no reason
    ]
    for text in malformed:
        try:
            parse_registry(text)
        except SystemExit:
            continue
        failures.append(f"malformed registry accepted: {text!r}")
    if parse_registry("1  " + reasons[0])[reasons[0]] != 1:
        failures.append("a well-formed entry was not parsed")
    if failures:
        for failure in failures:
            print(f"self-test FAILED: {failure}")
        return 1
    print(
        "self-test ok: undeclared, missing, duplicated and malformed input "
        "all rejected"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--user-log", help="capture of the suite as an unprivileged user"
    )
    parser.add_argument("--root-log", help="capture of the suite as uid 0")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="exercise the detector against synthetic input and exit",
    )
    args = parser.parse_args()
    if sum([bool(args.user_log), bool(args.root_log), bool(args.self_test)]) != 1:
        parser.error("exactly one of --user-log, --root-log or --self-test is required")
    if args.self_test:
        return self_test()
    if args.root_log:
        return run_root(args.root_log)
    return run_user(args.user_log)


if __name__ == "__main__":
    sys.exit(main())
