#!/usr/bin/env python3
"""Refuse a sub-second health-check timeout in the test suite.

A health check is the only thing between a healthy origin and a 503. When
its **timeout** is shorter than the scheduler can be trusted to run the check
task, one descheduled poll marks a healthy origin DOWN, `fall = 1` drops it,
and the next request answers 503 with no origin failure at all. That is what
`cli_e2e` and the `e2e_*` targets kept doing with `timeout = "100ms"` and
`HealthCheck::tcp(.., Duration::from_millis(100))`: the origin answered in
microseconds, the 100 ms budget was spent waiting for CPU, and the test
flaked — or, worse, asserted a 503 that proved nothing about the proxy.

The rule this gate enforces: in the test suite a health check's timeout is at
least **1 s**. The interval may stay short (80–150 ms): it is how often the
proxy *looks*, and the tests that assert a DOWN within 600–700 ms depend on
it. The timeout is the allowance for looking slowly, so it has to be long
even when the origin is a loopback mock.

What is scanned
---------------
Every `*.rs` under `eqproxy-*/tests/`, and every `eqproxy-*/src/**/*.rs` file
from its last `#[cfg(test)]` line onward (a unit test is part of the same
suite: `cargo test` runs it, and `health.rs` keeps a live-origin probe there),
in both forms the suite uses:

* Rust: `HealthCheck::tcp(<interval>, <timeout>)`, including calls split over
  several lines. The two arguments must be `Duration::from_millis(<n>)` or
  `Duration::from_secs(<n>)`; anything else (a constant, an expression) is
  **unproven** and rejected, because this gate reads text and cannot evaluate
  code.
* TOML embedded in a Rust string: a `timeout = "<n>ms"` under the nearest
  `[backend.<name>.health_check]` header of the same literal.

Production wiring is not a probe value: `main.rs` builds the check from the
operator's config (`HealthCheck::tcp(hc.interval, hc.timeout)`), so nothing
before `#[cfg(test)]` is scanned and a config-driven timeout is never
reported as unproven.

A probe in a comment is not a probe: lines whose trimmed text starts with
`//` are skipped.

Declarations
------------
`.github/scripts/short-health-probes.txt` holds the exceptions, one
`<path>::<test fn>  <reason>` per line (two spaces or a tab before the
reason; blank lines and `#` comments are ignored). The registry is exhaustive
in both directions: every sub-second probe must be below, and every entry
below must still cover a sub-second probe — a test that was fixed, renamed or
deleted fails until its entry is removed. An entry covers every sub-second
probe of that test, so its reason must say why each of them cannot mark a
healthy origin DOWN.

What this gate does not prove
-----------------------------
It does not run the checks, and it says nothing about the **production**
default or about a timeout an operator writes: it is a gate on the suite.
It also cannot evaluate a timeout built from a constant or an environment
variable; those are reported as unproven instead of accepted.

Usage
-----
    python3 .github/scripts/check-short-health-probes.py
    python3 .github/scripts/check-short-health-probes.py --self-test

Exit status is 0 when every probe of the suite is proven at 1 s or declared,
and 1 when one is not, when an entry no longer covers a probe, when the
registry is malformed or empty, or when a scanned file is missing.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / ".github" / "scripts" / "short-health-probes.txt"

# The minimum a suite probe's timeout may be, in milliseconds.
MIN_TIMEOUT_MS = 1000

CALL = re.compile(r"HealthCheck::tcp\s*\(")
ARG_DURATION = re.compile(r"Duration::from_(millis|secs)\s*\(\s*(\d+)\s*\)")
FN = re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)")

# A TOML table header, possibly embedded in a Rust string literal.
TABLE_HEADER = re.compile(r"\[\s*([A-Za-z_][A-Za-z0-9_.\-]*)\s*\]")
TIMEOUT_KEY = re.compile(r'timeout\s*=\s*\\?"([^"\\]+)\\?"')
DURATION_TEXT = re.compile(r"^(\d+)(ms|s|us)$")

# `<path>::<fn>` and the reason are separated by two spaces or a tab; the
# reason itself only uses single spaces.
SEPARATOR = re.compile(r"\s{2,}|\t+")


def test_module_start(text: str) -> int | None:
    """Line of the last `#[cfg(test)]` in a source file, if it has one."""
    lines = text.splitlines()
    return next(
        (
            index
            for index in range(len(lines) - 1, -1, -1)
            if lines[index].strip() == "#[cfg(test)]"
        ),
        None,
    )


def test_sources(root: Path) -> dict[str, tuple[str, int]]:
    """Test sources, keyed by path: `(text, first line to scan)`.

    `tests/` files are scanned whole. A `src/` file is scanned from its last
    `#[cfg(test)]` line, so production wiring (which takes the operator's
    config value) is not mistaken for a probe literal.
    """
    sources: dict[str, tuple[str, int]] = {}
    for crate in sorted(root.glob("eqproxy-*")):
        tests = crate / "tests"
        if tests.is_dir():
            for path in sorted(tests.rglob("*.rs")):
                sources[str(path.relative_to(root))] = (
                    path.read_text(encoding="utf-8", errors="replace"),
                    0,
                )
        sources_dir = crate / "src"
        if sources_dir.is_dir():
            for path in sorted(sources_dir.rglob("*.rs")):
                text = path.read_text(encoding="utf-8", errors="replace")
                anchor = test_module_start(text)
                if anchor is not None:
                    sources[str(path.relative_to(root))] = (text, anchor)
    if not sources:
        raise SystemExit(f"no test sources under {root}/eqproxy-*")
    return sources


def enclosing_fn(lines: list[str], start: int) -> str:
    """The function a line belongs to, or `<file>` when there is none."""
    for index in range(start, -1, -1):
        match = FN.match(lines[index])
        if match:
            return match.group(1)
    return "<file>"


def call_args(lines: list[str], start: int, open_paren: int) -> str | None:
    """The argument text of the call, with its parentheses balanced.

    Returns None when the file ends first (an unterminated call), which the
    caller reports as unproven rather than guessing.
    """
    depth = 0
    quoted = False
    escaped = False
    out: list[str] = []
    for line_index in range(start, len(lines)):
        line = lines[line_index]
        column = open_paren if line_index == start else 0
        for char in line[column:]:
            if quoted:
                out.append(char)
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
                continue
            if char == '"':
                quoted = True
                out.append(char)
            elif char == "(":
                depth += 1
                if depth > 1:
                    out.append(char)
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return "".join(out)
                out.append(char)
            else:
                out.append(char)
        out.append("\n")
    return None


def timeout_ms(text: str) -> int | None:
    match = DURATION_TEXT.match(text.strip())
    if not match:
        return None
    value, unit = int(match.group(1)), match.group(2)
    if unit == "s":
        return value * 1000
    if unit == "ms":
        return value
    return value // 1000


def rust_probes(
    path: str, text: str, start: int = 0
) -> list[tuple[str, int, str, int | None]]:
    """`(path, line, fn, timeout)` for every Rust probe; None is unproven."""
    lines = text.splitlines()
    found: list[tuple[str, int, str, int | None]] = []
    for index in range(start, len(lines)):
        line = lines[index]
        if line.lstrip().startswith("//"):
            continue
        for match in CALL.finditer(line):
            fn = enclosing_fn(lines, index)
            args = call_args(lines, index, match.end() - 1)
            if args is None:
                found.append((path, index + 1, fn, None))
                continue
            durations = ARG_DURATION.findall(args)
            if len(durations) != 2:
                found.append((path, index + 1, fn, None))
                continue
            unit, value = durations[1]
            found.append(
                (
                    path,
                    index + 1,
                    fn,
                    int(value) * 1000 if unit == "secs" else int(value),
                )
            )
    return found


def toml_probes(
    path: str, text: str, start: int = 0
) -> list[tuple[str, int, str, int | None]]:
    """`(path, line, fn, timeout)` for `timeout = ..` under a health_check."""
    lines = text.splitlines()
    found: list[tuple[str, int, str, int | None]] = []
    table = ""
    for index in range(start, len(lines)):
        line = lines[index]
        if line.lstrip().startswith("//"):
            continue
        header = TABLE_HEADER.search(line)
        if header:
            table = header.group(1)
        if not table.endswith(".health_check"):
            continue
        timeout = TIMEOUT_KEY.search(line)
        if timeout:
            found.append(
                (
                    path,
                    index + 1,
                    enclosing_fn(lines, index),
                    timeout_ms(timeout.group(1)),
                )
            )
    return found


def parse_registry(text: str) -> dict[str, str]:
    declared: dict[str, str] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = SEPARATOR.split(line, maxsplit=1)
        if len(parts) != 2:
            raise SystemExit(
                f"short-health-probes.txt:{number}: expected "
                "`<path>::<test fn>  <reason>` (two spaces or a tab before "
                "the reason)"
            )
        key, reason = parts[0].strip(), parts[1].strip()
        path, _, fn = key.rpartition("::")
        if not path.endswith(".rs") or not fn:
            raise SystemExit(
                f"short-health-probes.txt:{number}: `{key}` is not "
                "`<path>.rs::<test fn>`"
            )
        if not reason:
            raise SystemExit(f"short-health-probes.txt:{number}: missing reason")
        if key in declared:
            raise SystemExit(f"short-health-probes.txt:{number}: duplicate `{key}`")
        declared[key] = reason
    if not declared:
        raise SystemExit("short-health-probes.txt declares nothing")
    return declared


def read_registry() -> dict[str, str]:
    if not REGISTRY.is_file():
        raise SystemExit(f"registry missing: {REGISTRY}")
    return parse_registry(REGISTRY.read_text(encoding="utf-8"))


def problems(
    probes: list[tuple[str, int, str, int | None]], declared: dict[str, str]
) -> list[str]:
    """Every undeclared, unproven or rotted site, as human-readable lines."""
    found: list[str] = []
    covered: set[str] = set()
    for path, line, fn, timeout in probes:
        if timeout is not None and timeout >= MIN_TIMEOUT_MS:
            continue
        key = f"{path}::{fn}"
        if key in declared:
            covered.add(key)
            continue
        if timeout is None:
            found.append(
                f"{path}:{line} ({fn}): the timeout is not a literal "
                "Duration::from_millis/from_secs or is not a health_check "
                "timeout: it cannot be proven, so it is rejected"
            )
        else:
            found.append(
                f"{path}:{line} ({fn}): timeout is {timeout} ms, below "
                f"{MIN_TIMEOUT_MS} ms"
            )
    for key in sorted(set(declared) - covered):
        found.append(f"{key}: declared, but no sub-second probe was found there")
    return found


def run() -> int:
    declared = read_registry()
    probes: list[tuple[str, int, str, int | None]] = []
    for path, (text, start) in test_sources(ROOT).items():
        probes += rust_probes(path, text, start)
        probes += toml_probes(path, text, start)
    short = [probe for probe in probes if probe[3] is None or probe[3] < MIN_TIMEOUT_MS]
    print(
        f"suite health probes: {len(probes)} found, {len(short)} sub-second or "
        f"unproven, {len(declared)} declared in {REGISTRY.name}"
    )
    found = problems(probes, declared)
    if found:
        print("short health-probe contract violated:")
        for problem in found:
            print(f"  {problem}")
        print(
            "Raise the timeout to 1 s (the interval may stay short), or "
            "declare the site in .github/scripts/short-health-probes.txt with "
            "the reason it cannot mark a healthy origin DOWN."
        )
        return 1
    print("ok: every suite health probe has 1 s of timeout or a declared reason")
    return 0


def self_test() -> int:
    """Prove the detector still detects, without reading the tree."""
    good = (
        "async fn healthy() {\n"
        "    HealthCheck::tcp(Duration::from_millis(100), "
        "Duration::from_secs(1));\n"
        "}\n"
    )
    short = (
        "async fn flaky() {\n"
        "    HealthCheck::tcp(Duration::from_millis(80), "
        "Duration::from_millis(80));\n"
        "}\n"
    )
    split = (
        "async fn split() {\n"
        "    .with_health_check(HealthCheck::tcp(\n"
        "        Duration::from_millis(50),\n"
        "        Duration::from_millis(150),\n"
        "    ));\n"
        "}\n"
    )
    unproven = (
        "async fn constant() {\n"
        "    HealthCheck::tcp(PROBE_INTERVAL, PROBE_TIMEOUT);\n"
        "}\n"
    )
    commented = (
        "async fn doc() {\n"
        "    // HealthCheck::tcp(Duration::from_millis(10), "
        "Duration::from_millis(10))\n"
        "}\n"
    )
    # What a test writes into its config, as the Rust source spells it.
    toml_short = (
        "fn config() {\n"
        '    let body = "[backend.api.health_check]\\n\\\n'
        '                interval = \\"150ms\\"\\n\\\n'
        '                timeout = \\"100ms\\"\\n\\\n'
        '                fall = 1";\n'
        "}\n"
    )
    toml_good = toml_short.replace('\\"100ms\\"', '\\"1s\\"')
    toml_other_table = (
        "fn config() {\n"
        '    let body = "[admin]\\n\\\n'
        '                timeout = \\"100ms\\"\\n\\\n'
        '                token = \\"x\\"";\n'
        "}\n"
    )
    def scan(text: str) -> list[tuple[str, int, str, int | None]]:
        return rust_probes("tests.rs", text) + toml_probes("tests.rs", text)

    flaky = {"tests.rs::flaky": "deliberate"}
    split_decl = {"tests.rs::split": "deliberate"}
    failures = []
    if problems(scan(good), {}):
        failures.append("a 1 s probe was rejected")
    if not problems(scan(short), {}):
        failures.append("an undeclared short probe was accepted")
    if problems(scan(short), flaky):
        failures.append("a declared short probe was rejected")
    if not problems(scan(split), {}):
        failures.append("a multi-line short probe was accepted")
    if problems(scan(split), split_decl):
        failures.append("a declared multi-line short probe was rejected")
    if not any("not a literal" in p for p in problems(scan(unproven), {})):
        failures.append("a non-literal timeout was accepted")
    mixed = (
        "fn wiring() {\n"
        "    HealthCheck::tcp(cfg.interval, cfg.timeout);\n"
        "}\n"
        "#[cfg(test)]\n"
        "mod tests {\n"
        "    async fn unit() {\n"
        "        HealthCheck::tcp(Duration::from_millis(20), Duration::from_millis(200));\n"
        "    }\n"
        "}\n"
    )
    start = test_module_start(mixed)
    if start is None or len(rust_probes("src.rs", mixed, start)) != 1:
        failures.append("the cfg(test) anchor did not delimit the unit tests")
    if not problems(rust_probes("src.rs", mixed, start or 0), {}):
        failures.append("a short unit-test probe was accepted")
    if problems(scan(commented), {}):
        failures.append("a probe in a comment was flagged")
    if not problems(scan(toml_short), {}):
        failures.append("a 100 ms TOML timeout under health_check was accepted")
    if problems(scan(toml_good), {}):
        failures.append("a 1 s TOML timeout under health_check was rejected")
    if problems(scan(toml_other_table), {}):
        failures.append("a timeout outside health_check was flagged")
    if not any(
        "no sub-second probe" in p
        for p in problems(scan(good), {"tests.rs::gone": "x"})
    ):
        failures.append("a declaration for a vanished test was accepted")
    if not any(
        "no sub-second probe" in p
        for p in problems(scan(good), {"tests.rs::healthy": "x"})
    ):
        failures.append("a declaration whose test now only has a 1 s probe was accepted")
    malformed = [
        "tests.rs::flaky",  # no reason
        "tests.rs::flaky  ",  # empty reason
        "flaky  reason",  # no `::`
        "tests.rs::flaky  a\n\ntests.rs::flaky  b",  # duplicate
    ]
    for text in malformed:
        try:
            parse_registry(text)
        except SystemExit:
            continue
        failures.append(f"malformed registry accepted: {text!r}")
    if parse_registry("tests.rs::flaky  a reason")["tests.rs::flaky"] != "a reason":
        failures.append("a well-formed entry was not parsed")
    if failures:
        for failure in failures:
            print(f"self-test FAILED: {failure}")
        return 1
    print(
        "self-test ok: short, multi-line, non-literal, TOML, stale, "
        "duplicate and malformed input all rejected"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="exercise the detector against synthetic input and exit",
    )
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    return run()


if __name__ == "__main__":
    sys.exit(main())
