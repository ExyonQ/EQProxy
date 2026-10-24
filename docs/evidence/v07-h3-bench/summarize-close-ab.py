#!/usr/bin/env python3
"""S-H3-02 before/after summarizer for the h3 clean-close classification.

Reads the `run-<UTC>/` directories the unchanged `run.py` wrote on the
evidence host and prints, from their own files only:

- the artifact each campaign ran (image id, binary SHA-256, version);
- per-run handshakes/s, p50/p95/p99 handshake latency, proxy CPU and peak
  memory, all from `raw/S-H3-02-*.json`;
- the WARN lines and log bytes each proxy wrote (`logs/S-H3-02-*.log`),
  split by the message that produced them;
- medians per image plus HAProxy's median in the same campaign (the control
  for host drift between campaigns).

Usage (from the repository root):

    python3 docs/evidence/v07-h3-bench/summarize-close-ab.py \
        run-20261024T001018Z run-20261024T001614Z ...
"""

import gzip
import json
import re
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
WARN = re.compile(r"^WARN \[h3\] (.+?) \(peer [^)]+\)", re.M)


def proxy_log(run, rep):
    """The proxy log of one run, plain or gzipped (both are used in this
    directory: earlier campaigns keep `*.log.gz`, the S-H3-02 ones are stored
    compressed too)."""
    stem = HERE / run / "logs" / f"S-H3-02-eqproxy-rep{rep}"
    plain = stem.with_suffix(".log")
    if plain.exists():
        return plain.read_text(errors="replace")
    return gzip.open(stem.with_suffix(".log.gz"), "rt", errors="replace").read()


def load(run):
    report = json.loads((HERE / run / "report.json").read_text())
    artifacts = report["disclosure"]["artifacts"]
    rows = {}
    for rep in range(1, 6):
        raw = json.loads(
            (HERE / run / "raw" / f"S-H3-02-eqproxy-rep{rep}.json").read_text()
        )
        text = proxy_log(run, rep)
        shapes = {}
        for match in WARN.finditer(text):
            shapes[match.group(1)] = shapes.get(match.group(1), 0) + 1
        rows[rep] = {
            "hs": raw["generator"]["handshakes_per_sec"],
            "p50": raw["generator"]["handshake_ms"]["p50"],
            "p95": raw["generator"]["handshake_ms"]["p95"],
            "p99": raw["generator"]["handshake_ms"]["p99"],
            "cpu": raw["resources"]["proxy"]["cpu_percent_one_core"],
            "mem": raw["resources"]["proxy"]["memory_peak_bytes"],
            "errors": raw["generator"]["errors"],
            "sanity": raw["generator"]["sanity"],
            "warn": text.count("WARN"),
            "bytes": len(text.encode()),
            "shapes": shapes,
        }
    haproxy = report["summaries"]["S-H3-02"]["haproxy"]["median"]
    return {
        "run": run,
        "image": artifacts["eqproxy_image"],
        "binary": artifacts["eqproxy_binary_sha256"],
        "version": artifacts["eqproxy_version"],
        "load": report["disclosure"]["host"]["load_average"],
        "rows": rows,
        "haproxy": haproxy,
        "eq_median": report["summaries"]["S-H3-02"]["eqproxy"]["median"],
    }


def main(runs):
    data = [load(run) for run in runs]
    for item in data:
        rows = item["rows"]
        print(f"== {item['run']}")
        print(
            f"   image {item['image']['id']} created {item['image']['created']}\n"
            f"   binary {item['binary']}  version {item['version']}\n"
            f"   host load at campaign start {item['load']}"
        )
        print(
            "   rep  hs/s     p50      p95      p99      cpu%   peak MiB   WARN  log KiB"
        )
        for rep, row in rows.items():
            print(
                f"   {rep}  {row['hs']:8.1f} {row['p50']:8.2f} {row['p95']:8.2f} "
                f"{row['p99']:8.2f} {row['cpu']:6.1f} {row['mem'] / 2**20:9.2f} "
                f"{row['warn']:6d} {row['bytes'] / 1024:8.1f}"
            )
        med = lambda key: statistics.median(row[key] for row in rows.values())
        print(
            f"   median hs/s {med('hs'):.1f}  p50 {med('p50'):.2f}  p95 "
            f"{med('p95'):.2f}  p99 {med('p99'):.2f}  cpu {med('cpu'):.1f}%  "
            f"peak {med('mem') / 2**20:.2f} MiB  WARN {med('warn'):.0f}"
        )
        print(
            f"   HAProxy median in this campaign {item['haproxy']:.1f} hs/s "
            f"(ratio {med('hs') / item['haproxy']:.3f})"
        )
        shapes = {}
        for row in rows.values():
            for shape, count in row["shapes"].items():
                shapes[shape] = shapes.get(shape, 0) + count
        for shape, count in sorted(shapes.items(), key=lambda kv: -kv[1]):
            print(f"   WARN shape x{count}: {shape}")
        bad = [rep for rep, row in rows.items() if row["errors"] or row["sanity"] != "ok"]
        print(f"   invalid runs (errors != 0 or sanity != ok): {bad or 'none'}")
        print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    main(sys.argv[1:])
