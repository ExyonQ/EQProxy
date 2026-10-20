#!/usr/bin/env python3
"""glibc release binary vs musl container image, same scenario, same host.

What is compared (only this differs):
  A) the v0.6.1 release asset `eqproxy-linux-arm64` (glibc, built by CI) run
     inside `debian:bookworm-slim`, and
  B) the published image `ghcr.io/exyonq/eqproxy:0.6.1` (static musl on
     scratch).

Everything else is identical: the same config file (the published S-H1-04
scenario: 11 listeners, 200 backend entries, 20 rules), the same backend
container and IP, the same bridge network, the same published port, the same
`oha` on the host, the same warm-up and the same 5 x 10 s measured window with
alternating order.

Run:
  python3 run.py --binary ./eqproxy-linux-arm64 \
      --config ../v06-bench/configs/s-h1-04-eqproxy.toml --out raw

Outputs (JSON): one file per repetition with the full `oha` report, plus
`summary.json` with the medians used by the report.
"""

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import threading
import time
import urllib.request

NET = "eqparity"
SUBNET = "172.20.0.0/24"
BACKEND_IP = "172.20.0.2"
PROXY_IP = "172.20.0.20"
PORT = 19401
BACKEND_IMAGE = "python:3.12-alpine"
GLIBC_IMAGE = "debian:bookworm-slim"
MUSL_IMAGE = "ghcr.io/exyonq/eqproxy:0.6.1"
HERE = os.path.dirname(os.path.abspath(__file__))


def sh(cmd, timeout=120, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"{cmd[0]} failed ({r.returncode}): {r.stderr[-2000:]}")
    return r


def docker_rm(name):
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def wait_tcp(host_port, deadline_s=30):
    end = time.time() + deadline_s
    while time.time() < end:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{host_port}/", timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.2)
    return False


def stats(container):
    r = sh(["docker", "stats", "--no-stream", "--format",
            "{{.CPUPerc}}|{{.MemUsage}}", container], timeout=30, check=False)
    out = r.stdout.strip()
    if "|" not in out:
        return {"cpu": None, "mem": None}
    cpu, mem = out.split("|", 1)
    return {"cpu": cpu.strip(), "mem": mem.strip()}


def oha_with_stats(container, url, secs, conns):
    """Run oha while sampling the container's CPU and RSS.

    A single `docker stats --no-stream` after the run would report an idle
    process; the samples here are taken during the measured window.
    """
    samples = []
    stop = threading.Event()

    def sampler():
        while not stop.is_set():
            samples.append(stats(container))
            time.sleep(1.0)

    thread = threading.Thread(target=sampler, daemon=True)
    thread.start()
    try:
        report = oha(url, secs, conns)
    finally:
        stop.set()
        thread.join(timeout=10)
    # The first sample of a run can cover the container's startup window and
    # reports nonsense (thousands of %); the median of the steady samples is
    # the honest number.
    cpus = []
    for s in samples[1:]:
        try:
            cpus.append(float(s["cpu"].rstrip("%")))
        except (TypeError, ValueError):
            continue
    mems = [mem_mib(s["mem"]) for s in samples[1:] if s["mem"]]
    mems = [m for m in mems if m is not None]
    return (
        report,
        round(statistics.median(cpus), 1) if cpus else None,
        round(statistics.median(mems), 1) if mems else None,
    )


def mem_mib(value):
    """`docker stats` reports "12.3MiB / 7.75GiB"; keep the used part in MiB."""
    used = value.split("/")[0].strip()
    for unit, factor in (("GiB", 1024.0), ("MiB", 1.0), ("KiB", 1 / 1024.0)):
        if used.endswith(unit):
            try:
                return float(used[: -len(unit)]) * factor
            except ValueError:
                return None
    return None


def oha(url, secs, conns):
    r = sh(["oha", "-z", f"{secs}s", "-c", str(conns), "--latency-correction",
            "--no-tui", "--output-format", "json", url], timeout=secs + 60)
    return json.loads(r.stdout)


def start_backend():
    docker_rm("eqparity-back")
    sh(["docker", "run", "-d", "--network", NET, "--ip", BACKEND_IP,
        "--name", "eqparity-back", "-v", f"{HERE}/backend.py:/backend.py:ro",
        BACKEND_IMAGE, "python3", "/backend.py"], timeout=180)
    # Readiness: the api origin answers.
    end = time.time() + 30
    while time.time() < end:
        r = sh(["docker", "run", "--rm", "--network", NET, BACKEND_IMAGE,
                "python3", "-c",
                "import socket,sys; s=socket.create_connection(('172.20.0.2',19002),2); "
                "s.sendall(b'GET /healthz HTTP/1.1\\r\\nHost: x\\r\\nConnection: close\\r\\n\\r\\n'); "
                "print(s.recv(16).decode(errors='replace'))"],
               timeout=60, check=False)
        if "200" in (r.stdout or ""):
            return
        time.sleep(0.5)
    raise RuntimeError("backend origins never answered on 172.20.0.2:19002")


def start_proxy(kind, binary, config):
    docker_rm("eqparity-proxy")
    common = ["docker", "run", "-d", "--network", NET, "--ip", PROXY_IP,
              "--name", "eqparity-proxy", "-p", f"127.0.0.1:{PORT}:{PORT}"]
    if kind == "glibc":
        # The released asset, mounted read-only into the same Debian base the
        # v0.6.0 image used. No toolchain, no build: the file under test is the
        # artifact users download.
        cmd = common + ["-v", f"{os.path.abspath(binary)}:/eqproxy:ro",
                        "-v", f"{os.path.abspath(config)}:/c.toml:ro",
                        GLIBC_IMAGE, "/eqproxy", "run", "--config", "/c.toml"]
    else:
        cmd = common + ["-v", f"{os.path.abspath(config)}:/c.toml:ro",
                        MUSL_IMAGE, "run", "--config", "/c.toml"]
    sh(cmd, timeout=180)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True, help="release asset eqproxy-linux-*")
    ap.add_argument("--config", required=True)
    ap.add_argument("--out", default="raw")
    ap.add_argument("--reps", type=int, default=3, help="reps per block")
    ap.add_argument("--secs", type=int, default=10)
    ap.add_argument("--conns", type=int, default=50)
    args = ap.parse_args()

    if shutil.which("oha") is None:
        sys.exit("oha not found in PATH")
    out = os.path.join(HERE, args.out)
    os.makedirs(out, exist_ok=True)

    sh(["docker", "network", "rm", NET], check=False)
    sh(["docker", "network", "create", "--subnet", SUBNET, NET])

    # Pin the images so the report states exactly what ran.
    for img in (BACKEND_IMAGE, GLIBC_IMAGE, MUSL_IMAGE):
        sh(["docker", "pull", img], timeout=600, check=False)

    artifacts = {
        "glibc": {"kind": "glibc", "image": GLIBC_IMAGE},
        "musl": {"kind": "musl", "image": MUSL_IMAGE},
    }
    for name, meta in artifacts.items():
        r = sh(["docker", "image", "inspect", "--format",
                "{{.Id}} {{.RepoDigests}}", meta["image"]], check=False)
        meta["image_id"], meta["repo_digests"] = (r.stdout.strip().split(" ", 1) + [""])[:2]

    start_backend()
    url = f"http://127.0.0.1:{PORT}/"
    runs = {name: [] for name in artifacts}

    # Block design A B B A: each block starts the artifact once (a restart per
    # repetition would measure cold starts and pollute `docker stats`), warms
    # it up and then takes its reps. Drift hits both artifacts equally.
    blocks = ["glibc", "musl", "musl", "glibc"]
    rep_no = 0
    try:
        for block_index, name in enumerate(blocks, start=1):
            meta = artifacts[name]
            start_proxy(meta["kind"], args.binary, args.config)
            if not wait_tcp(PORT, deadline_s=30):
                logs = sh(["docker", "logs", "eqparity-proxy"], check=False).stderr[-1500:]
                raise RuntimeError(f"{name}: listener never served\n{logs}")
            # Health checks: interval 2s, rise 2 -> let the backends settle.
            time.sleep(7)
            oha(url, 5, args.conns)  # discarded warm-up, identical for both
            print(f"block {block_index}/{len(blocks)} {name}: "
                  f"warm-up done, measuring {args.reps}x{args.secs}s", flush=True)
            for _ in range(args.reps):
                rep_no += 1
                report, cpu, mem = oha_with_stats("eqparity-proxy", url, args.secs, args.conns)
                entry = {
                    "artifact": name,
                    "block": block_index,
                    "image": meta["image"],
                    "image_id": meta["image_id"],
                    "rep": rep_no,
                    "cpu": cpu,
                    "mem": mem,
                    "rps": report["summary"]["requestsPerSec"],
                    # oha reports percentiles in seconds; the report is in ms.
                    "latency_ms": {
                        k: round(v * 1000.0, 3)
                        for k, v in report["latencyPercentiles"].items()
                        if k in ("p50", "p90", "p95", "p99", "p99.9")
                    },
                    "status_codes": report.get("statusCodeDistribution", {}),
                    "success_rate": report["summary"]["successRate"],
                    "error_distribution": report.get("errorDistribution", {}),
                }
                runs[name].append(entry)
                with open(os.path.join(out, f"{name}-block{block_index}-rep{rep_no}.json"), "w") as fh:
                    json.dump(report, fh, indent=2)
                print(f"  {name} block {block_index} rep {rep_no}: {entry['rps']:.0f} rps "
                      f"p95={entry['latency_ms'].get('p95')} ms cpu={entry['cpu']}%", flush=True)
    finally:
        docker_rm("eqparity-proxy")
        docker_rm("eqparity-back")
        sh(["docker", "network", "rm", NET], check=False)

    def med(values):
        values = [v for v in values if v is not None]
        return statistics.median(values) if values else None

    summary = {
        "scenario": "S-H1-04 (11 listeners, 200 backend entries, 20 rules)",
        "config": os.path.abspath(args.config),
        "binary_sha256": sh(["shasum", "-a", "256", os.path.abspath(args.binary)]).stdout.split()[0],
        "oha": sh(["oha", "--version"]).stdout.strip(),
        "docker": sh(["docker", "version", "--format", "{{.Server.Version}}"]).stdout.strip(),
        "host": {
            "cpus": sh(["docker", "info", "--format", "{{.NCPU}}"]).stdout.strip(),
            "mem_bytes": sh(["docker", "info", "--format", "{{.MemTotal}}"]).stdout.strip(),
        },
        "reps": args.reps,
        "seconds_per_rep": args.secs,
        "connections": args.conns,
        "artifacts": {},
    }
    for name, meta in artifacts.items():
        entries = runs[name]
        summary["artifacts"][name] = {
            "image": meta["image"],
            "image_id": meta["image_id"],
            "repo_digests": meta["repo_digests"],
            "rps_median": med([e["rps"] for e in entries]),
            "rps_all": [e["rps"] for e in entries],
            "p50_median": med([e["latency_ms"].get("p50") for e in entries]),
            "p95_median": med([e["latency_ms"].get("p95") for e in entries]),
            "p99_median": med([e["latency_ms"].get("p99") for e in entries]),
            "cpu_median_pct": med([e["cpu"] for e in entries]),
            "cpu_all_pct": [e["cpu"] for e in entries],
            "mem_median_mib": med([e["mem"] for e in entries]),
            "mem_all_mib": [e["mem"] for e in entries],
            "success_rate_min": min(e["success_rate"] for e in entries),
            "status_codes_all": [e["status_codes"] for e in entries],
            "errors_all": [e["error_distribution"] for e in entries],
        }
    a, b = summary["artifacts"]["glibc"], summary["artifacts"]["musl"]
    summary["ratio_musl_over_glibc_rps"] = (b["rps_median"] or 0) / (a["rps_median"] or 1)
    summary["ratio_musl_over_glibc_p95"] = (b["p95_median"] or 0) / (a["p95_median"] or 1)

    with open(os.path.join(out, "summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2)
    print(json.dumps({k: summary[k] for k in
                      ("ratio_musl_over_glibc_rps", "ratio_musl_over_glibc_p95")}, indent=2))
    print(f"summary: {os.path.join(out, 'summary.json')}")


if __name__ == "__main__":
    main()
