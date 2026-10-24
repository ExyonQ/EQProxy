#!/usr/bin/env python3
"""S-H2-01 / S-H2-02: EQProxy vs HAProxy 3.4.6 with HTTP/2 active on both.

BENCHMARK_PLAN.md §3 defines the two scenarios; this harness runs them with
raw data:

- S-H2-01  HTTP/2 multiplexed: 4 TLS connections x 100 concurrent streams
           (400 in flight), GET /1024 (1 KiB), 3 s warm-up + 15 s measured,
           per-request latency from just before Do until the body is read and
           its length plus HTTP/2 protocol are validated.
- S-H2-02  HTTP/2 large payload: 4 connections x 8 streams, GET /1048576
           (1 MiB), 3 s + 15 s; throughput in req/s and MiB/s, CPU.

Both products terminate TLS 1.3 with ALPN h2 on the same container port and
forward to the same HTTP/1.1 origin (path-addressed bodies, keep-alive). The
generator is `load.go` (golang.org/x/net/http2); container counters come from
`probe/main.go` reading cgroup v2, mounted read-only even into the scratch
EQProxy image.

Outputs under run-<UTC>/: configs/, certs/, raw/ (one JSON per run), logs/
(proxy stdout/stderr, plain text), report.json, run.log. Every number in the
report is derived from these files; no value is hand-written.

Usage:
    python3 docs/evidence/v07-h2-bench/run.py [--reps 5] [--eq-image IMAGE]
"""

import argparse
import hashlib
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CERT = ROOT / "eqproxy-net" / "tests" / "fixtures" / "cert.pem"
KEY = ROOT / "eqproxy-net" / "tests" / "fixtures" / "key.pem"

EQ_IMAGE = "eqproxy-bench:v07"
HA_IMAGE = "haproxy:3.4.6"
LOAD_IMAGE = "eqproxy-h2load:v07"
NET = "h2bench"
PORT = 19443
ORIGIN_PORT = 9000
SINK_PORT = 9443
PRODUCTS = ("eqproxy", "haproxy")
SCENARIOS = {
    "S-H2-01": {"conns": 4, "streams": 100, "payload": 1024, "warmup": 3, "duration": 15},
    "S-H2-02": {"conns": 4, "streams": 8, "payload": 1 << 20, "warmup": 3, "duration": 15},
}
REPS = 5

EQPROXY_CONFIG = """schema_version = 1

[listener.h2]
listen = "0.0.0.0:{port}"
mode = "http"
backend = "api"
maxconn = 20000
idle_timeout = "30s"

[listener.h2.tls]
cert = "/certs/cert.pem"
key = "/certs/key.pem"
alpn = ["h2", "http/1.1"]

[backend.api]
server = "origin:{origin_port}"
"""

HAPROXY_CONFIG = """global
  maxconn 20000
defaults
  mode http
  timeout connect 5s
  timeout client 30s
  timeout server 30s
frontend fe
  bind :{port} ssl crt /certs/haproxy.pem alpn h2,http/1.1
  default_backend be
backend be
  server origin origin:{origin_port}
"""


def sh(cmd, **kw):
    proc = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if proc.returncode != 0:
        raise RuntimeError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def goarch():
    machine = platform.machine().lower()
    return {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64"}.get(machine, machine)


def docker_rm(name):
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def build_harness(tmp, log, load_override=None, probe_override=None):
    load_bin = tmp / "load"
    probe_bin = tmp / "probe"
    if load_override and probe_override:
        # Cross-compiled on the workstation when the evidence host has no Go
        # toolchain; the hashes are recorded exactly like a local build.
        shutil.copy(load_override, load_bin)
        shutil.copy(probe_override, probe_bin)
        load_bin.chmod(0o755)
        probe_bin.chmod(0o755)
    else:
        env = dict(os.environ, CGO_ENABLED="0", GOOS="linux", GOARCH=goarch())
        sh(["go", "build", "-trimpath", "-ldflags=-s", "-o", str(load_bin), "."], cwd=HERE, env=env)
        sh(["go", "build", "-trimpath", "-ldflags=-s", "-o", str(probe_bin), "./probe"], cwd=HERE, env=env)
    dockerfile = tmp / "load.Dockerfile"
    dockerfile.write_text(
        "FROM alpine:3.20\nCOPY load /load\nENTRYPOINT [\"/load\"]\n", encoding="utf-8"
    )
    sh(["docker", "build", "-f", str(dockerfile), "-t", LOAD_IMAGE, str(tmp)])
    log(f"[build] load sha256={sha256(load_bin)} probe sha256={sha256(probe_bin)}")
    return load_bin, probe_bin


def image_meta(image):
    fmt = "{{.Id}}|{{.RepoTags}}|{{.Created}}"
    out = sh(["docker", "image", "inspect", "--format", fmt, image]).stdout.strip()
    image_id, tags, created = out.split("|")
    return {"image": image, "id": image_id.replace("sha256:", "")[:16], "tags": tags, "created": created}


def probe(name):
    proc = sh(["docker", "exec", name, "/probe"])
    return json.loads(proc.stdout)


def origin_passive_opens():
    """Cumulative TCP accepts in the origin's network namespace.

    The origin initiates nothing, so every passive open is one backend
    connection a proxy opened. A delta per run exposes connection churn that
    the client-side counters cannot see (the proxy is a black box; this is
    its effect on the peer).
    """
    awk = ('/^Tcp:/ { if (!k) { for(i=2;i<=NF;i++) idx[$i]=i; k=1 } '
           'else { print $idx["PassiveOpens"] } }')
    out = sh(["docker", "exec", "h2bench-origin", "awk", awk, "/proc/net/snmp"])
    return int(out.stdout.strip())


def wait_ready(name, marker, log, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
        text = (logs.stdout or "") + (logs.stderr or "")
        if marker in text:
            return
        state = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", name],
            capture_output=True, text=True,
        ).stdout.strip()
        if state != "true":
            raise RuntimeError(f"{name} exited before becoming ready:\n{text}")
        time.sleep(0.1)
    raise RuntimeError(f"{name} not ready within {timeout}s (marker {marker!r})")


def start_proxy(product, config_path, certs_dir, probe_path, log, eq_image=EQ_IMAGE):
    docker_rm(f"h2bench-{product}")
    name = f"h2bench-{product}"
    common = ["docker", "run", "-d", "--name", name, "--network", NET,
              "--network-alias", product]
    if product == "eqproxy":
        cmd = common + [
            "-v", f"{config_path}:/etc/eqproxy.toml:ro",
            "-v", f"{certs_dir}:/certs:ro",
            "-v", f"{probe_path}:/probe:ro",
            eq_image, "run", "--config", "/etc/eqproxy.toml",
        ]
        marker = "listening on"
    else:
        cmd = common + [
            "-v", f"{config_path}:/usr/local/etc/haproxy/haproxy.cfg:ro",
            "-v", f"{certs_dir}:/certs:ro",
            "-v", f"{probe_path}:/probe:ro",
            HA_IMAGE,
        ]
        marker = "Loading success"
    sh(cmd)
    wait_ready(name, marker, log)
    return name


def run_generator(scenario, url, cert_dir, log):
    cfg = SCENARIOS[scenario]
    cmd = [
        "docker", "run", "--rm", "--network", NET,
        "-v", f"{cert_dir}:/certs:ro", LOAD_IMAGE,
        "-mode", "load", "-url", url, "-cacert", "/certs/cert.pem",
        "-sni", "localhost",
        "-conns", str(cfg["conns"]), "-streams", str(cfg["streams"]),
        "-payload", str(cfg["payload"]),
        "-warmup", f"{cfg['warmup']}s", "-duration", f"{cfg['duration']}s",
    ]
    proc = sh(cmd)
    return json.loads(proc.stdout)


def run_once(scenario, product, ctx, log):
    cfg = SCENARIOS[scenario]
    name = start_proxy(
        product, ctx["configs"][product], ctx["certs_dir"], ctx["probe"], log, ctx["eq_image"]
    )
    watched = {"proxy": name, "origin": "h2bench-origin", "sink": "h2bench-sink"}
    before = {key: probe(container) for key, container in watched.items()}
    opens_before = origin_passive_opens()
    t0 = time.time()
    started = utc_now()
    url = f"https://{product}:{PORT}/{cfg['payload']}"
    gen = run_generator(scenario, url, ctx["certs_dir"], log)
    t1 = time.time()
    after = {key: probe(container) for key, container in watched.items()}
    opens_after = origin_passive_opens()
    ended = utc_now()

    resources = {}
    for key in watched:
        cpu_usec = after[key]["cpu_usage_usec"] - before[key]["cpu_usage_usec"]
        resources[key] = {
            "cpu_percent_one_core": round(cpu_usec / 1e6 / (t1 - t0) * 100, 1),
            "cpu_seconds": round(cpu_usec / 1e6, 3),
            "memory_bytes": after[key]["memory_current"],
            "memory_peak_bytes": after[key]["memory_peak"],
        }
    logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
    (ctx["outdir"] / "logs" / f"{scenario}-{product}-rep{ctx['rep']}.log").write_text(
        (logs.stdout or "") + (logs.stderr or ""), encoding="utf-8"
    )
    docker_rm(name)

    record = {
        "scenario": scenario,
        "product": product,
        "rep": ctx["rep"],
        "order_index": ctx["order_index"],
        "url": url,
        "started_utc": started,
        "ended_utc": ended,
        "wall_seconds": round(t1 - t0, 3),
        "host_load_average": [round(v, 2) for v in os.getloadavg()],
        "upstream_connections_opened": opens_after - opens_before,
        "generator": gen,
        "resources": resources,
        "valid": gen.get("errors", 0) == 0 and gen.get("sanity") == "ok",
    }
    # The measurement is only a benchmark number when the client could run it
    # to completion: sanity failed, the protocol was not HTTP/2 or the client
    # itself errored on every request means there is nothing to compare.
    if gen.get("sanity") != "ok" or gen.get("proto") != "HTTP/2.0":
        raise RuntimeError(
            f"{scenario} {product} rep{ctx['rep']} is not a valid measurement: "
            f"sanity={gen.get('sanity')} proto={gen.get('proto')} "
            f"error_sample={gen.get('error_sample')}"
        )
    if gen.get("errors"):
        # Real product behaviour under the scenario load (502s, resets), not a
        # harness defect: recorded with the run so the report can state the
        # failure rate instead of hiding the affected repetition.
        log(f"[run] {scenario} {product} rep{ctx['rep']}: {gen['errors']} client errors "
            f"{gen.get('error_sample')}")
    return record


def calibrate(ctx, log):
    """Generator headroom: the same client against a local h2 sink."""
    out = {}
    sink = "h2bench-sink"
    for label, payload, conns, streams, warmup, duration in (
        ("load_c4s100_1k", 1024, 4, 100, 2, 10),
        ("load_c4s8_1m", 1 << 20, 4, 8, 2, 10),
    ):
        before = probe(sink)
        t0 = time.time()
        cmd = [
            "docker", "run", "--rm", "--network", NET,
            "-v", f"{ctx['certs_dir']}:/certs:ro", LOAD_IMAGE,
            "-mode", "load", "-url", f"https://sink:{SINK_PORT}/{payload}",
            "-cacert", "/certs/cert.pem", "-sni", "localhost",
            "-conns", str(conns), "-streams", str(streams), "-payload", str(payload),
            "-warmup", f"{warmup}s", "-duration", f"{duration}s",
        ]
        proc = sh(cmd)
        t1 = time.time()
        after = probe(sink)
        gen = json.loads(proc.stdout)
        if gen.get("errors", 0) != 0 or gen.get("sanity") != "ok" or gen.get("proto") != "HTTP/2.0":
            raise RuntimeError(f"sink calibration {label} failed: {gen.get('error_sample')}")
        entry = {
            "config": {"payload": payload, "conns": conns, "streams": streams,
                       "warmup_s": warmup, "duration_s": duration},
            "generator": gen,
            "sink": {
                "cpu_percent_one_core": round(
                    (after["cpu_usage_usec"] - before["cpu_usage_usec"]) / 1e6 / (t1 - t0) * 100, 1
                ),
                "memory_peak_bytes": after["memory_peak"],
            },
            "note": "Local HTTP/2 sink (same binary, real TLS + h2) measures the "
                    "client+sink pair; the slower of the two is the ceiling, so "
                    "this is a lower bound on what the generator can push.",
        }
        out[label] = entry
        log(f"[calibration] {label}: {gen['rps']:.1f} req/s, {gen['mib_per_sec']:.1f} MiB/s, "
            f"generator cpu {gen['generator_cpu_pct_one_core']:.0f}% of one core")
    return out


def host_info():
    uname = platform.platform()
    cpu_model = None
    memory = 0
    cpus = os.cpu_count()
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text().splitlines():
            if line.lower().startswith("model name"):
                cpu_model = line.split(":", 1)[1].strip()
                break
        meminfo = Path("/proc/meminfo")
        if meminfo.exists():
            for line in meminfo.read_text().splitlines():
                if line.startswith("MemTotal:"):
                    memory = int(line.split()[1]) * 1024
                    break
    else:
        cpu_model = subprocess.run(
            ["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True
        ).stdout.strip() or None
        raw = subprocess.run(
            ["sysctl", "-n", "hw.memsize"], capture_output=True, text=True
        ).stdout.strip()
        memory = int(raw) if raw.isdigit() else 0
        raw = subprocess.run(
            ["sysctl", "-n", "hw.ncpu"], capture_output=True, text=True
        ).stdout.strip()
        cpus = int(raw) if raw.isdigit() else cpus
    return {
        "uname": uname,
        "machine": platform.machine(),
        "cpu_model": cpu_model,
        "host_cpus": cpus,
        "host_memory_bytes": memory,
        "load_average": list(os.getloadavg()),
        "docker": sh(["docker", "version", "--format",
                      "client {{.Client.Version}} / server {{.Server.Version}}"]).stdout.strip(),
        "vm": sh(["docker", "info", "--format",
                  "cpus={{.NCPU}} memory={{.MemTotal}}"]).stdout.strip(),
    }


def summarise(scenario, runs):
    out = {}
    for product, records in runs.items():
        gens = [r["generator"] for r in records]
        entry = {
            "runs": len(records),
            "metric": "rps",
            "median": statistics.median(g["rps"] for g in gens),
            "min": min(g["rps"] for g in gens),
            "max": max(g["rps"] for g in gens),
            "mib_per_sec_median": statistics.median(g["mib_per_sec"] for g in gens),
            "mib_per_sec_min": min(g["mib_per_sec"] for g in gens),
            "mib_per_sec_max": max(g["mib_per_sec"] for g in gens),
            "latency_p50_ms": statistics.median(g["latency_ms"]["p50"] for g in gens),
            "latency_p95_ms": statistics.median(g["latency_ms"]["p95"] for g in gens),
            "latency_p99_ms": statistics.median(g["latency_ms"]["p99"] for g in gens),
            "latency_p99_ms_max": max(g["latency_ms"]["p99"] for g in gens),
            "cpu_percent_one_core": statistics.median(
                r["resources"]["proxy"]["cpu_percent_one_core"] for r in records
            ),
            "cpu_percent_one_core_min": min(
                r["resources"]["proxy"]["cpu_percent_one_core"] for r in records
            ),
            "cpu_percent_one_core_max": max(
                r["resources"]["proxy"]["cpu_percent_one_core"] for r in records
            ),
            "memory_peak_mib": round(
                statistics.median(r["resources"]["proxy"]["memory_peak_bytes"] for r in records) / 2**20, 2
            ),
            "origin_cpu_percent_one_core": statistics.median(
                r["resources"]["origin"]["cpu_percent_one_core"] for r in records
            ),
            "generator_cpu_percent_one_core": statistics.median(
                g["generator_cpu_pct_one_core"] for g in gens
            ),
            "errors_total": sum(g["errors"] for g in gens),
            "host_load_at_runs": [r["host_load_average"][0] for r in records],
            "invalid_runs": sum(1 for r in records if not r["valid"]),
            "status_codes": {
                str(code): sum((g.get("status_codes") or {}).get(str(code), 0) for g in gens)
                for code in {c for g in gens for c in (g.get("status_codes") or {})}
            },
            "upstream_connections_opened": sum(
                r["upstream_connections_opened"] for r in records
            ),
            "upstream_connections_per_1k_requests": round(
                sum(r["upstream_connections_opened"] for r in records)
                / max(sum(g["ok"] for g in gens), 1) * 1000, 2
            ),
            "proto": sorted({g.get("proto") for g in gens}),
        }
        out[product] = entry
    eq, ha = out["eqproxy"], out["haproxy"]
    out["gaps"] = {
        "metric_eq_over_ha": round(eq["median"] / ha["median"], 3),
        "bandwidth_eq_over_ha": round(eq["mib_per_sec_median"] / ha["mib_per_sec_median"], 3),
        "latency_p50_ha_over_eq": round(ha["latency_p50_ms"] / eq["latency_p50_ms"], 3),
        "latency_p99_ha_over_eq": round(ha["latency_p99_ms"] / eq["latency_p99_ms"], 3),
        "cpu_ratio_eq_over_ha": round(
            eq["cpu_percent_one_core"] / ha["cpu_percent_one_core"], 3
        ),
        "note": "metric ratios > 1 favour EQProxy; latency ratios > 1 mean "
                "EQProxy had the lower end-to-end latency; cpu ratio > 1 means "
                "EQProxy spent more CPU per second for the same offered load.",
    }
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reps", type=int, default=REPS)
    parser.add_argument(
        "--scenarios", default=",".join(SCENARIOS),
        help="comma-separated subset to run (default both). S-H2-01 churns backend "
             "connections hard enough in EQProxy to leave the host in a different "
             "state, so the two scenarios are published from separate campaigns.",
    )
    parser.add_argument("--keep", action="store_true", help="leave containers running")
    parser.add_argument("--load-binary", help="prebuilt linux load generator (skips go build)")
    parser.add_argument("--probe-binary", help="prebuilt linux probe (skips go build)")
    parser.add_argument(
        "--eq-image", default=EQ_IMAGE,
        help=f"EQProxy image under test (default {EQ_IMAGE})",
    )
    args = parser.parse_args()
    eq_image = args.eq_image
    scenarios = [s.strip() for s in args.scenarios.split(",") if s.strip()]
    unknown = [s for s in scenarios if s not in SCENARIOS]
    if unknown or not scenarios:
        raise SystemExit(f"unknown scenario(s): {unknown}; known: {list(SCENARIOS)}")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    outdir = HERE / f"run-{stamp}"
    (outdir / "configs").mkdir(parents=True)
    (outdir / "certs").mkdir()
    (outdir / "raw").mkdir()
    (outdir / "logs").mkdir()
    log_path = outdir / "run.log"

    def log(line):
        print(line, flush=True)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    for f in (CERT, KEY):
        if not f.exists():
            raise SystemExit(f"missing fixture certificate: {f}")
    for name in (f"h2bench-{p}" for p in PRODUCTS):
        docker_rm(name)
    for name in ("h2bench-origin", "h2bench-sink"):
        docker_rm(name)
    subprocess.run(["docker", "network", "rm", NET], capture_output=True)
    sh(["docker", "network", "create", NET])

    tmp = Path(tempfile.mkdtemp(prefix="h2bench-"))
    try:
        if bool(args.load_binary) != bool(args.probe_binary):
            raise SystemExit("--load-binary and --probe-binary go together")
        load_bin, probe_bin = build_harness(
            tmp, log,
            Path(args.load_binary) if args.load_binary else None,
            Path(args.probe_binary) if args.probe_binary else None,
        )

        certs_dir = outdir / "certs"
        shutil.copy(CERT, certs_dir / "cert.pem")
        shutil.copy(KEY, certs_dir / "key.pem")
        (certs_dir / "haproxy.pem").write_bytes(CERT.read_bytes() + KEY.read_bytes())

        eq_cfg = outdir / "configs" / "eqproxy.toml"
        eq_cfg.write_text(
            EQPROXY_CONFIG.format(port=PORT, origin_port=ORIGIN_PORT), encoding="utf-8"
        )
        ha_cfg = outdir / "configs" / "haproxy.cfg"
        ha_cfg.write_text(
            HAPROXY_CONFIG.format(port=PORT, origin_port=ORIGIN_PORT), encoding="utf-8"
        )

        images = {
            "eqproxy": image_meta(eq_image),
            "haproxy": image_meta(HA_IMAGE),
            "load": image_meta(LOAD_IMAGE),
        }
        eq_version = sh(["docker", "run", "--rm", eq_image, "--version"]).stdout.strip()
        ha_vv = sh(["docker", "run", "--rm", HA_IMAGE, "haproxy", "-vv"]).stdout.strip().splitlines()
        modules_file = HERE / "go-modules.txt"
        if modules_file.exists():
            go_mod = modules_file.read_text()
        else:
            try:
                go_mod = sh(["go", "list", "-m", "all"], cwd=HERE).stdout
            except Exception as exc:  # noqa: BLE001 - recorded, never invented
                go_mod = f"NOT EXECUTED: no Go toolchain on this host ({exc})\n"

        # Extract the exact binary the image runs, for the artifact hash.
        cid = sh(["docker", "create", eq_image]).stdout.strip()
        binary = tmp / "eqproxy"
        sh(["docker", "cp", f"{cid}:/opt/eqproxy", str(binary)])
        docker_rm(cid)

        sh([
            "docker", "run", "-d", "--name", "h2bench-origin", "--network", NET,
            "--network-alias", "origin", "-v", f"{probe_bin}:/probe:ro", LOAD_IMAGE,
            "-mode", "origin", "-addr", f":{ORIGIN_PORT}",
        ])
        wait_ready("h2bench-origin", "origin listening", log)
        sh([
            "docker", "run", "-d", "--name", "h2bench-sink", "--network", NET,
            "--network-alias", "sink", "-v", f"{certs_dir}:/certs:ro",
            "-v", f"{probe_bin}:/probe:ro", LOAD_IMAGE,
            "-mode", "sink", "-addr", f":{SINK_PORT}",
            "-cert", "/certs/cert.pem", "-key", "/certs/key.pem",
        ])
        wait_ready("h2bench-sink", "sink listening", log)

        host = host_info()

        disclosure = {
            "date_utc": utc_now(),
            "plan": "BENCHMARK_PLAN.md §2 disclosure, §3 scenarios, §4 metrics, §5 bias controls",
            "artifacts": {
                "eqproxy_image": images["eqproxy"],
                "eqproxy_binary_sha256": sha256(binary),
                "eqproxy_version": eq_version,
                "haproxy_image": images["haproxy"],
                "haproxy_vv": ha_vv,
                "generator_image": images["load"],
                "generator_binary_sha256": sha256(load_bin),
                "probe_binary_sha256": sha256(probe_bin),
                "go_modules": go_mod.splitlines(),
                "certificate_sha256": sha256(certs_dir / "cert.pem"),
                "certificate": "CN=localhost, SAN DNS:localhost + IP:127.0.0.1",
            },
            "host": host,
            "generator": {
                "what": "golang.org/x/net/http2 client over TLS (ALPN h2), real "
                        "certificate verification, StrictMaxConcurrentStreams so one "
                        "transport is one connection, closed-loop, no coordinated-omission "
                        "correction",
                "S-H2-01": {"conns": 4, "streams": 100, "payload": 1024,
                            "warmup_s": 3, "duration_s": 15},
                "S-H2-02": {"conns": 4, "streams": 8, "payload": 1048576,
                            "warmup_s": 3, "duration_s": 15},
            },
            "topology": "one Linux host; origin, sink, both proxies and the generator "
                        "are containers on one bridge network; no host port publishing "
                        "on the measured path",
            "equivalence": [
                "same HTTP/1.1 origin (path-addressed body, Content-Length, keep-alive)",
                "same certificate, TLS 1.3, ALPN h2, 30 s idle timeout",
                "same container port 19443, maxconn 20000 in both",
                "no compression enabled in either product; no rules/rewrites in this scenario",
                "100 client streams per connection (plan §3); EQProxy advertises 128, "
                "HAProxy's default tune.h2.max-concurrent-streams is 100",
            ],
            "differences": [
                "EQProxy translates every h2 stream into one HTTP/1.1 exchange through "
                "its engine (ADR-0006); HAProxy forwards natively over HTX",
            ],
        }

        log(f"[build] eqproxy image {images['eqproxy']['id']} binary {sha256(binary)[:16]}")
        log(f"[host] {host['uname']} · {host['vm']} · {host['docker']} · load {host['load_average']}")

        ctx = {
            "outdir": outdir,
            "certs_dir": certs_dir,
            "probe": probe_bin,
            "configs": {"eqproxy": eq_cfg, "haproxy": ha_cfg},
            "eq_image": eq_image,
            "rep": 0,
            "order_index": 0,
        }
        calibration = calibrate(ctx, log)

        results = {}
        for scenario in scenarios:
            results[scenario] = {p: [] for p in PRODUCTS}
            log(f"[scenario] {scenario} {json.dumps(SCENARIOS[scenario])}")
            for rep in range(1, args.reps + 1):
                order = PRODUCTS if rep % 2 else tuple(reversed(PRODUCTS))
                for idx, product in enumerate(order):
                    ctx["rep"] = rep
                    ctx["order_index"] = idx
                    record = run_once(scenario, product, ctx, log)
                    gen = record["generator"]
                    per_1k = record["upstream_connections_opened"] / max(gen["ok"], 1) * 1000
                    log(f"[run] {scenario} {product} rep{rep}: "
                        f"rps={gen['rps']:.1f} mib_s={gen['mib_per_sec']:.1f} "
                        f"p50={gen['latency_ms']['p50']:.2f}ms "
                        f"cpu={record['resources']['proxy']['cpu_percent_one_core']:.0f}% "
                        f"gen_cpu={gen['generator_cpu_pct_one_core']:.0f}% "
                        f"errors={gen['errors']} backend_conns_per_1k={per_1k:.2f}")
                    (outdir / "raw" / f"{scenario}-{product}-rep{rep}.json").write_text(
                        json.dumps(record, indent=2), encoding="utf-8"
                    )
                    results[scenario][product].append(record)

        summaries = {s: summarise(s, results[s]) for s in scenarios}
        report = {
            "disclosure": disclosure,
            "calibration": calibration,
            "results": results,
            "scenarios": scenarios,
            "summaries": summaries,
        }
        (outdir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        for scenario, summary in summaries.items():
            log(f"[gaps] {scenario}: {json.dumps(summary['gaps'])}")
        log(f"report: {outdir / 'report.json'}")
    finally:
        if not args.keep:
            for name in [f"h2bench-{p}" for p in PRODUCTS] + ["h2bench-origin", "h2bench-sink"]:
                docker_rm(name)
            subprocess.run(["docker", "network", "rm", NET], capture_output=True)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001 - the harness must fail loudly, not guess
        print(f"error: {exc}", file=sys.stderr)
        raise
