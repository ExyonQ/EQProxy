#!/usr/bin/env python3
"""S-H3-01 / S-H3-02: EQProxy vs HAProxy 3.4.6 with HTTP/3 active on both.

BENCHMARK_PLAN.md §3 defines the two scenarios; this harness runs them with
raw data:

- S-H3-01  HTTP/3 (QUIC) 1 KiB payload: closed-loop GETs over 8 QUIC
           connections x 8 concurrent h3 streams (64 in flight), 15 s measured
           after a 3 s warm-up, per-request latency from just before the request
           is written until the body is fully read.
- S-H3-02  HTTP/3 massive handshake: 16 concurrent fresh QUIC handshakes
           (no session resumption, no 0-RTT), 10 s measured after 2 s warm-up.

Both products terminate TLS 1.3 + ALPN h3 on the same container port 19443
(HAProxy needs a dedicated `quic4@` bind), forward to the same HTTP/1.1 origin
(1 KiB body, keep-alive) and use the same certificate, congestion controller
(cubic) and 30 s idle timeout. The load generator is `load.go` (quic-go
0.64.1, its own QUIC/h3/QPACK stack); the container counters come from
`probe/main.go` reading cgroup v2, mounted read-only even into the scratch
EQProxy image.

Outputs under run-<UTC>/: configs/, certs/, raw/ (one JSON per run),
logs/ (proxy stdout/stderr), report.json, run.log. Every number in the report
is derived from these files; no value is hand-written.

Usage:
    python3 docs/evidence/v07-h3-bench/run.py [--reps 5] [--keep]
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
LOAD_IMAGE = "eqproxy-h3load:v07"
NET = "h3bench"
PORT = 19443
ORIGIN_PORT = 9000
SINK_PORT = 9443
PRODUCTS = ("eqproxy", "haproxy")
SCENARIOS = {
    "S-H3-01": {"mode": "load", "conns": 8, "streams": 8, "warmup": 3, "duration": 15},
    "S-H3-02": {"mode": "handshake", "conns": 16, "warmup": 2, "duration": 10},
}
REPS = 5

EQPROXY_CONFIG = """schema_version = 1

[listener.h3]
listen = "0.0.0.0:{port}"
mode = "http"
backend = "api"
maxconn = 20000
idle_timeout = "30s"
quic = true

[listener.h3.tls]
cert = "/certs/cert.pem"
key = "/certs/key.pem"

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
  bind quic4@:{port} ssl crt /certs/haproxy.pem quic-cc-algo cubic
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
    docker_rm(f"h3bench-{product}")
    name = f"h3bench-{product}"
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
        "-mode", cfg["mode"], "-url", url, "-cacert", "/certs/cert.pem",
        "-conns", str(cfg["conns"]),
        "-warmup", f"{cfg['warmup']}s", "-duration", f"{cfg['duration']}s",
    ]
    if cfg["mode"] == "load":
        cmd += ["-streams", str(cfg["streams"])]
    proc = sh(cmd)
    return json.loads(proc.stdout)


def run_once(scenario, product, ctx, log):
    cfg = SCENARIOS[scenario]
    name = start_proxy(
        product, ctx["configs"][product], ctx["certs_dir"], ctx["probe"], log, ctx["eq_image"]
    )
    watched = {"proxy": name, "origin": "h3bench-origin"}
    if cfg["mode"] == "load":
        watched["sink"] = "h3bench-sink"
    before = {key: probe(container) for key, container in watched.items()}
    t0 = time.time()
    started = utc_now()
    url = f"https://{product}:{PORT}/"
    gen = run_generator(scenario, url, ctx["certs_dir"], log)
    t1 = time.time()
    after = {key: probe(container) for key, container in watched.items()}
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
        "generator": gen,
        "resources": resources,
    }
    if gen.get("errors", 0) != 0 or gen.get("sanity") != "ok":
        raise RuntimeError(
            f"{scenario} {product} rep{ctx['rep']} is not a valid measurement: "
            f"errors={gen.get('errors')} sanity={gen.get('sanity')} "
            f"error_sample={gen.get('error_sample')}"
        )
    return record


def calibrate(ctx, log):
    """Generator headroom: the same client against a local h3 sink."""
    out = {}
    sink = "h3bench-sink"
    load_cfg = SCENARIOS["S-H3-01"]
    hs_cfg = SCENARIOS["S-H3-02"]
    for label, mode, conns, streams, warmup, duration in (
        ("load_c8s8", "load", load_cfg["conns"], load_cfg["streams"], 2, 10),
        ("handshake_c16", "handshake", hs_cfg["conns"], None, 2, 10),
    ):
        before = probe(sink)
        t0 = time.time()
        cmd = [
            "docker", "run", "--rm", "--network", NET,
            "-v", f"{ctx['certs_dir']}:/certs:ro", LOAD_IMAGE,
            "-mode", mode, "-url", f"https://sink:{SINK_PORT}/", "-cacert", "/certs/cert.pem",
            "-conns", str(conns), "-warmup", f"{warmup}s", "-duration", f"{duration}s",
        ]
        if streams:
            cmd += ["-streams", str(streams)]
        proc = sh(cmd)
        t1 = time.time()
        after = probe(sink)
        gen = json.loads(proc.stdout)
        if gen.get("errors", 0) != 0 or gen.get("sanity") != "ok":
            raise RuntimeError(f"sink calibration {label} failed: {gen.get('error_sample')}")
        entry = {
            "config": {"mode": mode, "conns": conns, "streams": streams,
                       "warmup_s": warmup, "duration_s": duration},
            "generator": gen,
            "sink": {
                "cpu_percent_one_core": round(
                    (after["cpu_usage_usec"] - before["cpu_usage_usec"]) / 1e6 / (t1 - t0) * 100, 1
                ),
                "memory_peak_bytes": after["memory_peak"],
            },
            "note": "Local HTTP/3 sink (quic-go server, same binary) measures the "
                    "client+sink pair; the slower of the two is the ceiling, so "
                    "this is a lower bound on what the generator can push.",
        }
        out[label] = entry
        log(f"[calibration] {label}: {json.dumps(entry['generator'].get('rps')
                                                  or entry['generator'].get('handshakes_per_sec'))}"
            f" req/s or hs/s, generator cpu "
            f"{entry['generator']['generator_cpu_pct_one_core']:.0f}% of one core")
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
    cfg = SCENARIOS[scenario]
    metric = "rps" if cfg["mode"] == "load" else "handshakes_per_sec"
    lat = "latency_ms" if cfg["mode"] == "load" else "handshake_ms"
    out = {}
    for product, records in runs.items():
        gens = [r["generator"] for r in records]
        entry = {
            "runs": len(records),
            "metric": metric,
            "median": statistics.median(g[metric] for g in gens),
            "min": min(g[metric] for g in gens),
            "max": max(g[metric] for g in gens),
            "latency_p50_ms": statistics.median(g[lat]["p50"] for g in gens),
            "latency_p95_ms": statistics.median(g[lat]["p95"] for g in gens),
            "latency_p99_ms": statistics.median(g[lat]["p99"] for g in gens),
            "latency_p99_ms_max": max(g[lat]["p99"] for g in gens),
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
            "status_codes": sorted({code for g in gens for code in (g.get("status_codes") or {})}),
        }
        out[product] = entry
    eq, ha = out["eqproxy"], out["haproxy"]
    lat_key = lat
    out["gaps"] = {
        "metric_eq_over_ha": round(eq["median"] / ha["median"], 3),
        "latency_p50_ha_over_eq": round(
            statistics.median(
                [r["generator"][lat_key]["p50"] for r in runs["haproxy"]]
            ) / statistics.median(
                [r["generator"][lat_key]["p50"] for r in runs["eqproxy"]]
            ), 3),
        "latency_p99_ha_over_eq": round(
            statistics.median(
                [r["generator"][lat_key]["p99"] for r in runs["haproxy"]]
            ) / statistics.median(
                [r["generator"][lat_key]["p99"] for r in runs["eqproxy"]]
            ), 3),
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
    parser.add_argument("--keep", action="store_true", help="leave containers running")
    parser.add_argument("--load-binary", help="prebuilt linux load generator (skips go build)")
    parser.add_argument("--probe-binary", help="prebuilt linux probe (skips go build)")
    parser.add_argument(
        "--eq-image", default=EQ_IMAGE,
        help=f"EQProxy image under test (default {EQ_IMAGE})",
    )
    args = parser.parse_args()
    eq_image = args.eq_image

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
    for name in (f"h3bench-{p}" for p in PRODUCTS):
        docker_rm(name)
    for name in ("h3bench-origin", "h3bench-sink"):
        docker_rm(name)
    subprocess.run(["docker", "network", "rm", NET], capture_output=True)
    sh(["docker", "network", "create", NET])

    tmp = Path(tempfile.mkdtemp(prefix="h3bench-"))
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
        # The evidence host may have no Go toolchain (the binaries are
        # cross-compiled); the module list is then taken from the file the
        # workstation generated from the same go.mod/go.sum.
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
            "docker", "run", "-d", "--name", "h3bench-origin", "--network", NET,
            "--network-alias", "origin", "-v", f"{probe_bin}:/probe:ro", LOAD_IMAGE,
            "-mode", "origin", "-addr", f":{ORIGIN_PORT}",
        ])
        wait_ready("h3bench-origin", "origin listening", log)
        sh([
            "docker", "run", "-d", "--name", "h3bench-sink", "--network", NET,
            "--network-alias", "sink", "-v", f"{certs_dir}:/certs:ro",
            "-v", f"{probe_bin}:/probe:ro", LOAD_IMAGE,
            "-mode", "sink", "-addr", f":{SINK_PORT}",
            "-cert", "/certs/cert.pem", "-key", "/certs/key.pem",
        ])
        wait_ready("h3bench-sink", "sink listening", log)

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
                "what": "quic-go 0.64.1 HTTP/3 client (docs/evidence/v07-h3-bench/load.go), "
                        "real TLS verification against the fixture CA, no 0-RTT, no session "
                        "resumption, closed-loop, no coordinated-omission correction",
                "load": {"conns": SCENARIOS["S-H3-01"]["conns"],
                         "streams": SCENARIOS["S-H3-01"]["streams"],
                         "warmup_s": SCENARIOS["S-H3-01"]["warmup"],
                         "duration_s": SCENARIOS["S-H3-01"]["duration"]},
                "handshake": {"conns": SCENARIOS["S-H3-02"]["conns"],
                              "warmup_s": SCENARIOS["S-H3-02"]["warmup"],
                              "duration_s": SCENARIOS["S-H3-02"]["duration"],
                              "0_rtt": "off (client does not attempt it; EQProxy does not "
                                      "implement it, ADR-0013)",
                              "session_resumption": "off (fresh handshake every dial)"},
            },
            "topology": f"one host ({host['uname']}, {host['cpu_model']}, "
                        f"{host['host_cpus']} CPUs exposed to Docker as {host['vm']}); "
                        "origin, sink, both proxies and the generator are containers on "
                        "one bridge network; no host port publishing on the measured path",
            "equivalence": [
                "same HTTP/1.1 origin (1 KiB, Content-Length, keep-alive) and same body",
                "same certificate, TLS 1.3, ALPN h3, cubic congestion control, 30 s idle timeout",
                "same container port 19443; HAProxy uses a dedicated quic4@ bind for QUIC",
                "no compression enabled in either product; no rules/rewrites in this scenario",
                "no health checks in either product for this scenario (static origin)",
                "maxconn 20000 in both",
            ],
            "differences": [
                "EQProxy translates every h3 request into one HTTP/1.1 exchange through its "
                "engine (architecture, ADR-0013); HAProxy forwards natively",
                "HAProxy's TCP bind also offers h2/http1.1 (unused here); EQProxy's TCP path is "
                "part of the same listener",
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
        for scenario in SCENARIOS:
            results[scenario] = {p: [] for p in PRODUCTS}
            log(f"[scenario] {scenario} {json.dumps(SCENARIOS[scenario])}")
            for rep in range(1, args.reps + 1):
                order = PRODUCTS if rep % 2 else tuple(reversed(PRODUCTS))
                for idx, product in enumerate(order):
                    ctx["rep"] = rep
                    ctx["order_index"] = idx
                    record = run_once(scenario, product, ctx, log)
                    gen = record["generator"]
                    value = gen.get("rps") if SCENARIOS[scenario]["mode"] == "load" \
                        else gen.get("handshakes_per_sec")
                    log(f"[run] {scenario} {product} rep{rep}: "
                        f"{'rps' if SCENARIOS[scenario]['mode'] == 'load' else 'hs/s'}="
                        f"{value:.1f} p50={gen.get('latency_ms', gen.get('handshake_ms'))['p50']:.2f}ms "
                        f"cpu={record['resources']['proxy']['cpu_percent_one_core']:.0f}% "
                        f"gen_cpu={gen['generator_cpu_pct_one_core']:.0f}%")
                    (outdir / "raw" / f"{scenario}-{product}-rep{rep}.json").write_text(
                        json.dumps(record, indent=2), encoding="utf-8"
                    )
                    results[scenario][product].append(record)

        summaries = {s: summarise(s, results[s]) for s in SCENARIOS}
        report = {
            "disclosure": disclosure,
            "calibration": calibration,
            "results": results,
            "summaries": summaries,
        }
        (outdir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        for scenario, summary in summaries.items():
            log(f"[gaps] {scenario}: {json.dumps(summary['gaps'])}")
        log(f"report: {outdir / 'report.json'}")
    finally:
        if not args.keep:
            for name in [f"h3bench-{p}" for p in PRODUCTS] + ["h3bench-origin", "h3bench-sink"]:
                docker_rm(name)
            subprocess.run(["docker", "network", "rm", NET], capture_output=True)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001 - the harness must fail loudly, not guess
        print(f"error: {exc}", file=sys.stderr)
        raise
