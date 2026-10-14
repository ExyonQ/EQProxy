#!/usr/bin/env python3
"""Phase 2c first benchmarks: S-TCP-01, S-H1-01, S-TLS-01, EQProxy vs haproxy 3.4.6.

Honest-plan harness (BENCHMARK_PLAN.md): same host, same backends, same
topology for both products. Backends (TCP echo + HTTP/1.1 1 KiB origin) and
both proxies run as containers on one user-defined bridge network; load
generators run on the host against published proxy ports. Full configs are
stored with the raw data.

EQProxy requires literal IP:PORT backend addresses (hostnames are rejected
by design), so the harness resolves the backend container IP and injects it;
haproxy uses the same literal IP for symmetry.

Outputs one JSON document on stdout: disclosure + per-scenario repetitions
with raw RPS/latency numbers. The caller redirects it to the evidence dir.

Requires: docker, python3, oha (for HTTP scenarios).
"""

import asyncio
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time

HAPROXY_IMAGE = "haproxy:3.4.6"
PY_IMAGE = "python:3.14-slim"
NET = "bench2c"
ECHO_PORT = 19001
ORIGIN_PORT = 19002
EQ_TCP, EQ_HTTP, EQ_TLS = 19101, 19102, 19103
HA_TCP, HA_HTTP, HA_TLS = 19201, 19202, 19203
PAYLOAD = 1024  # 1 KiB, per S-H1-01 / S-TLS-01
OHA_SECS = 10
REPS = 5
TCP_CONNS = 32
TCP_MSGS_PER_CONN = 300


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


async def tcp_worker(port, n_msgs, payload, latencies):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        for _ in range(n_msgs):
            t0 = time.perf_counter()
            writer.write(payload)
            await writer.drain()
            await reader.readexactly(len(payload))
            latencies.append((time.perf_counter() - t0) * 1000.0)
    finally:
        writer.close()


async def run_tcp_scenario(port):
    payload = os.urandom(PAYLOAD)
    await tcp_worker(port, 10, payload, [])  # warm-up, discarded
    latencies: list = []
    t0 = time.perf_counter()
    await asyncio.gather(*[tcp_worker(port, TCP_MSGS_PER_CONN, payload, latencies) for _ in range(TCP_CONNS)])
    dt = time.perf_counter() - t0
    latencies.sort()
    n = len(latencies)

    def pct(p):
        return latencies[min(n - 1, int(n * p / 100))]

    return {
        "ops": n,
        "seconds": round(dt, 3),
        "rps": round(n / dt, 1),
        "p50_ms": round(pct(50), 3),
        "p95_ms": round(pct(95), 3),
        "p99_ms": round(pct(99), 3),
    }


def run_oha(url, insecure=False):
    base = ["oha", "-z", f"{OHA_SECS}s", "-c", "50", "--no-tui", "--output-format", "json"]
    if insecure:
        base.append("--insecure")
    sh(base + [url], timeout=OHA_SECS + 60)  # warm-up, discarded
    r = sh(base + [url], timeout=OHA_SECS + 60)
    if r.returncode != 0:
        raise RuntimeError(f"oha failed: {r.stderr[-2000:]}")
    data = json.loads(r.stdout)
    dist = data.get("latencyPercentiles") or {}
    summary = data.get("summary", {}) or {}
    rps = (data.get("rps") or {}).get("mean")
    if rps is None:
        rps = summary.get("requestsPerSec")

    def ms(key):
        v = dist.get(key)
        return round(v * 1000.0, 3) if v is not None else None

    return {
        "requests_per_sec": round(rps, 1) if rps is not None else None,
        "p50_ms": ms("p50"),
        "p95_ms": ms("p95"),
        "p99_ms": ms("p99"),
        "total_requests": summary.get("total"),
        "success_rate": summary.get("successRate"),
        "status_code_distribution": data.get("statusCodeDistribution"),
        "error_distribution": data.get("errorDistribution"),
    }


EQ_TOML_TCP = """schema_version = 1
shutdown_grace = "5s"
[listener.web]
listen = "0.0.0.0:{port}"
backend = "api"
mode = "tcp"
maxconn = 4096
[backend.api]
server = "{host}:19001"
"""

EQ_TOML_HTTP = """schema_version = 1
shutdown_grace = "5s"
[listener.web]
listen = "0.0.0.0:{port}"
backend = "api"
mode = "http"
maxconn = 4096
[backend.api]
server = "{host}:19002"
"""

EQ_TOML_TLS = """schema_version = 1
shutdown_grace = "5s"
[listener.web]
listen = "0.0.0.0:{port}"
backend = "api"
mode = "http"
maxconn = 4096
[listener.web.tls]
cert = "/etc/eqproxy/cert.pem"
key = "/etc/eqproxy/key.pem"
alpn = ["http/1.1"]
[backend.api]
server = "{host}:19002"
"""

HA_TCP_CFG = """global
  log stdout format raw local0
defaults
  log global
  timeout connect 5s
  timeout client 60s
  timeout server 60s
listen tcp_in
  bind *:PORT
  mode tcp
  server s1 HOST:19001
"""

HA_HTTP_CFG = """global
  log stdout format raw local0
defaults
  log global
  mode http
  option httplog
  option http-keep-alive
  timeout connect 5s
  timeout client 60s
  timeout server 60s
  timeout http-request 5s
frontend http_in
  bind *:PORT
  default_backend origin
backend origin
  server s1 HOST:19002 maxconn 4096
"""

HA_TLS_CFG = """global
  log stdout format raw local0
  ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384
defaults
  log global
  mode http
  option httplog
  option http-keep-alive
  timeout connect 5s
  timeout client 60s
  timeout server 60s
  timeout http-request 5s
frontend tls_in
  bind *:PORT ssl crt /usr/local/etc/haproxy/certs/combined.pem alpn h1,http/1.1
  default_backend origin
backend origin
  server s1 HOST:19002 maxconn 4096
"""


def docker_run(name, image, ports, mounts, extra=()):
    sh(["docker", "rm", "-f", name], timeout=30)
    cmd = ["docker", "run", "-d", "--name", name, "--network", NET]
    for hp, cp in ports:
        cmd += ["-p", f"127.0.0.1:{hp}:{cp}"]
    for src, dst, ro in mounts:
        cmd += ["-v", f"{src}:{dst}{':ro' if ro else ''}"]
    cmd += [image] + list(extra)
    r = sh(cmd, timeout=120)
    if r.returncode != 0:
        raise RuntimeError(f"docker run {name} failed: {r.stderr[-2000:]}")
    time.sleep(2)
    r = sh(["docker", "inspect", "-f", "{{.State.Running}}", name], timeout=30)
    if r.stdout.strip() != "true":
        logs = sh(["docker", "logs", name], timeout=30)
        raise RuntimeError(f"container {name} not running: {logs.stdout[-2000:]} {logs.stderr[-2000:]}")
    return name


def main():
    for tool in ("docker", "oha"):
        if not shutil.which(tool):
            print(f"missing required tool: {tool}", file=sys.stderr)
            sys.exit(2)
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    tmp = tempfile.mkdtemp(prefix="bench2c-")
    fixtures = os.path.join(repo, "eqproxy-net", "tests", "fixtures")

    ha_ver = sh(["docker", "run", "--rm", HAPROXY_IMAGE, "haproxy", "-vv"], timeout=60).stdout
    eq_ver = sh([os.path.join(repo, "target", "release", "eqproxy"), "--help"], timeout=30).stdout

    eq_image = "eqproxy-bench:phase2c"
    r = sh(["docker", "build", "-f", "docker/Dockerfile", "-t", eq_image, "."], timeout=900, cwd=repo)
    if r.returncode != 0:
        raise RuntimeError(f"eqproxy image build failed: {r.stderr[-3000:]}")

    sh(["docker", "network", "rm", NET], timeout=30)
    r = sh(["docker", "network", "create", NET], timeout=60)
    if r.returncode != 0:
        raise RuntimeError(f"network create failed: {r.stderr[-1000:]}")

    containers = []
    try:
        containers.append(
            docker_run(
                "bench2c-back", PY_IMAGE, [],
                [(os.path.join(repo, "scripts", "bench_backends.py"), "/srv/backends.py", True)],
                ["python", "/srv/backends.py"],
            )
        )
        # Literal backend IP: EQProxy rejects hostnames for server addrs.
        host_ip = sh(
            ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", "bench2c-back"],
            timeout=30,
        ).stdout.strip()
        if not host_ip:
            raise RuntimeError("backend container has no IP")
        # Sanity: backend echo reachable from another container before benching.
        r = sh(
            ["docker", "run", "--rm", "--network", NET, PY_IMAGE, "python", "-c",
             f"import socket;s=socket.create_connection(('{host_ip}',19001),timeout=5);s.sendall(b'q');print(s.recv(1))"],
            timeout=60,
        )
        if r.returncode != 0 or "b'q'" not in r.stdout:
            raise RuntimeError(f"backend echo not reachable: {r.stdout[-500:]} {r.stderr[-500:]}")

        certs = os.path.join(tmp, "certs")
        os.makedirs(certs)
        combined = os.path.join(certs, "combined.pem")
        with open(combined, "wb") as f:
            for name in ("cert.pem", "key.pem"):
                f.write(open(os.path.join(fixtures, name), "rb").read())

        paths = {}
        for name, template, port in (
            ("eq-tcp.toml", EQ_TOML_TCP, EQ_TCP),
            ("eq-http.toml", EQ_TOML_HTTP, EQ_HTTP),
            ("eq-tls.toml", EQ_TOML_TLS, EQ_TLS),
        ):
            p = os.path.join(tmp, name)
            open(p, "w").write(template.format(port=port, host=host_ip))
            paths[name] = p
        for name, template, port in (
            ("ha-tcp.cfg", HA_TCP_CFG, 19301),
            ("ha-http.cfg", HA_HTTP_CFG, 19302),
            ("ha-tls.cfg", HA_TLS_CFG, 19303),
        ):
            p = os.path.join(tmp, name)
            open(p, "w").write(template.replace("PORT", str(port)).replace("HOST", host_ip))
            paths[name] = p

        eq_mounts = [
            (os.path.join(fixtures, "cert.pem"), "/etc/eqproxy/cert.pem", True),
            (os.path.join(fixtures, "key.pem"), "/etc/eqproxy/key.pem", True),
        ]
        containers.append(
            docker_run("eq-tcp", eq_image, [(EQ_TCP, EQ_TCP)],
                       [(paths["eq-tcp.toml"], "/etc/eqproxy/tcp.toml", True)],
                       ["run", "--config", "/etc/eqproxy/tcp.toml"])
        )
        containers.append(
            docker_run("eq-http", eq_image, [(EQ_HTTP, EQ_HTTP)],
                       [(paths["eq-http.toml"], "/etc/eqproxy/http.toml", True)],
                       ["run", "--config", "/etc/eqproxy/http.toml"])
        )
        containers.append(
            docker_run("eq-tls", eq_image, [(EQ_TLS, EQ_TLS)],
                       [(paths["eq-tls.toml"], "/etc/eqproxy/tls.toml", True)] + eq_mounts,
                       ["run", "--config", "/etc/eqproxy/tls.toml"])
        )
        containers.append(
            docker_run("ha-tcp", HAPROXY_IMAGE, [(HA_TCP, 19301)],
                       [(paths["ha-tcp.cfg"], "/usr/local/etc/haproxy/haproxy.cfg", True)])
        )
        containers.append(
            docker_run("ha-http", HAPROXY_IMAGE, [(HA_HTTP, 19302)],
                       [(paths["ha-http.cfg"], "/usr/local/etc/haproxy/haproxy.cfg", True)])
        )
        containers.append(
            docker_run("ha-tls", HAPROXY_IMAGE, [(HA_TLS, 19303)], [
                (paths["ha-tls.cfg"], "/usr/local/etc/haproxy/haproxy.cfg", True),
                (combined, "/usr/local/etc/haproxy/certs/combined.pem", True),
            ])
        )

        results = {"S-TCP-01": {}, "S-H1-01": {}, "S-TLS-01": {}}
        for _ in range(REPS):
            results["S-TCP-01"].setdefault("eqproxy", []).append(asyncio.run(run_tcp_scenario(EQ_TCP)))
            results["S-TCP-01"].setdefault("haproxy", []).append(asyncio.run(run_tcp_scenario(HA_TCP)))
        for _ in range(REPS):
            results["S-H1-01"].setdefault("eqproxy", []).append(run_oha(f"http://127.0.0.1:{EQ_HTTP}/"))
            results["S-H1-01"].setdefault("haproxy", []).append(run_oha(f"http://127.0.0.1:{HA_HTTP}/"))
        for _ in range(REPS):
            results["S-TLS-01"].setdefault("eqproxy", []).append(run_oha(f"https://127.0.0.1:{EQ_TLS}/", insecure=True))
            results["S-TLS-01"].setdefault("haproxy", []).append(run_oha(f"https://127.0.0.1:{HA_TLS}/", insecure=True))
    finally:
        for c in containers:
            sh(["docker", "rm", "-f", c], timeout=60)
        sh(["docker", "network", "rm", NET], timeout=60)

    def summarize(runs, key):
        vals = sorted(r[key] for r in runs if r.get(key) is not None)
        if not vals:
            return {"runs": runs, "summary": None}
        return {"runs": runs, "summary": {"median": vals[len(vals) // 2], "min": vals[0], "max": vals[-1]}}

    doc = {
        "disclosure": {
            "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "eqproxy_commit": sh(["git", "rev-parse", "HEAD"], timeout=30, cwd=repo).stdout.strip(),
            "eqproxy_help": eq_ver.splitlines()[:5],
            "haproxy_image": HAPROXY_IMAGE,
            "haproxy_vv": ha_ver.splitlines()[:12],
            "hardware": {
                "cpu": sh(["sysctl", "-n", "machdep.cpu.brand_string"], timeout=30).stdout.strip(),
                "cores_logical": os.cpu_count(),
                "ram_bytes": sh(["sysctl", "-n", "hw.memsize"], timeout=30).stdout.strip(),
                "platform": platform.platform(),
                "docker": sh(["docker", "--version"], timeout=30).stdout.strip(),
            },
            "topology": "one Mac host; backends + both proxies in Docker Desktop containers on one bridge "
            "network, generators on host loopback via published ports. Limitation: VM hop for all "
            "containerized roles, no CPU affinity.",
            "backend_ip": host_ip,
            "generator": {
                "tcp": f"this script (asyncio, {TCP_CONNS} conns x {TCP_MSGS_PER_CONN} x 1 KiB echo)",
                "http": "oha 1.14.0, -z 10s -c 50, 1 KiB body, keep-alive",
                "tls": "oha 1.14.0 --insecure, -z 10s -c 50, test cert (SAN 127.0.0.1), ALPN h1",
            },
            "repetitions": REPS,
            "duration_per_rep": f"{OHA_SECS}s (oha)",
            "eqproxy_configs": {k: open(v).read() for k, v in paths.items() if k.startswith("eq-")},
            "haproxy_configs": {k: open(v).read() for k, v in paths.items() if k.startswith("ha-")},
            "warmup": "one short run per scenario per proxy, discarded",
        },
        "scenarios": {
            sid: {proxy: summarize(runs, "rps" if sid == "S-TCP-01" else "requests_per_sec") for proxy, runs in per.items()}
            for sid, per in results.items()
        },
        "latencies": {
            sid: {proxy: {k: summarize(runs, k)["summary"] for k in keys} for proxy, runs in per.items()}
            for (sid, per), keys in [
                (("S-TCP-01", results["S-TCP-01"]), ["p50_ms", "p95_ms", "p99_ms"]),
                (("S-H1-01", results["S-H1-01"]), ["p50_ms", "p95_ms", "p99_ms"]),
                (("S-TLS-01", results["S-TLS-01"]), ["p50_ms", "p95_ms", "p99_ms"]),
            ]
        },
    }
    print(json.dumps(doc, indent=2))


if __name__ == "__main__":
    main()
