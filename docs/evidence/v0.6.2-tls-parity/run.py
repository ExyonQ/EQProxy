#!/usr/bin/env python3
"""TLS parity harness — glibc build vs static musl build, same host, same image base.

Measures, per architecture:
  * ECDSA P-256 termination under load (oha, 10 s, -c 50, N reps)
  * handshake rate: TLS 1.2 full vs resumed, TLS 1.3 full vs resumed
    (openssl s_time), plus the s_client verdict behind it
  * ALPN behaviour: what is negotiated by default, what happens when a client
    offers h2, and what the proxy does when the listener advertises h2

Both binaries run inside the *same* Debian base image, so the only variable is
the libc the binary was linked against (the earlier v0.6.1 report compared the
musl asset inside Debian against the musl asset inside scratch, which is a
different experiment; see the erratum in ../v0.6.1-parity/README.md).

Usage:
  python3 run.py --binary ./eqproxy --label glibc --arch amd64 --out glibc-amd64.json
"""

import argparse
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

PROBE_IMAGE = "eqprobe-tls:bookworm"
NET = "eqlsp-net"
SUBNET = "172.25.0.0/24"
BACK_IP = "172.25.0.10"
PROXY_IP = "172.25.0.20"
PORT = 19443
PORT_H2 = 19444


def run(cmd, check=True, stdin=None):
    proc = subprocess.run(
        cmd, shell=isinstance(cmd, str), capture_output=True, text=True, input=stdin
    )
    if check and proc.returncode != 0:
        raise SystemExit(
            f"command failed ({proc.returncode}): {cmd}\n{proc.stdout}\n{proc.stderr}"
        )
    return proc


def docker_cleanup():
    run(f"docker rm -f eqps-proxy eqps-proxy-h2 eqps-back >/dev/null 2>&1", check=False)
    run(f"docker network rm {NET} >/dev/null 2>&1", check=False)


def ensure_probe_image():
    if run(f"docker image inspect {PROBE_IMAGE}", check=False).returncode == 0:
        return
    dockerfile = (
        "FROM debian:bookworm-slim\n"
        "RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends "
        "openssl curl ca-certificates >/dev/null && rm -rf /var/lib/apt/lists/*\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "Dockerfile"), "w") as fh:
            fh.write(dockerfile)
        run(f"docker build -q -t {PROBE_IMAGE} {tmp}")


def make_cert(workdir):
    cert = os.path.join(workdir, "ec.crt")
    key = os.path.join(workdir, "ec.key")
    run(
        [
            "openssl", "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", key, "-out", cert, "-days", "3",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
    )
    return cert, key


def config(path, port, alpn, cert, key, plain=False):
    alpn_list = ", ".join(f'"{p}"' for p in alpn)
    tls = "" if plain else f"""[listener.web.tls]
cert = "/certs/ec.crt"
key = "/certs/ec.key"
alpn = [{alpn_list}]
"""
    body = f"""schema_version = 1
[listener.web]
listen = "0.0.0.0:{port}"
mode = "http"
backend = "api"
{tls}[backend.api]
server = "{BACK_IP}:80"
"""
    with open(path, "w") as fh:
        fh.write(body)


def proxy_image(workdir, binary, tag):
    shutil.copy(binary, os.path.join(workdir, "eqproxy"))
    os.chmod(os.path.join(workdir, "eqproxy"), 0o755)
    dockerfile = (
        "FROM debian:bookworm-slim\n"
        "COPY eqproxy /opt/eqproxy\n"
        "COPY ec.crt ec.key /certs/\n"
        'ENTRYPOINT ["/opt/eqproxy"]\n'
    )
    with open(os.path.join(workdir, "Dockerfile"), "w") as fh:
        fh.write(dockerfile)
    run(f"docker build -q -t {tag} {workdir}")


def oha_once(url, seconds):
    out = run(
        f"oha -z {seconds}s -c 50 --insecure --latency-correction "
        f"--output-format json {url}"
    ).stdout
    data = json.loads(out)
    return {
        "rps": data["summary"]["requestsPerSec"],
        "p50_ms": data["latencyPercentiles"]["p50"] * 1000,
        "p95_ms": data["latencyPercentiles"]["p95"] * 1000,
        "p99_ms": data["latencyPercentiles"]["p99"] * 1000,
        "success_rate": data["summary"]["successRate"],
        "status_codes": data["statusCodeDistribution"],
        "errors": data.get("errorDistribution") or {},
    }


def probe(script):
    """Runs a shell snippet inside the probe container on the harness network.

    Probe output is evidence, not a gate: a failing command is part of the
    result (e.g. curl exit 55 against an h2-only listener), so the exit status
    is captured instead of aborting the run.
    """
    wrapped = f"( {script} ) 2>&1; echo \"probe_exit=$?\""
    proc = run(
        ["docker", "run", "--rm", "--network", NET, PROBE_IMAGE, "sh", "-c", wrapped],
        check=False,
    )
    return (proc.stdout + proc.stderr).strip()


def s_time(tls, mode, seconds):
    out = probe(
        f"openssl s_time -connect {PROXY_IP}:{PORT} -{tls} -{mode} "
        f"-time {seconds} -www /dev/null 2>&1 | tail -1"
    )
    match = re.search(r"(\d+) connections in", out)
    return int(match.group(1)) if match else None


def session_check(tls):
    """Full handshake, save session, reconnect with it; report what happened."""
    script = f"""
echo Q | openssl s_client -connect {PROXY_IP}:{PORT} -servername localhost -{tls} -sess_out /tmp/s.pem >/dev/null 2>&1
if [ ! -s /tmp/s.pem ]; then echo "no-session-saved"; exit 0; fi
echo Q | openssl s_client -connect {PROXY_IP}:{PORT} -servername localhost -{tls} -sess_in /tmp/s.pem 2>&1 | grep -E "^(New|Reused)" | head -1
"""
    lines = [
        line
        for line in probe(script).splitlines()
        if line.startswith(("New", "Reused", "no-session-saved"))
    ]
    return lines[0] if lines else "no-verdict"


def capability_probes():
    brief = probe(
        f"echo Q | openssl s_client -connect {PROXY_IP}:{PORT} -servername localhost -brief "
        f"| grep -E 'Protocol version|Ciphersuite|Signature type'"
    )
    alpn_offer = probe(
        f"echo Q | openssl s_client -connect {PROXY_IP}:{PORT} -servername localhost -alpn h2 "
        f"| grep -E 'ALPN'"
    )
    http_default = probe(
        f"curl -sk --http2 -o /dev/null -w '%{{http_version}} %{{http_code}}' https://{PROXY_IP}:{PORT}/"
    )
    # Listener that advertises h2 only: what does the proxy do then?
    http_h2_only = probe(
        f"curl -sk --http2 -o /dev/null -w '%{{http_version}} %{{http_code}}' https://{PROXY_IP}:{PORT_H2}/"
    )
    alpn_h2_listener = probe(
        f"echo Q | openssl s_client -connect {PROXY_IP}:{PORT_H2} -servername localhost -alpn h2 "
        f"| grep -E 'ALPN'"
    )
    return {
        "handshake": brief.splitlines(),
        "client_offers_h2_alpn_result": alpn_offer,
        "curl_http2_against_alpn_http1.1": http_default,
        "alpn_h2_listener_negotiation": alpn_h2_listener,
        "curl_http2_against_alpn_h2": http_h2_only,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--label", required=True, choices=["glibc", "musl"])
    ap.add_argument("--arch", required=True, choices=["arm64", "amd64"])
    ap.add_argument("--reps", type=int, default=8)
    ap.add_argument("--seconds", type=int, default=10)
    ap.add_argument("--handshake-reps", type=int, default=5)
    ap.add_argument("--out", required=True)
    ap.add_argument(
        "--plain",
        action="store_true",
        help="control run: plain HTTP listener (no TLS), load only",
    )
    ap.add_argument(
        "--skip-handshakes",
        action="store_true",
        help="load only: used for interleaved A B B A blocks where the handshake "
        "rates are measured once per label",
    )
    args = ap.parse_args()

    workdir = tempfile.mkdtemp(prefix="eqps-")
    docker_cleanup()
    ensure_probe_image()
    make_cert(workdir)
    config(
        os.path.join(workdir, "http1.toml"),
        PORT,
        ["http/1.1"],
        "ec.crt",
        "ec.key",
        plain=args.plain,
    )
    config(os.path.join(workdir, "h2.toml"), PORT_H2, ["h2"], "ec.crt", "ec.key")
    tag = f"eqps-proxy-{args.label}-{args.arch}"
    proxy_image(workdir, args.binary, tag)

    run(f"docker network create --subnet {SUBNET} {NET} >/dev/null")
    run(f"docker run -d --network {NET} --ip {BACK_IP} --name eqps-back nginx:alpine >/dev/null")
    run(
        f"docker run -d --network {NET} --ip {PROXY_IP} --name eqps-proxy "
        f"-p {PORT}:{PORT} -v {workdir}/http1.toml:/c.toml:ro {tag} run --config /c.toml >/dev/null"
    )
    if not args.plain:
        run(
            f"docker run -d --network {NET} --ip {PROXY_IP.replace('.20', '.21')} --name eqps-proxy-h2 "
            f"-v {workdir}/h2.toml:/c.toml:ro {tag} run --config /c.toml >/dev/null"
        )
    time.sleep(4)

    url = f"{'http' if args.plain else 'https'}://127.0.0.1:{PORT}/"
    print(f"[{args.label}/{args.arch}] warming up")
    for _ in range(2):
        oha_once(url, 3)

    print(f"[{args.label}/{args.arch}] {args.reps} load reps")
    runs = [oha_once(url, args.seconds) for _ in range(args.reps)]

    print(f"[{args.label}/{args.arch}] handshake rates")
    rates = {}
    for tls in () if (args.skip_handshakes or args.plain) else ("tls1_2", "tls1_3"):
        new = [s_time(tls, "new", 5) for _ in range(args.handshake_reps)]
        reuse = [s_time(tls, "reuse", 5) for _ in range(args.handshake_reps)]
        rates[tls] = {
            "full": new,
            "resumed": reuse,
            "full_median": statistics.median(new) if all(new) else None,
            "resumed_median": statistics.median(reuse) if all(reuse) else None,
            "session_check": session_check(tls),
        }

    caps = {} if args.plain else capability_probes()
    docker_cleanup()

    summary = {
        "label": args.label,
        "arch": args.arch,
        "binary": os.path.abspath(args.binary),
        "binary_sha256": run(["sha256sum", args.binary], check=False).stdout.split()[0]
        if shutil.which("sha256sum")
        else run(["shasum", "-a", "256", args.binary]).stdout.split()[0],
        "reps": args.reps,
        "load": {
            "rps_median": statistics.median(r["rps"] for r in runs),
            "p50_ms_median": statistics.median(r["p50_ms"] for r in runs),
            "p95_ms_median": statistics.median(r["p95_ms"] for r in runs),
            "p99_ms_median": statistics.median(r["p99_ms"] for r in runs),
            "success_rate_min": min(r["success_rate"] for r in runs),
            "status_codes": sorted({k for r in runs for k in r["status_codes"]}),
            "runs": runs,
        },
        "handshakes": rates,
        "capabilities": caps,
    }
    with open(args.out, "w") as fh:
        json.dump(summary, fh, indent=2)
    print(json.dumps({k: summary[k] for k in ("label", "arch", "load", "handshakes", "capabilities")}, indent=2)[:4000])
    print(f"written {args.out}")


if __name__ == "__main__":
    sys.exit(main())
