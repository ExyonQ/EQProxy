#!/usr/bin/env python3
"""HTTP/3 close classification E2E against the **built release binary**.

The question this harness answers: a normal `CONNECTION_CLOSE` (QUIC
application code `0`, or `H3_NO_ERROR` = `0x0100`, RFC 9114 §8.1) ends a
session and must not log anything; a real error (an HTTP/3 protocol error
code) must still be counted and logged. Both are checked on the real binary
with `aioquic` as the client (independent QUIC + h3 + QPACK stack), and the
counters in the periodic `METRICS` line are read back from `proxy.log`.

Reproduce (from the repository root):

    python3 -m venv /tmp/h3venv
    /tmp/h3venv/bin/pip install aioquic==1.2.0
    cargo build --release -p eqproxy-cli
    /tmp/h3venv/bin/python docs/evidence/v07-h3-close/run.py

Results are written next to this file under `run-<UTC>/`.
"""

import asyncio
import hashlib
import json
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration

# The origin server, the h3 client and the port helper are the ones the
# HTTP/3 E2E already uses: a real asyncio HTTP/1.1 origin and a real h3
# client, not a stand-in for either.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "v07-http3"))
import run as h3run  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
BINARY = ROOT / "target" / "release" / "eqproxy"
CERT = h3run.CERT
KEY = h3run.KEY
WAIT = 15.0

H3_WARN = "HTTP/3"


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def parse_counters(text: str, key: str):
    """Reads the last `h3[clean_closes=N connection_errors=M]` pair."""
    matches = re.findall(
        rf"h3\[clean_closes=(\d+) connection_errors=(\d+)\]",
        text,
    )
    if not matches:
        return None
    clean, errors = matches[-1]
    return int(clean), int(errors)


def warn_lines(text: str) -> list[str]:
    return [
        line
        for line in text.splitlines()
        if line.startswith("WARN") and H3_WARN in line
    ]


async def wait_for_counters(path: Path, clean: int, errors: int) -> tuple[int, int]:
    """Waits until the binary itself reports the expected counters.

    The counters come from the binary's own `METRICS` line: the close is
    observed by the accept loop asynchronously, so polling the process output
    is the honest signal (a sleep would only guess).
    """
    deadline = time.time() + WAIT
    last = (-1, -1)
    while time.time() < deadline:
        text = path.read_text(errors="replace")
        seen = parse_counters(text, "h3")
        if seen is not None:
            last = seen
            if seen[0] >= clean and seen[1] >= errors:
                return seen
        await asyncio.sleep(0.05)
    raise AssertionError(
        f"counters never reached clean>={clean} errors>={errors}; last seen {last}"
    )


async def main() -> int:
    if not BINARY.exists():
        print(f"missing binary: {BINARY}; run cargo build --release -p eqproxy-cli")
        return 1

    outdir = Path(__file__).resolve().parent / f"run-{utc_stamp()}"
    outdir.mkdir(parents=True, exist_ok=True)

    origin = h3run.Origin()
    origin_port = await origin.start()
    proxy_port = h3run.free_port()
    config = f"""schema_version = 1

[listener.h3]
listen = "127.0.0.1:{proxy_port}"
mode = "http"
backend = "api"
quic = true
idle_timeout = "10s"

[listener.h3.tls]
cert = "{CERT}"
key = "{KEY}"
alpn = ["h2", "http/1.1"]

[backend.api]
server = "127.0.0.1:{origin_port}"
"""
    config_path = outdir / "eqproxy.toml"
    config_path.write_text(config)

    plan = subprocess.run(
        [str(BINARY), "config", "plan", "--config", str(config_path)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    (outdir / "plan.txt").write_text(plan.stdout + plan.stderr)

    log_path = outdir / "proxy.log"
    log = open(log_path, "wb")
    started = time.time()
    proxy = subprocess.Popen(
        [str(BINARY), "run", "--config", str(config_path), "--metrics-interval", "200ms"],
        stdout=log,
        stderr=log,
    )

    deadline = time.time() + WAIT
    while time.time() < deadline:
        text = log_path.read_text(errors="replace")
        if f"listening on 127.0.0.1:{proxy_port}" in text:
            break
        if proxy.poll() is not None:
            print(log_path.read_text(errors="replace"))
            return 1
        await asyncio.sleep(0.05)
    else:
        print("proxy did not report its listener in time")
        proxy.kill()
        return 1

    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    configuration.load_verify_locations(cafile=str(CERT))
    configuration.server_name = "localhost"

    failures: list[str] = []
    steps: list[dict] = []

    def client_factory():
        return connect(
            "127.0.0.1",
            proxy_port,
            configuration=configuration,
            create_protocol=h3run.H3Client,
            wait_connected=True,
        )

    # 1. A served session closed normally (aioquic sends application code 0).
    async with client_factory() as client:
        answer = await h3run.journey(client, "clean_after_request", b"GET", b"/hello")
        if answer["status"] != 200 or answer["body_text"] != "hello from origin":
            failures.append(f"GET /hello: {answer['status']} {answer['body_text']!r}")
        client.close(error_code=0, reason_phrase="done")
        await asyncio.sleep(0.05)
        await wait_for_counters(log_path, 1, 0)
        steps.append(
            {
                "step": "clean_close_after_request",
                "close_code": 0,
                "status": answer["status"],
                "body_text": answer["body_text"],
            }
        )
        text = log_path.read_text(errors="replace")
        if warn_lines(text):
            failures.append(f"a normal close logged a WARN: {warn_lines(text)}")

    # 2. H3_NO_ERROR (0x0100) with no request: the session ends before any
    #    stream, which is the same normal end.
    async with client_factory() as client:
        client.close(error_code=0x0100, reason_phrase="bye")
        await asyncio.sleep(0.05)
        await wait_for_counters(log_path, 2, 0)
        text = log_path.read_text(errors="replace")
        if warn_lines(text):
            failures.append(f"H3_NO_ERROR logged a WARN: {warn_lines(text)}")
        steps.append({"step": "h3_no_error_close", "close_code": 0x0100, "warn": 0})

    # 3. A real HTTP/3 protocol error is never swallowed: counted, logged once.
    async with client_factory() as client:
        client.close(error_code=0x0101, reason_phrase="protocol error")
        await asyncio.sleep(0.05)
        await wait_for_counters(log_path, 2, 1)
        text = log_path.read_text(errors="replace")
        warns = warn_lines(text)
        if len(warns) != 1:
            failures.append(f"expected exactly one WARN for the protocol error, got {warns}")
        elif "H3_GENERAL_PROTOCOL_ERROR" not in warns[0]:
            failures.append(f"the WARN does not name the cause: {warns[0]!r}")
        steps.append({"step": "protocol_error_close", "close_code": 0x0101, "warns": warns})

    # 4. The listener keeps serving after both kinds of end.
    async with client_factory() as client:
        after = await h3run.journey(client, "served_after_closes", b"GET", b"/hello")
        if after["status"] != 200 or after["body_text"] != "hello from origin":
            failures.append(
                f"GET /hello after closes: {after['status']} {after['body_text']!r}"
            )
        client.close(error_code=0, reason_phrase="done")
        await asyncio.sleep(0.05)
        await wait_for_counters(log_path, 3, 1)
        steps.append(
            {
                "step": "served_after_closes",
                "status": after["status"],
                "body_text": after["body_text"],
            }
        )
    await asyncio.sleep(0.2)

    proxy.send_signal(signal.SIGINT)
    try:
        code = proxy.wait(timeout=WAIT)
    except subprocess.TimeoutExpired:
        proxy.kill()
        code = proxy.wait()
    log.close()
    elapsed = time.time() - started

    text = log_path.read_text(errors="replace")
    final_metrics = next(
        (line for line in reversed(text.splitlines()) if line.startswith("METRICS ")),
        "",
    )
    final_counters = parse_counters(final_metrics, "h3")
    if final_counters != (3, 1):
        failures.append(f"final h3 counters {final_counters} != (3, 1): {final_metrics!r}")
    if "tls_failures=0" not in final_metrics:
        failures.append(f"unexpected TLS failures in {final_metrics!r}")
    if "proxied=2" not in final_metrics:
        failures.append(f"the two GETs were not proxied: {final_metrics!r}")
    if code != 0:
        failures.append(f"the proxy exited with {code} on SIGINT")
    warns = warn_lines(text)
    if len(warns) != 1:
        failures.append(f"final WARN count {len(warns)} (only the protocol error may log)")

    await origin.stop()
    origin_seen = [request["head"].split("\r\n", 1)[0] for request in origin.requests]

    payload = {
        "date_utc": datetime.now(timezone.utc).isoformat(),
        "binary": str(BINARY),
        "binary_sha256": hashlib.sha256(BINARY.read_bytes()).hexdigest(),
        "client": "aioquic",
        "proxy_port": proxy_port,
        "origin_port": origin_port,
        "proxy_exit": code,
        "wall_seconds": round(elapsed, 2),
        "steps": steps,
        "warn_lines": warns,
        "final_metrics": final_metrics,
        "origin_requests": origin_seen,
        "plan_exit": plan.returncode,
        "failures": failures,
    }
    (outdir / "results.json").write_text(json.dumps(payload, indent=2) + "\n")

    summary = [
        f"binary          {BINARY}",
        f"sha256          {payload['binary_sha256']}",
        f"client          aioquic (independent QUIC + h3 implementation)",
        f"proxy exit      {code}",
        f"wall            {elapsed:.2f} s",
        f"plan exit       {plan.returncode}",
        f"final metrics   {final_metrics}",
        f"WARN lines      {len(warns)}",
    ]
    for line in warns:
        summary.append(f"  {line}")
    summary.append("verdict         " + ("PASS" if not failures else "FAIL"))
    for failure in failures:
        summary.append(f"  - {failure}")
    (outdir / "summary.txt").write_text("\n".join(summary) + "\n")
    print("\n".join(summary))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
