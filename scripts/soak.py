#!/usr/bin/env python3
"""Soak harness for EQProxy (24h gate): real load, real binary, measured RSS.

The harness is self-contained (stdlib only) and exercises the full v0.5
feature set in production shape: HTTP listener with bounded queue, safe
retries, active + passive health checks and forwarded headers.

Usage:
    python3 soak.py --binary ./target/release/eqproxy --duration 24h \
        --rate 200 --workers 64 --out results/

Published budgets (checked at the end, verdict in summary.txt/json):
    * steady RSS (avg after 5 min warmup) <= 64 MiB
    * peak RSS <= 128 MiB
    * error rate == 0% (no failed exchanges, no non-200 answers)
    * clean SIGINT shutdown (exit code 0)
"""

import argparse
import asyncio
import csv
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time

BUDGET_STEADY_RSS_MIB = 64
BUDGET_PEAK_RSS_MIB = 128
WARMUP_SECONDS = 300
RSS_SAMPLE_SECONDS = 30

# Latency histogram upper bounds in milliseconds (last bucket: +inf).
LATENCY_BUCKETS_MS = [
    0.25, 0.5, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192,
]

CONFIG_TEMPLATE = """schema_version = 1
shutdown_grace = "30s"

[listener.web]
listen = "127.0.0.1:{listen_port}"
backend = "api"
mode = "http"
maxconn = 4096
connect_timeout = "2s"
idle_timeout = "30s"
client_header_timeout = "5s"
server_header_timeout = "10s"
forwarded_headers = "append"

[backend.api]
servers = [
  {{ addr = "127.0.0.1:{backend_a_port}", weight = 1 }},
  {{ addr = "127.0.0.1:{backend_b_port}", weight = 1 }},
]
maxqueue = 256
timeout_queue = "500ms"
retries = 1

[backend.api.health_check]
type = "tcp"
interval = "5s"
timeout = "2s"
fall = 3
rise = 2
passive = true
"""


def parse_duration(text: str) -> float:
    match = re.fullmatch(r"(\d+)([smh])", text)
    if not match:
        raise argparse.ArgumentTypeError(f"duration like 30m / 24h, got {text!r}")
    value, unit = int(match.group(1)), match.group(2)
    return value * {"s": 1, "m": 60, "h": 3600}[unit]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Backend:
    """Minimal real HTTP/1.1 keep-alive backend (answers 200 'ok')."""

    def __init__(self) -> None:
        self.requests = 0
        self.server: asyncio.base_events.Server | None = None
        self.port = 0

    async def start(self) -> None:
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                length = 0
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        length = int(line.split(b":", 1)[1])
                if length:
                    await reader.readexactly(length)
                writer.write(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                await writer.drain()
                self.requests += 1
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.LimitOverrunError):
            pass
        finally:
            writer.close()

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()


class Latency:
    def __init__(self) -> None:
        self.count = 0
        self.total_ms = 0.0
        self.buckets = [0] * (len(LATENCY_BUCKETS_MS) + 1)

    def observe(self, ms: float) -> None:
        self.count += 1
        self.total_ms += ms
        for index, bound in enumerate(LATENCY_BUCKETS_MS):
            if ms <= bound:
                self.buckets[index] += 1
                return
        self.buckets[-1] += 1

    def percentile_ms(self, fraction: float) -> float:
        if self.count == 0:
            return 0.0
        target = self.count * fraction
        seen = 0
        for index, hits in enumerate(self.buckets):
            seen += hits
            if seen >= target:
                return LATENCY_BUCKETS_MS[index] if index < len(LATENCY_BUCKETS_MS) else float("inf")
        return float("inf")

    def avg_ms(self) -> float:
        return self.total_ms / self.count if self.count else 0.0


class LoadWorker:
    """One keep-alive connection, paced to contribute rate/workers rps."""

    def __init__(self, port: int, period: float, stats: dict, latency: Latency) -> None:
        self.port = port
        self.period = period
        self.stats = stats
        self.latency = latency

    async def run(self, stop: asyncio.Event) -> None:
        reader = writer = None
        next_at = time.monotonic()
        while not stop.is_set():
            next_at += self.period
            try:
                if writer is None:
                    reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
                started = time.monotonic()
                writer.write(b"GET /soak HTTP/1.1\r\nhost: soak\r\n\r\n")
                await writer.drain()
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
                status = head.split(b" ", 2)[1]
                length = 0
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        length = int(line.split(b":", 1)[1])
                if length:
                    await asyncio.wait_for(reader.readexactly(length), timeout=10)
                elapsed_ms = (time.monotonic() - started) * 1000
                if status == b"200":
                    self.stats["ok"] += 1
                    self.latency.observe(elapsed_ms)
                else:
                    self.stats["bad_status"] += 1
            except Exception:
                self.stats["errors"] += 1
                if writer is not None:
                    writer.close()
                    reader = writer = None
            delay = next_at - time.monotonic()
            if delay > 0:
                try:
                    await asyncio.wait_for(stop.wait(), timeout=delay)
                except asyncio.TimeoutError:
                    pass
        if writer is not None:
            writer.close()


def read_rss_kib(pid: int) -> tuple[int, float]:
    """(VmRSS in KiB, CPU seconds) of the proxy process."""
    rss_kib, cpu = 0, 0.0
    try:
        with open(f"/proc/{pid}/status", encoding="ascii") as status:
            for line in status:
                if line.startswith("VmRSS:"):
                    rss_kib = int(line.split()[1])
        with open(f"/proc/{pid}/stat", encoding="ascii") as stat:
            fields = stat.read().rsplit(")", 1)[1].split()
            ticks = int(fields[11]) + int(fields[12])
            cpu = ticks / os.sysconf("SC_CLK_TCK")
    except OSError:
        pass
    return rss_kib, cpu


async def run_soak(args, out_dir: str) -> dict:
    backend_a, backend_b = Backend(), Backend()
    await backend_a.start()
    await backend_b.start()

    listen_port = free_port()
    config_path = os.path.join(out_dir, "soak.toml")
    with open(config_path, "w", encoding="utf-8") as config:
        config.write(
            CONFIG_TEMPLATE.format(
                listen_port=listen_port,
                backend_a_port=backend_a.port,
                backend_b_port=backend_b.port,
            )
        )

    proxy_log = open(os.path.join(out_dir, "eqproxy.log"), "w", encoding="utf-8")
    proxy = subprocess.Popen(
        [args.binary, "run", "--config", config_path],
        stdout=proxy_log,
        stderr=subprocess.STDOUT,
    )

    # Readiness: the listener must actually answer TCP (banner != readiness).
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if proxy.poll() is not None:
            raise RuntimeError("eqproxy exited before serving; see eqproxy.log")
        try:
            with socket.create_connection(("127.0.0.1", listen_port), timeout=1):
                break
        except OSError:
            time.sleep(0.2)
    else:
        raise RuntimeError("eqproxy never accepted a connection; see eqproxy.log")

    stats = {"ok": 0, "errors": 0, "bad_status": 0}
    latency = Latency()
    stop = asyncio.Event()
    period = args.workers / args.rate
    workers = [
        LoadWorker(listen_port, period, stats, latency) for _ in range(args.workers)
    ]
    tasks = [asyncio.create_task(worker.run(stop)) for worker in workers]

    rss_path = os.path.join(out_dir, "rss.csv")
    samples: list[tuple[float, int, float]] = []
    started = time.monotonic()
    next_sample = started
    with open(rss_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["elapsed_s", "rss_kib", "cpu_s", "requests_ok"])
        while time.monotonic() - started < args.duration:
            now = time.monotonic()
            if now >= next_sample:
                rss_kib, cpu = read_rss_kib(proxy.pid)
                samples.append((now - started, rss_kib, cpu))
                writer.writerow([int(now - started), rss_kib, round(cpu, 2), stats["ok"]])
                csv_file.flush()
                next_sample += RSS_SAMPLE_SECONDS
            await asyncio.sleep(min(1, max(0, next_sample - time.monotonic())))

    stop.set()
    await asyncio.gather(*tasks)
    proxy.send_signal(signal.SIGINT)
    try:
        exit_code = proxy.wait(timeout=60)
    except subprocess.TimeoutExpired:
        proxy.kill()
        exit_code = -9
    proxy_log.close()
    await backend_a.stop()
    await backend_b.stop()

    elapsed = time.monotonic() - started
    steady = [r for (t, r, _) in samples if t >= WARMUP_SECONDS]
    # Short runs never reach the warmup window: fall back to the average
    # of all samples and flag it, never report a silent 0.
    warmup_completed = bool(steady)
    if not steady:
        steady = [r for (_, r, _) in samples]
    steady_rss = sum(steady) / len(steady) if steady else 0
    peak_rss = max((r for (_, r, _) in samples), default=0)
    total = stats["ok"] + stats["errors"] + stats["bad_status"]
    error_rate = (stats["errors"] + stats["bad_status"]) / total if total else 1.0

    def mib(kib: float) -> float:
        return round(kib / 1024, 2)

    verdict = {
        "steady_rss_mib": mib(steady_rss),
        "peak_rss_mib": mib(peak_rss),
        "error_rate_pct": round(error_rate * 100, 4),
        "clean_shutdown": exit_code == 0,
        "budget_steady_rss_mib": BUDGET_STEADY_RSS_MIB,
        "budget_peak_rss_mib": BUDGET_PEAK_RSS_MIB,
    }
    # Honest verdict: unmeasured RSS (no /proc samples) can never pass.
    verdict["rss_measured"] = peak_rss > 0
    verdict["warmup_completed"] = warmup_completed
    verdict["pass"] = (
        verdict["rss_measured"]
        and verdict["steady_rss_mib"] <= BUDGET_STEADY_RSS_MIB
        and verdict["peak_rss_mib"] <= BUDGET_PEAK_RSS_MIB
        and verdict["error_rate_pct"] == 0.0
        and verdict["clean_shutdown"]
    )

    summary = {
        "binary": args.binary,
        "duration_requested_s": args.duration,
        "duration_actual_s": round(elapsed, 1),
        "target_rate_rps": args.rate,
        "workers": args.workers,
        "requests_ok": stats["ok"],
        "requests_errors": stats["errors"],
        "requests_bad_status": stats["bad_status"],
        "achieved_rps": round(stats["ok"] / elapsed, 2) if elapsed else 0,
        "latency_ms": {
            "avg": round(latency.avg_ms(), 3),
            "p50": latency.percentile_ms(0.50),
            "p95": latency.percentile_ms(0.95),
            "p99": latency.percentile_ms(0.99),
        },
        "backend_a_requests": backend_a.requests,
        "backend_b_requests": backend_b.requests,
        "proxy_exit_code": exit_code,
        "budgets": verdict,
        "host": {
            "uname": os.uname().sysname + " " + os.uname().release + " " + os.uname().machine,
            "cpus": os.cpu_count(),
        },
    }
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, help="path to the built eqproxy binary")
    parser.add_argument("--duration", type=parse_duration, default=parse_duration("24h"))
    parser.add_argument("--rate", type=float, default=200.0, help="target requests/second")
    parser.add_argument("--workers", type=int, default=64, help="concurrent keep-alive connections")
    parser.add_argument("--out", default="results", help="output directory")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)
    summary = asyncio.run(run_soak(args, args.out))

    with open(os.path.join(args.out, "summary.json"), "w", encoding="utf-8") as out:
        json.dump(summary, out, indent=2)
    budgets = summary["budgets"]
    lines = [
        "EQProxy soak summary",
        f"duration: {summary['duration_actual_s']}s of {summary['duration_requested_s']}s requested",
        f"requests: ok={summary['requests_ok']} errors={summary['requests_errors']} bad_status={summary['requests_bad_status']}",
        f"throughput: {summary['achieved_rps']} rps (target {summary['target_rate_rps']})",
        f"latency ms: avg={summary['latency_ms']['avg']} p50={summary['latency_ms']['p50']} p95={summary['latency_ms']['p95']} p99={summary['latency_ms']['p99']}",
        f"rss: steady={budgets['steady_rss_mib']} MiB (budget {budgets['budget_steady_rss_mib']}) peak={budgets['peak_rss_mib']} MiB (budget {budgets['budget_peak_rss_mib']}) measured={budgets['rss_measured']}",
        f"error rate: {budgets['error_rate_pct']}% (budget 0%)",
        f"shutdown: exit={summary['proxy_exit_code']} clean={budgets['clean_shutdown']}",
        f"VERDICT: {'PASS' if budgets['pass'] else 'FAIL'}",
    ]
    text = "\n".join(lines) + "\n"
    with open(os.path.join(args.out, "summary.txt"), "w", encoding="utf-8") as out:
        out.write(text)
    print(text)
    return 0 if budgets["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
