#!/usr/bin/env python3
"""HTTP/3 (B-H2) E2E evidence against the **built release binary**.

The client is `aioquic` (an independent HTTP/3 implementation: QUIC + h3 +
QPACK + TLS 1.3), so a successful exchange proves the binary really speaks
HTTP/3 — there is no TCP/h1 fallback in that client. The origin is a real
asyncio HTTP/1.1 server; the proxy is `target/release/eqproxy` started from a
TOML configuration with `quic = true`.

Reproduce (from the repository root):

    python3 -m venv /tmp/h3venv
    /tmp/h3venv/bin/pip install aioquic==1.2.0
    cargo build --release -p eqproxy-cli
    /tmp/h3venv/bin/python docs/evidence/v07-http3/run.py

The second, independent client is `interop-quic-go/` (Go 1.26+, quic-go
v0.64.1, its own QUIC/h3/QPACK stack); the harness builds it in a temporary
directory and runs the same assertions:

    /tmp/h3venv/bin/python docs/evidence/v07-http3/run.py --client quic-go

Results are written next to this file under `run-<UTC>[-quic-go]/`.
"""

import argparse
import asyncio
import gzip
import hashlib
import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

ROOT = Path(__file__).resolve().parents[3]
CERT = ROOT / "eqproxy-net" / "tests" / "fixtures" / "cert.pem"
KEY = ROOT / "eqproxy-net" / "tests" / "fixtures" / "key.pem"
BINARY = ROOT / "target" / "release" / "eqproxy"
GO_DIR = Path(__file__).resolve().parent / "interop-quic-go"
WAIT = 15.0


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


class Origin:
    """Real HTTP/1.1 origin that records every request it served."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.server: asyncio.base_events.Server | None = None
        self.port = 0

    async def start(self) -> int:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self.port

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()

    async def _read_message(self, reader):
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), WAIT)
        text = head.decode("latin-1")
        lower = text.lower()
        body = b""
        if "transfer-encoding: chunked" in lower:
            pieces = []
            while True:
                line = await asyncio.wait_for(reader.readuntil(b"\r\n"), WAIT)
                size = int(line.strip().split(b";")[0], 16)
                if size == 0:
                    # Consume trailers up to the blank line.
                    while True:
                        trailer = await asyncio.wait_for(reader.readuntil(b"\r\n"), WAIT)
                        if trailer == b"\r\n":
                            break
                    break
                piece = await asyncio.wait_for(reader.readexactly(size), WAIT)
                pieces.append(piece)
                await asyncio.wait_for(reader.readexactly(2), WAIT)
            body = b"".join(pieces)
        elif "content-length:" in lower:
            length = 0
            for line in lower.split("\r\n"):
                if line.startswith("content-length:"):
                    length = int(line.split(":", 1)[1].strip())
            if length:
                body = await asyncio.wait_for(reader.readexactly(length), WAIT)
        return text, body

    async def _handle(self, reader, writer):
        try:
            head, body = await self._read_message(reader)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
            writer.close()
            return
        request_line = head.split("\r\n", 1)[0]
        path = request_line.split(" ")[1] if " " in request_line else "/"
        self.requests.append(
            {"head": head, "body_len": len(body), "body_md5": hashlib.md5(body).hexdigest()}
        )
        if path == "/hello":
            payload, status, ctype = b"hello from origin", 200, "text/plain"
            out = (
                f"HTTP/1.1 {status} OK\r\nContent-Type: {ctype}\r\n"
                f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
            ).encode() + payload
        elif path == "/echo":
            payload = f"{len(body)} bytes".encode()
            out = (
                f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
            ).encode() + payload
        elif path == "/trailers":
            out = (
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                b"5\r\nhello\r\n8\r\n chunked\r\n0\r\nx-origin: yes\r\n\r\n"
            )
        elif path == "/compress":
            payload = b"a" * 8192
            out = (
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                + f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()
                + payload
            )
        elif path == "/slow":
            await asyncio.sleep(0.3)
            out = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nslow"
        else:
            out = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        writer.write(out)
        await writer.drain()
        writer.close()


class H3Client(QuicConnectionProtocol):
    """Minimal h3 client over aioquic's QUIC connection."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.states: dict[int, dict] = {}
        self.waiters: dict[int, asyncio.Future] = {}

    def quic_event_received(self, event):
        for http_event in self.http.handle_event(event):
            stream_id = http_event.stream_id
            state = self.states.setdefault(
                stream_id,
                {"status": None, "headers": {}, "body": bytearray(), "trailers": {}, "ended": False},
            )
            if isinstance(http_event, HeadersReceived):
                if state["status"] is None:
                    for name, value in http_event.headers:
                        if name == b":status":
                            state["status"] = int(value)
                        elif not name.startswith(b":"):
                            state["headers"].setdefault(name.decode(), []).append(
                                value.decode()
                            )
                else:
                    for name, value in http_event.headers:
                        state["trailers"][name.decode()] = value.decode()
                if http_event.stream_ended:
                    state["ended"] = True
            elif isinstance(http_event, DataReceived):
                state["body"].extend(http_event.data)
                if http_event.stream_ended:
                    state["ended"] = True
            if state["ended"] and stream_id in self.waiters:
                waiter = self.waiters.pop(stream_id)
                if not waiter.done():
                    waiter.set_result(state)

    def start(self, method: bytes, path: bytes, headers=(), body=None, length=True):
        stream_id = self._quic.get_next_available_stream_id()
        request_headers = [
            (b":method", method),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
            (b":path", path),
        ]
        if body is not None and length:
            request_headers.append((b"content-length", str(len(body)).encode()))
        request_headers.extend(headers)
        self.http.send_headers(stream_id, request_headers, end_stream=body is None)
        if body is not None:
            self.http.send_data(stream_id, body, end_stream=True)
        self.transmit()
        waiter = self._loop.create_future()
        self.waiters[stream_id] = waiter
        return waiter


async def journey(client, name, method, path, headers=(), body=None, length=True):
    answer = await asyncio.wait_for(
        client.start(method, path, headers, body, length), WAIT
    )
    return {
        "journey": name,
        "status": answer["status"],
        "headers": answer["headers"],
        "body_len": len(answer["body"]),
        "body_md5": hashlib.md5(bytes(answer["body"])).hexdigest(),
        "body_text": bytes(answer["body"])[:64].decode("utf-8", "replace"),
        "trailers": answer["trailers"],
        "_body": bytes(answer["body"]),
    }


def run_go_client(proxy_port: int, outdir: Path) -> tuple[list[dict], dict]:
    """Builds and runs the quic-go client (second independent implementation).

    The client only performs the requests and returns JSON; the assertions
    below run on exactly the same fields as the aioquic journeys.
    """
    # Built in a temporary directory: the evidence keeps the source, the
    # build log and the binary hash, never a 10 MiB artifact.
    with tempfile.TemporaryDirectory(prefix="eqproxy-h3-go-") as tmp:
        binary = Path(tmp) / "interop-quic-go"
        build = subprocess.run(
            ["go", "build", "-trimpath", "-o", str(binary), "."],
            cwd=GO_DIR,
            capture_output=True,
            text=True,
            timeout=180,
        )
        (outdir / "go-build.log").write_text(build.stdout + build.stderr)
        if build.returncode != 0:
            raise RuntimeError(f"go build failed: {build.stderr.strip()}")

        run = subprocess.run(
            [str(binary), "-addr", f"127.0.0.1:{proxy_port}", "-cert", str(CERT)],
            capture_output=True,
            text=True,
            timeout=WAIT * 3,
        )
        (outdir / "go-client.log").write_text(run.stdout + run.stderr)
        if run.returncode != 0:
            raise RuntimeError(f"go client failed: {run.stderr.strip()}")
        binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    raw = json.loads(run.stdout)
    results = []
    for entry in raw:
        body = base64_decode(entry["body_b64"])
        results.append(
            {
                "journey": entry["journey"],
                "status": entry["status"],
                # Go canonicalizes header names; the checks below (shared with
                # aioquic) use lowercase keys, so normalize the shape here.
                "headers": {k.lower(): v for k, v in entry["headers"].items()},
                "body_len": len(body),
                "body_md5": hashlib.md5(body).hexdigest(),
                "body_text": body[:64].decode("utf-8", "replace"),
                # aioquic reports one string per trailer; Go reports a list.
                "trailers": {
                    k.lower(): (v[0] if v else "")
                    for k, v in (entry.get("trailers") or {}).items()
                },
                "error": entry.get("error", ""),
                "_body": body,
            }
        )
    module = subprocess.run(
        ["go", "list", "-m", "github.com/quic-go/quic-go"],
        cwd=GO_DIR,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout.strip()
    return results, {
        "build_exit": build.returncode,
        "binary_sha256": binary_hash,
        "module": module,
    }


def base64_decode(text: str) -> bytes:
    import base64

    return base64.b64decode(text)


def check(results: list[dict]) -> list[str]:
    failures = []
    by_name = {entry["journey"]: entry for entry in results}

    get = by_name["get"]
    if get["status"] != 200 or get["body_text"] != "hello from origin":
        failures.append(f"GET /hello: {get['status']} {get['body_text']!r}")

    upload = by_name["post_streaming"]
    if upload["status"] != 200 or upload["body_text"] != "262144 bytes":
        failures.append(f"POST /echo: {upload['status']} {upload['body_text']!r}")

    trailers = by_name["chunked_trailers"]
    if trailers["status"] != 200 or trailers["trailers"].get("x-origin") != "yes":
        failures.append(f"GET /trailers: {trailers['status']} {trailers['trailers']}")

    compressed = by_name["compression"]
    encoding = ",".join(compressed["headers"].get("content-encoding", []))
    try:
        plain = gzip.decompress(compressed["_body"])
    except OSError:
        plain = b""
    if compressed["status"] != 200 or encoding != "gzip" or plain != b"a" * 8192:
        failures.append(
            f"GET /compress: status={compressed['status']} encoding={encoding!r} "
            f"plain={len(plain)}"
        )

    shed = by_name["direct_rule"]
    if shed["status"] != 418 or shed["body_text"] != '{"shed":true}':
        failures.append(f"GET /shed: {shed['status']} {shed['body_text']!r}")

    # CONNECT is exercised by the aioquic client and by the Rust E2E suite;
    # quic-go's client does not issue a plain CONNECT, so it is checked only
    # when the client ran it.
    connect = by_name.get("connect_refused")
    if connect is not None and connect["status"] != 501:
        failures.append(f"CONNECT: {connect['status']}")
    return failures


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HTTP/3 E2E evidence through the release binary")
    parser.add_argument(
        "--client",
        choices=["aioquic", "quic-go"],
        default="aioquic",
        help="independent HTTP/3 client to drive the journeys",
    )
    return parser.parse_args()


async def main() -> int:
    args = parse_args()
    if not BINARY.exists():
        print(f"missing binary: {BINARY}; run cargo build --release -p eqproxy-cli")
        return 1

    stamp = utc_stamp()
    suffix = "" if args.client == "aioquic" else f"-{args.client}"
    outdir = Path(__file__).resolve().parent / f"run-{stamp}{suffix}"
    outdir.mkdir(parents=True, exist_ok=True)

    origin = Origin()
    origin_port = await origin.start()
    proxy_port = free_port()
    config = f"""schema_version = 1

[listener.h3]
listen = "127.0.0.1:{proxy_port}"
mode = "http"
backend = "api"
quic = true
idle_timeout = "10s"

[listener.h3.compression]
gzip = true
types = ["text/*"]

[[listener.h3.rules]]
name = "shed"
path = "/shed"
direct_response = {{ status = 418, content_type = "application/json", body = '{{"shed":true}}' }}

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

    log = open(outdir / "proxy.log", "wb")
    started = time.time()
    proxy = subprocess.Popen(
        [str(BINARY), "run", "--config", str(config_path), "--metrics-interval", "1s"],
        stdout=log,
        stderr=log,
    )

    # Wait for the real readiness line, not for a timer.
    deadline = time.time() + WAIT
    while time.time() < deadline:
        text = (outdir / "proxy.log").read_text(errors="replace")
        if f"listening on 127.0.0.1:{proxy_port}" in text:
            break
        if proxy.poll() is not None:
            print((outdir / "proxy.log").read_text())
            return 1
        await asyncio.sleep(0.05)
    else:
        print("proxy did not report its listener in time")
        proxy.kill()
        return 1

    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    configuration.load_verify_locations(cafile=str(CERT))
    configuration.server_name = "localhost"

    results = []
    client_info: dict = {}
    if args.client == "aioquic":
        client_label = "aioquic 1.2.0 (independent QUIC + h3 implementation)"
        async with connect(
            "127.0.0.1",
            proxy_port,
            configuration=configuration,
            create_protocol=H3Client,
            wait_connected=True,
        ) as client:
            results.append(await journey(client, "get", b"GET", b"/hello"))
            upload = bytes((i % 251 for i in range(256 * 1024)))
            results.append(
                await journey(
                    client, "post_streaming", b"POST", b"/echo", body=upload, length=False
                )
            )
            results.append(await journey(client, "chunked_trailers", b"GET", b"/trailers"))
            results.append(
                await journey(
                    client,
                    "compression",
                    b"GET",
                    b"/compress",
                    headers=[(b"accept-encoding", b"gzip")],
                )
            )
            results.append(await journey(client, "direct_rule", b"GET", b"/shed"))
            results.append(await journey(client, "connect_refused", b"CONNECT", b"/tunnel"))
    else:
        # The Go client blocks on subprocesses; run it off the loop so the
        # asyncio origin keeps answering the requests it drives.
        results, client_info = await asyncio.to_thread(run_go_client, proxy_port, outdir)
        client_label = f"{client_info['module']} (independent QUIC + h3 implementation)"

    failures = check(results)
    origin_requests = list(origin.requests)

    # Cross-checks on what the origin actually received.
    hello = next((r for r in origin_requests if r["head"].startswith("GET /hello ")), None)
    if hello is None:
        failures.append("origin never received GET /hello")
    elif "host: localhost" not in hello["head"].lower():
        failures.append("h3 :authority did not become host")
    upload_seen = next((r for r in origin_requests if r["head"].startswith("POST /echo ")), None)
    if upload_seen is None:
        failures.append("origin never received POST /echo")
    else:
        if "transfer-encoding: chunked" not in upload_seen["head"].lower():
            failures.append("the body without content-length was not chunked upstream")
        if upload_seen["body_len"] != 256 * 1024:
            failures.append(f"origin body length {upload_seen['body_len']}")
    direct_seen = any(r["head"].startswith("GET /shed ") for r in origin_requests)
    if direct_seen:
        failures.append("a direct_response rule reached the origin")

    proxy.send_signal(signal.SIGINT)
    try:
        code = proxy.wait(timeout=WAIT)
    except subprocess.TimeoutExpired:
        proxy.kill()
        code = proxy.wait()
    log.close()
    elapsed = time.time() - started
    text = (outdir / "proxy.log").read_text(errors="replace")
    final_metrics = next(
        (line for line in reversed(text.splitlines()) if line.startswith("METRICS ")),
        "",
    )
    if "proxied=4" not in final_metrics:
        failures.append(f"the binary did not count the four proxied exchanges: {final_metrics!r}")
    if "tls_failures=0" not in final_metrics:
        failures.append(f"unexpected TLS failures in {final_metrics!r}")

    await origin.stop()

    binary_hash = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    payload = {
        "date_utc": datetime.now(timezone.utc).isoformat(),
        "binary": str(BINARY),
        "binary_sha256": binary_hash,
        "version": subprocess.run(
            [str(BINARY), "--version"], capture_output=True, text=True
        ).stdout.strip(),
        "client": client_label,
        "client_run": client_info,
        "config": config,
        "plan_exit": plan.returncode,
        "plan": plan.stdout,
        "proxy_exit": code,
        "elapsed_s": round(elapsed, 3),
        "journeys": [
            {key: value for key, value in entry.items() if key != "_body"}
            for entry in results
        ],
        "origin_requests": [
            {"request_line": r["head"].split("\r\n", 1)[0], "head": r["head"], "body_len": r["body_len"]}
            for r in origin_requests
        ],
        "final_metrics": final_metrics,
        "failures": failures,
        "verdict": "PASS" if not failures else "FAIL",
    }
    (outdir / "results.json").write_text(json.dumps(payload, indent=2) + "\n")

    summary = [
        f"HTTP/3 (B-H2) E2E — {payload['verdict']}",
        f"binary: {BINARY}",
        f"sha256: {binary_hash}",
        f"client: {client_label}",
        f"config: {config_path}",
        f"plan exit: {plan.returncode}",
        f"proxy exit: {code} in {elapsed:.2f}s",
        "",
        "journeys:",
    ]
    for entry in payload["journeys"]:
        summary.append(
            f"  {entry['journey']:<16} status={entry['status']} "
            f"body={entry['body_len']}B trailers={entry['trailers']}"
        )
    summary.append("")
    summary.append(f"origin saw {len(origin_requests)} request(s)")
    summary.append(f"metrics: {final_metrics}")
    summary.append("")
    summary.append("failures: " + ("none" if not failures else "; ".join(failures)))
    summary.append("")
    summary.append(
        "not covered here: WebSocket/Extended CONNECT over h3, gRPC over h3, "
        "interim 1xx responses (h3 0.0.8 has no informational frame), 0-RTT, "
        "connection migration."
    )
    (outdir / "summary.txt").write_text("\n".join(summary) + "\n")
    print("\n".join(summary))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
