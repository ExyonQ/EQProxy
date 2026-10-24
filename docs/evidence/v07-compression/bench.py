#!/usr/bin/env python3
"""Raw compression data for the v0.7 slices (B-N6 / C11 / H6).

The real release binary is measured on this host, over a real TCP socket: an
independent Python origin serves three fixed corpora, one persistent client
connection sends N requests per run, and every response is checked (each gzip
member or Brotli stream must decode to the origin's exact bytes, using two
independent decoders: Python's zlib and the Brotli reference module).

What is measured: bytes on the wire per request, ratio against identity, and
wall-clock requests per second for one sequential client. What is NOT
measured: concurrency, TLS, backends on other hosts, or any comparison with
another proxy. Those are the version gate's S-H2/S-H3 scenarios, not this one.

    python3 docs/evidence/v07-compression/bench.py --binary target/release/eqproxy

Writes `raw.jsonl` (one line per repetition) and `bench.md` next to this file.
"""

import argparse
import hashlib
import json
import random
import socket
import statistics
import subprocess
import tempfile
import threading
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import brotli

HERE = Path(__file__).resolve().parent
TEXT = (
    "<!doctype html><html><head><title>eqproxy compression bench</title></head><body>"
    + "".join(
        f"<article id='a{i}'><h2>Item {i}</h2><p>"
        + "the quick brown fox jumps over the lazy dog "
        + f"</p><span class='price'>{i * 7 % 1000}</span></article>"
        for i in range(6000)
    )
    + "</body></html>"
).encode()
JSON_BODY = json.dumps(
    {"items": [{"id": i, "title": f"item-{i}", "tags": ["a", "b", "c"], "ok": i % 3 == 0}
               for i in range(14000)]}
).encode()
_rng = random.Random(7)
BINARY = bytes(_rng.randrange(256) for _ in range(256 * 1024))

CORPORA = {
    "text": ("/text", "text/html; charset=utf-8", TEXT),
    "json": ("/json", "application/json", JSON_BODY),
    "binary": ("/binary", "application/octet-stream", BINARY),
}

# (label, coding, gzip level, brotli quality)
CONFIGS = [
    ("identity", "identity", None, None),
    ("gzip-level-1", "gzip", 1, None),
    ("gzip-level-6", "gzip", 6, None),
    ("gzip-level-9", "gzip", 9, None),
    ("brotli-quality-1", "br", None, 1),
    ("brotli-quality-5", "br", None, 5),
    ("brotli-quality-11", "br", None, 11),
]

REQUESTS = 50
REPS = 5
WARMUP = 3


class Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802 - http.server API
        for _name, (path, content_type, body) in CORPORA.items():
            if self.path == path:
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
        self.send_error(404)

    def log_message(self, *args):  # silence the per-request log
        pass


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def read_head(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(65536)
        if not chunk:
            raise RuntimeError("connection closed while reading the head")
        data += chunk
    head, rest = data.split(b"\r\n\r\n", 1)
    return head, rest


def read_all(sock, head, rest):
    lower = head.lower()
    if b"transfer-encoding: chunked" in lower:
        body = b""
        pending = rest
        while True:
            while b"\r\n" not in pending:
                pending += sock.recv(65536)
            line, pending = pending.split(b"\r\n", 1)
            size = int(line.split(b";")[0], 16)
            if size == 0:
                # Trailer section: read lines until the empty one.
                while True:
                    while b"\r\n" not in pending:
                        pending += sock.recv(65536)
                    line, pending = pending.split(b"\r\n", 1)
                    if not line:
                        return head, body
            while len(pending) < size + 2:
                pending += sock.recv(65536)
            body += pending[:size]
            pending = pending[size + 2:]
    for line in lower.split(b"\r\n"):
        if line.startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1])
            body = rest
            while len(body) < length:
                body += sock.recv(65536)
            return head, body[:length]
    raise RuntimeError("response without framing")


def decode(coding, body):
    """Decodes with an independent implementation, never the encoder's crate."""
    if coding == "gzip":
        return zlib.decompress(body, 16 + zlib.MAX_WBITS)
    if coding == "br":
        return brotli.decompress(body)
    raise ValueError(coding)


def one_run(port, corpus, coding):
    path, _ctype, plain = CORPORA[corpus]
    accept = "identity" if coding == "identity" else coding
    sock = socket.create_connection(("127.0.0.1", port), timeout=120)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        request = (
            f"GET {path} HTTP/1.1\r\nHost: t\r\nAccept-Encoding: {accept}\r\n"
            "Connection: keep-alive\r\n\r\n"
        ).encode()
        for _ in range(WARMUP):
            sock.sendall(request)
            head, rest = read_head(sock)
            read_all(sock, head, rest)
        started = time.perf_counter()
        wire = 0
        valid = 0
        encoded = 0
        for _ in range(REQUESTS):
            sock.sendall(request)
            head, rest = read_head(sock)
            head, body = read_all(sock, head, rest)
            wire += len(body)
            lower = head.lower()
            if coding != "identity" and f"content-encoding: {coding}".encode() in lower:
                encoded += 1
                if decode(coding, body) == plain:
                    valid += 1
            elif body != plain:
                raise RuntimeError("identity body differs from the origin's")
        elapsed = time.perf_counter() - started
    finally:
        sock.close()
    return {
        "corpus": corpus,
        "plain_bytes": len(plain),
        "requests": REQUESTS,
        "seconds": elapsed,
        "requests_per_second": REQUESTS / elapsed,
        "wire_bytes_per_request": wire / REQUESTS,
        "compressed_responses": encoded,
        "valid_decoded": valid,
    }


def compression_block(coding, level, quality):
    if coding == "identity":
        return ""
    if coding == "gzip":
        return f"[listener.web.compression]\ngzip = true\nlevel = {level}\n"
    return f"[listener.web.compression]\nbrotli = true\nbrotli_quality = {quality}\n"


def start_proxy(binary, coding, level, quality):
    port = free_port()
    config = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
    config.write(
        "schema_version = 1\n"
        "[listener.web]\n"
        f'listen = "127.0.0.1:{port}"\n'
        'mode = "http"\n'
        'backend = "api"\n'
        'connect_timeout = "2s"\n'
        'idle_timeout = "60s"\n'
        f"{compression_block(coding, level, quality)}"
        "[backend.api]\n"
        f'server = "127.0.0.1:{ORIGIN_PORT}"\n'
    )
    config.close()
    process = subprocess.Popen(
        [binary, "run", "--config", config.name, "--metrics-interval", "1h"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.time() + 15
    while time.time() < deadline:
        line = process.stderr.readline()
        if not line:
            raise RuntimeError("eqproxy closed stderr before listening")
        if "listening on " in line:
            return process, config.name, port
    raise RuntimeError("eqproxy did not announce its listener")


def stop_proxy(process, config_path):
    process.send_signal(2)  # SIGINT: the same drain path operators use
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        raise
    Path(config_path).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="target/release/eqproxy")
    parser.add_argument("--out", default=str(HERE))
    args = parser.parse_args()

    global ORIGIN_PORT
    ORIGIN_PORT = free_port()
    server = ThreadingHTTPServer(("127.0.0.1", ORIGIN_PORT), Origin)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    binary = str(Path(args.binary).resolve())
    digest = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
    rustc = subprocess.run(["rustc", "--version"], capture_output=True, text=True).stdout.strip()
    host = subprocess.run(["uname", "-sm"], capture_output=True, text=True).stdout.strip()

    rows = []
    for label, coding, level, quality in CONFIGS:
        process, config_path, port = start_proxy(binary, coding, level, quality)
        try:
            for corpus in CORPORA:
                for rep in range(REPS):
                    result = one_run(port, corpus, coding)
                    result.update(
                        {
                            "config": label,
                            "coding": coding,
                            "level": level,
                            "quality": quality,
                            "rep": rep + 1,
                        }
                    )
                    rows.append(result)
                    print(
                        f"{label:18s} {corpus:6s} rep{rep + 1}: "
                        f"{result['wire_bytes_per_request']:9.0f} B/req  "
                        f"{result['requests_per_second']:8.1f} req/s  "
                        f"valid={result['valid_decoded']}/{result['compressed_responses']}",
                        flush=True,
                    )
        finally:
            stop_proxy(process, config_path)
    server.shutdown()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with (out / "raw.jsonl").open("w") as raw:
        for row in rows:
            raw.write(json.dumps(row, sort_keys=True) + "\n")

    def median(label, corpus, field):
        values = [r[field] for r in rows if r["config"] == label and r["corpus"] == corpus]
        return statistics.median(values)

    lines = [
        "# Compresión gzip y Brotli — datos crudos (C11 / H6)",
        "",
        "Language: **Spanish** (raw data; the evidence document is in English).",
        "",
        f"- Binary: `{binary}`, sha256 `{digest}`",
        f"- Toolchain: `{rustc}`",
        f"- Host: `{host}`, loopback TCP, one sequential client, no TLS",
        f"- {REPS} repetitions × {REQUESTS} requests per cell (plus {WARMUP} warm-up);",
        "  every compressed response was decoded and compared with the origin's bytes",
        "  (zlib for gzip, the Brotli reference module for `br`).",
        "- `raw.jsonl` holds one line per repetition (all columns).",
        "",
        "| Config | Corpus | Wire B/req (median) | Ratio vs identity | Req/s median [min–max] | Válidos |",
        "|---|---|---|---|---|---|",
    ]
    for label, _coding, _level, _quality in CONFIGS:
        for corpus in CORPORA:
            wire = median(label, corpus, "wire_bytes_per_request")
            base = median("identity", corpus, "wire_bytes_per_request")
            ratio = wire / base if base else 1.0
            rps_values = [
                r["requests_per_second"]
                for r in rows
                if r["config"] == label and r["corpus"] == corpus
            ]
            rps = statistics.median(rps_values)
            spread = f"{rps:,.1f} [{min(rps_values):,.1f}–{max(rps_values):,.1f}]"
            valid = sum(
                r["valid_decoded"] for r in rows if r["config"] == label and r["corpus"] == corpus
            )
            compressed = sum(
                r["compressed_responses"]
                for r in rows
                if r["config"] == label and r["corpus"] == corpus
            )
            lines.append(
                f"| `{label}` | `{corpus}` | {wire:,.0f} | {ratio:.3f} | {spread} | "
                f"{valid}/{compressed} |"
            )
    lines += [
        "",
        "El corpus `binary` (`application/octet-stream`) queda fuera de la lista de",
        "tipos por defecto: sus filas comprimidas muestran el caso en que no se",
        "comprime (ratio 1.000) aun aceptando el cliente esa codificación.",
        "",
        "Los req/s son una medición indicativa de un cliente secuencial en un portátil",
        "compartido: el rango entre repeticiones (columna min–max y `raw.jsonl`) es",
        "amplio y no se promete ninguna cifra de rendimiento. Lo que sí es estable y",
        "reproducible es el tamaño en el cable y el ratio por corpus.",
        "",
    ]
    (out / "bench.md").write_text("\n".join(lines))
    print("\n".join(lines))


if __name__ == "__main__":
    main()
