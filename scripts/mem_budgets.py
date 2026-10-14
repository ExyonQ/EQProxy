#!/usr/bin/env python3
"""Phase 2c measured memory budgets (SPEC 7.3, first measurement).

Starts the release binary with a local echo/origin backend, opens N idle
client connections (TCP mode and HTTP keep-alive mode), and reports proxy
RSS before/after via `ps`. Output: JSON on stdout.

Idle connections hold their buffers allocated, so (after - before) / N is
an upper-bound-ish estimate of per-connection steady-state cost.
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import socketserver
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

N = 200
BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "target", "release", "eqproxy"))


def rss(pid):
    r = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True)
    return int(r.stdout.strip())  # KiB


def start_echo():
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            while True:
                d = self.request.recv(65536)
                if not d:
                    return
                self.request.sendall(d)

    class S(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True

    srv = S(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1]


def start_origin():
    body = b"X" * 1024

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1]


def start_proxy(cfg_text):
    tmp = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
    tmp.write(cfg_text)
    tmp.close()
    proc = subprocess.Popen([BIN, "run", "--config", tmp.name],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    if proc.poll() is not None:
        raise RuntimeError("proxy exited during startup")
    return proc, tmp.name


def tcp_conns(port, n):
    socks = []
    for _ in range(n):
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.sendall(b"warm")
        assert s.recv(4) == b"warm"
        socks.append(s)
    return socks


def http_conns(port, n):
    socks = []
    for _ in range(n):
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(65536)
            if not chunk:
                raise RuntimeError("origin closed during warm-up")
            resp += chunk
        socks.append(s)
    return socks


def measure(mode, backend_port, opener):
    proxy_port = 19501 if mode == "tcp" else 19502
    cfg = f"""schema_version = 1
shutdown_grace = "2s"
[listener.web]
listen = "127.0.0.1:{proxy_port}"
backend = "api"
mode = "{mode}"
maxconn = 4096
[backend.api]
server = "127.0.0.1:{backend_port}"
"""
    proc, path = start_proxy(cfg)
    try:
        time.sleep(1.0)
        base = rss(proc.pid)
        held = opener(proxy_port, N)
        time.sleep(2.0)  # let allocator settle
        peak = rss(proc.pid)
        for s in held:
            s.close()
        held.clear()
        time.sleep(1.0)
        after = rss(proc.pid)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        os.unlink(path)
    return {
        "mode": mode,
        "connections": N,
        "rss_before_kib": base,
        "rss_with_conns_kib": peak,
        "rss_after_close_kib": after,
        "kib_per_conn": round((peak - base) / N, 2),
    }


def main():
    echo_port = start_echo()
    origin_port = start_origin()
    out = {
        "platform": sys.platform,
        "binary": BIN,
        "results": [measure("tcp", echo_port, tcp_conns), measure("http", origin_port, http_conns)],
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
