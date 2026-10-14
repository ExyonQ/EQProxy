#!/usr/bin/env python3
"""Bench backends for scripts/bench_phase2c.py. Runs inside a container:
TCP echo on 19001 and a keep-alive HTTP/1.1 origin serving 1 KiB on 19002.
"""

import socketserver
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ECHO_PORT = 19001
ORIGIN_PORT = 19002
BODY = b"X" * 1024


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            self.request.sendall(data)


class EchoServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class OriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *a):
        pass


class OriginServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    echo = EchoServer(("0.0.0.0", ECHO_PORT), EchoHandler)
    origin = OriginServer(("0.0.0.0", ORIGIN_PORT), OriginHandler)
    import threading

    threading.Thread(target=echo.serve_forever, daemon=True).start()
    print("backends up: echo :19001, origin :19002", flush=True)
    origin.serve_forever()
