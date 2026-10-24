#!/usr/bin/env python3
"""WebSockets over HTTP/2 (RFC 8441) through the built EQProxy binary.

The client is the independent `hyper-h2` implementation (the HTTP/2 stack used
by `h2` in Python) over a real TCP socket; the origin is a real TCP server that
speaks the HTTP/1.1 WebSocket handshake and echoes bytes. The proxy is the
release binary built from this tree, started with a real config file.

Journeys:
  tunnel    CONNECT + `:protocol = websocket`, the backend answers 101, both
            directions carry bytes on one h2 stream, then half-close.
  refused   the backend answers 404 to the upgrade: the client sees a normal
            HTTP/2 404 with its body, never an empty tunnel.
  protocol  `:protocol = not-a-protocol` is refused with 501 and the backend is
            never contacted.

Usage:
  python3 docs/evidence/v07-ws/run.py [--out docs/evidence/v07-ws/run.txt]
"""

import argparse
import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

import h2.config
import h2.connection
import h2.events
import h2.settings

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
BIN = os.path.join(ROOT, "target", "release", "eqproxy")
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

SEEN = {"handshakes": [], "tunnels": 0, "closed": 0, "accepted": 0}


class Origin:
    """A real WebSocket origin over HTTP/1.1 (handshake + byte echo)."""

    def __init__(self):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            SEEN["accepted"] += 1
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, conn):
        conn.settimeout(10)
        try:
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                head += chunk
            text = head.decode("latin-1")
            SEEN["handshakes"].append(text)
            path = text.split(" ")[1]
            if path.startswith("/refuse"):
                body = b"no tunnel here"
                conn.sendall(
                    b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n"
                    b"Content-Length: %d\r\nConnection: close\r\n\r\n%s"
                    % (len(body), body)
                )
                return
            key = ""
            protocol = None
            for line in text.split("\r\n")[1:]:
                name, _, value = line.partition(":")
                lowered = name.strip().lower()
                if lowered == "sec-websocket-key":
                    key = value.strip()
                if lowered == "sec-websocket-protocol":
                    protocol = value.strip().split(",")[0].strip()
            accept = base64.b64encode(
                hashlib.sha1((key + GUID).encode()).digest()
            ).decode()
            response = (
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n" % accept
            )
            if protocol:
                response += "Sec-WebSocket-Protocol: %s\r\n" % protocol
            response += "\r\n"
            conn.sendall(response.encode())
            SEEN["tunnels"] += 1
            while True:
                data = conn.recv(65536)
                if not data:
                    SEEN["closed"] += 1
                    return
                conn.sendall(data)
        except OSError:
            return
        finally:
            conn.close()

    def close(self):
        self.stop.set()
        self.listener.close()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def config_text(proxy_port, origin_port):
    return f"""schema_version = 1

[listener.ws]
listen = "127.0.0.1:{proxy_port}"
mode = "http"
backend = "ws"
maxconn = 64
connect_timeout = "2s"
idle_timeout = "30s"
client_header_timeout = "5s"
server_header_timeout = "5s"

[backend.ws]
server = "127.0.0.1:{origin_port}"
"""


def start_proxy(text):
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".toml", prefix="eqproxy-ws-", delete=False
    )
    handle.write(text)
    handle.close()
    process = subprocess.Popen(
        [BIN, "run", "--config", handle.name, "--metrics-interval", "1h"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    return process, handle.name


def wait_listening(port, deadline=10.0):
    end = time.time() + deadline
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"eqproxy did not listen on 127.0.0.1:{port}")


class H2Client:
    """hyper-h2 client with extended CONNECT enabled."""

    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        self.conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
        )
        self.conn.initiate_connection()
        self.conn.update_settings(
            {h2.settings.SettingCodes.ENABLE_CONNECT_PROTOCOL: 1}
        )
        self.sock.sendall(self.conn.data_to_send())

    def request(self, headers, end_stream=False):
        stream_id = self.conn.get_next_available_stream_id()
        self.conn.send_headers(stream_id, headers, end_stream=end_stream)
        self.sock.sendall(self.conn.data_to_send())
        return stream_id

    def send(self, stream_id, data, end_stream=False):
        self.conn.send_data(stream_id, data, end_stream=end_stream)
        self.sock.sendall(self.conn.data_to_send())

    def received(self, stream_id, want_data=None, want_status=False, timeout=10):
        """Waits for DATA (and an optional END_STREAM) on `stream_id`."""
        collected = b""
        headers = None
        status = None
        ended = False
        reset = None
        end = time.time() + timeout
        while time.time() < end:
            self.sock.settimeout(max(0.1, end - time.time()))
            try:
                chunk = self.sock.recv(65535)
            except socket.timeout:
                break
            if not chunk:
                break
            for event in self.conn.receive_data(chunk):
                if isinstance(event, h2.events.ResponseReceived):
                    if event.stream_id == stream_id:
                        headers = dict(event.headers)
                        status = int(headers.get(":status", "0"))
                elif isinstance(event, h2.events.DataReceived):
                    if event.stream_id == stream_id:
                        collected += event.data
                        self.conn.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )
                elif isinstance(event, h2.events.StreamEnded):
                    if event.stream_id == stream_id:
                        ended = True
                elif isinstance(event, h2.events.StreamReset):
                    if event.stream_id == stream_id:
                        reset = event.error_code
            self.sock.sendall(self.conn.data_to_send())
            if ended or reset is not None:
                break
            if want_status and status is not None:
                break
            if want_data is not None and len(collected) >= want_data:
                break
        return {
            "status": status,
            "headers": headers,
            "data": collected,
            "ended": ended,
            "reset": reset,
        }

    def close(self):
        try:
            self.conn.close_connection()
            self.sock.sendall(self.conn.data_to_send())
        except OSError:
            pass
        self.sock.close()


def report(name, **facts):
    line = {"journey": name, **facts}
    print(json.dumps(line, sort_keys=True), flush=True)
    return line


def journey_tunnel(port):
    client = H2Client(port)
    stream = client.request(
        [
            (":method", "CONNECT"),
            (":protocol", "websocket"),
            (":scheme", "http"),
            (":authority", "ws.test"),
            (":path", "/chat?room=7"),
            ("sec-websocket-protocol", "chat, superchat"),
        ]
    )
    opened = client.received(stream, want_status=True)
    assert opened["status"] == 200, f"status {opened['status']}"
    headers = opened["headers"]
    assert headers.get("sec-websocket-protocol") == "chat", headers
    assert "sec-websocket-accept" not in headers, headers
    assert "upgrade" not in headers, headers

    first = b"hola desde h2"
    client.send(stream, first)
    echo = client.received(stream, want_data=len(first))
    assert echo["data"] == first, echo
    second = b"segundo mensaje"
    client.send(stream, second)
    echo2 = client.received(stream, want_data=len(second))
    assert echo2["data"] == second, echo2

    client.send(stream, b"", end_stream=True)
    client.close()
    return report(
        "tunnel",
        status=opened["status"],
        protocol=headers.get("sec-websocket-protocol"),
        bytes_first=len(first),
        bytes_second=len(second),
        backend_requests=len(SEEN["handshakes"]),
    )


def journey_refused(port):
    client = H2Client(port)
    stream = client.request(
        [
            (":method", "CONNECT"),
            (":protocol", "websocket"),
            (":scheme", "http"),
            (":authority", "ws.test"),
            (":path", "/refuse"),
        ]
    )
    answer = client.received(stream)
    client.close()
    assert answer["status"] == 404, answer
    assert answer["data"] == b"no tunnel here", answer
    return report(
        "refused",
        status=answer["status"],
        body=answer["data"].decode(),
        ended=answer["ended"],
    )


def journey_protocol(port):
    client = H2Client(port)
    stream = client.request(
        [
            (":method", "CONNECT"),
            (":protocol", "not-a-protocol"),
            (":scheme", "http"),
            (":authority", "ws.test"),
            (":path", "/chat"),
        ]
    )
    answer = client.received(stream)
    client.close()
    assert answer["status"] == 501, answer
    return report("protocol", status=answer["status"], ended=answer["ended"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "run.txt"))
    args = parser.parse_args()

    origin = Origin()
    proxy_port = free_port()
    proxy, config_path = start_proxy(config_text(proxy_port, origin.port))
    lines = []
    try:
        wait_listening(proxy_port)
        lines.append(journey_tunnel(proxy_port))
        lines.append(journey_refused(proxy_port))
        lines.append(journey_protocol(proxy_port))
    except Exception:
        proxy.terminate()
        print(proxy.stderr.read() if proxy.stderr else "", file=sys.stderr)
        raise
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proxy.kill()
        os.unlink(config_path)
        origin.close()

    summary = {
        "backend": SEEN,
        "binary": BIN,
        "sha256": hashlib.sha256(open(BIN, "rb").read()).hexdigest(),
        "client": "hyper-h2 " + __import__("h2").__version__,
    }
    print(json.dumps(summary, sort_keys=True), flush=True)
    if args.out:
        with open(args.out, "w") as handle:
            for line in lines:
                handle.write(json.dumps(line, sort_keys=True) + "\n")
            handle.write(json.dumps(summary, sort_keys=True) + "\n")
    print("PASS", flush=True)


if __name__ == "__main__":
    main()
