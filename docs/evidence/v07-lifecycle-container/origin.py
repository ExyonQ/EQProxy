"""Independent HTTP/2 origin for the v0.7 container evidence.

hyper-h2 4.2.0 over a real TLS socket (ALPN h2). Not the Rust `h2` crate and
not a mock: an independent implementation records exactly what arrives.

  GET /echo              200, body = "ok:<x-req header>"
  GET /hold?ms=1500      200 after sleeping ms (drain evidence)
  GET /slow?ms=500       200 after sleeping ms
  GET /goaway            200, then GOAWAY(last_stream_id=this stream)
  GET /refuse-once       the FIRST request carrying `x-refuse: 1` is reset
                         with RST_STREAM(REFUSED_STREAM) and never answered
                         (RFC 9113 §8.1.4: not processed); later ones are
                         answered normally
  GET /sessions          200, body = JSON {"sessions":N,"streams":M}

Every stream is appended to the JSONL file given as argv[4].
"""
import json
import socket
import ssl
import struct
import sys
import threading
import time

import h2.config
import h2.connection
import h2.errors
import h2.events

CERT, KEY, PORT, RECORD = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
LOCK = threading.RLock()
SESSIONS = 0
STREAMS = 0
REFUSALS = 1
COND = threading.Condition(LOCK)
LOG = open(RECORD, "a", buffering=1)


def header_map(pairs):
    """hyper-h2 hands both names and values to the server as bytes."""
    out = {}
    for name, value in pairs:
        if isinstance(name, bytes):
            name = name.decode()
        if isinstance(value, bytes):
            value = value.decode()
        out[name] = value
    return out


def record(event):
    with LOCK:
        LOG.write(json.dumps(event) + "\n")


class Session:
    """One accepted TLS connection carrying exactly one h2 session."""

    def __init__(self, stream, ident):
        self.conn_socket = stream
        self.ident = ident
        self.conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False)
        )
        self.conn.initiate_connection()
        stream.sendall(self.conn.data_to_send())

    def serve(self):
        while True:
            chunk = self.conn_socket.recv(65535)
            if not chunk:
                return
            events = self.conn.receive_data(chunk)
            for event in events:
                if isinstance(event, h2.events.RequestReceived):
                    threading.Thread(
                        target=self.answer,
                        args=(event.stream_id, header_map(event.headers)),
                        daemon=True,
                    ).start()
                elif isinstance(event, h2.events.ConnectionTerminated):
                    return
            data = self.conn.data_to_send()
            if data:
                self.conn_socket.sendall(data)

    def answer(self, stream_id, headers):
        global STREAMS, REFUSALS
        path = headers.get(":path", "/")
        req = headers.get("x-req", "")
        with COND:
            STREAMS += 1
            record(
                {
                    "t": round(time.time(), 3),
                    "connection": self.ident,
                    "stream": stream_id,
                    "method": headers.get(":method"),
                    "path": path,
                    "x_req": req,
                    "content_length": headers.get("content-length"),
                }
            )
        try:
            if headers.get("x-refuse") == "1":
                with LOCK:
                    refuse = REFUSALS > 0
                    if refuse:
                        REFUSALS -= 1
                if refuse:
                    # Never read the body and never answer: exactly the
                    # "I did not process this stream" the client may replay.
                    with LOCK:
                        self.conn.reset_stream(
                            stream_id,
                            error_code=h2.errors.ErrorCodes.REFUSED_STREAM,
                        )
                        data = self.conn.data_to_send()
                    self.conn_socket.sendall(data)
                    record(
                        {
                            "t": round(time.time(), 3),
                            "connection": self.ident,
                            "stream": stream_id,
                            "x_req": req,
                            "refused": True,
                        }
                    )
                    return
            if path.startswith("/hold"):
                query = dict(
                    part.split("=", 1) for part in path.split("?", 1)[1].split("&")
                )
                hold_ms = int(query.get("ms", "1500"))
                with COND:
                    started = time.time()
                    record(
                        {
                            "t": round(started, 3),
                            "connection": self.ident,
                            "stream": stream_id,
                            "path": path,
                            "x_req": req,
                            "phase": "start",
                        }
                    )
                time.sleep(hold_ms / 1000.0)
                with COND:
                    record(
                        {
                            "t": round(time.time(), 3),
                            "connection": self.ident,
                            "stream": stream_id,
                            "path": path,
                            "x_req": req,
                            "phase": "end",
                            "held_ms": hold_ms,
                        }
                    )
            elif path.startswith("/goaway"):
                self.respond(stream_id, 200, b"ok:" + req.encode())
                self.goaway(stream_id)
                return
            elif path.startswith("/slow"):
                query = dict(
                    part.split("=", 1) for part in path.split("?", 1)[1].split("&")
                )
                time.sleep(int(query.get("ms", "500")) / 1000.0)
            elif path.startswith("/sessions"):
                with LOCK:
                    body = json.dumps({"sessions": SESSIONS, "streams": STREAMS}).encode()
                self.respond(stream_id, 200, body)
                return
            self.respond(stream_id, 200, b"ok:" + req.encode())
            record(
                {
                    "t": round(time.time(), 3),
                    "connection": self.ident,
                    "stream": stream_id,
                    "x_req": req,
                    "phase": "answered",
                }
            )
        except Exception as exc:  # noqa: BLE001 - evidence server
            record({"error": repr(exc)})

    def goaway(self, stream_id):
        """Announce a graceful close (the stream we just answered is the last
        one processed): new streams on this session must be refused, while the
        streams already open keep being served.

        hyper-h2's ``close_connection`` moves its state machine to CLOSED and
        aborts the outstanding streams, which a real server does not do (the
        whole point of GOAWAY is to finish them). So the GOAWAY frame is put
        on the wire directly (RFC 9113 §6.8: 8-byte payload, no debug data)
        and the connection's state machine stays open to answer stream 3.
        """
        payload = struct.pack("!II", stream_id & 0x7FFFFFFF, 0)
        frame = (
            len(payload).to_bytes(3, "big") + b"\x07" + b"\x00"
            + (0).to_bytes(4, "big") + payload
        )
        with LOCK:
            record(
                {
                    "t": round(time.time(), 3),
                    "connection": self.ident,
                    "goaway_sent": stream_id,
                }
            )
        self.conn_socket.sendall(frame)

    def respond(self, stream_id, status, body):
        with LOCK:
            self.conn.send_headers(
                stream_id,
                [
                    (":status", str(status)),
                    ("content-length", str(len(body))),
                    ("x-origin", "hyper-h2"),
                ],
            )
            self.conn.send_data(stream_id, body, end_stream=True)
            data = self.conn.data_to_send()
        self.conn_socket.sendall(data)


def handle(sock, ident):
    global SESSIONS
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT, KEY)
    context.set_alpn_protocols(["h2"])
    try:
        stream = context.wrap_socket(sock, server_side=True)
    except Exception as exc:  # noqa: BLE001
        record({"tls_error": repr(exc)})
        return
    if stream.selected_alpn_protocol() != "h2":
        record({"alpn": stream.selected_alpn_protocol()})
        return
    with LOCK:
        SESSIONS += 1
        record({"session_opened": ident})
    session = Session(stream, ident)
    try:
        session.serve()
    except Exception as exc:  # noqa: BLE001 - evidence server
        record({"session_error": repr(exc), "connection": ident})
    finally:
        with LOCK:
            record({"session_closed": ident})


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", PORT))
    server.listen(64)
    print(f"origin listening on {PORT}", flush=True)
    ident = 0
    while True:
        sock, _ = server.accept()
        ident += 1
        threading.Thread(target=handle, args=(sock, ident), daemon=True).start()


if __name__ == "__main__":
    main()
