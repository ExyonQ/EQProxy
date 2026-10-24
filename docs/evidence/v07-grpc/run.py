#!/usr/bin/env python3
"""gRPC end-to-end against the built EQProxy binary with a real gRPC stack.

The origin is a genuine `grpcio` server (TLS, ALPN h2) and the client is the
same `grpcio` implementation: no re-implementation of the protocol and no
interceptor standing in for the proxy. The proxy is the release binary built
from this tree, started with a real config file.

Journeys:
  bidi    two messages, each answered while the request stream is still open,
          then a clean half-close with `grpc-status: 0` in the trailers.
  bulk    a 256 KiB message echoed byte-for-byte (both flow-control windows).
  status  a unary method aborting with NOT_FOUND: the gRPC status must reach
          the client through the proxy's trailers.
  long    an optional N-second bidi stream (default 360 s, one message every
          20 s): the Q5 journey for streams longer than five minutes.

Usage:
  python3 docs/evidence/v07-grpc/run.py [--long-seconds 360] [--long-interval 20]
"""

import argparse
import json
import os
import queue
import socket
import subprocess
import sys
import tempfile
import time
from concurrent import futures

import grpc

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
CERT = os.path.join(ROOT, "eqproxy-net", "tests", "fixtures", "cert.pem")
KEY = os.path.join(ROOT, "eqproxy-net", "tests", "fixtures", "key.pem")
BIN = os.path.join(ROOT, "target", "release", "eqproxy")

# Invocation metadata of every call the origin served (x-forwarded-for comes
# from the proxy; the rest is what the real client sent).
SEEN = []


def identity(value):
    return value


class Echo:
    """A generic gRPC service: streaming echo and a NOT_FOUND unary method."""

    def service(self, handler_call_details):
        method = handler_call_details.method
        if method.endswith("/Fail"):
            return grpc.unary_unary_rpc_method_handler(
                self.fail,
                request_deserializer=identity,
                response_serializer=identity,
            )
        return grpc.stream_stream_rpc_method_handler(
            self.echo,
            request_deserializer=identity,
            response_serializer=identity,
        )

    def echo(self, request_iterator, context):
        SEEN.append(dict(context.invocation_metadata()))
        for message in request_iterator:
            yield message

    def fail(self, request, context):
        SEEN.append(dict(context.invocation_metadata()))
        context.abort(grpc.StatusCode.NOT_FOUND, "no such item")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_origin():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=16))
    server.add_generic_rpc_handlers((Echo(),))
    with open(CERT, "rb") as cert, open(KEY, "rb") as key:
        credentials = grpc.ssl_server_credentials([(key.read(), cert.read())])
    port = server.add_secure_port("127.0.0.1:0", credentials)
    server.start()
    return server, port


def proxy_config(proxy_port, origin_port):
    return f"""schema_version = 1

[listener.grpc]
listen = "127.0.0.1:{proxy_port}"
mode = "http"
backend = "grpc"
maxconn = 128
connect_timeout = "2s"
idle_timeout = "120s"
client_header_timeout = "5s"
server_header_timeout = "30s"
max_stream_duration = "0s"
forwarded_headers = "append"

[backend.grpc]
server = "127.0.0.1:{origin_port}"

[backend.grpc.tls]
verify = true
ca_file = "{CERT}"
server_name = "localhost"
alpn = ["h2"]
"""


def start_proxy(config_text):
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".toml", prefix="eqproxy-grpc-", delete=False
    )
    handle.write(config_text)
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


def next_with_timeout(iterator, seconds):
    pool = futures.ThreadPoolExecutor(max_workers=1)
    try:
        return pool.submit(next, iterator).result(timeout=seconds)
    finally:
        pool.shutdown(wait=False)


def report(name, **facts):
    line = {"journey": name, **facts}
    print(json.dumps(line, sort_keys=True), flush=True)
    return line


def journey_bidi(channel):
    requests = queue.Queue()

    def feed():
        while True:
            message = requests.get()
            if message is None:
                return
            yield message

    call = channel.stream_stream("/eqproxy.Echo/Bidi")(iter(feed()))
    started = time.time()
    requests.put(b"alpha")
    first = next_with_timeout(call, 5)
    first_at = time.time() - started
    assert first == b"alpha", f"first echo mismatch: {first!r}"
    # The stream is still open here: this is the bidi proof, not a buffered
    # request/response pair.
    requests.put(b"beta")
    second = next_with_timeout(call, 5)
    assert second == b"beta", f"second echo mismatch: {second!r}"
    requests.put(None)
    try:
        while next_with_timeout(call, 5) is not None:
            pass
    except StopIteration:
        pass
    call.trailing_metadata()  # blocks until the server finished the stream
    status = call.code()
    assert status == grpc.StatusCode.OK, f"status: {status}"
    return report(
        "bidi",
        first_echo_seconds=round(first_at, 3),
        second_echo=True,
        grpc_status=status.name,
        seen=SEEN[-1],
    )


def journey_bulk(channel, size=256 * 1024):
    payload = bytes((i % 251) for i in range(size))
    call = channel.stream_stream("/eqproxy.Echo/Bulk")(iter([payload]))
    echo = next_with_timeout(call, 15)
    assert echo == payload, f"payload mismatch ({len(echo)} bytes)"
    call.trailing_metadata()
    assert call.code() == grpc.StatusCode.OK
    return report("bulk", bytes=len(payload), equal=True, grpc_status=call.code().name)


def journey_status(channel):
    call = channel.unary_unary("/eqproxy.Echo/Fail")
    try:
        call(b"anything", timeout=5)
    except grpc.RpcError as error:
        assert error.code() == grpc.StatusCode.NOT_FOUND, error
        assert error.details() == "no such item", error.details()
        return report(
            "status",
            grpc_status=error.code().name,
            details=error.details(),
            x_forwarded_for=SEEN[-1].get("x-forwarded-for"),
        )
    raise AssertionError("the NOT_FOUND status did not reach the client")


def journey_long(channel, seconds, interval):
    requests = queue.Queue()

    def feed():
        while True:
            message = requests.get()
            if message is None:
                return
            yield message

    call = channel.stream_stream("/eqproxy.Echo/Long")(iter(feed()))
    started = time.time()
    count = 0
    slowest = 0.0
    while time.time() - started < seconds:
        tick = time.time()
        message = f"tick-{count}".encode()
        requests.put(message)
        echo = next_with_timeout(call, 20)
        assert echo == message, f"echo mismatch at {count}: {echo!r}"
        slowest = max(slowest, time.time() - tick)
        count += 1
        remaining = seconds - (time.time() - started)
        time.sleep(min(interval, max(0.0, remaining)))
    requests.put(None)
    try:
        while next_with_timeout(call, 20) is not None:
            pass
    except StopIteration:
        pass
    call.trailing_metadata()
    elapsed = time.time() - started
    assert call.code() == grpc.StatusCode.OK, f"status: {call.code()}"
    return report(
        "long",
        seconds=round(elapsed, 1),
        messages=count,
        interval_seconds=interval,
        slowest_round_trip_seconds=round(slowest, 3),
        grpc_status=call.code().name,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--long-seconds", type=float, default=360.0)
    parser.add_argument("--long-interval", type=float, default=20.0)
    args = parser.parse_args()

    origin, origin_port = start_origin()
    proxy_port = free_port()
    proxy, config_path = start_proxy(proxy_config(proxy_port, origin_port))
    try:
        wait_listening(proxy_port)
        channel = grpc.insecure_channel(f"127.0.0.1:{proxy_port}")
        grpc.channel_ready_future(channel).result(timeout=10)
        journey_bidi(channel)
        journey_bulk(channel)
        journey_status(channel)
        if args.long_seconds > 0:
            journey_long(channel, args.long_seconds, args.long_interval)
        channel.close()
    except Exception:
        proxy.terminate()
        tail = proxy.stderr.read() if proxy.stderr else ""
        print(tail, file=sys.stderr)
        raise
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proxy.kill()
        os.unlink(config_path)
        origin.stop(0)
    print("PASS", flush=True)


if __name__ == "__main__":
    main()
