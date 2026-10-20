#!/usr/bin/env python3
"""Backend origins for the glibc-vs-musl parity run (S-H1-04 shape).

One asyncio process serves every port the benchmark config references:

- 19002/19003: the `api`/`mgmt` origins, 200 with a 1 KiB body and the
  received path echoed in `x-seen-path`.
- 21000..21499: the 500 origins of S-H1-05, kept so the same container can
  serve both scenarios (this report only uses 19002/19003).

Why one process and not one thread per port: a thread-per-port server made
health checks time out under load (GIL scheduling), which flapped servers to
`down` and changed the scenario. Accepted sockets get TCP_NODELAY so the
response does not pay the Nagle/delayed-ACK stall inside the origin.

Same file as the maintainer-local scripts/bench_v06_backends.py, published
here so this report can be reproduced without the local-only folder.
"""

import asyncio
import socket

ORIGIN_PORTS = (19002, 19003)
MANY_BASE = 21000
MANY_COUNT = 500
BODY = b"X" * 1024
HEAD = (
    b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n"
    b"Content-Type: application/octet-stream\r\nx-seen-path: "
)


async def handle(reader, writer):
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            headers = b""
            while True:
                h = await reader.readline()
                if h in (b"\r\n", b"\n", b""):
                    break
                headers += h
            parts = line.split()
            path = parts[1] if len(parts) > 1 else b"/"
            writer.write(HEAD + path + b"\r\n\r\n" + BODY)
            await writer.drain()
            low = (line + headers).lower()
            if b"connection: close" in low or b"http/1.0" in low:
                break
    except (ConnectionError, asyncio.IncompleteReadError, asyncio.CancelledError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


def make_sock(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.bind(("0.0.0.0", port))
    s.listen(128)
    s.setblocking(False)
    return s


async def main():
    ports = (*ORIGIN_PORTS, *(MANY_BASE + i for i in range(MANY_COUNT)))
    for port in ports:
        await asyncio.start_server(handle, sock=make_sock(port))
    print(f"backends up: {len(ports)} origins, 1 asyncio process", flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
