# ADR-0013 — HTTP/3 termination over QUIC (B-H2)

- **Status:** accepted (2026-10-23)
- **Context:** SPEC requirement A4 (user decision, 2026-10-12: HTTP/3 to
  clients is mandatory), roadmap v0.7 item B-H2/B-E2/B-E13; the h2 and gRPC
  slices had already turned the listener into a protocol-negotiating front
  door, but a client that only speaks QUIC could not be served at all.
- **Deciders:** project owner + implementation.

## Context

HTTP/3 is HTTP over QUIC: UDP instead of TCP, TLS 1.3 mandatory, ALPN `h3`,
and h3 framing (HEADERS/DATA on QUIC streams, QPACK for headers, dedicated
control streams). It is not "HTTP/2 over a different socket": QUIC brings
its own handshake, stream lifecycle, flow control and connection IDs, so the
existing TCP+TLS listener cannot serve it.

The repository already had one exchange engine (the h1 engine) with routing
rules, auth, rate limiting, header actions, mirroring, retries, the
keep-alive pool and response compression, plus a translation layer for h2
that turns each stream into one h1 message on an in-memory duplex. A second
independent HTTP implementation for h3 would duplicate all of those
decisions and drift from them.

## Decision

1. **Opt in per listener with `quic = true`.** The dataplane opens a QUIC
   endpoint on the listener's *own* bound address and port over UDP (never a
   second, implicit port). The configuration gate requires `mode = "http"`
   and a `[listener.X.tls]` table, rejects `alpn = ["h3"]` on the TCP TLS
   table (h3 belongs to the QUIC endpoint, which offers it automatically) and
   rejects `proxy_receive` (a QUIC connection has no preamble to carry a
   PROXY v1 line). `:0` resolves the TCP port first and the UDP socket binds
   the same resolved port, so the "one address" contract also holds in tests.

2. **Real protocol stack: `quinn` 0.11 + `h3` 0.0.8 + `h3-quinn` 0.0.10.**
   quinn is built with `rustls-aws-lc-rs` and without default features so the
   single crypto provider of the workspace (ADR-0004) is kept and `ring` is
   not pulled in. The QUIC server config is derived from the very same
   rustls `ServerConfig` the TCP listener uses (certificates, SNI entries,
   mTLS verifier), with ALPN forced to `h3`; the listener's `idle_timeout`
   becomes the QUIC transport idle timeout, and `MAX_CONCURRENT_STREAMS` the
   transport bidir-stream limit.

3. **Every h3 request becomes one h1 exchange through the existing engine.**
   The translation reuses the h2 path's `build_request_head` (origin-form
   request line, `:authority` → `host`, hop-by-hop headers stripped, framing
   chosen explicitly). One task owns the h3 `RequestStream` and applies
   response commands; another reads the h1 answer and sends those commands
   through a bounded channel (4 × 16 KiB). That keeps a slow request body
   from blocking an early answer and keeps buffering bounded. An h3 stream
   without END_STREAM on HEADERS is sent upstream as `chunked`; a body-less
   request is peeked once (`poll_recv_data` is stateful) and keeps exact
   framing.

4. **Lifecycle is the TCP lifecycle.** `BoundProxy::bind` opens the UDP
   endpoint before any accept loop runs (fail-closed: a bad QUIC/TLS config
   or a busy UDP port aborts startup with the other sockets closed). A hot
   reload keeps the endpoints of kept listeners, can turn QUIC on or off for
   one listener, and rejects a change to the settings a live endpoint freezes
   (`ProxyError::QuicTlsReload`). Shutdown sends CONNECTION_CLOSE and stops
   accepting.

   **Amended by [ADR-0025](0025-certificate-renewal-without-restart.md)
   (2026-10-25):** the endpoint freezes its ALPN, client-CA verifier and
   minimum TLS version, but **not** the certificate resolver, which it
   consults on every handshake. A chain, key or SNI-name change is therefore
   adopted in place and hot on HTTP/3; only a change to those three frozen
   settings is still refused.

5. **`maxconn` counts QUIC connections.** When a listener is full, the
   handshake is refused (`Incoming::refuse`) and `connections_rejected` is
   incremented — the same explicit refusal TCP does, never an unbounded
   accept queue.

6. **Grease is disabled on the server connection.** h3 0.0.8 appends a grease
   frame immediately before FIN on the first completed stream of a
   connection. aioquic 1.2.0 (an independent QUIC/h3 client) then swallows
   the end-of-stream: its DATA event stays `stream_ended = false` and a
   correct, complete response never resolves. Greasing is optional (RFC 9114
   §7.2.8), so `send_grease(false)` is set for interop. The first E2E run
   with aioquic failed exactly this way; the fix was verified by the same
   harness (see `docs/evidence/v07-http3.md`).

## Deliberate limits of this slice

- **No `CONNECT` over h3**: WebSocket/Extended CONNECT over HTTP/3 (RFC 9220)
  is not implemented; a CONNECT answers `501` before any backend contact.
- **No interim (1xx) responses**: h3 0.0.8 has no `send_informational`; an
  upstream `100 Continue`/`103` is logged and skipped, the final response is
  still relayed.
- **No gRPC-over-h3**: the gRPC relay is an HTTP/2 stream feature; an h3 gRPC
  request is translated to h1 like any other request.
- **No HTTP/3 to backends**, no 0-RTT, no connection migration: backends stay
  HTTP/1.1 or HTTP/2 per their TLS ALPN.
- A QUIC listener's TLS material cannot be rotated by SIGHUP; a process
  restart is required (the reload is rejected, never partially applied).

## Alternatives considered

- **A separate h3 request engine** (own rules/auth/compression): rejected —
  duplicate decisions drift, and the h2 slice already proved the
  translate-and-reuse shape.
- **Serving h3 only when the client offers it via Alt-Svc on the TCP
  listener**: a separate discovery feature (advertising), orthogonal to
  termination; not needed to meet B-H2, and it would not make a QUIC-only
  client work.
- **Hand-rolled QUIC/h3**: rejected by SPEC §4 (no own cryptography, no
  parsing complex protocols when maintained libraries exist).
- **Ignoring the aioquic hang**: rejected — an interop-only "works with our
  own client" claim is exactly the kind of verification theater the process
  forbids.

## Consequences

- An HTTP/3 client reaches the same routing/auth/compression decisions as an
  HTTP/1.1 or HTTP/2 client, verified with a real h3 client and with two
  independent implementations, aioquic 1.2.0 and quic-go 0.64.1, through the
  release binary.
- Operators must remember that QUIC shares the TCP port on UDP: the firewall
  needs UDP opened, and cert rotation for a QUIC listener needs a restart.
- The UDP endpoint adds no new counters: QUIC connections count in
  `client[accepted/rejected/completed]`, and each exchange is counted by the
  h1 engine (`proxied`, compression, rules) exactly like any other.
