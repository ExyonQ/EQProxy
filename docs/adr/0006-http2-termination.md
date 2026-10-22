# ADR-0006: HTTP/2 termination strategy

Language: **English**.

- State: **Accepted** (2026-10-22, first v0.7 slice)
- Date: 2026-10-22
- Related: [ADR-0004](0004-network-stack-and-crate-layout.md) (crates and
  network stack), SPEC §4 ("do not parse complex protocols with our own code
  if maintained libraries exist"), SPEC §13 (semantic difference log)

## Context

v0.6.3 closed a trap: `alpn = ["h2"]` was accepted by the configuration gate,
negotiated on the wire and then failed every request, because the dataplane is
HTTP/1.1 only. The gate in `eqproxy-config` rejected the token instead. The
v0.7 roadmap (`B-H1`, `B-N1`, `B-I1`, `B-E2`) asks for HTTP/2 for real, so the
gate has to go and something has to answer between the handshake and the byte
stream.

The dataplane already carries a lot of behaviour that an HTTP/2 path must not
re-implement: routing rules (host/path/method/header/cookie/map/IP), four rule
actions, header actions with templates, CORS/HSTS, basic and subrequest
authentication, rate limiting, mirroring, retries, the keep-alive pool with its
reuse contract (A16), per-phase timeouts, `max_stream_duration`, and the whole
error vocabulary (`502` on a dead backend, `503` with the custom local
response, `504` on header timeout…). A second implementation would drift from
it on the first fix.

Two shapes were possible:

1. **Rewrite the exchange engine** so it is generic over a client protocol
   adapter, and implement two adapters (h1 bytes, h2 streams).
2. **Translate per stream**: turn one h2 stream into exactly one HTTP/1.1
   message on an in-memory pipe and run the existing engine on it (`h2 ⇄ h1`).

Option 1 is the theoretically cleaner boundary, but it means rewriting
`http1::serve_http` (≈900 lines of interleaved routing, actions, forwarding,
pool and timeout handling) and re-verifying every one of the 300+ tests that
exercise it through the real dataplane. Option 2 keeps the engine byte-for-byte
and adds a translation layer that can be tested on its own.

The HPACK/framing side is never hand-written: SPEC §4 forbids re-implementing
maintained protocol machinery. The `h2` crate (0.4) provides framing, HPACK,
flow control, stream state and GOAWAY; it is the crate the Rust ecosystem's
clients and servers ship.

## Decision

- **Termination**: the listener terminates HTTP/2 with `h2`. The protocol is
  chosen by ALPN `h2` on a TLS listener, or by the h2c connection preface
  (RFC 9113 §3.4) on a plaintext one, detected with `peek` so a false answer
  leaves the connection untouched for the HTTP/1.1 engine.
- **Translation**: each accepted stream becomes one HTTP/1.1 message on a
  bounded 64 KiB duplex pipe; `http1::serve_http` handles it unchanged. The
  response is parsed by the same strict h1 parser and relayed as h2 frames.
- **Upstream stays HTTP/1.1** in this slice. The backend gate keeps rejecting
  `alpn = ["h2"]` on a backend used by an `http` listener, because that would
  be the v0.6.3 trap in the other direction.
- **Framing translation**: `content-length` is preserved; a body without it
  goes out as `transfer-encoding: chunked`; chunked responses are decoded into
  DATA and their trailers become trailing HEADERS; hop-by-hop h1 headers never
  cross in either direction.
- **Explicit refusals**: `101` from a backend resets the stream (h2 has no
  protocol switch), `CONNECT` is answered `501`, and a body shorter than its
  declared length resets the stream instead of ending it.
- **Bounds**: at most 128 concurrent streams per connection (each holds one
  backend exchange), 16 KiB DATA reads, and send capacity is reserved before
  each DATA frame so nothing buffers without limit.

## Consequences

> Update (2026-10-22, second slice): the "upstream stays HTTP/1.1" decision
> was replaced by [ADR-0007](0007-http2-backend.md), which speaks HTTP/2 to a
> backend that negotiates `h2`. The rest of this ADR still describes the
> dataplane.

- Every h2 request sees the same decisions and error surfaces as h1. Fixing a
  rule bug fixes it for both protocols.
- A stream costs one extra task and one 64 KiB pipe, plus header
  re-serialization. That cost is measured in the evidence document and is the
  price for not duplicating the engine; upstream h2 is the next slice.
- HTTP/2-only features that the h1 engine cannot express are out of scope
  until upstream h2 exists: server push, extended CONNECT (WebSockets over
  h2, `B-I18`), gRPC end-to-end streaming (`B-I12`) and `http2_protocol_options`
  parity. They are listed as pending in the roadmap, not claimed.
- The h2 crate brings `bytes`, `http`, `tokio-util` and `tracing` into the
  dependency graph; `cargo-deny`/`cargo-machete` keep them honest and the
  inventory is part of the release gate.
