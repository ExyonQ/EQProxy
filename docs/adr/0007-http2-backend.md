# ADR-0007: HTTP/2 to the backend

Language: **English**.

- State: **Accepted, superseded in part by [ADR-0008](0008-http2-backend-multiplexing.md)**
  (2026-10-22, third v0.7 slice): the "one exchange at a time per session"
  decision and the pooling paragraph below no longer hold — exchanges now
  take independent streams on a shared session.
- Date: 2026-10-22
- Related: [ADR-0006](0006-http2-termination.md) (client-side termination),
  SPEC §4 (use maintained protocol libraries), SPEC §13 (semantic difference
  log)

## Context

ADR-0006 left the upstream side on HTTP/1.1 and kept the configuration gate
rejecting `alpn = ["h2"]` on a backend used by an `http` listener — the v0.6.3
trap in the other direction. The v0.7 roadmap asks for `http2_protocol_options`
parity (`B-H1`/`B-N1`/`B-I1`/`B-E2`), and gRPC (`B-I12`) cannot exist without
it: a gRPC server refuses HTTP/1.1 request bytes.

Two shapes were again possible:

1. **Refactor the exchange engine** into a backend-protocol abstraction and
   implement an h1 and an h2 client behind it.
2. **Mirror ADR-0006**: keep the engine's byte stream exactly as it is and
   bridge it to a real h2 session — `h1 message ⇄ one h2 stream`.

The engine (`http1::serve_http`) owns the retry policy, the keep-alive pool
with its A16 reuse contract, `Content-Length`/chunked forwarding, trailing
headers, `Expect: 100-continue`, upgrade tunnels and every error path. Option 1
touches all of it at once; option 2 leaves it byte-for-byte and puts the h2
knowledge in one module that can be tested in isolation.

## Decision

- **Opt-in, negotiated**: the backend speaks HTTP/2 when its TLS handshake
  negotiates `h2` — that is, `[backend.X.tls] alpn` lists it and the server
  agrees. There is no h2c-to-backend option yet; a plaintext backend keeps
  speaking HTTP/1.1. A `tcp` listener relays bytes and never inspects ALPN.
- **Handshake in the connect phase**: `h2::client::handshake` runs inside
  `connect_backend_to`, so an h2 backend that cannot speak h2 is a connect
  failure (retried per B-H7, answered `502`), never an open connection that
  fails per request. It is bounded by `connect_timeout`.
- **Bridge, not a second engine**: `backend_h2` (originally `bridge`,
  restructured as `connect` + `open` in ADR-0008) publishes an in-memory
  64 KiB duplex to the engine and translates one h1 message per h2 stream.
  Request: `content-length` kept only when the h1 side declared one, chunked
  bodies as DATA, h1 trailers as trailing HEADERS, hop-by-hop headers and
  `host`/`expect`/`te` stripped (`:authority` carries the host). Response:
  a backend `content-length` is preserved (the h1 side copies exactly that
  many bytes and the pool stays aligned); without one the body is relayed as
  `chunked` and h2 trailers become h1 trailers.
- **Pooling unchanged** (superseded by ADR-0008): the pipe pair is a normal
  pooled connection, so one exchange at a time per h2 session. It was the
  price of not touching the engine in this slice; ADR-0008 removes the pool
  from the h2 path and multiplexes streams instead.
- **Explicit refusals**: `CONNECT` (no `101` in h2) and a host-less request
  are refused, and the engine answers `502`; a body shorter or longer than its
  declared length cuts the pipe instead of ending a message cleanly.
- **Gate removed**: `eqproxy-config` no longer rejects `alpn = ["h2"]` on a
  backend used by an `http` listener — it is served now. The token stays valid
  for `tcp` listeners, as before.

## Consequences

- An h2 client can reach an h2 backend with HTTP/2 on both sides; an h1 client
  reaches it through the same engine and the same session.
- Each backend exchange pays one h1 parse plus one h2 encode (and the mirror on
  the response). That cost is not measured in this slice and is not claimed as
  free; it is the price of a single engine.
- h2 interim (`1xx`) responses from a backend are consumed by the client
  library and never forwarded; `100-continue` is answered by the proxy itself.
- A backend that pairs `content-length` with trailers loses the trailers (h1
  cannot express that combination without re-framing); chunked h2 answers
  carry them.
- gRPC still needs client-side extended CONNECT/h2 streaming plus a request
  body that is not `content-length`-framed end to end; this slice does not
  claim `B-I12`.
