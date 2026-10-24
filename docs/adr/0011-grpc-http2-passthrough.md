# ADR-0011: gRPC streams are relayed end to end, not translated

Language: **English**.

- State: **Accepted** (2026-10-23, seventh v0.7 slice)
- Date: 2026-10-23
- Related: [ADR-0006](0006-http2-termination.md) (h2 termination),
  [ADR-0007](0007-http2-backend.md) (h2 to the backend),
  [ADR-0008](0008-http2-backend-multiplexing.md) (one session, many streams),
  [ADR-0009](0009-http2-session-lifecycle.md) (idle close, GOAWAY, replay),
  SPEC §7.5 (HTTP semantics), SPEC §13 (semantic difference log)

## Context

HTTP/2 is delivered in three pieces: termination at the listener, a real h2
session to the backend, and multiplexing/lifecycle on top. Every one of them
sits behind the **single HTTP/1.1 exchange engine**: an h2 stream becomes one
h1 message on an in-memory pipe, that engine routes it, and the answer is
translated back. That design is why routing rules, auth, retries, the pool and
the error surface exist once.

It is also why gRPC does not work bidirectionally. A gRPC call is one HTTP/2
stream whose directions are independent:

- the client keeps sending DATA frames after it has sent a message, while the
  server answers on the same stream;
- the status arrives in **trailing HEADERS** (`grpc-status`, `grpc-message`),
  not in the response head;
- long-lived streams are normal: a stream may stay open for minutes with a
  message every few seconds.

The h1 engine forwards the whole request body before it reads the response
head. A bidi stream therefore never sees its first answer until the client
half-closes — the exchange deadlocks against its own protocol. Translating to
h1 also cannot represent a trailers-only status with the client being an h2
peer.

The proxy already has all the machinery a real relay needs: the h2 client
session hub (ADR-0008), per-stream admission and GOAWAY handling (ADR-0009),
`capacity`/flow-control helpers, and the routing decision (`decide`) plus the
header helpers the h1 engine uses.

## Decision

When a request is gRPC (`content-type: application/grpc` or
`application/grpc+…`, `POST`) **and** the backend is configured for HTTP/2
(ALPN `h2`), EQProxy relays the stream itself instead of translating it:

1. **Decisions stay shared.** The h2 request is rendered as the same h1 head
   the h1 engine would forward (`build_request_head`), parsed with the strict
   parser, and passed through the **same** helpers: `cfg.decide` (routing
   rules), rate limiter, `auth::check`, rule header actions, forwarded
   headers, rewrite. No second implementation of any of them.
2. **One backend stream per exchange.** `open_grpc_stream` picks a server
   with the normal balancer/queue policy, takes the single-flight handshake
   (`session_for`), admits the stream on the session (`Session::enter`), and
   sends the request HEADERS. The gRPC request keeps `te: trailers` (an h2
   requirement) and never carries h1 framing.
3. **Both directions run at once.** The client's DATA/trailers are forwarded
   to the backend while the backend's HEADERS/DATA/trailers are forwarded to
   the client. HTTP/2 flow control is the only buffer: capacity is released
   only after the peer accepted the chunk.
4. **Timeouts are the stream's, not the message's.** `idle_timeout` cuts a
   stream with no DATA in either direction (counted as inactivity).
   `max_stream_duration`, when configured, ends a running stream with
   `grpc-status: 4` (DEADLINE_EXCEEDED) trailers; before the response head it
   is a `504`, exactly like the h1 engine's total cap.
5. **No replay.** A stream the peer refused after opening it is not
   replayed: a gRPC exchange is not idempotent. Connect-phase failures keep
   the B-H7 retry policy because nothing reached the server.

Anything else — a non-gRPC request, a redirect/direct rule, a backend without
`h2` — returns the request untouched to the existing h1 translation. The
pass-through is an addition, never a replacement.

## Consequences

**Positive**

- gRPC bidi works end to end: answers arrive before the client half-closes,
  trailers cross both ways, and N streams share the one backend session from
  ADR-0008 (proved by a real `grpcio` client and a barrier in the origin).
- Every routing/auth/header feature applies to gRPC because the decision
  pipeline is the h1 one.
- Message size is bounded by flow control, not by a proxy buffer: a 256 KiB
  message crosses both windows unmodified.

**Negative / explicit limits**

- Compression is not applied to gRPC streams (gRPC has its own message
  compression); the `[listener.X.compression]` policy is ignored on this path.
- Mirroring is not applied: a mirror copy needs a complete body, and a
  stream never has one.
- A trailers-only backend answer is forwarded as an ended stream; the client
  gets its status without DATA.
- `CONNECT` over h2, WebSockets over h2 and HTTP/3 remain out of scope
  (B-I18, B-H2).
- The pass-through needs an h2 backend. A gRPC backend reachable only over
  h1 cannot be served correctly — gRPC requires HTTP/2 — so the request
  keeps the h1 translation and fails there explicitly rather than pretending.

## Alternatives considered

- **Make the h1 engine full-duplex.** It would fix bidi for every path at
  once, but it rewrites the framing guarantees (early responses, request-body
  draining, pooled connection alignment) that 396 tests and the A16 pool
  contract rest on. The blast radius is the whole dataplane for a benefit
  only h2-to-h2 gRPC can use.
- **Buffer the request body and then relay.** Breaks the defining property
  of bidi streams and turns long streams into unbounded memory.
- **A separate h2-to-h2 proxy for gRPC.** Duplicates routing, auth and
  headers; two implementations drift. Reusing `decide` and the head helpers
  keeps one source of truth.
