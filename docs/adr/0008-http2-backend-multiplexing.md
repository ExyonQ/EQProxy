# ADR-0008: HTTP/2 backend multiplexing

Language: **English**.

- State: **Accepted** (2026-10-22, third v0.7 slice)
- Date: 2026-10-22
- Related: [ADR-0007](0007-http2-backend.md) (HTTP/2 to the backend),
  [ADR-0006](0006-http2-termination.md) (client-side termination),
  SPEC §7.6 (keep-alive pool), SPEC §13 (semantic difference log)

## Context

ADR-0007 gave the backend real HTTP/2 but kept the engine's exclusive pool:
one exchange held the h2 connection, so an h2 backend served one request at a
time — half the reason HTTP/2 exists. The pool's contract is byte alignment
(A16): a connection is returned only after a clean message boundary. An h2
session has no "message boundary" in that sense: streams are independent and
interleaved, so pooling the session is the wrong shape.

Two options:

1. **Give the pool an h2 mode**: reuse the session object and hand it to N
   exchanges concurrently. The pool's ownership model (`checkout` /
   `checkin` with exclusive access) does not express sharing, and the engine
   would need to know, per connection, whether it may interleave.
2. **Separate the session from the connection**: the backend keeps a hub of
   sessions (one per server address), and each exchange gets its own stream
   on the shared session behind a private in-memory pipe. The engine keeps
   seeing a single-use connection; concurrency is a property of the hub.

## Decision

- **Session hub per backend**: `backend_h2::Hub` maps server address →
  live session. `ResolvedBackend.h2` is `Some` exactly when the backend TLS
  offers `h2`, and every exchange to that backend goes through the hub.
- **One stream per exchange**: `open` creates a bounded 64 KiB duplex, spawns
  the h1⇄h2 relay for that pipe and returns the engine's halves. The pipe is
  never pooled: `BackendConn.poolable = false` makes `http1::serve_http` skip
  the check-in, so a pipe belongs to one exchange by construction.
- **The handshake is single-flight**: a cold server takes a per-address gate
  (`Hub::connect_gate`) while it dials and handshakes. Exchanges that arrive
  meanwhile wait for the gate, re-check the hub and take a stream on the
  session it installs. Without the gate, two concurrent first requests each
  dial their own connection — measured, not theorised: the dataplane test
  went from 2 accepted backend connections to 1.
- **A dead session is forgotten, not resurrected**: the connection task sets
  `alive = false` and removes the entry when the h2 connection ends. The next
  exchange looks up, finds nothing and dials again; the test forces the
  backend to hang up and asserts exactly one replacement session.
- **Counters keep their meaning**: a stream on a live session counts
  `backend_connections_reused`; a new session counts
  `backend_connections_opened`; a failed dial or handshake counts
  `connect_failures` and answers `502` after the B-H7 retry policy.
- **Health checks, balancing and affinity keep operating per server**, as
  before: the hub changes how an established server is used, not how it is
  chosen or probed.
- **`tcp` listeners never multiplex**: `DialTimeouts.http` is only set for
  `mode = "http"`, so a byte tunnel relays the TLS stream as it always did,
  even when its ALPN selects `h2`.

## Consequences

- A concurrent workload now uses one TCP+TLS+h2 connection per backend
  server instead of one per in-flight exchange; the session carries as many
  streams as the peer's `SETTINGS_MAX_CONCURRENT_STREAMS` allows, and the
  `h2` crate queues a stream that arrives at the limit.
- The per-stream 64 KiB pipe bounds memory per exchange and gives a slow h2
  backend backpressure; the TLS socket is a single writer shared by streams,
  so a stalled exchange occupies pipe space, not the session.
- A session that dies between lookup and `send_request` fails that exchange
  with `502` (no bytes were sent, so nothing is delivered twice) and the
  following request dials a fresh session. This is the same fail-explicit
  rule the h1 pool follows for a server-side idle close (SPEC §7.6).
- No idle close yet: an unused backend keeps one TLS+h2 session open for the
  life of the process. Sessions are replaced on death, not on idleness.
- No test claims throughput or latency: the increment measures only that
  concurrent exchanges overlap and share one session.
- GOAWAY is handled by the `h2` crate (new streams are refused, the
  connection ends); the hub then dials a new session on the next exchange.
  No graceful drain of in-flight streams across a GOAWAY is claimed.
