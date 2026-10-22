# ADR-0009: Backend HTTP/2 session lifecycle

Language: **English**.

- State: **Accepted** (2026-10-22, fourth v0.7 slice)
- Date: 2026-10-22
- Supersedes: ADR-0008 §Consequences ("No idle close yet", "No graceful
  drain … is claimed")
- Related: [ADR-0008](0008-http2-backend-multiplexing.md) (multiplexing),
  [ADR-0007](0007-http2-backend.md) (HTTP/2 to the backend), SPEC §7.6
  (keep-alive pool), SPEC §13 (semantic difference log)

## Context

ADR-0008 made concurrent exchanges share one h2 session per backend server.
Two lifecycle gaps remained, both consequences of the hub owning the session
for the life of the process:

1. **No idle close.** An unused backend kept its TLS+h2 session open forever.
   The h1 pool closes idle connections after its window (A16/SPEC §7.6); the
   hub had no equivalent.
2. **GOAWAY was implicit.** The `h2` crate refuses new streams on a session
   that received a GOAWAY and ends the connection once its streams finish,
   but the hub could not express "do not hand this session out" or "this
   stream was refused, replay it". A request that raced a GOAWAY failed with
   `502` even when the peer had explicitly said it never processed it.

## Decision

### Idle close

- The session's idle window is the listener's `idle_timeout` (the same
  per-operation inactivity bound the exchange pipes already use, and the
  value that bounds a client's keep-alive wait after the previous slice).
  The window is fixed when the session is dialed; listeners that share a
  backend are expected to agree, which the documented defaults do.
- One mutex per session guards `{sender, active exchanges, last idle, going
  away}`. **Admitting an exchange and closing the session are the same
  critical section**, so a close can never cut an exchange that was already
  admitted; `ExchangeSlot` decrements on drop and stamps the idleness start.
- A monitor task per session sleeps a quarter of the window (bounded to
  10 ms – 500 ms), and once the session is idle it takes the sender out,
  unregisters the session and ends the connection. New exchanges dial a fresh
  one.
- The `h2` **client** API has no client-side GOAWAY (`go_away_gracefully` is
  server-only in `h2 0.4`), so an idle close ends the connection after its
  last stream instead of announcing it. Nothing is in flight at that point,
  so no stream is lost; the peer sees a normal connection close.

### GOAWAY drain

- A received GOAWAY is detected where it surfaces: `send_request` or the
  response future returns `h2::Error` with `is_go_away() && is_remote()`.
  The session is retired (removed from the hub, sender dropped) and counted
  in `h2_goaway_received`; **streams already accepted keep running** because
  the relay holds its own sender clone and the `h2` connection stays alive
  until they finish. The connection task then removes the session.
- New exchanges therefore never take a stream on a session the peer is
  closing: they either find nothing in the hub (fresh dial) or are refused by
  the drained session and replayed.

### Safe refusal replay

- A refusal is replayable **only** when the peer states that it did not
  process the stream: a received GOAWAY, or `RST_STREAM` with
  `REFUSED_STREAM` (RFC 9113 §8.1.4). A connection cut after processing is
  **not** replayable, and neither is any failure after request bytes were
  forwarded — the replay would need a buffered body and could duplicate side
  effects.
- One replay per exchange, on a fresh session: the retired session is not
  reused, the dialer holds the same server address (balancing is not re-run,
  so the retry budget is not spent twice), and the replay re-sends the very
  same request head. The relay aborts before writing anything to the client,
  so the client cannot observe the attempt.

## Consequences

- An idle backend no longer holds a session for the process lifetime: after
  `idle_timeout` it closes and the next exchange pays one handshake.
- A GOAWAY drains in flight work and moves new work to a fresh session; a
  request that races it is served once, not failed. `h2_refused_retried`
  counts the replays, `h2_goaway_received` the sessions the peer announced,
  `h2_sessions_idle_closed` the idleness closes.
- A refused stream **with a request body** is not replayed (the body was
  consumed from the engine's pipe): it fails as before. Replaying bodies
  would require a bounded replay buffer, which this slice does not add.
- A session that refuses streams is retired, even though `REFUSED_STREAM`
  does not itself close the session. The alternative — replaying onto the
  same session — retries into the same refusal; one handshake is the cheaper
  price, and refusals are exceptional (the `h2` crate queues at the peer's
  concurrency limit instead).
- No benchmark is claimed: the idle close and the replay add one handshake,
  and no throughput or latency figure is measured.
