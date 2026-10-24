# ADR-0015: Backend idle-pool sizing

Language: **English**.

- State: **Accepted** (2026-10-23, v0.7 slice 10)
- Date: 2026-10-23
- Related: [ADR-0008](0008-http2-backend-multiplexing.md) (h2 session hub),
  [ADR-0009](0009-http2-session-lifecycle.md) (idle close of h2 sessions),
  SPEC §7.6, BENCHMARK_PLAN §3 (S-H2-01)

## Context

The A16 keep-alive pool kept **at most 64 idle connections per server**, a
constant chosen in Phase 3 for a v0.6 workload of tens of concurrent
exchanges. The v0.7 S-H2-01 campaign (h2 to the proxy, **400 streams in
flight**, HTTP/1.1 origin) showed what that constant costs when concurrency
is higher: with 400 exchanges open, only 64 connections were parked on
completion and the remaining 336 were dropped, so the next wave re-dialled
them. Measured in
[`v07-h2-bench.md`](../evidence/v07-h2-bench.md):

| Metric | EQProxy (64-slot pool) | HAProxy 3.4.6 |
|---|---|---|
| Throughput | 5 704.0 req/s | 57 453.2 req/s (0.099×) |
| Backend connections opened | 141 155 (28 231/run) | 6 106 (797–1 880/run) |
| Backend connections per 1 000 requests | 192.85 | 1.22 |
| Responses | 731 939 × `200`, **7 473 × `502`** | 5 017 486 × `200`, 0 errors |

The churn exhausted the ephemeral port range and produced the `502`s: the
proxy was not slow at proxying, it was busy opening and closing the same
connections. A fixed constant is wrong in both directions — too small for a
multiplexed front end, wastefully large for a quiet deployment — and raising
it to another constant only moves the cliff.

## Options

1. **Raise the constant** (for example 512). One-line change, but it is a
   guess: the next workload with more concurrency hits the same wall, and
   every deployment pays the larger idle set even when it never needs it.
2. **Expose `pool_idle` in the configuration.** Gives operators a knob, but
   the default stays wrong, the benchmark scenario would have to be tuned to
   pass, and nothing tells the operator which value their traffic needs.
3. **Size the cap from the concurrency actually observed.** The balancer
   already counts the exchanges in flight per server (`ActiveGuard`, B-H5);
   the pool can follow the peak of that number, clamped between a floor and a
   hard ceiling. No new configuration, no fixed cliff, bounded memory.

## Decision

Option 3.

- **Peak, recorded at borrow time.** `Pool::note_in_flight` is called where a
  connection is handed to an exchange (pool hit or fresh dial), with the
  balancer's in-flight count for that server, this exchange included. Sizing
  at check-in alone would race a burst that is still starting: the first
  completions would measure a low count and drop connections that the burst
  needs. The peak is monotonic per server for the life of the process.
- **Clamp.** The idle cap is `clamp(peak_in_flight, IDLE_FLOOR_PER_SERVER,
  IDLE_CEILING_PER_SERVER)`: floor **64** (the previous behaviour, kept as
  cold-start headroom) and ceiling **4096** (a workload cannot pin sockets
  and descriptors without bound). Above the ceiling the previous behaviour
  returns: excess is dropped at check-in and re-dialled later.
- **Expiry unchanged.** Idle connections still expire after 60 s
  (`DEFAULT_POOL_IDLE_TIMEOUT`), so a burst's leftovers are released without
  another exchange having to arrive.
- **Reuse contract unchanged (A16).** Only a cleanly finished exchange is
  parked, and a checkout still yields a message-aligned connection or
  nothing.
- **No idle close of a live backend h1 connection**, as before; the pool is
  reaped lazily by expiry and by checkout.

## Consequences

- At 400 streams in flight the pool keeps ~400 connections instead of 64, so
  the second wave is served from the pool: the E2E test asserts that the
  first wave dials exactly 400, that the second dials none, that all 400 are
  pool hits and that the origin accepts no new connection during the second
  wave (`pool_sizing_keeps_a_400_stream_burst_without_churn`). The origin
  holds every request while a wave is open, so the 400 exchanges really are
  concurrent instead of depending on scheduling.
- Connections opened per 1 000 requests should fall from ~193 to single
  digits in the S-H2-01 campaign; the campaign is rerun and published
  separately, and this ADR makes no throughput claim before that data exists.
- Memory grows with the observed peak (one idle socket plus buffers per
  parked connection, bounded by the ceiling); a deployment that once saw a
  burst keeps the larger cap until restart, but the sockets themselves are
  closed by the idle expiry, so the steady-state footprint returns to the
  live count.
- The cap is **not** a substitute for `maxconn`: the listener's admission
  limit still bounds client connections, and the pool cannot keep more idle
  sockets than were actually opened.
- The peak is per selected server address (the pool's key), so a backend
  pool that balances across N servers sizes each one from its own share of
  the concurrency.
