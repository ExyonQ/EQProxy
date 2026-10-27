# ADR-0028: A maintenance window closes what is ours, not just the rotation

Language: **English**.

- State: **Accepted** (2026-10-26, roadmap v0.8 / B8, after ADR-0018 and
  ADR-0024)
- Date: 2026-10-26
- Related: [ADR-0018](0018-first-write-path-server-state.md) (the state this
  extends), [ADR-0024](0024-drain-observability.md) (the finished-drain event
  this reuses the shape of), [ADR-0029](0029-panel-sessions-and-csrf.md) (the
  panel that offers the state), [SPEC §9](../SPEC.md),
  [PARITY_MATRIX.md](../../PARITY_MATRIX.md),
  [evidence](../evidence/v08-maintenance.md)

## Context

ADR-0018 introduced per-server administration state with two values, and its
own pending list said why it stopped there:

> `maintenance` state earns its place when the pool can close a server's idle
> connections at the transition, instead of letting them age out on their own
> timer.

A `drain` removes a server from **new** selections and lets in-flight
exchanges finish. That is the right primitive for a rolling deploy, and it is
deliberately cheap: the keep-alive pool keeps the server's parked sockets and
the backend HTTP/2 session keeps its connection, so a drained server that comes
back does not pay a handshake. For a patch window that is exactly wrong: the
box is about to be rebooted, and EQProxy is still holding live TCP sockets and
an h2 connection on it. Closing them by waiting for the pool's idle timeout
leaves them there for minutes, and there is no way for an operator to say "I am
taking this machine now" instead of "stop sending me new work".

Two constraints shaped the answer:

- **One meaning per state.** `drain` must keep meaning "no new exchanges, keep
  everything else": an operator who drains a server during a deploy relies on
  the pool staying warm. Reusing `drain` for the patch window would silently
  change it.
- **The pool is not the only holder.** After ADR-0007/0008 the dataplane also
  keeps one HTTP/2 session per TLS server, multiplexed across exchanges. A
  window that closed only the h1 pool would leave the h2 session open.

## Decision

### A third state, with the same selection semantics as `drain`

`ServerMode` gains `Maintenance` (`"maintenance"` on the wire; the reference's
`maint` is not accepted as an alias — a typo must not remove a server). For
selection, a maintenance slot is a removed slot: it is never picked, retries
and affinity skip it, and it is reported in the status JSON with the same
`state`/`active`/`drained` triple. `drained` is generalised to "removed **and**
nothing in flight", so one field answers both windows.

### At the transition, the idle material is closed

`PUT /api/v1/backends/{backend}/servers/{target}/state {"state":"maintenance"}`
sets the state **first**, then sweeps the server's parked material for the
resolved address:

- the HTTP/1.1 keep-alive pool closes its idle sockets
  (`Pool::close_idle`), and
- the backend HTTP/2 hub removes the session from its registry and closes it
  at once when nothing is in flight — or the moment its last stream ends
  (`Hub::close_idle`, `close_when_idle`).

The order matters: a connection parked between the state write and the sweep
is caught by the sweep, and a connection of an exchange that finishes later is
never parked at all, because the completion path refuses to pool a
`maintenance` slot (`ActiveGuard::mode`). Both halves are needed; either one
alone leaves a window where a socket survives.

An exchange already in flight is **never cut**: it finishes on the server, the
client gets its answer, and the window opens when the last guard drops.

### The window opening is an event

`ActiveGuard::drop` already computed the exact moment the last exchange ends
(ADR-0024). On a maintenance slot that moment writes one line:

```
INFO server ready for maintenance: backend=api target=127.0.0.1:9000 active=0
```

A slot put into maintenance while idle is already finished: it reports
`drained: true` immediately and no line is written, because nothing ended.

### Observability: a gauge, and no drain counter

`/metrics` gains `eqproxy_backend_servers_maintenance`, a label-free gauge
counting slots declared in that state (with or without work left). The
per-slot `active`/`drained` pair that says *how far* a window is lives in
`GET /api/v1/status`, where the budget is the configured topology.

`eqproxy_backend_drains_completed_total` stays **drain-only**. A maintenance
window is not a drain, and extending the counter would make one published
series mean two things. Anyone alerting on "drains completed" keeps the same
signal.

## Consequences

- An operator has one action that means "take this box now": rotation stops,
  our sockets leave, the client traffic that was already on it completes, and
  the event is in the log at the exact instant.
- Two states to learn instead of one, with a clear difference: `drain` keeps
  the pool warm, `maintenance` empties it. The panel offers both next to
  `ready` and the status shows which one is in force.
- The state is runtime-only and survives `SIGHUP` like every per-server state
  (ADR-0018); it does not survive a restart, and the file remains the baseline.
- A raw-TCP listener has no backend pool of its own: there, `maintenance` is a
  removal from selection like `drain`, and there is nothing to close. The
  journey and the E2E name this rather than implying protocol coverage that was
  not measured.
- A server that is marked down by health checks **and** in maintenance is
  reported as both: the health machine is a separate axis, and a window does
  not stop the probes.

## Alternatives considered

- **Close the pool on every `drain`.** Simple, and wrong: it changes what
  `drain` costs (a warm pool is the point of draining during a deploy) and
  makes the cheap operation the expensive one.
- **A separate action route (`PUT …/close`) next to `drain`.** Two operations
  for one intent, and a client could sequence them wrong; the state machine
  would then have a "drained but still holding sockets" value nobody wants.
- **Let the idle timer do it.** The pool's idle window is minutes by design; a
  patch window cannot wait for it, and the sockets would still be on the box
  when the operator pulls it.
- **Cut in-flight exchanges as well.** That turns an administrative window
  into a connection reset for real users; the drain semantics already get this
  right, and maintenance reuses them.

## References

- [ADR-0018](0018-first-write-path-server-state.md) — the state model and its
  pending item this closes.
- [ADR-0024](0024-drain-observability.md) — the finished state as a field and
  the event written where the last guard drops.
- [ADR-0008](0008-http2-backend-multiplexing.md) — the backend h2 session the
  window closes.
- [Evidence: v08-maintenance](../evidence/v08-maintenance.md) — release-binary
  journey: the origin's own open-connection count drops to zero at the
  transition, an in-flight exchange finishes, and the gauge/counter contract
  holds.
