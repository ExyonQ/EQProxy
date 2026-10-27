# ADR-0024: A finished drain is an event, not a poll

Language: **English**.

- State: **Accepted** (2026-10-25, roadmap v0.8 / H3, after ADR-0018)
- Date: 2026-10-25
- Related: [ADR-0018](0018-first-write-path-server-state.md) (the drain this
  observes), [ADR-0017](0017-read-only-admin-plane.md) (the read plane and
  `/metrics`), [ADR-0020](0020-structured-access-log.md) (log shape),
  [SPEC §7.3/§9](../SPEC.md), [PARITY_MATRIX.md](../../PARITY_MATRIX.md)

## Context

ADR-0018 gave the admin plane a real drain: a server leaves rotation at the
next pick and the exchanges already running finish on it. It also promised the
operator could watch the drain, and the status JSON reports `active`, the
exchanges in flight on each slot. That answers **how many are left**.

H3 ("drenaje observable: cuántas conexiones quedan y cuándo termina") asks for
the second half: **when it ends**. Before this ADR the only answer was to poll
`GET /api/v1/status` and compare `active` against zero across two reads, which
tells the operator nothing at the moment it happens and cannot be alerted on
without a scraper inventing the transition itself.

Two constraints shape the answer:

- **CE4 (bounded cardinality).** Every series in `/metrics` is a fixed name
  with no labels except `eqproxy_build_info`. Per-server labels would grow with
  the configured topology — and per-route ones with the config's routes — so a
  scrape could grow the index. A drain signal must not open that door.
- **The truth is in the dataplane.** `active` is incremented when an exchange
  takes its slot and decremented when the guard holding it drops. Any observer
  that infers completion from a timer poll can be late, and a signal computed
  in the admin plane's handler would put a side effect in a `GET`.

## Decision

### The finished state is a field, not a subtraction

`ServerView` gained `drained: bool = mode == Drain && active == 0`. It is
reported per slot in `GET /api/v1/status` and in the `PUT …/state` answer, so
one read answers both halves of H3 for a given slot:

```json
{"addr":"127.0.0.1:9000","resolved":"127.0.0.1:9000","weight":1,
 "state":"drain","healthy":true,"active":1,"drained":false}
```

After the last exchange ends the same slot reads `"active":0,"drained":true`.
A slot declared in `drain` while idle reads `"drained":true` immediately and
correctly: there was nothing to wait for.

### The event is recorded where it happens

`ActiveGuard::drop` already knew the moment the count reached zero. It now
checks the slot's administrative mode there, releases the server table, and —
only when the decrement lands on zero **and** the slot is drained — increments
the backend's `drains_completed` counter and writes one line:

```
INFO server drained: backend=api target=127.0.0.1:9000 active=0 events=1
```

Why there, and not in a watcher:

- **No timer, no lag.** The line is written in the drop that ends the drain,
  so its timestamp is the event's.
- **Exactly once per episode.** The decrement that reaches zero happens once;
  concurrent drops cannot both see zero. A drain with no in-flight exchange
  produces no line at all, because no exchange finished after it was declared.
- **The lock is not held during I/O.** The event data (`target`) is copied out
  and the guard dropped before the log line, so no writer waits on stderr.
- **The secret boundary is untouched.** The line carries the backend, the
  configured target and the count — never a token, a peer or a client.

### Two label-free series, and where the detail lives

`/metrics` gained exactly two lines, both derived from the live topology when
a scrape arrives:

```
# TYPE eqproxy_backend_servers_draining gauge
eqproxy_backend_servers_draining 1
# TYPE eqproxy_backend_drains_completed_total counter
eqproxy_backend_drains_completed_total 1
```

- `eqproxy_backend_servers_draining` counts slots **declared** in `drain`
  (with or without work left): the "I am taking this out" signal.
- `eqproxy_backend_drains_completed_total` counts finished episodes, summed
  over the backends.
- Neither carries a label, so a scrape cannot grow the index (CE4), and both
  exist from the first second at `0`, so a dashboard or alert can be written
  against a running process instead of only against a drain.

The per-slot detail — which server, how many exchanges, whether it finished —
stays in the JSON status, where the budget **is** the configured topology and
the reader asked for one document. A per-server Prometheus breakdown remains
unimplemented on purpose: it is the "detail opt-in with an explicit budget"
item of CE4, and it needs a config surface, not a free label.

## Alternatives rejected

- **A background watcher that polls the balancers.** Reports completion up to
  one tick late, needs a constant to tune, and duplicates state the drop
  already has.
- **Counting in the status handler when it sees `drained`.** A `GET` would
  change process state, and the count would depend on who scraped and how
  often.
- **`eqproxy_backend_server_state{backend,server}` in Prometheus.** Real
  cardinality growth driven by configuration, exactly what CE4 forbids before
  an explicit opt-in budget exists.
- **Logging every drain transition (`drain`/`ready`).** The write is already
  audited per attempt; a second line per transition would duplicate the audit
  trail without the identity that makes it useful.

## Consequences

- An operator can watch `active` fall to zero, read `drained: true` in the
  same document, alert on `drains_completed_total`, and grep one line naming
  the slot. Nothing has to be inferred from two polls.
- The counter lives in the `Balancer`. A `SIGHUP` reload builds a fresh
  balancer, so the counter restarts at `0` on reload — truthful for the
  lifetime of that balancer, and the same limit ADR-0018 records for the
  in-memory drain registry. The gauge has no such issue: it is derived from
  the live topology on every scrape.
- The event line is bounded by the number of drain episodes, not by traffic.
- `ServerView`, the status JSON and the `PUT` answer gained a field. `/api/v1`
  is still untagged, so this remains inside the window ADR-0018 opened.

## Pending (not decided here)

- `maintenance` with idle-pool closure (ADR-0018's pending item).
- Per-server request counters behind an explicit opt-in budget (CE4).
- Drain completion as an `INFO` line only; a durable audit sink is the panel's
  multi-user item.
