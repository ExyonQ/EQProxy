# ADR-0026: Per-server and per-route metrics under an explicit series budget

Language: **English**.

- State: **Accepted** (2026-10-25, roadmap v0.8 / CE4)
- Date: 2026-10-25
- Related: [ADR-0017](0017-read-only-admin-plane.md) (the read plane),
  [ADR-0020](0020-structured-access-log.md) (bounded sinks that count their
  own loss), [ADR-0024](0024-drain-observability.md) (the last label-free
  series this plane added), [SPEC §9](../SPEC.md), [THREAT_MODEL.md](../../THREAT_MODEL.md)

## Context

The v0.8 plane exported one fixed, label-free family per counter. That is the
right default — a scrape cannot grow the index — but it answers \"the proxy is
slow\" with no way to ask **which server** or **which rule**. The references
`Envoy #21685` and `#3351` describe the same trap from the other side: the
moment a proxy exposes per-target stats unbounded, a Kubernetes churn or a
hostile client turns the metrics store into the incident.

`[metrics] detailed` existed since the admin plane landed, but it only flipped
a boolean in the status JSON: nothing was measured behind it. A flag that
promises detail and delivers none is worse than no flag.

## Decision

### Detail is opt-in, and the budget is the contract

```
[metrics]
detailed = true     # default false
max_series = 128    # default 128, validated 1..=4096
```

`detailed = false` is the default and records nothing: the hot path costs one
relaxed atomic load and allocates nothing. When it is on, the registry tracks
two families:

| Series | Labels | Value |
|---|---|---|
| `eqproxy_server_requests_total` | `backend`, `server` | proxied exchanges served by that address |
| `eqproxy_server_errors_total` | `backend`, `server` | those answered `5xx` by that address |
| `eqproxy_route_requests_total` | `listener`, `route` | proxied exchanges matched by that rule |

`server` is the address that actually served the exchange, not the configured
target: under DNS re-resolution a new address starts a new series, and the
budget is what bounds that churn. `route` exists only for a matched rule —
traffic that fell through to the listener's default backend has no rule, and
inventing a `route=\"default\"` label would spend budget on a pseudo-route and
collide with a real rule of that name.

`max_series` counts **leaves** across both families. A series that would
exceed it is refused and the observation is counted in
`eqproxy_metrics_detail_dropped_total`; a series that already exists keeps
counting regardless. The registry therefore never grows past the number the
operator set, and the refusal is never silent.

Four label-free series describe the budget itself and are always exported:

```
eqproxy_metrics_detail_enabled        0 | 1
eqproxy_metrics_detail_series         live leaves
eqproxy_metrics_detail_budget         the configured ceiling
eqproxy_metrics_detail_dropped_total  refused observations
```

Without them a scraper cannot tell \"no traffic\" from \"detail off\" from \"the
budget refused it\" — the same reasoning ADR-0020 applied to a full access-log
sink.

### Where an exchange is counted

Once, where the exchange completes, which is also where
`http_requests_proxied` moves:

- the HTTP/1.1 engine, which HTTP/2 and HTTP/3 streams are also driven
  through, so all three protocols are attributed by the same code;
- the gRPC passthrough, with the server the stream was opened on.

Protocol-switch tunnels (`101` upgrades, `CONNECT`, and the WebSocket tunnel
that the extended CONNECT relays through the h1 engine) leave the engine on a
separate branch before that point and are **not** attributed per server; they
keep their own `ws_tunnels` / tunnel counters. The invariant the detail
families promise is therefore exact: while the window is open,
`sum(server requests)` equals the part of `http_requests_proxied` collected in
it. Per-server WebSocket statistics need the tunnel branch instrumented and a
global counter that counts tunnels: a separate change, named as pending.

`ResolvedListener::decide_routed` returns the matched rule's name next to the
decision (borrowed from the listener: no allocation). `decide` stays as the
wrapper existing call sites use.

### Hot enable and disable

`detailed` moves on a committed `SIGHUP`/`POST` reload. Enabling starts an
empty window; disabling **drops** the collected series, because an export
whose `enabled` gauge is `0` must not show counts from a window that is no
longer tracked. The refusal counter is monotonic like every counter.

`max_series` is fixed at startup. Shrinking it under live series would need an
eviction policy nobody asked for, so a reload that changes it logs
`WARN … restart to apply it` and the live budget is what
`eqproxy_metrics_detail_budget` reports.

### Rendering

Label values are escaped (`\\`, `\"`, newline) before they reach the
exposition format: rule names and backend names come from the configuration
and may contain a quote. The families are emitted only while detail is on and
only when at least one series of that family exists; the accounting four are
always emitted.

The same rows are in `GET /api/v1/status` under `metrics_detail`
(`enabled`, `budget`, `series`, `dropped`, `rows[]`), so an operator can read
the breakdown without a Prometheus server.

## Consequences

- The default export is byte-for-byte the same fixed family as before plus
  four gauges; cardinality under 9 series.
- With detail on, a scrape grows with the traffic, never above `max_series`,
  and the ceiling is visible in the same scrape.
- A refused observation is visible (`dropped_total`), not silently folded
  into a neighbour.
- The `RwLock` protecting the maps is read on every attributed exchange and
  written only when a new series appears; atomics inside each series mean two
  exchanges on the same series never serialize.

## Pending (not decided here)

- Latency histograms per server/route: they need the same budget story and
  are a separate cost decision.
- Eviction and TTL for series whose server left the configuration: the
  budget already bounds the damage; a policy needs a window definition.
- Per-route bytes in/out: the body copies do not currently carry the route
  name, and threading it through them is a separate change.
- Per-server WebSocket and CONNECT tunnels: they bypass the completion point
  that moves `http_requests_proxied`, so attributing them needs the tunnel
  branch instrumented and the global counter extended to tunnels.
