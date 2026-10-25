# ADR-0017: A read-only administration plane on its own listener

Language: **English**.

- State: **Accepted** (2026-10-24, first slice of roadmap v0.8 / SPEC §9)
- Date: 2026-10-24
- Related: [SPEC §9](../SPEC.md) (administration and web panel),
  [THREAT_MODEL.md](../../THREAT_MODEL.md), [ADR-0002](0002-configuration-format.md)
  (configuration format)

## Context

Roadmap v0.8 opens with the gap every HAProxy operator knows as the `stats
socket` (and every Envoy operator as the `admin` listener): a way to ask a
running proxy what it is doing without parsing the log or restarting it. Two
things are needed before any write path is even discussable:

1. **A machine-readable state view** — listeners, backends, servers and the
   live counters, in a form a dashboard or a script can consume.
2. **A scrape endpoint** — Prometheus text, so the proxy fits an existing
   monitoring stack instead of inventing one.

SPEC §9 also sets a hard rule that shapes the design: *the panel is not a
requirement to operate the proxy*. Whatever is built for administration must
be additive; a dead, hung or misconfigured plane may not take a single proxied
connection with it.

The threats are concrete. The counters are operationally sensitive (traffic
volume, failure rates, topology), the bearer token is a credential, and an
administration listener reachable from the internet without TLS would leak
that token on every request. THREAT_MODEL T17 ("no secrets in any response")
applies from the first byte.

## Decision

Ship a **read-only administration plane** as its own listener, configured by
an optional `[admin]` table:

```toml
[admin]
listen = "127.0.0.1:9001"        # its own address; loopback by default
token_file = "/etc/eqproxy/admin.token"   # or token = "…" (≥ 16 bytes)
# allow_remote = true            # non-loopback binds are refused without it
```

### Surface

- `GET /api/v1/status` — version, uptime, the validated topology (listener
  name, address, mode, backend, `maxconn`; backend balance, health-check flag
  and servers with weights) and a snapshot of the counters, as JSON.
- `GET /metrics` — the same counters as Prometheus text
  (`text/plain; version=0.0.4`).
- Everything else: `404`. Every method but `GET`: `405` with `Allow: GET`.
  Heads over 8 KiB: `431`. Exchanges over 5 s: `408`.

### Authentication

Every route requires `Authorization: Bearer <token>`, compared in constant
time. The token comes from exactly one of `token` or `token_file` (trailing
newline trimmed); validation rejects neither/both and tokens under 16 bytes.
Without the token the answer is `401` with `WWW-Authenticate: Bearer` and a
body that names nothing — an unauthorized caller learns neither the routes
nor the topology. The token never appears in a response or a log line.

### Isolation

The plane is a separate `TcpListener`, accept loop and task. The dataplane
never awaits it; the CLI only holds a handle to stop it on shutdown.
`AdminHandle::abort()` exists as a test seam to prove the dataplane keeps
serving with the plane dead (SPEC §9), and the E2E test does exactly that. A
plane that cannot bind its configured port is a startup error (fail closed):
a configured plane that silently does not exist is worse than no plane.

### Cardinality

Every exported series is a fixed name with no labels; the only label is
`version` on `eqproxy_build_info`, whose value is the build's own version.
A scrape therefore cannot grow the index (CE4). Per-server, per-route or
per-client breakdowns need an explicit opt-in and a documented budget; they
are not part of this slice.

### Why not mount it on the public listener

A path prefix on the proxy listener would share the public port, the public
TLS policy, the public `maxconn` budget and the public routing rules with a
credentialed endpoint. SPEC §9 demands strict separation, and the operational
consequence is real: an admin request would compete with traffic for
connections, and a public listener without TLS would carry the token in the
clear. A separate socket has its own address, its own accept loop and its own
failure domain.

### Why loopback by default

This slice has no TLS on the plane. Binding a non-loopback address therefore
means sending the bearer token in the clear over the network, so validation
refuses it unless `allow_remote = true` is set deliberately (and warns when
it is). TLS and Unix sockets arrive with the write path
(`B-H14 (p)`, roadmap v0.8); until then the safe default is local only.

### Why no write endpoint yet

The roadmap asks for hot backend creation, drain/maintenance and certificate
management. Every one of those is a write, and SPEC §9 requires RBAC, write
auditing, session/CSRF protection and optimistic concurrency for writes. None
of that exists yet. Shipping a write endpoint with bearer auth alone would be
one credential away from a full takeover, so this slice stops at reads; the
authenticated read plane is the seam the write API will plug into.

## Consequences

- Operators get `curl -H "Authorization: Bearer …" /api/v1/status` and a
  Prometheus target without restarting anything.
- The plane cannot be used to change the proxy: no drain, no reload, no
  certificate rotation yet. Those remain CLI/config operations
  (`SIGHUP`, `eqproxy config …`) until the write slice lands.
- A remote bind needs an explicit `allow_remote = true` and still has no TLS;
  the roadmap's Unix-socket step is the intended fix for local-only remote
  administration.
- `SIGHUP` (hot config reload) does **not** move the admin listener or
  rotate its token: the address and the secret are fixed at startup and a
  change needs a restart. Moving the plane under live traffic before the
  write API exists would add a failure mode (old address gone, new one not
  yet open) without a use case; it is part of the Unix-socket/TLS step.
- The metrics text, the JSON shape and the routes are now a public contract;
  changing them is a versioned API change (`/api/v1`).
- The counters' names in Prometheus are `eqproxy_<counter>_total` (gauge:
  `eqproxy_connections_active`, `eqproxy_config_reload_last_swap_seconds`);
  `dns_resolutions_ok` exports as `eqproxy_dns_resolutions_total` because the
  Prometheus convention wins over the internal field name.

## Pending (not decided here)

- Write API: backend create/modify/delete, drain/maintenance, certificate
  management — with RBAC, audit log, CSRF/session model and optimistic
  concurrency, as SPEC §9 requires.
- TLS on the plane, or a Unix socket (`B-H14 (p)`).
- Access log (structured) configuration: roadmap v0.8, separate ADR.
- Web panel UI: a client of this API, never a second implementation.
- Per-server/per-route metrics: opt-in with an explicit cardinality budget
  (CE4).
