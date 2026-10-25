# ADR-0018: The first write path — per-server administration state

Language: **English**.

- State: **Accepted** (2026-10-24, second slice of roadmap v0.8 / SPEC §9)
- Date: 2026-10-24
- Related: [ADR-0017](0017-read-only-admin-plane.md) (the read-only plane this
  extends), [ADR-0015](0015-backend-idle-pool-sizing.md) (idle pool),
  [SPEC §9](../SPEC.md), [THREAT_MODEL.md](../../THREAT_MODEL.md)

## Context

ADR-0017 shipped the authenticated read plane and deferred every write until
RBAC, auditing, CSRF and concurrency control existed. The roadmap's first
operational action is the HAProxy `stats socket` one: take a backend server
out of rotation without restarting the proxy and without cutting the requests
already running on it (B-H12/B-E8, H3). That action is a **declared state**,
not a document edit: an operator says "this server is draining", and the
proxy's job is to stop selecting it and let the in-flight work finish.

The write surface is small enough to be the place where the whole write model
is settled, so whatever is decided here is what hot backend creation and
certificate rotation will reuse.

## Decision

### Surface

One route, one verb:

```
PUT /api/v1/backends/{backend}/servers/{target}/state
Content-Type: application/json

{"state": "ready" | "drain"}
```

`{target}` is the server's **configured** target, exactly as written in the
TOML (`HOSTNAME:PORT` or `IP:PORT`) and exactly as `GET /api/v1/status`
reports it under `addr` — not the address a DNS name currently resolves to.
The slot is keyed by the configured target, so a DNS re-resolution never
loses its declared state.

The answer is `200` with `{"backend", "server", "state", "previous",
"active", "healthy", "changed"}` and `Cache-Control: no-store`. Declaring the
same state again is a `200` with `"changed": false`: the operation is
idempotent by construction, not by accident.

`GET /api/v1/status` now reports each server with live data:

```json
{"addr":"127.0.0.1:9000","resolved":"127.0.0.1:9000","weight":1,
 "state":"drain","healthy":true,"active":3}
```

`state` is the administration decision, `healthy` the B11 health machine and
`active` the exchanges in flight — three independent axes, because an operator
needs to see a drained server is still healthy, and how much work it still
holds (H3: observable draining).

### Roles: two secrets, one privilege boundary

`[admin]` gains an optional `write_token` / `write_token_file`:

```toml
[admin]
listen = "127.0.0.1:9001"
token_file = "/etc/eqproxy/admin.token"             # read (GET)
write_token_file = "/etc/eqproxy/admin-write.token" # read + write
```

- No write secret: the plane is read-only and every `PUT` is
  `403 write_disabled`. Absent is off, never an implicit grant.
- The read token opens the two `GET`s and nothing else (`403 forbidden` on a
  write attempt).
- The write token opens the `GET`s too (more privileged, never less).
- Both are compared in constant time, both are at least 16 bytes, and
  validation refuses a configuration where they are equal: one secret per
  privilege level. Two roles are the minimum RBAC this API needs; a third
  (viewer/operator/admin) arrives with the panel's user model, not before.

The authorization matrix is per endpoint and tested both at the pure routing
layer and over TCP (`e2e_admin.rs`).

### CSRF, sessions and browser-originated requests

There is no cookie on the plane, so classic CSRF does not apply; a request is
authenticated only by an `Authorization` header that a cross-site page cannot
set. Two hazards remain on a loopback listener and are closed explicitly:

- **DNS rebinding**: any request carrying `Origin` is refused
  (`403 origin_forbidden`), even with a valid token. Nothing on the plane is
  meant to be called by a browser.
- **Simple cross-origin form posts**: a write requires
  `Content-Type: application/json` (`415` otherwise). A cross-origin simple
  request cannot send that content type without a preflight, and the plane
  serves no CORS headers at all.

Body handling is bounded: `Content-Length` is required (`411`), at most
1 KiB (`413`), duplicate length headers are ambiguous and refused, and the
body must be a JSON object with exactly one `state` key (`400` otherwise).
Chunked framing is not accepted for a 17-byte declaration.

### Concurrency: why no `If-Match`

SPEC §9 asks for optimistic concurrency on write operations. It does not apply
to this route: a `PUT` here **declares** the desired state rather than
modifying a document read by the client, so there is no lost update to
protect — the last declaration is the operator's intent, and the response
reports the transition. The state is not a counter and no read-modify-write
happens inside the proxy. When the write path starts handling configuration
documents (hot backend creation), that endpoint will carry an `ETag`/revision
and require `If-Match`; this ADR fixes the distinction instead of erasing it.

### Audit

Every write **attempt** — accepted, forbidden, malformed or unknown target —
emits exactly one line on stderr:

```json
AUDIT {"event":"admin_write","ts_unix":1790000000,"remote":"127.0.0.1:50123",
"role":"operate","method":"PUT","path":"/api/v1/backends/api/servers/127.0.0.1:9000/state",
"status":200,"backend":"api","server":"127.0.0.1:9000","from":"ready","to":"drain"}
```

The secret never appears in the line; the role and the peer are the identity
this slice can attest. The process log is the sink (the container/supervisor
collects it); a file-backed, retention-managed sink belongs with the panel's
multi-user audit. An audit line is written whether or not the request changed
anything, so a probe leaves a trace.

### Where the state lives

`ServerModes` is one process-wide registry keyed by `(backend, configured
target)`, created by `run` before the dataplane and handed to every
`Balancer` — including the ones a `SIGHUP` reload builds. Consequences:

- A drain takes effect on the next pick (the balancer checks the registry
  inside its selection lock); no dataplane restart, no connection cut.
- The in-flight exchange keeps its server: selection already happened, and
  the drain does not touch the health machine or the active counter.
- A reload does **not** silently return a drained server to rotation.
- The registry is in memory. Restarting the process starts every server
  `ready`; persistence is a later decision (and would need a documented
  desired-vs-applied model like SPEC §9 demands for multi-instance).

### Drain is not "maintenance" yet

A second state that behaves identically would be theatre. `drain` is the
graceful removal this slice can implement truthfully: no new exchanges,
in-flight finish, idle pooled connections age out on their own timer. A
`maintenance` state earns its place when the pool can close a server's idle
connections on transition (so a patch window can start as soon as `active`
hits zero) and when the operator can tell the two apart; until then the route
accepts `ready` and `drain` only, and an unknown value is a `400` that names
no alias.

## Consequences

- An operator can drain and restore a server with one authenticated request,
  under live traffic, and watch `active` fall to zero in `status` (H3).
- With every server drained, the dataplane answers the existing explicit
  `503` and counts `no_available_server`; the behaviour is the same as "all
  servers down", tested end to end.
- The admin's view of listeners and of the backend/server set is the config
  loaded at startup. A `SIGHUP` reload changes the dataplane; the plane keeps
  reporting the startup set until the process restarts. The **drain registry**
  itself survives the reload, so this staleness is a reporting limit, not a
  routing one. Hot backend creation (the next slice) introduces a live
  topology store and removes the gap.
- A reload that removes a backend or server leaves an inert registry entry;
  it cannot affect anything because no balancer consults a target it does not
  have, and the admin rejects unknown targets against its view.
- The status JSON gained fields (`resolved`, `state`, `healthy`, `active`) and
  the backends are now built from the same resolved instances the dataplane
  uses. `/api/v1` is not tagged yet; this is the last window in which the
  shape can still change without a version bump.

## Pending (not decided here)

- `maintenance` with idle-pool closure, and per-server `weight` overrides.
- Durable audit sink, retention and per-token identity (labels or token ids).
- Live topology in the admin plane and hot backend creation (`B-E1`, `CE2`).
- TLS or a Unix socket on the plane (`B-H14 (p)`), which also removes the
  `allow_remote` caveat.
- Web panel UI and its session/CSRF model: a client of this API, never a
  second implementation.
