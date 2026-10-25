# ADR-0019: Hot backend and listener configuration through the admin API

Language: **English**.

- State: **Accepted** (2026-10-25, roadmap v0.8 B-E1/H2/CE2)
- Date: 2026-10-25
- Related: [ADR-0017](0017-read-only-admin-plane.md) (read plane and its
  reserved write path), [ADR-0018](0018-first-write-path-server-state.md)
  (first write: per-server state), [SPEC §9](../SPEC.md) (administration and
  web panel), [ADR-0002](0002-configuration-format.md) (TOML)

## Context

Every write the read plane deliberately left out is a control-plane in
disguise: HAProxy's `stats socket` can add a server, Envoy's admin listener can
change a cluster, and operators expect both. Roadmap v0.8 makes the gap
explicit (**B-E1**, **H2**, **CE2**): create and modify backends and listeners
through the API, with the **same validation as the TOML**, and an atomic swap
demonstrated in E2E **under traffic** without interrupting established
connections. The acceptance gate names less than one second.

SPEC §9 requires optimistic concurrency for writes and forbids a second
configuration path with weaker checks. The existing SIGHUP reload already
knows how to validate a candidate, resolve it and swap it fail-closed; the
write API must reuse that machinery, not replicate it.

## Decision

### Routes and body

- `PUT /api/v1/backends/{name}` — body is the **body of a `[backend.<name>]`
  table**, in TOML.
- `PUT /api/v1/listeners/{name}` — body is the body of a
  `[listener.<name>]` table.

The body is the table, not a whole document and not a patch: the PUT
**replaces** that table, so omitted keys take their documented defaults, in
the same way rewriting a section in the file would. Both shapes an operator
has at hand are accepted: the bare body (`server = "…"`, nested tables as
inline tables or `[tls]` headers) and the complete section copied from the
file (`[backend.<name>]` with its nested `[backend.<name>.…]` tables). A name
not present yet is created. There is no `DELETE` in this slice; taking a
backend out remains a file operation.

The request must carry `Content-Type: application/toml`, a declared
`Content-Length` of at most 64 KiB, no `Origin` header (a browser never
belongs on the plane), and the **write role**. A body that fails to parse is
`400 invalid_body`; a table that parses but fails the document checks is
`400 invalid_config` with the validator's message. A TLS file, CA or map the
candidate refers to is read during resolution exactly as at startup; a
missing file is `400 invalid_config`, never a half-applied generation.

### Optimistic concurrency

`GET /api/v1/status` now returns a `revision` (an opaque generation tag) and
the same value as `ETag`. Every configuration `PUT` must send
`If-Match: "<revision>"`:

- missing or repeated: `428 precondition_required`;
- stale: `412 precondition_failed`, with the **current** revision in the body
  and `ETag`, so the client can re-read and retry;
- current: the candidate is considered.

The comparison happens in the single writer (below), not at the socket, so
two requests with the same precondition cannot both commit.

### One writer, one generation

The API and SIGHUP feed the **same** queue in the CLI; one task owns the
applied document and its revision. For each message it reconstructs the whole
candidate (last committed document plus the changed table), runs
`eqproxy_config::check` over it and resolves it to listeners and backends.
Only then does it ask the dataplane for a swap, and it advances the applied
document, revision and reported topology **only after** the dataplane
confirms the commit. A rejected candidate therefore leaves the running
generation, the revision and the API view exactly as they were.

The dataplane swap is the SIGHUP machinery: all sockets that must be opened
are bound first; a failure closes them and leaves the old listeners serving
(fail-closed). A listener whose name and configured address are unchanged
**keeps its socket**, so new connections see the new generation while
established ones finish with the generation they were accepted with. A
backend-only change therefore keeps the accepted address and swaps routing
under it.

### Answers

`200` is sent only after the swap committed, with `revision`, `summary`
(listeners kept/added/removed), the measured `elapsed_ms` and the bound
addresses; `ETag` carries the new revision. `409 swap_rejected` means the
candidate was valid but the dataplane refused to commit (a bind conflict, a
live QUIC endpoint whose TLS material cannot be replaced); nothing changed.
`503 config_unavailable` means no writer is attached (never on a plane
started with a write token). `500 apply_unconfirmed` means the writer did not
answer within 10 s: the outcome is unknown, and the client must re-read the
status revision before retrying. The swap itself is local and bound work, so
this is a liveness guard, not an expected outcome.

Every attempt, accepted or refused, writes one `AUDIT` line as in ADR-0018:
role, peer, method, path, status, never the body or a secret.

### The file remains the baseline

These are **runtime** changes, not a rewrite of the TOML file. The file is
still the startup baseline; `SIGHUP` re-reads it and replaces the runtime
generation wholesale (revision bumps, topology follows, traffic keeps
serving). This is the HAProxy runtime-API model, and it keeps a
container-mounted, possibly read-only file authoritative. Persisting a
desired state, or a drift view between file and running config, is a separate
slice (SPEC §9 multi-instance).

The admin listener and its tokens also remain fixed at startup (ADR-0017):
editing `[admin]` through the API would drop the connection that is
answering.

## Consequences

- An operator can create a backend, point a listener at it, and watch the
  status revision move without restarting or dropping in-flight requests.
- Every apply is a full document validation and a full re-resolution: a
  changed backend restarts health checking, DNS and the idle pool of the new
  generation. Untouched backends are rebuilt too, so their counters restart.
  This is the same cost as SIGHUP and is documented rather than hidden.
- A table PUT is a replacement, not a merge. Sending `server = "…"` without
  the rest of the table resets that backend's algorithm, timeouts, TLS and
  health check to defaults. Clients should read the current table before
  writing (the status view is the live one, the file is the baseline).
- The revision is process-local: a restart starts again at `v1`. It orders
  writes within a process, which is what `If-Match` needs; it is not a
  cross-restart version identity.
- Two roles, one audit line and no session model are still the v0.8 scope;
  RBAC beyond read/write, a durable audit sink and TLS on the plane remain
  pending (ADR-0018 and roadmap B-H14(p)).

## Pending (not decided here)

- `DELETE`/disable routes, and drain a whole backend through configuration.
- Persisting runtime mutations, desired-vs-applied drift and multi-instance
  reconciliation (SPEC §9).
- Certificate management in hot, panel UI (a client of this API), RBAC,
  sessions/CSRF cookies, durable auditing.
- TLS or a Unix socket for the plane, and moving it under traffic.
