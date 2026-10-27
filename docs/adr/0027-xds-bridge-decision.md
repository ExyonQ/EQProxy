# ADR-0027: No xDS bridge — the hot admin API is the E2 answer

Language: **English**.

- State: **Accepted** (2026-10-26, roadmap v0.8 gate)
- Date: 2026-10-26
- Related: [ADR-0019](0019-hot-config-writes-via-admin-api.md) (the write API
  this decision names as the equivalent), [ADR-0017](0017-read-only-admin-plane.md)
  (the plane it reuses), [ADR-0025](0025-certificate-renewal-without-restart.md)
  (certificates, the `SDS`-adjacent concern, handled locally by its own
  endpoint), [SPEC §9](../../SPEC.md) (administration, optimistic concurrency,
  one write path), [SPEC §13](../../SPEC.md) (semantic difference log),
  roadmap gap B-E1 and complaint CE2 (the gap this closes)

## Context

Envoy's product *is* xDS: a control plane outside the proxy streams listeners
(LDS), routes (RDS), clusters (CDS), endpoints (EDS) and secrets (SDS) over
gRPC, in a whole-resource (SotW) or delta dialect, with version/nonce,
ACK/NACK and resource names as the coordination surface. The same power is the
complaint: operators end up building their own control plane to batch updates,
bound propagation, add back pressure, cache and debug convergence (complaint
CE2 of the parity roadmap, and the
[Matt Klein post](https://mattklein123.dev/2020/03/15/2020-03-14-on-the-state-of-envoy-proxy-control-planes/)).
Envoy also runs fully static (`static_resources`), which is the shape the
migration matrix translates ([docs/migration/envoy.yaml](../migration/envoy.yaml)).

Roadmap v0.8 answered the operational half with
[ADR-0019](0019-hot-config-writes-via-admin-api.md): `PUT /api/v1/backends/{name}`
and `PUT /api/v1/listeners/{name}` replace one TOML table, run the **same**
`eqproxy_config::check` and resolution as startup, require `If-Match` against a
`revision`, and commit through the single configuration writer — the SIGHUP
machinery — so the dataplane swaps fail-closed and established connections
keep the generation they were accepted with. The file remains the baseline and
the next `SIGHUP` replaces the runtime generation. The release-binary E2E
`run_admin_plane_applies_backend_config_under_traffic` creates a backend under
live traffic, asserts `elapsed_ms < 1000` on three applies (backend update,
new backend, listener repoint), and a connection accepted before the first
swap keeps serving on the generation it accepted.

The v0.8 gate asked for one last thing: a decision, in an ADR, between
implementing an xDS bridge and declaring the **E2 «own API»** equivalent.
E2 is not a shrug: the master roadmap requires the difference in SPEC §13, a
migration note, and a test that demonstrates the behaviour being claimed.

## Decision

### E2, not a bridge

EQProxy does **not** implement xDS in v0.8 — neither a client of an external
control plane nor an xDS server in front of the dataplane. The E2 equivalent is
the runtime write API of ADR-0019, and it is the answer the gate records.

"Equivalent" here means exactly this, and no more:

- One configuration path. API writes and `SIGHUP` feed the same writer, the
  same validator, the same resolver and the same atomic swap. There is no
  second, weaker path for dynamic input (SPEC §9).
- Per-table updates with optimistic concurrency (`If-Match`, `428`/`412`), a
  whole-document validation before any socket moves, and a `200` only after
  the commit. A rejected candidate leaves the running generation untouched.
- Runtime state, not a desired-state store: the revision is process-local, the
  file stays authoritative at startup and replaces the generation on SIGHUP,
  and nothing persists the API-applied tables.
- No streaming protocol, no version/nonce negotiation, no per-resource
  subscriptions, no delta updates and no `SDS`. Certificates are files plus
  the hot reload endpoint of ADR-0025; routing, balancing and health stay the
  typed TOML model.

### Why not now

- **No demonstrated demand.** Nothing in this repository — no config, no
  migration note, no roadmap item — asks EQProxy to consume xDS; the static
  bootstrap is what the Envoy migration covers. Building a protocol surface
  on speculation is the cost CE2 describes, inverted onto this project.
- **The operational gain is already delivered.** The API changes routing in
  under a second under traffic, without restarting, dropping connections or
  operating a control plane. xDS would add a transport, not a capability the
  v0.8 gate asks for.
- **Two sources of truth are the real risk.** xDS resources are whole
  listeners/clusters/routes with fields EQProxy does not model (filters,
  weighted cluster internals, retry budgets, outlier detection, LB policies).
  A bridge that silently drops them would be a weaker second configuration
  path; one that rejects them would be a different product. Neither belongs
  inside the proxy without a mapping contract and its own tests.
- **Security surface.** An xDS endpoint is a long-lived, authenticated inbound
  stream that mutates the running configuration. The admin plane already owns
  that role, with one token model, one audit line and one writer; adding a
  second ingress multiplies the authorization story for zero present use.

### If an xDS bridge is ever built

It is an **adapter**, not a mode of the proxy, and it must be chosen by a new
ADR after a concrete need exists. The constraints are fixed here so a future
implementation cannot quietly bypass them:

1. **Direction: client, not server.** The only useful direction is consuming
   an existing control plane (Istio, Contour, Gloo, a bespoke one) — EQProxy
   as the xDS *client*. Serving xDS *to* other proxies would make EQProxy a
   control plane, which is the thing this project avoids.
2. **Read-only mapping to the same candidate document.** Resources are
   translated into the tables of one candidate TOML document, validated with
   `eqproxy_config::check`, and applied through the same writer and swap. No
   direct mutation of listeners, pools or rules.
3. **Named subset, declared loss.** CDS, EDS, LDS and RDS in SotW at most;
   no SDS, no delta, no ADS multiplexing, no filter chains. Every unsupported
   field is refused with a named error, never ignored.
4. **No persistence, no drift engine.** The file remains the baseline and
   SIGHUP replaces the generation, exactly as with API writes.
5. **Its own evidence.** A mapping table (xDS resource → TOML table, with the
   fields that do not fit), E2E against a real control plane, and a test that
   the same validator rejects a mapped candidate.

A separate out-of-process translator that speaks xDS and calls the public API
is the lower-risk shape of the same idea; it needs no new listener in the
proxy and is compatible with this ADR. It is not built now either.

## Alternatives considered

| Alternative | Why not |
|---|---|
| Full xDS server/client in the core now | Protocol surface, auth, versioning, mapping and tests with no named user; adds a second write path with weaker guarantees, which SPEC §9 forbids |
| xDS bridge as a v0.8 requirement | Turns an optional ecosystem integration into a release gate and delays the API that already solves the operational case |
| File + `SIGHUP` only | Already exists, but requires rewriting the baseline and a signal; the API is the equivalent that does not need either, and both share the writer |
| Out-of-process translator calling the API | Viable later, and the recommended shape if a real control plane appears; nothing to maintain until then |

## Consequences

- The v0.8 gate closes with E2 «own API»: the difference is registered in
  [SPEC §13](../../SPEC.md) item 15, the migration limitation is stated in
  [docs/migration/README.md](../migration/README.md), and the equivalence is
  demonstrated by `run_admin_plane_applies_backend_config_under_traffic`
  (release binary, `elapsed_ms < 1000`, and the kept connection finishes on
  its accepted generation).
- An Envoy deployment configured exclusively through xDS is **not** migrated
  by the static converter, which reads `static_resources`; this ADR says so
  instead of implying support. Static Envoy bootstraps remain covered by the
  migration matrix.
- No new dependency, listener, certificate path or audit path enters the
  proxy for this decision. The threat model, the one-token model and the
  single writer stay as ADR-0017/0018/0019 left them.
- If demand appears, the cost is a new ADR plus the mapping contract above —
  not a rewrite of the write path, because the bridge would feed it.

## Pending (not decided here)

- Whether any real deployment needs an xDS client adapter, and which control
  plane it would be tested against.
- Transport and versioning of such an adapter (gRPC service versions, SotW
  first), and how it authenticates to the control plane.
- The mapping table itself: which xDS fields are refused, mapped or declared
  out of scope.
- Desired-state persistence, drift and multi-instance reconciliation, still
  separate from this decision (ADR-0019 pending list, SPEC §9).
