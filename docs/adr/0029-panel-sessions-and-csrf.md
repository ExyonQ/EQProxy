# ADR-0029: The panel is a session client of the API, rendered as forms

Language: **English**.

- State: **Accepted** (2026-10-26, roadmap v0.8 / D6, after ADR-0017 and
  ADR-0019)
- Date: 2026-10-26
- Related: [ADR-0017](0017-read-only-admin-plane.md) (the bearer plane this
  extends), [ADR-0018](0018-first-write-path-server-state.md) and
  [ADR-0028](0028-maintenance-closes-the-idle-pool.md) (the states it offers),
  [ADR-0019](0019-hot-config-writes-via-admin-api.md) (the document write),
  [ADR-0025](0025-certificate-renewal-without-restart.md) (the renewal action),
  [SPEC §9](../SPEC.md), [THREAT_MODEL.md](../../THREAT_MODEL.md)

## Context

SPEC §9 asks for a web panel with authentication, RBAC, write auditing, session
and CSRF protection, **and** that the panel is never required to operate the
proxy. ADR-0017 answered the first half with a token-authenticated JSON API and
one hard rule that every write so far relies on:

> a request carrying `Origin` is refused — no browser caller.

That rule is exactly right for a token API: a browser page cannot attach a
`Bearer` header cross-origin without a preflight, and no CORS headers are
served, so refusing the browser removes the DNS-rebinding path. It also means a
browser **cannot** drive those routes at all: a same-origin `<form>` or `fetch`
sends `Origin`, and putting the write token in a page would store a secret in
the browser.

So the panel needs a second, explicit authentication mode on the same plane —
not a second implementation of the writes, and not a relaxation of the API's
rule.

## Decision

### One implementation, two front doors

The panel is served by the admin plane itself (`[admin] panel = true`, off by
default; with it off every `/panel` path is an unknown route). Every action it
offers calls the **same** function the JSON route calls:

- per-server state → `apply_server_state` (the body of
  `PUT …/servers/{target}/state`), including the maintenance sweep of
  ADR-0028;
- table writes and the certificate renewal → the same `ConfigChange` message
  the JSON routes build, through the same applier, with the same `If-Match`
  revision and the same validation, and the answer is only a `200` after the
  dataplane committed.

The panel never parses TOML, never decides what `maintenance` means and never
writes to the dataplane itself. It is a client of the plane, as ADR-0017
required.

### Sessions, exchanged from the bearer token

`POST /panel/login` takes the token in a form field and answers with:

- `eqproxy_session=<32 random bytes, hex>; HttpOnly; SameSite=Strict;
  Path=/panel; Max-Age=1800` — the session cookie is scoped to the panel, so
  no API route ever sees it, and it cannot be read by a script;
- a redirect to `/panel`. A failed login is `401` with the login page and one
  `AUDIT` line with role `none`; the token value is never echoed or logged.

The session's **role is the role of the token that opened it** (read token →
read-only session, write token → operator). The table is in memory only:
bounded at 16 sessions (oldest evicted), idle timeout 30 minutes, revoked on
logout, gone with the process. Nothing is persisted, no request body is stored,
and the session id and CSRF token come from the system CSPRNG
(`aws-lc-rs`, already in the graph); if the CSPRNG fails the login is refused
instead of inventing a weak secret.

### Forms, no JavaScript

Every action is an HTML `<form method="post">`; the CSS is a second static
resource. There is no script, so:

- the whole panel is verifiable with an HTTP client (and the E2E does exactly
  that: login, parse the CSRF field out of the page, drive the action);
- the content security policy grants **no** script at all:
  `default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none';
  frame-ancestors 'none'`, with `nosniff` and `no-referrer`.

### CSRF: a token bound to the session, plus a declared origin

Every state-changing form carries `<input type="hidden" name="csrf">` with the
session's own token, compared in constant time against the session record. A
cross-site request cannot read that token, so it cannot ride the cookie. On top
of that, a request that declares `Sec-Fetch-Site: cross-site` is refused, and a
declared `Origin` must have this very host (the authority is compared, so a TLS
front end may send `https`); a client that declares no origin (a script) is
allowed through because the CSRF token is still required. There is no CORS
header anywhere and the cookie is `SameSite=Strict`.

The JSON API keeps its own contract unchanged: bearer token, **no** cookie, no
`Origin`, declared media type. The two modes cannot be mixed by accident: a
cookie is only read under `/panel`, and a panel form is only accepted with a
form media type.

### RBAC and auditing

The role check is server-side, per route, as before: a read session can load
the dashboard and nothing else (a `POST` answers `403 read_only_session`, or
`write_disabled` when the plane has no write token at all). The page hides what
the role cannot do, but hiding is cosmetic — the refusal is the server's.

Every panel `POST` leaves one `AUDIT` JSON line exactly like the API's, naming
the role, the peer, the method, the real path and the outcome. Logins and
refusals included. No session id, no CSRF token and no secret is ever in a log
line or a response.

### Where the panel cannot be reached, and why that is fine

The panel binds wherever `[admin]` binds: loopback by default, optionally a
Unix socket. A panel on a Unix socket is reachable only by a client that can
open the socket; the pages still work through it with an HTTP client, and the
browser is simply not a client that can. Nothing here weakens the socket's
policy (ADR-0021/0022/0023), which is enforced at `connect`.

## Consequences

- The roadmap's "panel over the API" exists without a second write path, a
  second configuration parser or a build step: one HTML page, one stylesheet,
  and the plane's own functions.
- A browser can drive the plane without storing a bearer token: the token is
  used once, at login, and only the session cookie remains (unreadable to
  scripts).
- The panel inherits the API's optimistic concurrency: a table write needs the
  current revision, and a stale one is refused with the applier's code.
- An operator who never sets `panel = true` has no new surface at all: the
  routes do not exist.
- Cost: a second authentication mode to keep correct. It is fenced by tests —
  the session store, the CSRF check, the origin check, the role matrix and the
  "panel off is a `404`" case all have their own assertions
  ([e2e_panel.rs](../../eqproxy-net/tests/e2e_panel.rs)).
- The panel is server-rendered: a richer UI (live updates, diffs) would need a
  script, and that would trade the current policy for a narrower one. Deferred
  until there is demand, with an ADR of its own.

## Alternatives considered

- **Put the bearer token in the page (memory/sessionStorage) and call the JSON
  API.** Simple, and it stores a plane-wide secret in the browser, where any
  XSS or extension can read it; it would also require relaxing the API's
  "no `Origin`" rule for every route.
- **Cookie-only writes without a CSRF token, relying on `SameSite=Strict`.**
  One defence instead of two, and it silently depends on every browser honouring
  the attribute; the token costs one hidden field.
- **A separate panel process / static bundle.** A second deployment, a second
  way to be misconfigured, and a second place where the API's semantics could
  drift — exactly what ADR-0017's "the panel is a client, never a second
  implementation" forbids.
- **Full RBAC with users and groups.** SPEC §9's long-term shape, but the plane
  has two secrets and no user store; inventing a user model here would be a
  second product. The role is the token's role, and that is what is enforced
  and audited.

## References

- [ADR-0017](0017-read-only-admin-plane.md) — the plane, its tokens and its
  no-origin rule.
- [ADR-0019](0019-hot-config-writes-via-admin-api.md) — the document write the
  panel drives.
- [ADR-0028](0028-maintenance-closes-the-idle-pool.md) — the state the panel
  offers next to `drain`.
- [THREAT_MODEL.md](../../THREAT_MODEL.md) — the panel's threats and controls.
- [e2e_panel.rs](../../eqproxy-net/tests/e2e_panel.rs) — the session, CSRF,
  origin, RBAC and opt-in assertions over real sockets.
