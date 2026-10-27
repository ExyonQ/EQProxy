# D6/Q1/CE1 — the web panel over the release binary, v0.8

Language: **English**.

**Increment:** the panel of [ADR-0029](../adr/0029-panel-sessions-and-csrf.md)
(`[admin] panel = true`), the last box of the v0.8 roadmap. The panel is a
server-rendered **client of the administration API**: every action it offers
calls the same function the JSON API calls, so "what the form did" is the
running document and the dataplane's behaviour, not a page that only looks
changed. This page is the release-binary journey of that surface, with an
origin that counts what it serves.

The journey answers the questions the E2E suite cannot answer about the
artifact itself: does the release build render and drive the panel, does the
dataplane really follow what the forms wrote, and is the feature really
opt-in?

| Piece | Where |
|---|---|
| `/panel` path ownership (nothing else reaches the router) | [panel.rs:215](eqproxy-net/src/panel.rs#L215) |
| Login: bearer token → in-memory session, `401` on refusal | [panel.rs:374](eqproxy-net/src/panel.rs#L374) |
| Cross-site refusal, then the per-session CSRF token | [panel.rs:308](eqproxy-net/src/panel.rs#L308), [:311](eqproxy-net/src/panel.rs#L311) |
| A read session reads and cannot write anything | [panel.rs:325](eqproxy-net/src/panel.rs#L325) |
| State, table and certificate actions (shared implementation) | [panel.rs:414](eqproxy-net/src/panel.rs#L414), [:524](eqproxy-net/src/panel.rs#L524), [:569](eqproxy-net/src/panel.rs#L569) |
| Panel dispatch and the `303` back to the page | [admin.rs:941](eqproxy-net/src/admin.rs#L941), [:986](eqproxy-net/src/admin.rs#L986) |
| Opt-in configuration and state | [admin.rs:243](eqproxy-net/src/admin.rs#L243), [:306](eqproxy-net/src/admin.rs#L306), [schema.rs:559](eqproxy-config/src/schema.rs#L559) |
| Startup announces the panel it serves | [main.rs:3023](eqproxy-cli/src/main.rs#L3023) |
| The same journey on the debug profile | [cli_e2e.rs:4210](eqproxy-cli/tests/cli_e2e.rs#L4210) (`run_panel_applies_a_table_and_drains_a_server`) |
| Panel E2E suite (real admin socket) | [e2e_panel.rs](eqproxy-net/tests/e2e_panel.rs) — five tests, see below |

## Binary under test

- `target/release/eqproxy`, `eqproxy 0.7.0`, sha256
  `47fff1c8cef6193640d3cecbba166b7dbd1f84bf5c5acf392d42b9adb0279c9c`
  (`cargo build --release -p eqproxy-cli`, final tree of the increment).
- Host: macOS 26.5.1 arm64 (Darwin), `python3.13`.
- Journey: [`scripts/evidence/v08-panel/journey.py`](../../scripts/evidence/v08-panel/journey.py)
  (local-only harness, per the `docs/` rule), run from the repository root.
- Raw run: [`docs/evidence/v08-panel/raw/run-20261027T004000Z/`](v08-panel/raw/run-20261027T004000Z/)
  — `journey.txt` (transcript), `eqproxy.toml` (the panel config),
  `eqproxy-panel-off.toml`, `eqproxy.log` (the proxy's own log, `AUDIT` lines
  included), `eqproxy-panel-off.log` (the second process, panel off),
  `status-after-apply.json`, `status-after-drain.json`.

## Command

```console
$ python3.13 scripts/evidence/v08-panel/journey.py
binary: /Volumes/Lexar/Cursor/EQProxy/target/release/eqproxy
version: eqproxy 0.7.0
sha256: 47fff1c8cef6193640d3cecbba166b7dbd1f84bf5c5acf392d42b9adb0279c9c  target/release/eqproxy
dataplane 127.0.0.1:54386 · admin 127.0.0.1:54387 · origins a=54384 b=54385
```

Exit code **0**, 42 `PASS`, 0 `FAIL`, last line `ALL PASS`.

## What the journey observed (and what it does not prove)

Each line below is from the raw `journey.txt`. Five runs of this harness are
on disk: `run-20261027T003417Z` crashed before writing a transcript (the
harness read a status field called `target`; the document says `addr`) — its
proxy log and status JSON remain. `run-20261027T003501Z` reached the end with
a wrong expectation (with the panel off, an anonymous request is answered
`401` by the auth gate before routing ever sees the path, so the `404` needs a
valid token; the harness now asserts both). The green intermediates are
`run-20261027T003531Z` (40 checks) and `run-20261027T003913Z` (42);
`run-20261027T004000Z`, cited here, is the final run.

1. **Anonymous: the login page, never a secret, never the dashboard.**

   ```
   PASS an anonymous GET /panel answers the login page: 200
   PASS the login form is the page's action: 
   PASS the page carries the no-script policy and is not cached: {'csp': "default-src 'none'; style-src 'self'; fo", 'cc': 'no-store'}
   PASS the dashboard is not served anonymously: 
   PASS no secret appears on the login page: 
   PASS an unknown /panel path is 404: 404
   ```

2. **Refusals before any session exists:**

   ```
   PASS a wrong token is refused with 401: 401
   PASS the page names the refusal: 
   PASS a foreign Origin on login is 403: 403
   ```

3. **The read token opens a read-only session** — RBAC as an observation, not
   a claim: the page is the dashboard, it says so, and the same session's write
   attempt is refused by the server.

   ```
   PASS the read token opens a session: 303
   PASS the session cookie is HttpOnly, SameSite=Strict and scoped to /panel: eqproxy_session=6e6dfe5a…
   PASS login never echoes the token: 
   PASS the read session reads the dashboard: 200
   PASS the page marks the session read-only: 
   PASS the read session is offered no write surface: 
   PASS a write from the read session is refused: 403
   ```

4. **The write token renders the whole write surface** (three states per slot,
   both table editors, the certificate reload), with the live revision next to
   the form and no secret anywhere on the page:

   ```
   PASS the write session renders the dashboard: 200
   PASS the page offers the three states, the editors and the certificate reload: 
   PASS the page carries a CSRF token and the live revision: v1
   PASS no secret appears on the dashboard: 
   ```

5. **A cookie alone is not authorisation** — a form needs the session's CSRF
   token and a same-site request:

   ```
   PASS a form with a wrong CSRF token is 403 csrf_required: 403
   PASS a cross-site form POST is 403: 403
   PASS a form without a session is sent back to the login page: 303
   ```

6. **Applying a whole `[backend.*]` table through the form really moves the
   dataplane** (the origin is the observation: `b` only answers after the
   write):

   ```
   PASS before the write the origin is the only server: a
   PASS the panel applies the table with a 303: 303
   PASS the browser is sent back to the page with the outcome: /panel?applied=1
   PASS the running revision moved and lists both servers: {'revision': 'v2', 'slots': ['127.0.0.1:54384', '127.0.0.1:54385']}
   PASS the dataplane really serves the new server: ['a', 'b']
   PASS the original server still serves: {'a': 4, 'b': 2}
   ```

7. **Draining from the page takes the slot out of rotation**, the read plane
   says `drain`, and `ready` returns it:

   ```
   PASS the panel drains the server with a 303: 303
   PASS the redirect names the applied state: /panel?applied=drain
   PASS status publishes the drain: [('127.0.0.1:54384', 'ready'), ('127.0.0.1:54385', 'drain')]
   PASS the drained server takes no new request: {'answers': ['a'], 'served_b': 2, 'before': 2}
   PASS the panel returns the server with a 303: 303
   PASS the server rejoins rotation: ['a', 'b']
   ```

   The `served_b` counter is frozen across ten requests: the drained origin
   never saw another exchange, not merely "fewer".

8. **The certificate reload form goes through the same applier** and comes back
   with the page's own outcome (the certificate machinery itself has its own
   page, [v08-certificate-renewal](v08-certificate-renewal.md)):

   ```
   PASS the certificate form is applied with a 303: 303
   PASS the certificate reload reports success on the page: /panel?applied=1
   ```

9. **Every panel write leaves its `AUDIT` line**, and no secret reaches the
   process log:

   ```
   PASS every panel write leaves its AUDIT line: {'lines': 11, 'routes': ['/panel/backends/api', '/panel/certificates/reload', '/panel/login', '/panel/servers/api/127.0.0.1:54385/state', '/panel/servers/{backend}/{target}/state']}
   PASS no secret reaches the process log: 
   ```

   The first `AUDIT` of the run, from `eqproxy.log`:

   ```
   AUDIT {"event":"admin_write","ts_unix":1793061554,"remote":"127.0.0.1:…","role":"operate","method":"POST","path":"/panel/certificates/reload","status":200,"backend":null,"server":null,"from":null,"to":null}
   ```

10. **Opt-in, on a second process** started from the same file with
    `panel = false`: the route is still behind the token (the gate runs before
    routing), and with a valid token it does not exist.

    ```
    PASS without the panel the route is behind the token like any other: 401
    PASS with a valid token the panel is a 404 when it is off: 404
    ```

## Tests that cover what the journey does not

- **The five panel E2E cases** on a real admin socket
  ([e2e_panel.rs](eqproxy-net/tests/e2e_panel.rs)):
  `the_login_flow_opens_a_session_and_the_token_never_leaks` ([:207](eqproxy-net/tests/e2e_panel.rs#L207)),
  `a_session_is_required_and_a_stale_cookie_is_cleared` ([:296](eqproxy-net/tests/e2e_panel.rs#L296)),
  `the_csrf_token_and_the_origin_are_what_authorise_a_form_post` ([:355](eqproxy-net/tests/e2e_panel.rs#L355)),
  `a_read_session_reads_and_cannot_write_anything` ([:482](eqproxy-net/tests/e2e_panel.rs#L482), which also
  refuses the read session on `/panel/certificates/reload` and on the table
  editors individually) and
  `the_panel_is_not_served_unless_the_config_turns_it_on` ([:543](eqproxy-net/tests/e2e_panel.rs#L543)).
- **Session bookkeeping** is unit-tested inside the module: the idle window
  (`a_session_is_only_valid_for_its_idle_window`, [panel.rs:846](eqproxy-net/src/panel.rs#L846)),
  the bound and its eviction
  (`the_session_table_is_bounded_and_evicts_the_oldest`, [panel.rs:856](eqproxy-net/src/panel.rs#L856)),
  one logout revoking only its own session, an id and its CSRF token being
  independent secrets, and the cookie being scoped and never echoed as a value.
- **Path ownership and escaping** have their own unit tests
  ([panel.rs:897](eqproxy-net/src/panel.rs#L897),
  [panel.rs:981](eqproxy-net/src/panel.rs#L981)),
  so `/api/v1/status` can never be served as a page and a configured name
  cannot become markup.
- **The same journey on the debug profile** is part of the suite
  ([cli_e2e.rs:4210](eqproxy-cli/tests/cli_e2e.rs#L4210)); this page is its
  release-binary counterpart, and both drive the real forms over real sockets.

## Not executed in this run

- **The panel over a Unix socket or with `allow_remote`**: **NOT EXECUTED**.
  This run uses loopback TCP, like the rest of the v0.8 journeys; the socket
  transport and its ACLs have their own pages
  ([v08-admin-unix-socket](v08-admin-unix-socket.md), [v08-admin-unix-acl](v08-admin-unix-acl.md)).
- **Several sessions at once (two browsers, eviction under load)**: **NOT
  EXECUTED** — the bound and the eviction are unit tests, not a concurrent
  journey.
- **A certificate reload with real TLS listeners**: **NOT EXECUTED** here; the
  form's wiring is what this page proves, the rotation is in
  [v08-certificate-renewal](v08-certificate-renewal.md).
- **Docker image / Docker Scout**: **NOT EXECUTED** — nothing is published
  here.

## Limitations

- The panel is HTTP on the administration plane: it is meant to sit on
  loopback or a Unix socket, next to its bearer tokens (ADR-0017, ADR-0021).
  No TLS is offered on the admin plane itself.
- Sessions live in memory only: a restart, or 30 idle minutes, ends them, and
  the page has no JavaScript, so the dashboard is rendered per request and
  does not live-update.
- The panel owns three write actions plus login/logout; it is not a general
  administration UI: there is no `DELETE`, no persistence, no drift view
  (SPEC §9 lists what remains pending).
