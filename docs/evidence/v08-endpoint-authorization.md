# Endpoint authorization matrix (v0.8 gate, SPEC §9)

Language: **English**.

**Increment:** roadmap v0.8, gate clause *"Tests de autorización por
endpoint; el proxy sigue sirviendo con el panel caído (test explícito);
secretos ausentes en toda respuesta (T17)"*. This slice is **test-only**: no
production code changes, so there is no new binary behaviour to exercise. The
gate is closed by the matrix below plus two existing tests, cited with their
names.

**Tree under test:** workspace `HEAD`-less working tree of 2026-10-25,
`cargo test --workspace` → 29 binaries, **500 passed, 0 failed**.
**Host:** macOS arm64 (Darwin). **Toolchain:** Rust 1.97.1.

## The matrix

`eqproxy-net/tests/e2e_admin.rs::every_route_is_authorized_by_the_matrix`
starts the real admin plane on a loopback socket with a read token and a write
token, and sends one raw HTTP request per cell. Every route the plane serves is
covered, plus an unknown route and an unserved method:

| Request | anonymous | read token | write token |
|---|---|---|---|
| `GET /api/v1/status` | 401 | 200 | 200 |
| `GET /metrics` | 401 | 200 | 200 |
| `GET /nope` (unknown) | 401 | 404 | 404 |
| `PUT /api/v1/backends/api/servers/127.0.0.1:19000/state` | 401 | 403 | 200 |
| `PUT /api/v1/backends/api` (document) | 401 | 403 | 503 `config_unavailable` |
| `PUT /api/v1/listeners/web` (document) | 401 | 403 | 503 `config_unavailable` |
| `POST /api/v1/certificates/reload` | 401 | 403 | 503 `config_unavailable` |
| `DELETE /api/v1/status` (unserved method) | 401 | 405 `Allow: GET, PUT, POST` | 405 `Allow: GET, PUT, POST` |

The `503` cells are deliberate: the write token **passes the role gate** and
reaches the applier, which this test does not attach (`AdminState::apply =
None`). A `200` there would be a lie the test cannot back — the plane answers
"config unavailable", and the assertion pins that. The `405` `Allow` list is
configuration-wide (this plane has a write token): it names the methods the
plane serves, not the methods the caller may use, which is the HTTP meaning of
the header.

Every answer — 401, 403, 404, 405, 503 and the two 200s — is swept for both
bearer tokens, so a secret cannot reach a response body or header through any
of these paths (T17). A 401 must also carry `WWW-Authenticate: Bearer` and
must not contain `listeners`/`backends`: an unauthenticated caller learns
nothing about the topology (asserted in the helper, so it applies to every 401
in the matrix).

Finally the test asserts that **none of the refusals changed state**: both
servers are still `ready` and the status still reports revision `v1`.

## The other two clauses

- **The proxy keeps serving with the panel down.**
  `the_dataplane_keeps_serving_when_the_admin_task_dies` (same file) runs a
  TCP echo backend through the dataplane, aborts the admin task, asserts the
  admin port refuses connections, and then proves a second round-trip through
  the proxy still echoes. The plane is not in the dataplane's failure path.
- **No secrets in any answer.** The matrix sweep above covers every admin
  response with both tokens. On the binary level, the two E2E journeys assert
  that neither token appears in the process log: see
  [`v08-metrics-detail.md`](v08-metrics-detail.md) (`no secret in the log`) and
  [`v08-certificate-renewal.md`](v08-certificate-renewal.md) (same
  assertion). Audit lines carry role, peer, method, path, status and a
  transition — never the token (visible in the `AUDIT {…}` transcripts of the
  tests).

## Commands and results

```console
$ cargo fmt --all -- --check                              → ok
$ cargo clippy --workspace --all-targets -- -D warnings    → exit 0
$ cargo test --workspace                                   → 29 binaries, 500 passed, 0 failed
$ cargo test -p eqproxy-net --test e2e_admin               → 15 passed, 0 failed
$ cargo test -p eqproxy-net --test e2e_admin every_route_is_authorized_by_the_matrix
                                                           → 1 passed, 0 failed
```

`cargo test --workspace` includes the matrix and the panel-down test; the
targeted runs are listed because they are the ones the gate names.

## Limits

- **Test-only increment:** no release binary was rebuilt (no production code
  changed); the "binary" evidence for this slice is the library/plane the
  binary links, exercised over real sockets.
- The matrix covers the **TCP** admin endpoint. The Unix-socket endpoint shares
  the same router (`respond`), and its own tests already cover the token gate;
  the matrix was not re-run over a Unix socket.
- A read-only plane (no write token) answers `403 write_disabled` for writes;
  that is covered by `without_a_write_token_the_state_route_stays_read_only`
  and the admin unit tests, not by a separate matrix row.
- The `403` body distinguishes `forbidden` from `write_disabled`; both are
  asserted elsewhere, only the status is asserted here.
