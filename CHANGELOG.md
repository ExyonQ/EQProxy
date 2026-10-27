# Changelog — EQProxy

Language: **English**. Format follows "Keep a Changelog" (Added / Changed /
Fixed); versions are `vMAJOR.MINOR.PATCH` git tags.

## [v0.8.0] — 2026-10-27

### Added

- **Web panel (v0.8 slice 11, D6/Q1/CE1; ADR-0029).** `[admin] panel = true`
  (off by default; with it off every `/panel` path is a `404` like any other
  unknown route) serves a server-rendered client of the administration plane:
  a dashboard with the live listeners and, per backend, its policy and its
  servers with `state`/`healthy`/`active`/`drained`, plus a `ready`/`drain`/
  `maintenance` form per slot, a form per `[backend.*]`/`[listener.*]` table
  and the certificate reload. No JavaScript is shipped, so every action is a
  plain `POST` form: `POST /panel/login` exchanges the bearer token once for
  an `HttpOnly`, `SameSite=Strict` cookie scoped to `Path=/panel`, plus a CSRF
  token that every later form carries and the server checks against that
  session (a cross-site `POST` would need a token it cannot read). Sessions
  live in memory only — 30 minutes idle, at most 16, and a logout revokes just
  its own session — and a read-role session reads but cannot write. Every
  action calls the same function the JSON API calls (`apply_server_state`, the
  configuration writer with the form's `revision` as `If-Match`, and the
  certificate action), so the panel cannot drift from the API; each attempt
  writes its `AUDIT` line and no secret is echoed. The page is one template
  and a stylesheet under `default-src 'none'; style-src 'self';
  form-action 'self'`, so there is no script to audit. Tests: five E2E over a
  real admin socket (login flow with the token never echoed, session required
  and a stale cookie cleared, CSRF plus `Origin`, a read session cannot write,
  and the panel absent unless the configuration turns it on) and a journey
  over the real binary that logs in, applies a backend table and drains a
  server through the forms
  ([e2e_panel.rs](eqproxy-net/tests/e2e_panel.rs)).
- **Per-server `maintenance` closes the idle material (v0.8 slice 10,
  D6/H3/B-H12/B-E8; ADR-0028).** The third per-server administration state:
  `maintenance` removes the slot from selection exactly as `drain` does and,
  at the transition, closes what the proxy has parked on it — the keep-alive
  pool and the backend HTTP/2 session, which leaves the hub and ends when its
  last stream does —, so nothing of ours stays on a machine about to be
  patched. Afterwards the slot refuses to park a finished exchange on it, and
  selection never picks it. The window opens as an event, not a poll:
  `INFO server ready for maintenance: backend=… target=… active=0` is written
  where the last in-flight guard drops, the label-free
  `eqproxy_backend_servers_maintenance` gauge counts the windows, and
  `eqproxy_backend_drains_completed_total` keeps its one meaning — a
  maintenance window never moves it. The wire route is
  `PUT …/servers/{target}/state` with `{"state":"maintenance"}`. Tests: admin
  and balancer unit cases (round trip, the slot is never selected, a finished
  exchange is not re-parked, gauge and counters), two dataplane E2E cases with
  a real HTTP/2 origin (an idle session ends at the transition; an in-flight
  stream is cut loose only when it ends), the wire route in the admin E2E, and
  a journey over the release binary whose origin counts **its own** open
  sockets — `open: 1` before the window, `open: 0` at it, the client
  connection untouched and an in-flight exchange only ending when it finishes
  ([evidence](docs/evidence/v08-maintenance.md)).
- **Backup servers, `backup = true` (v0.8, B8).** A server slot can be
  declared a backup: the balancer keeps a second tier and consults it only
  when no primary is eligible (down, draining, `weight = 0`, unresolved or
  excluded by a retry), so primaries take traffic back on the next request
  after recovery and the backup stays cold otherwise. Inside the tier **one
  rung serves at a time** — the first operational backup, which is the
  reference default (`all_backups = true` selects `option allbackups`, below)
  — and the check
  happens inside the one selection function both algorithms (round-robin,
  leastconn) share with the affinity and hash paths. `GET /api/v1/status`
  reports `backup` per slot so the read plane says which role a server plays.
  Tests: schema parse/validation, seven balancer unit cases (idle backup,
  failover and recovery, drained and weight-0 primaries, retry exclusion,
  affinity, all-backups, leastconn), a CLI E2E that fails a primary over to
  the backup and revives it, and a journey over the release binary with three
  real origins and HTTP health checks
  ([evidence](docs/evidence/v08-backup.md)).
- **Backup failover ladder, `priority` (v0.8, B8; EQProxy extension).** The
  backup tier is ordered: `priority` (0..=255, backup only) is the failover
  order, higher first, and ties keep configuration order. Only the first
  operational rung serves; when it fails the next one takes over, and a
  recovered higher rung takes the traffic back on the next request. The
  reference has no numeric priority on `server` lines, so the field is
  documented as an extension, rejected on a non-backup slot instead of being
  a silent no-op, bounded and reported in `GET /api/v1/status` and
  `config diff` (`addr(weight,backup,priority)`), and declared with its range
  in the public JSON Schema. Tests: config validation (range and
  backup-only), four balancer unit cases (ladder order and ties, retry across
  rungs, affinity, leastconn), a CLI E2E that walks the ladder down and back
  up through the real binary, and a journey against the release binary with
  one primary and two real backup origins
  ([evidence](docs/evidence/v08-priority.md)).
- **Backup pooling, `all_backups = true` (v0.8, B7/B8; `option allbackups`).**
  A backend can balance its whole backup tier instead of serving one rung at
  a time: when no primary is eligible, every operational backup is a
  candidate, so the configured algorithm (`roundrobin`, `leastconn`) and the
  server `weight`s spread the load across the pool — and, as the reference
  states, there is no priority order between the backups anymore. Pairing it
  with a `priority` rung, or enabling it in a backend with no `backup = true`
  slot to balance, is a configuration error instead of a silent no-op (both
  named with the field path and a fix), and the public JSON Schema declares
  the field. `GET /api/v1/status` publishes the live policy per backend,
  `config explain` names it and `config diff` reports the transition
  (`all_backups: false -> true`). Tests: config validation, six balancer unit
  cases (2:1 pool split, ladder dropped, dead member out with retry
  exclusion, all-down, leastconn inside the pool, affinity inside the pool),
  status/diff assertions, a CLI E2E that walks primary → pool → survivor →
  pool → primary with exact weighted counts, and a journey over the release
  binary with three real origins for both algorithms
  ([evidence](docs/evidence/v08-allbackups.md)).
- **Endpoint-by-endpoint authorization matrix (v0.8 gate, SPEC §9).** A new
  E2E asserts, over real sockets and for all three callers (anonymous, read
  token, write token), what every admin route answers: `GET /api/v1/status`
  and `GET /metrics` (401/200/200), `PUT …/servers/{target}/state`
  (401/403/200), both document writes and `POST /api/v1/certificates/reload`
  (401/403, and 503 `config_unavailable` when the role gate passes but no
  applier is attached — never a 200 it cannot back), an unknown route
  (401/404/404) and an unserved method (401 without a token, 405 with the
  plane's `Allow` list). Every answer is swept for the two bearer tokens
  (T17), a 401 must disclose neither the topology nor anything about the
  token, and the run ends by proving that no refusal changed the server state or the
  revision. The gate's other two clauses are covered by existing tests: the
  dataplane keeps serving after the admin task is aborted
  (`the_dataplane_keeps_serving_when_the_admin_task_dies`) and the binary
  journeys assert no token in the process log.
- **Per-server and per-route metrics, opt-in and budgeted (v0.8 slice 9, CE4;
  ADR-0026).** `[metrics] detailed = true` (off by default) makes the
  dataplane attribute each completed exchange to the server that served it
  and to the rule that matched it: `eqproxy_server_requests_total` and
  `eqproxy_server_errors_total` (`backend`, `server`) plus
  `eqproxy_route_requests_total` (`listener`, `route` — only for a matched
  rule; default-backend traffic gets no invented label). `max_series`
  (default 128, validated 1..=4096) is a hard ceiling counted across both
  families: a series that does not fit is refused and counted in
  `eqproxy_metrics_detail_dropped_total`, an existing series keeps counting,
  and four label-free `eqproxy_metrics_detail_*` series report enabled, live
  series, budget and refusals in every scrape — so "no traffic", "detail
  off" and "budget refused it" are distinguishable, and a flag that promises
  detail without measuring it is no longer possible. `GET /api/v1/status`
  carries the same rows under `metrics_detail`; `detailed` moves on `SIGHUP`
  (enabling starts an empty window, disabling drops it), while `max_series`
  is fixed at startup and a reload that changes it warns and keeps the live
  budget. Label values are escaped before the exposition format. Detail
  follows `http_requests_proxied` — h1/h2/h3 through the h1 engine and gRPC
  streams — and protocol switches (including WebSocket) stay pending. Tests:
  config validation (`0` and `4097` rejected, default 128), the core registry
  (budget refusal, refusal counting, disable-drops-window, escaping), admin
  rendering/status, and a journey against the release binary that enables on
  `SIGHUP`, asserts exact per-server and per-route counts with a 5xx split,
  disables and proves the window is gone, then runs a second process with
  `max_series = 2` that tracks two series and counts the observation it
  refused.
- **Certificate renewal without a restart (v0.8 slice 8, D7; ADR-0025).**
  `POST /api/v1/certificates/reload` (write token, no `Origin`, no body)
  re-reads the configuration and its certificate files through the same
  single writer as `SIGHUP` and answers only after the dataplane committed,
  with `listener`, `listen`, `fingerprint` (`sha256:<hex>` of the leaf really
  served), `changed` and `quic` per TLS listener; `GET /api/v1/status`
  reports the same `tls_fingerprint`. The material moved behind a resolver
  every handshake consults, so a renewal is one atomic swap: established
  connections keep running, new h1/h2/h3 handshakes get the new certificate,
  and a live QUIC endpoint — which cannot be reconfigured — no longer forces
  a restart for a chain, key or SNI-name change (ALPN, the mTLS client CA and
  the minimum version are still refused with `QuicTlsReload` and a message
  that names them). A candidate that fails validation (a PEM that does not
  parse, a key that does not match) answers `400`, keeps the previous
  certificate serving, and now also logs `ERROR config reload rejected: …`
  and moves `config_reload_failures` — a rejected `SIGHUP` used to be silent.
  The fingerprint uses AWS-LC, already the rustls provider: no new crate.
  Tests: TLS unit tests (fingerprint identity, adoption allowed for material
  and refused for ALPN/mTLS/version), the h3 rotation E2E (the connection
  opened before the renewal keeps serving, the rotated-out root fails, the
  new one works), the kept-socket TCP rotation E2E extended with a live
  in-flight connection, admin-plane unit tests (RBAC, `Origin`, body, method
  list) and a journey against the release binary that rotates the files on
  disk, checks the DER a real TLS client receives before and after, and
  proves a corrupt PEM is rejected without touching the live certificate.
- **A finished drain is observable (v0.8 slice 7, H3; ADR-0024).** The
  per-server status gained `drained` (`state = "drain"` with no exchange left
  in flight), `PUT …/state` answers it too, and the moment the last in-flight
  exchange ends is recorded where it happens — in the drop of its in-flight
  guard — as one `INFO server drained: backend=… target=… active=0` line and a
  counter, instead of being inferred from polling. `/metrics` gained two
  label-free series, `eqproxy_backend_servers_draining` (slots declared in
  drain) and `eqproxy_backend_drains_completed_total` (finished episodes), so
  cardinality cannot grow with the topology (CE4); the per-slot detail stays
  in the JSON status, where the budget is the configured config. Tests: two
  balancer unit tests (the event fires exactly once, an idle drain reports
  finished without an event) and a new E2E journey with the real binary and a
  gated origin — `active=1`/`drained=false` while the drain is open,
  `active=0`/`drained=true`/counter `1` when the held exchange ends, one log
  line naming the slot, and `503` for new traffic; a control run with the
  event disabled fails that journey.

- **Named users in the admin socket's POSIX ACL (v0.8 slice 6, B-H14;
  ADR-0023).** `unix_socket_acl_uids = [501, 502]` grants those uids `rw` on
  the socket file through its POSIX access ACL, **in addition to** the owning
  group, so a user outside the group can `connect` without widening it. The
  kernel enforces the ACL at `connect`, before the process sees a peer; the
  peer-uid allowlist and the bearer token still apply afterwards. The option
  requires `unix_socket_mode = "0660"` plus `unix_socket_gid` (the mode's
  group class is the ACL mask), is Linux-only, deduplicates and caps the list
  at 64 entries. There is no `libacl`: the entries are written as the
  `system.posix_acl_access` extended attribute in its documented kernel
  layout, then replaced or **removed** on `SIGHUP` together with the rest of
  the socket policy, so an emptied list leaves no stale user. Tests: encoder
  unit tests (tag order, mask, dedup, size), validation (Linux-only, `0660`
  pairing, duplicates, cap, TCP socket), an encoder/reload test on Linux and
  a container journey with four real uids — owner, ACL-only, group-only and
  outsider — plus `getfacl` before and after the reload. The journey asserts
  every observation and runs against the image of **each** published
  architecture (`linux/arm64`, `linux/amd64`); a control run that names the
  outsider in the ACL fails it, so its green is not vacuous. The release
  workflow runs that journey on the `-candidate` image of both architectures
  and stops before promoting the digest if either fails. A
  pull-request job runs the same published file on **native** `amd64` and
  `arm64` runners (`ubuntu-24.04-arm`), so no leg depends on syscall
  emulation; each leg checks its own `uname -m` before starting and fails if
  the label did not land on the architecture the matrix declares.

- **Hot reload of the admin socket policy (v0.8 slice 6, B-H14; ADR-0022).**
  `unix_socket_mode`, `unix_socket_gid` and `unix_socket_allow_uids` are no
  longer startup-only: a `SIGHUP` applies them to the socket the running
  process already bound. The file policy is written `chown`-then-`chmod` and
  the accept loop reads the peer-uid list per connection from a shared cell,
  so the next peer is judged by the new list while the listener, its queue
  and every open connection stay untouched. The policy moves before the
  dataplane swap and is put back when the swap is refused, so a rejected
  generation leaves neither a new mode nor a new list behind; a policy the
  process cannot write (a group it does not belong to) is rejected as a whole
  with the failing syscall named and the previous policy still in force. The
  endpoint and the tokens remain fixed at startup and a reload that changes
  them warns instead of pretending. Tests: in-process E2E (widen to `0660` +
  group, deny the owner through the reloaded list, restore owner-only, refuse
  a foreign gid with the live policy unchanged) and CLI E2E with the real
  binary (three SIGHUPs: applied, rejected, applied again; the dataplane keeps
  serving throughout and the socket file is still removed on shutdown).

- **Group-shared admin socket and peer-uid allowlist (v0.8 slice 6, B-H14;
  ADR-0022).** `unix_socket_mode = "0660"` plus a numeric
  `unix_socket_gid` lets a group reach the admin plane instead of only the
  owner; `0600` remains the default and refuses a gid, and no other mode is
  accepted. The socket is `chown`ed before `chmod` (which can clear mode
  bits); a failed group change aborts startup and removes the file it just
  created. `unix_socket_allow_uids` adds a fail-closed uid allowlist checked
  against the kernel's `SO_PEERCRED`/`getpeereid` answer immediately after
  `accept` and before any HTTP byte: a peer outside the list, or one whose
  uid the kernel does not report, is closed with a warning and learns
  nothing about the route. The bearer token still applies afterwards; the
  three layers (filesystem, uid, token) are independent. Tests: validation
  (mode/gid pairing, unsupported mode, duplicate and socket-less uid lists),
  in-process E2E with the real credential (allowed uid, 0660 + group owner,
  denied uid gets EOF) and CLI E2E with the real binary (allowed run answers
  `200`; denied run closes the connection but keeps proxying traffic).
  Named users joined the ACL in the next slice (ADR-0023, below); group names,
  abstract sockets and socket activation remain pending for v0.9.1, and the
  policy itself (mode, gid, uid allowlist, ACL) now reloads on `SIGHUP`.

- **Admin plane on a Unix domain socket (v0.8 slice 5, B-H14 first step;
  ADR-0021).** `[admin]` now takes `unix_socket` as the alternative to
  `listen`: exactly one endpoint, resolved against the configuration file.
  The socket is created with mode `0600`, so the filesystem decides who may
  connect while the bearer token (and the separate write token) still decides
  what the caller may do; the routes, limits and `AUDIT` lines are unchanged,
  and a Unix peer is audited as `unix-socket:uid=<uid>`. Startup refuses a
  path that is already served (no stealing), replaces a stale socket left by
  a crash, and refuses to delete any file that is not a socket. A clean
  shutdown unlinks only the inode this process created, so a restart does not
  inherit a dead name; `allow_remote` with `unix_socket` is rejected instead
  of ignored. Tests: unit (validation of both/neither/empty/`allow_remote`),
  in-process E2E (mode `0600`, token gate, status/metrics, live-socket
  conflict, stale replacement, regular-file preservation, unlink on
  shutdown) and CLI E2E with the real binary over the socket plus proxied
  traffic and SIGINT. Remaining for v0.9.1 (B-H14): shared-group sockets,
  `SO_PEERCRED` allowlists, abstract sockets and socket activation.

- **Structured access log (v0.8 slice 4, B-N14/B-I14/B-E8; ADR-0020).** An
  optional `[access_log]` writes one line per HTTP request answered by the
  dataplane engine — HTTP/1.1, every HTTP/2 stream and every HTTP/3 request,
  which all share `http1::serve_http` — to stdout or an append-only file
  (`path`, relative to the configuration file), as `json` (default) or the
  nginx `combined` shape. Entries carry listener, client, protocol, method,
  path without the query string, host, status, duration, backend/server when
  one served and the response byte count when exactly known; an unparsed head
  is logged with `-` fields and an exchange that ended without a response with
  status 0. The sink is a bounded channel (4096) drained by its own task: a
  full or failed sink drops lines and advances `access_log_dropped` instead of
  delaying a request, and shutdown flushes what is queued. Destination and
  format are fixed at startup (a `SIGHUP` that edits them warns and keeps the
  running sink); an unopenable destination fails startup instead of serving
  without the configured log. The query string and request headers other than
  `Referer`/`User-Agent` are never logged. Tests: unit (JSON/combined shape,
  UTC calendar, one-line escaping, drop accounting, flush on shutdown), E2E
  in-process (HTTP/1.1 parsed and unparsed entries, HTTP/2 protocol field) and
  CLI E2E with the real binary under 40 concurrent requests and a SIGINT.

- **Read-only administration plane (v0.8 slice 1, D6/B-H12/B-N14/B-I14/B-E8;
  ADR-0017).** An optional `[admin]` table opens a listener of its own, with a
  bearer token from `token` or `token_file` (at least 16 bytes, constant-time
  comparison, never echoed). It serves `GET /api/v1/status` (version, uptime,
  the validated listeners/backends/servers and the live counters as JSON) and
  `GET /metrics` (Prometheus text with a fixed series set — the only label is
  the build version, so a scrape cannot grow the index). Every route requires
  the token (401 with `WWW-Authenticate` otherwise), only `GET` is served
  (405 + `Allow: GET`), unknown routes are 404, heads over 8 KiB are 431 and
  an exchange has 5 s. The plane is a separate socket and task: the dataplane
  keeps serving with it dead (E2E test aborts it mid-run), and a configured
  plane that cannot bind fails startup. Validation keeps the plane on loopback
  unless `allow_remote = true` (this slice has no TLS there), refuses a
  concrete port already used by a `[listener.*]` (two `:0` binds are not a
  collision: the kernel picks distinct ports) and requires exactly one secret.
  `eqproxy config schema` exports the new keys; `eqproxy.toml.example`
  documents them. Writes, RBAC, auditing and the panel UI were still pending at
  this slice; ADR-0018, ADR-0019, ADR-0025 and ADR-0029 delivered them later
  in v0.8.

- **Per-server drain over the admin plane (v0.8 slice 2, B-H12/B-E8/H3;
  ADR-0018).** `PUT /api/v1/backends/{backend}/servers/{target}/state` with
  `{"state":"ready"|"drain"}` takes a server out of selection without
  touching its in-flight exchanges, and `ready` returns it. The write needs
  its own `write_token`/`write_token_file`, distinct from the read token; with
  no write secret every write is `403 write_disabled`, and the read role gets
  `403 forbidden`. The request must be JSON, at most 1 KiB, declare its
  length, and carry no `Origin` (a browser never belongs on the plane); each
  attempt writes one `AUDIT` JSON line (role, peer, outcome, `from`/`to`,
  never the secret). `GET /api/v1/status` now reports per server the
  configured target, the resolved address, weight, `state`, `healthy` and
  `active`, so a drain is observable (H3). The state registry is shared by
  every balancer and survives `SIGHUP`; with every server drained the proxy
  answers the existing explicit `503` and counts `no_available_server`. With
  `maintenance` and the idle-pool closure still pending at this slice (ADR-0028
  delivered them for the window); the durable audit sink and a live-updating
  topology view remain pending.

- **Hot backend and listener configuration through the API (v0.8 slice 3,
  B-E1/H2/CE2; ADR-0019).** `PUT /api/v1/backends/{name}` and
  `PUT /api/v1/listeners/{name}` take that TOML table — bare body or the full
  section copied from the file — (`application/toml`, declared length up to
  64 KiB, `Origin` refused, write role), create the name when absent and
  replace the table otherwise. The
  status answer now carries a `revision` and the same value as `ETag`; every
  write is conditional: missing `If-Match` is `428`, a stale one is `412`
  with the current revision. One configuration task serializes API writes
  and `SIGHUP`, validates and resolves the **whole** document first (missing
  certificates or maps, unknown backends, invalid tables are `400` and never
  reach the dataplane), and answers `200` only after the swap commits; a bind
  conflict or a frozen QUIC endpoint is `409` and leaves the old generation
  serving. A listener kept by name and address keeps its socket, so four
  concurrent clients proxied across a backend change, a backend creation and
  a listener repoint with **zero failed requests** in the E2E (real binary,
  real origins), each generation observed in the responses. Runtime changes
  are not written to the file: the next `SIGHUP` re-reads the baseline and
  replaces them (asserted in the same test). `DELETE`, persistence, drift and
  RBAC beyond the two tokens remain pending.

### Changed

- **Roadmap milestone numbering (owner decision, 2026-10-25).** After v0.8
the roadmap advances `0.8.5`, `0.9.0`, `0.9.1`… and continues `0.9.2`, `0.9.3`
up to `0.9.50`; `1.0.0` only when the owner decides. The
extensions-and-converter milestone is now **v0.8.5** (was v0.9) and the
parity-certification gate **v0.9.1** (was v1.0). The forward references in
this changelog, `README.md`, ADR-0021/0022/0023, `docs/equivalences.md` and the
two v0.8 admin-socket evidence pages were updated to the new numbers; the
roadmap's own files are local-only and are renumbered in the maintainer's
tree.

- **The Docker Hub page is published by CI, not edited on the website.**
  `docs/docker-hub-readme.md` is the single source: after every stable release
  (and on demand, to repair drift) `.github/workflows/dockerhub-page.yml`
  renders `{{version}}` from `Cargo.toml` and `{{packages}}` from the Scout
  SBOM of the published image, re-checks the 0 critical / 0 high sentence with
  `--exit-code` on both architectures, PATCHes the description and reads it
  back, so a page that disagrees with the release fails the run instead of
  shipping. The page drifted twice by hand: v0.7.0 still carried 0.6.3 strings
  and the wrong package count.

## [v0.7.0] — 2026-10-24

### Added

- **HTTP/3 over QUIC (v0.7 slice 9, B-H2/B-E2/B-E13).** A listener with
  `quic = true` and a `[listener.X.tls]` table serves real **h3** on its own
  address and port over UDP (QUIC, TLS 1.3, ALPN `h3` forced; the same
  certificate, SNI entries and client CA as TCP). The configuration gate
  requires `mode = "http"`, rejects `alpn = ["h3"]` on the TCP table and
  rejects `proxy_receive` (QUIC has no preamble). Each h3 request becomes one
  HTTP/1.1 exchange through the existing engine — routing rules, auth, rate
  limiting, header actions, mirroring, retries, the keep-alive pool and
  compression decide exactly once — with `:authority` → `host`, hop-by-hop
  headers stripped, `content-length` preserved, bodies without a length sent
  upstream as `chunked` and no-body requests kept unframed; h3 trailers map
  to h1 trailers and back. `CONNECT` answers `501`, a backend `101` resets
  the stream, a truncated body resets instead of ending cleanly, interim 1xx
  are skipped (h3 0.0.8 has no informational frame) and a dead backend is the
  engine's `502`. QUIC connections count in `maxconn` (explicit refusal when
  full); startup is fail-closed (the UDP endpoint opens before traffic); a
  hot reload keeps a kept endpoint and can turn QUIC on/off, but a **TLS
  material change on a live endpoint needs a restart** (the swap is rejected,
  never half-applied). h3's server grease is disabled for interoperability:
  aioquic 1.2.0 lost the end of stream when an unknown frame followed DATA.
  Verified with 8 new tests (7 real-socket dataplane E2E with a real `h3`
  client + 1 configuration-gate test) and independent `aioquic` 1.2.0
  through the release binary (GET, 256 KiB streaming POST, trailers, gzip,
  a rule `418`, `CONNECT` `501`, clean SIGINT). The interop gate closed with a
  second independent implementation: `quic-go` 0.64.1 (its own QUIC/h3/QPACK
  stack) repeated the HTTP journeys through the same binary — GET, 256 KiB
  streaming POST without a length, trailers, gzip and a rule `418`, with
  `proxied=4` — and the aioquic run was repeated after the harness change;
  both pass. WebSocket over h3, gRPC over h3, 0-RTT, connection migration and
  HTTP/3 to backends stay out. Design in
  `docs/adr/0013-http3-quic.md`, evidence in `docs/evidence/v07-http3.md`.
- **WebSockets over HTTP/2 (RFC 8441 extended CONNECT, v0.7 slice 8).** An
  h2 client opens the socket with `CONNECT` + `:protocol = websocket`; the
  proxy advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`, renders the stream as
  the real h1 handshake (`GET`, `Upgrade: websocket`, a generated
  `Sec-WebSocket-Key`, the client's subprotocols) and runs it through the
  same h1 engine, so routing rules, auth, rate limiting, header actions,
  `forwarded_headers` and the tunnel stay one implementation. A backend
  `101` becomes an h2 `200` (never a `101`, and never the internal
  `Sec-WebSocket-Accept`); bytes are relayed both ways with the client's
  flow-control window as the only buffer. A non-`101` answer is relayed as a
  normal HTTP/2 response (status, headers, body), an unknown `:protocol` and
  a classic CONNECT stay `501`, and a silent tunnel is cut by
  `idle_timeout`. New counters: `ws[tunnels=… failures=…]`. Verified with 10
  new tests (4 unit + 6 real-socket dataplane E2E) and `hyper-h2` 4.2.0
  through the release binary. Backends that speak **only** h2 and
  `permessage-deflate` negotiation are out of this slice.
- **gRPC over HTTP/2, end to end (v0.7 slice 7).** A `POST` whose
  `content-type` is `application/grpc` (or `application/grpc+…`, never
  `grpc-web`) is relayed as a real HTTP/2 stream when the chosen backend
  negotiated ALPN `h2`, instead of the h1 translation that cannot answer
  before the client half-closes. The request HEADERS are built from the same
  h1 head the engine would forward, so routing rules, the rate limiter,
  authentication, rule header actions, forwarded headers and `rewrite`
  behave identically; `te: trailers` is sent to the backend; DATA and
  trailers are relayed in both directions at once with HTTP/2 flow control
  as the only buffer, and `grpc-status` reaches the client in trailing
  HEADERS (including a trailers-only answer). `idle_timeout` cuts a silent
  stream (counted as inactivity) and `max_stream_duration` ends a running
  one with `grpc-status: 4` (DEADLINE_EXCEEDED) trailers, or a `504` before
  the response head. A refused stream is never replayed (gRPC is not
  idempotent); connect-phase failures keep the B-H7 rule. Compression and
  mirroring do not apply to gRPC streams, and a redirect/direct rule or a
  backend without `h2` keeps the h1 translation. New counters:
  `grpc[streams=… errors=…]`. Verified with 12 new tests (4 unit + 8
  real-socket dataplane E2E: bidi echo before half-close, 256 KiB across
  both flow-control windows, two concurrent streams on one backend session,
  idle cut, deadline status, forwarded headers, h1 fallback and a dead
  backend's explicit `502`) and with the real `grpcio` 1.66.1 stack: a TLS
  server and a client through the release binary exercise bidi, 256 KiB,
  `NOT_FOUND` in trailers and a 6-minute stream with a message every 20 s.
  <!-- soak:gate:start -->
  The 24-hour soak of the version gate **passed** on 2026-10-23T23:09:55Z:
  86400.0 s, 4267 messages,
  0 broken streams and 0 failed probes, final `grpc-status: OK`
  (binary `0672763af6af`). Evidence in
  `docs/evidence/v07-grpc-soak-24h.md`.
  **The soak criterion is met; the remaining gate items are listed in
  the roadmap.**
<!-- soak:gate:end -->
- **Response compression: gzip and Brotli, streaming and measured (v0.7
  slices 5–6).** A `http` listener can opt in with
  `[listener.X.compression]`: `gzip = true` (`level` 1–9, default 6) and/or
  `brotli = true` (`brotli_quality` 0–11, default 5), plus `min_size` (default
  1 KiB) and `types` (text/JSON/JS/XML/SVG). Negotiation follows RFC 9110
  §12.5.3: explicit entries decide, `q=0` refuses, `*` covers the coding,
  malformed q-values refuse; the higher q-value wins and a tie goes to Brotli,
  and a coding the listener did not enable is never selected. Eligible bodies
  are compressed **while they are relayed** (nothing buffered whole) and sent
  as a chunked response: `Content-Length` is dropped, `Content-Encoding:
  gzip`/`br` and `Transfer-Encoding: chunked` are added, `Vary:
  Accept-Encoding` appears once, and the status line is presented as HTTP/1.1.
  gzip is a member written by EQProxy over `flate2` raw deflate; Brotli is the
  pure-Rust `brotli` crate's streaming writer, flushed after every relayed
  block so nothing is held back. Nothing is re-encoded: bodies with
  `Content-Encoding`/`Content-Range`/`Cache-Control: no-transform`, `HEAD`,
  1xx/204/206/304, HTTP/1.0 clients, media types outside the list and declared
  bodies below `min_size` stay identity. Backend chunked trailers are
  validated and re-emitted after the compressed stream. h2 clients receive the
  same bytes as DATA through the existing h1⇄h2 translation (no second
  compressor). The gate rejects either coding on a `tcp` listener, gzip levels
  outside 1–9, Brotli qualities outside 0–11 and media types that are not
  `type/subtype`, `type/*` or `*/*`, using the runtime grammar. New counters:
  `compression[gzip=… brotli=… bytes_in=… bytes_out=…]`. Verified with 16
  compression tests (3 core unit on negotiation, 8 dataplane on both encoders
  and the response decision, 5 CLI E2E through the real binary: every gzip
  refusal case, Brotli preference/q-values/refusals/trailers with the decoded
  body compared, validate/explain for both codings, and h2c with real curl for
  each). Measured with the release binary against an independent Python origin
  over loopback (`scripts/evidence/v07-compression/bench.py`, raw data
  committed): 771 214 B of text → 49 799 B with gzip 6 (ratio 0.065) and
  12 726 B with Brotli 5 (0.017); 1 037 124 B of JSON → 77 132 B (0.074) and
  30 380 B (0.029); a 256 KiB `application/octet-stream` body stays at 1.000
  because the type is not eligible. Every compressed response was decoded with
  an independent decoder (zlib, Brotli reference module) and compared with the
  origin's bytes. Design in
  [ADR-0010](docs/adr/0010-response-compression.md); evidence in
  [docs/evidence/v07-compression.md](docs/evidence/v07-compression.md).

- **HTTP/2 backend session lifecycle (v0.7 fourth slice).** Sessions now have
  the lifecycle their name implies. An idle session (no exchange for the
  listener's `idle_timeout`) is removed from the hub and closed, and an
  exchange in flight is never cut by that close: admitting an exchange and
  closing the session are one critical section. A peer `GOAWAY` retires the
  session (new exchanges dial a fresh one) while the streams it already
  accepted finish — the drain. A stream the peer refused **before processing
  it** — a received `GOAWAY`, or `RST_STREAM` with `REFUSED_STREAM` (RFC 9113
  §8.1.4) — is replayed **once** on a fresh session with the same request
  head, when no request body was consumed; a stream cut after processing, or
  one whose body was already forwarded, is never replayed, so nothing runs
  twice. New counters: `h2_sessions_idle_closed`, `h2_goaway_received`,
  `h2_refused_retried` (rendered as the `h2[...]` METRICS group). Verified
  with 3 dataplane E2E journeys over real sockets (an idle close that skips
  an exchange in flight, a graceful server GOAWAY draining the accepted
  stream while the next exchange takes a fresh session, and a refused stream
  replayed exactly once) and two journeys through the release binary against
  an independent Python `hyper-h2` origin. Design in
  [ADR-0009](docs/adr/0009-http2-session-lifecycle.md), evidence in
  [docs/evidence/v07-http2-session-lifecycle.md](docs/evidence/v07-http2-session-lifecycle.md).

- **HTTP/2 backend multiplexing (v0.7 third slice).** An `h2` backend now
  serves concurrent requests on **one session**: every exchange takes its own
  stream behind a private 64 KiB pipe, and the engine's pool is bypassed on
  that path (a pipe belongs to exactly one exchange, so it is never checked
  in). The first exchange to a cold server handshakes under a per-address
  gate, so simultaneous first requests share the session it installs instead
  of dialing one each — without the gate, two concurrent requests produced
  two backend TCP connections (measured by the dataplane test). A session
  that dies is forgotten by its connection task and replaced by the next
  exchange; the request that races the death fails with `502` and sends
  nothing, so no request is delivered twice. Counters keep their meaning:
  a stream on a live session counts as `reused`, a new session as `opened`.
  A `tcp` listener never interprets ALPN and still relays bytes even when the
  backend negotiates `h2`. Verified with 3 new dataplane E2E journeys (two
  in-flight exchanges completing only on a single multiplexed session, a
  killed session being replaced exactly once, a TCP tunnel unaffected by
  `h2` ALPN) and a journey through the release binary: four concurrent
  `curl` requests, each held 1.2 s by an independent hyper-h2 origin, all
  completed in 1.20–1.21 s (1.29 s wall) on **one** connection with streams
  1/3/5/7, over both an h1 listener and an h2/TLS listener. Design in
  [ADR-0008](docs/adr/0008-http2-backend-multiplexing.md), evidence in
  [docs/evidence/v07-http2-multiplexing.md](docs/evidence/v07-http2-multiplexing.md).

- **HTTP/2 to the backend (`http2_protocol_options` parity, v0.7 second
  slice).** A backend whose TLS handshake negotiates `h2` — `[backend.X.tls]
  alpn = ["h2"]` — is now reached with a **real HTTP/2 session** instead of
  HTTP/1.1 bytes: framing, HPACK and flow control from the `h2` crate, one
  HTTP/1.1 message per stream through the existing engine (same routing,
  actions, retries, pool and errors). The h2 handshake runs in the connect
  phase, so a backend that cannot speak h2 fails as a connect error (retried,
  `502`) rather than an open connection that fails per request.
  Translation, both directions: `content-length` kept only when the h1 side
  declared one, chunked bodies sent as DATA, h1 trailers as trailing HEADERS;
  a backend `content-length` preserved, anything else relayed as `chunked`,
  and h2 trailers arriving as h1 trailers. `CONNECT` and host-less requests
  are refused (`502`), and a body shorter or longer than declared cuts the
  connection instead of ending a message cleanly. One exchange at a time per
  session (the pool is exclusive): no h2-to-backend multiplexing yet. This
  makes HTTP/2 end to end possible (h2 client → h2 origin) and is the
  prerequisite for gRPC. Verified with 4 unit tests, 7 E2E journeys against a
  real h2-over-TLS server (h1→h2, h2→h2, pooled session reuse, trailers in
  both directions, `HEAD`, `CONNECT` refusal, failed ALPN negotiation), 1 CLI
  E2E, and a live journey through the release binary and `curl` against an
  independent Python `h2` origin (one backend session serving five exchanges,
  `opened=1 reused=4 proxied=5`). Design in
  [ADR-0007](docs/adr/0007-http2-backend.md), evidence in
  [docs/evidence/v07-http2-backend.md](docs/evidence/v07-http2-backend.md).

- **HTTP/2 termination on `mode = "http"` listeners (v0.7, first slice).** A
  client that negotiates `h2` — ALPN on TLS, or the h2c connection preface on
  a plaintext listener, detected with `peek` so an HTTP/1.1 connection is
  never disturbed — gets real HTTP/2: framing, HPACK and flow control from the
  `h2` crate, one stream mapped to exactly one HTTP/1.1 exchange inside the
  existing engine (routing rules, auth, rate limiting, mirroring, redirects,
  direct answers, retries, pool and timeouts are the same code, not a
  copy), and the answer translated back into HEADERS/DATA. Request bodies
  without `content-length` go upstream as `chunked`; chunked responses are
  decoded into DATA and their trailers become trailing HEADERS; hop-by-hop
  headers never cross in either direction. (The upstream side got its own
  HTTP/2 slice in this same release — see the entry above.) Explicit
  failures instead of silent ones: a `101` from a backend resets the stream,
  `CONNECT` over h2 answers `501`, and a body shorter than its declared
  `content-length` resets the stream instead of ending cleanly. Bounded by
  design: 128 concurrent streams per connection, 16 KiB DATA reads, capacity
  reserved before every frame. The h2 behaviour of the `h1 ⇄ h2` translation
  is verified over real sockets with a real h2 client (6 E2E journeys,
  including three streams that only finish if they advance together, chunked
  bodies with trailers, TLS `h2` ALPN and the truncation reset) and through
  the real binary with real `curl` clients (`HTTP/2 200` over h2c and over
  TLS, plus the same listener still answering HTTP/1.1). Design rationale in
  [ADR-0006](docs/adr/0006-http2-termination.md).

### Changed

- **The container image runs on Wolfi.** The runtime stage is
  `cgr.dev/chainguard/wolfi-base` pinned by index digest (ADR-0016) instead of
  `scratch`: 36 packages, **0 critical / 0 high** from Docker Scout on
  linux/amd64 and linux/arm64, and `docker exec … sh` works for operators. The
  binary is still a statically linked musl executable (the Dockerfile's `file`
  gate fails the build otherwise), it runs as 65532, and `config apply` still
  writes its state directory. The release workflow repeats the journeys on
  both architectures and promotes only the scanned digest.
- **HTTP/3 per-request cost cut by 60 % (B-H2, S-H3-01).** Profiling the
  released HTTP/3 artifact (`perf` on a DWARF build plus a counting-allocator
  build) put ~18 % of CPU in musl's malloc lock and ~11 % more in the kernel
  spinlock/futex path it drives, at **108 allocations and 44 KiB of zeroed
  memory per proxied request**. Three changes follow the measurement: the
  process uses **mimalloc** as its global allocator (ADR-0014), body-less h3
  requests relay the answer directly onto the stream (no relay task, no
  command channel, no timer per step) and answer chunks are read into
  exact-size `BytesMut`s instead of a 16 KiB zeroed scratch buffer plus a
  second copy, with a 16 KiB pipe instead of 64 KiB. Same host and generator,
  S-H3-01: 18 403.7 → **32 587.4 req/s** (+77 %), p50 3.26 → **1.73 ms**, CPU
  per request 205 → **88 µs**. The full 5×2 campaign re-measured 32 941.3 vs
  HAProxy's 49 279.1 req/s (**0.668×**, up from 0.341×), p99 5.42 vs 4.39 ms;
  **peak memory rose from 9.23 to 44.93 MiB** (mimalloc per-thread heaps, now
  above HAProxy's 32.55 MiB — the one metric that regressed) and S-H3-02 is
  unchanged (0.707×). Still classified **Worse**, not Comparable. Evidence in
  [v07-h3-profile.md](docs/evidence/v07-h3-profile.md), decision in
  [ADR-0014](docs/adr/0014-global-allocator.md).


- **`alpn = ["h2"]` is accepted on a `mode = "http"` listener and on a
  backend used by one.** v0.6.3 rejected both because the dataplane could
  neither serve h2 nor speak it; now it does both, so the gate no longer
  refuses a configuration that works. The CLI E2Es that asserted the
  rejections check the acceptance instead (real fixtures, exit 0, `config
  OK`), and the listener-side acceptance test is unchanged. An empty backend
  ALPN list keeps HTTP/1.1, exactly as before.

- **The release pipeline now re-pulls the published image and replays the
  journeys on it.** After promotion and the Docker Hub mirror, the workflow
  pulls `:<version>` from both registries on both architectures, asserts the
  pulled image is the scanned index, and runs `--version`, the `alpn = ["h2"]`
  rejection, `config apply` and live proxied traffic. A tag that resolves to
  the right digest is no longer the last word: the bytes users pull have to
  run. The step is exercised on the next tag; for v0.6.3 the same journeys
  were run by hand against the published artifacts.
- **Every release also ships the source tarball of the tagged commit,
  checksummed in `SHA256SUMS.txt`.** `eqproxy-<version>-src.tar.gz` is
  exported with `git archive` from the released commit, so only tracked
  files travel: the maintainer-local material (`ROADMAP EQPROXY/`,
  `SERVIDORES.md`, `.dockerignore`, `scripts/`) cannot leak into an asset.
  Before upload the export is asserted against the same commit (every
  workspace member plus `Cargo.lock` present, the `Cargo.toml` version is the
  released one, no local-only path) and the same commit yields byte-identical
  bytes, so re-running a tag refreshes the asset with the same digest. The
  four binary lines of `SHA256SUMS.txt` are written exactly as before and the
  tarball line is appended (five lines, verified with `-c` before upload), so
  no existing checksum changes.
- **The Scout report requirement is scoped to tag runs.** A manual
  `workflow_dispatch` dry run never reached the checksum steps: it demanded
  `SCOUT-<version>-linux-<arch>.md` that only a tagged, pushed image produces,
  and aborted right after assembling `dist/`. A dry run now assembles,
  exports and checksums (`dry run: no Scout reports expected`); a tag run still
  refuses to create a release without both reports.
- **Release pages carry only the notes of their own version.** The release job
  passed `CHANGELOG.md` whole to `gh release create/edit`, so every release
  page from v0.5.0 onwards also listed all previous releases: v0.6.3's page had
  45 201 characters of changelog, from v0.1.0 up. The notes are now extracted
  for the released version — heading, date and that section only, 3 678
  characters for v0.6.3 — and a tag whose version has no section fails the
  release instead of publishing a stale body. The published v0.6.3 page was
  corrected the same way.

### Fixed

- **An exchange that races the backend's GOAWAY is no longer answered with
  `502`.** When the peer announced GOAWAY while a bodiless request was being
  admitted, h2 could report the refused stream as `RST_STREAM(CANCEL)`
  instead of a GOAWAY error; EQProxy classified that as a protocol error and
  answered `502` on Linux (the macOS timing took the GOAWAY branch, so the
  suite passed there). The session now probes the h2 handle for the stored
  GOAWAY before admitting a stream and is retired when the peer already
  announced it; if the GOAWAY lands between the lookup and the admission, the
  exchange is moved to a fresh session, and a request that carried **no
  body** is replayed once when the race is lost on the wire. A body-carrying
  request is still never replayed. Reproduced on Linux against the real
  `h2::server` (`RST_STREAM(CANCEL)`, previously a deterministic failure) and
  verified with 5/5 single-journey runs, 3×13/13 for
  `e2e_backend_h2`, the whole `eqproxy-net` suite on Linux and
  `cargo test --workspace` on macOS (424 passed); details in
  `docs/evidence/v07-http2-session-lifecycle.md` §5.1.
- **A clean HTTP/3 close is no longer counted as a protocol error, and no
  longer floods the log (S-H3-02).** The h3 error alone does not say whether a
  peer ended the session normally, so EQProxy wrote
  `WARN [h3] HTTP/3 connection error … ApplicationClose: 0x0` for every
  connection a client closed the way RFC 9114 §8.1 describes and counted it in
  `h3_connection_errors`: a 10 s handshake run produced **13 859–15 123** such
  lines, one per handshake. `classify_h3_close` now reads the QUIC close reason
  kept next to the connection: `H3_NO_ERROR` or application code `0` (what
  aioquic and quic-go send) counts `h3_clean_closes` and logs nothing, while a
  protocol code, a transport error, a stateless reset or a timeout still
  counts `h3_connection_errors` and logs the cause — at both ends, the h3
  handshake and the session. The periodic line reads
  `h3[clean_closes=… connection_errors=…]`. Verified with 4 new unit tests
  (one close code at a time, the transport errors that must stay errors, and
  the two operator lines verbatim), 3 new dataplane E2E tests (application
  code `0`, `H3_NO_ERROR`, and a protocol-error close that still counts and
  logs while the listener keeps serving) and the release binary against
  `aioquic` 1.2.0: two clean closes leave **0** WARN, an
  `H3_GENERAL_PROTOCOL_ERROR` close leaves
  exactly **1**, and the proxy serves again afterwards
  (`h3[clean_closes=3 connection_errors=1]`). The S-H3-02 before/after
  campaign on `netcup-bench` (two amd64 images built from one tree, five
  repetitions each) measures **15 227 → 26 WARN lines** and **1.67 MiB →
  5.08 KiB** of log per run at the same offered load, i.e. the noise is gone;
  handshakes/s moved 1 251.5 → 1 331.7 (**+6.4 %**), which is inside the
  −4.4 % drift the HAProxy control shows on the same scenario and is therefore
  **not** claimed as a speedup. Evidence in
  [docs/evidence/v07-h3-close.md](docs/evidence/v07-h3-close.md).
- **Backend idle pool sized from the load actually in flight (S-H2-01).** The
  A16 pool kept at most 64 idle connections per server, so a workload with
  **400 streams in flight** parked 64 of them per wave and re-dialled the
  other 336: the S-H2-01 campaign measured **141 155 backend connections**
  (192.85 per 1 000 requests) against HAProxy's 6 106 (1.22), exhausted the
  ephemeral port range and answered **7 473 × `502`**. The cap now follows
  the peak of exchanges in flight on that server, reported by the balancer
  when a connection is borrowed (never at check-in, which would race a burst
  that is still starting), clamped between the previous 64 and **4 096**;
  the 60 s idle expiry is unchanged, so a burst's leftovers are released.
  A new dataplane E2E (`pool_sizing_keeps_a_400_stream_burst_without_churn`)
  drives 4 h2 connections × 100 streams against a keep-alive h1 origin that
  holds every request while a wave is open (so the 400 exchanges really are
  concurrent instead of depending on scheduling) and asserts that the first
  wave dials exactly 400, that the second dials **zero** new connections
  while reusing all 400, and that the origin accepts no new connection during
  the second wave; with the cap fixed at 64 it fails (wave 2 dials 336 more:
  736 vs 400).
  The S-H2-01/02 campaign was repeated with the new image on the same host:
  S-H2-01 **5 704.0 → 40 872.0 req/s** (0.099× → **0.742×** HAProxy), backend
  connections per 1 000 requests **192.85 → 0.55**, **7 473 → 0** `502`s, p99
  470.39 → 22.51 ms; S-H2-02 **0.975× → 1.081×** (still 1.24× the CPU and 3.2×
  the memory). Design in
  [ADR-0015](docs/adr/0015-backend-idle-pool-sizing.md), evidence in
  [docs/evidence/v07-h2-pool-sizing.md](docs/evidence/v07-h2-pool-sizing.md).
- **Keep-alive idle wait used the client header-phase bound.** A connection
  that had already served an exchange was closed after
  `client_header_timeout` (default 5 s) of silence even though
  `idle_timeout` (default 60 s) is the documented inactivity window: a client
  that kept a connection idle for 5 s lost it. The wait for the next request
  on a keep-alive connection is now bounded by `idle_timeout` and counted as
  `idle_timeouts`; the header phase of a new connection keeps its bound and
  still answers `408`. The hot-maps E2E test (a keep-alive connection held
  across a data swap) exposed this as a flake that became deterministic under
  load; it passes now because the product honours the documented window, not
  because the test was relaxed
  (`keepalive_wait_is_bounded_by_idle_timeout_not_the_header_one`).

### Documentation

- **HTTP/3 benchmarked against HAProxy 3.4.6 (S-H3-01/S-H3-02), with the
  loss published.** Both products served h3 on the same port, certificate,
  congestion controller and origin, on an idle Linux host, 5 repetitions
  each, raw data in `docs/evidence/v07-h3-bench/run-20261023T134656Z/`.
  EQProxy is **Worse** on both scenarios: S-H3-01 16 838.6 vs 49 323.8 req/s
  (0.341×), p50 3.58 vs 1.06 ms, 351 % vs 198 % of one core (5.2× CPU per
  request); S-H3-02 1 209 vs 1 637 handshakes/s (0.739×), p50 13.0 vs
  8.8 ms. Memory is lower (9.2 vs 32.7 MiB peak). The handshake path is
  single-core bound and every peer close logs a warning (13.9k–15.1k lines
  per 10 s run), both disclosed in `docs/evidence/v07-h3-bench.md`; no
  favourable scenario is omitted and no claim of parity is made.

## [v0.6.3] — 2026-10-21

Patch release closing the two defects found while measuring TLS parity: a
configuration that asked for HTTP/2 could pass the gate and then fail every
request, and the container had no writable state directory, so `config apply`
and `config rollback` always failed inside it. No wire behaviour of a valid
configuration changes.

### Fixed

- **`alpn = ["h2"]` / `["h2c"]` is rejected by the config gate instead of
  silently negotiating a protocol the dataplane cannot speak.** With
  `mode = "http"` rustls completed the handshake for h2, then every request
  failed (`curl` exit 52) while the proxy counters showed
  `client[accepted=0]`. The error names the field, the cause and the fix
  (`alpn = ["http/1.1"]`), with the file/line context of the other gate
  errors. `mode = "tcp"` is untouched: it relays bytes without parsing them,
  so an h2 hint there is a legitimate tunnel choice. A backend TLS entry is
  rejected only when an HTTP-mode listener routes to that backend, because
  that listener only ever sends HTTP/1.1 over the connection.
- **`config apply` and `config rollback` work in the published image.** The
  state directory defaulted to `./.eqproxy`, which is `/` in the container,
  and uid 65532 cannot write there: both commands exited 1 with
  `Permission denied`. The runtime stage now ships
  `/var/lib/eqproxy` owned by 65532 and sets `EQPROXY_STATE_DIR` to it, so the
  commands work out of the box; mount a volume on that path to keep history
  across container replacements. The image also exposes 8443, the port the
  documented TLS listener uses.
- **Reports no longer panic when the reader closes the pipe.** `println!`
  aborts on `EPIPE`, so `eqproxy config explain | head` (and any long report
  piped into `grep -q`, as the release script does) died with "failed
  printing to stdout: Broken pipe". Reports now go through a writer that
  treats a closed reader as success; the exit code stays 0.

### Documentation

- The Docker Hub page used the `0.6.1` tag in every example, named uid
  **65534** for a file-readability requirement when the image runs as
  **65532**, and did not mention the state directory or volume. All three are
  corrected and the page points at v0.6.3.
- The TLS parity report's note that `alpn = ["h2"]` "is accepted by the
  config gate" is now historical: v0.6.3 rejects it at validation time.
- **Erratum:** the v0.6.1 parity report labelled one column "glibc", but that
  column ran the release asset — which is a static musl build — inside Debian.
  Both sides were the same binary, so the report measured the image base and
  the user, not libc. The erratum is at the top of
  `docs/evidence/v0.6.1-parity/README.md`; its "no measurable cost" result
  stands for packaging only.
- TLS parity measured with **genuinely built glibc binaries** on both
  architectures (`docs/evidence/v0.6.2-tls-parity/`). Findings: ECDSA P-256
  termination works and is at parity on arm64 (−2.4 %, p 0.28) but the musl
  build is **20 % behind on amd64** under load (p 0.001) and **11 % behind with
  no TLS at all** (p 0.0001), so the gap is libc-general, not handshake cost;
  **TLS 1.2 sessions resume and TLS 1.3 ones do not** (no ticketer is
  configured, so no ticket is ever sent); and HTTP/2 does not exist, while
  `alpn = ["h2"]` was accepted by the config gate (v0.6.3 rejects it) and
  negotiates a protocol the proxy cannot serve (curl exit 52, zero accepted
  connections).
- The published Linux binaries are musl only, so the glibc build that carries
  the tier-1 performance claims is not the artifact users download. Shipping
  glibc variants is an open decision, not a claim.

## [v0.6.2] — 2026-10-20

Patch release with two goals: the image is now scanned **and** exercised on
both architectures before a release tag exists, and the two RustSec advisories
published after v0.6.1 (`webpki-roots` 1.0.9, `rustls-webpki` 0.103.15) are
fixed. No configuration key, wire behaviour or rule semantics changed.

### Changed

- **Docker Scout now gates both image architectures, before any release
  exists.** The image job built and scanned only `linux/amd64`;
  `linux/arm64` reached the registries unscanned. It now builds the
  multi-arch manifest once, pushes it under a throwaway
  `<version>-candidate` tag, records the index digest, scans **both**
  `linux/amd64` and `linux/arm64` (`docker scout cves --only-severity
  critical,high --exit-code`), runs the container E2E journeys
  (`--version`, `config validate`, live proxied traffic) on both
  architectures, and only then promotes that exact digest to `<version>` /
  `:latest` and mirrors it to Docker Hub — no rebuild, so the scanned bytes
  are the published bytes. The GitHub release job now `needs` the image job,
  so a release cannot be created next to an unscanned image, and the two
  `SCOUT-<version>-linux-<arch>.md` reports ship as release assets. A
  post-promotion step re-reads every published tag's digest and fails if it
  differs from the scanned one.

### Security

- `webpki-roots` 1.0.9 → 1.0.10 and `rustls-webpki` 0.103.15 → 0.103.16.
  RUSTSEC-2026-0381 (2026-10-19, "Bundled root certificates allow trust in
  distrusted emSign intermediates") and RUSTSEC-2026-0382 (2026-10-20,
  "Certificate verification may accept distrusted intermediates") were
  published after the v0.6.1 audit and turned the next `veyra audit` into
  REJECTED. The bump is the advisory's own fix, not a suppression: no test or
  check changed, `cargo fmt`/`clippy -D warnings`/`cargo test --workspace`
  (327 passed, 0 failed) still pass. **The published v0.6.1 binaries and image
  were built before the advisories and keep the old roots** — the fix ships
  with the next tag.

### Documentation

- README and the Docker Hub page now state what the artifacts already were:
  the `eqproxy-linux-amd64` / `eqproxy-linux-arm64` release binaries are
  **static musl** (no libc, no interpreter, runnable from `FROM scratch`),
  verified against the published v0.6.1 assets in
  `docs/evidence/release-v0.6.1-scout-both-arch.md`.

## [v0.6.1] — 2026-10-20

«Rules, routing and traffic», patch release. It closes every scope box that
v0.6.0 had postponed by owner decision: multi-certificate TLS per SNI, the
two Envoy rule actions (`hash_policy` and `request_mirror`), the native
filter equivalence table (B-E4) and the public JSON Schema with editor
autocompletion (Q1/CE1, which also completes CE8). The v0.6 roadmap now
reads 32/32 scope boxes and 6/6 version-gate criteria. No behaviour of an
existing deployment changes: every addition is opt-in and every new key is
rejected by the config gate when malformed.

### Added

- Multi-certificate TLS per SNI (B-I2/B-H10/B-E9; Envoy `filter_chains` per
  SNI, nginx multiple `ssl_certificate`): `[[listener.*.tls.certs]]` entries
  add `cert`/`key`/`names` to a listener. The `cert`/`key` pair of
  `[listener.*.tls]` stays the **default** certificate — it answers clients
  without SNI and names no entry claims, like nginx's default server — and
  each entry answers the names it declares: exact names first, then the
  longest wildcard, with `*.example.com` covering exactly one extra label
  (RFC 6125). Names are case-insensitive and tolerate a trailing dot; the
  config gate rejects an empty `names` list, a name claimed by two
  certificates, malformed labels, a wildcard that is not the leftmost label
  and IP literals (a TLS client never sends an IP as SNI, RFC 6066) — each
  error naming the field, the cause and a valid example. `config explain`
  lists the names of each listener (`sni=[…]`). The hot certificate reload
  path rebuilds the resolver, so the SNI set swaps in hot (verified: the
  same name answers with the previous certificate, then with the reloaded
  one, on the same listener). Verified end to end: unit tests for the name
  grammar and the resolver preference order, a dataplane E2E with real
  handshakes that records the presented leaf per SNI (exact, wildcard,
  two-label miss, unknown name, no SNI, case-insensitivity) and the real
  binary driven by
  `openssl s_client -servername … -showcerts` for both names plus the
  default fallbacks, with traffic through the SNI tunnel.
- Envoy rule actions `hash_policy` and `request_mirror` (B-H3), the last two
  pieces of the rule engine. `hash_policy = { key = "source" | "path" |
  "host" | "cookie:NAME" | "header:NAME" }` makes a `split` pick its target
  by **weighted rendezvous hashing** instead of the rotation: the same key
  keeps its target across requests and connections, the weight sets each
  target's share of keys, and removing a target only remaps the keys it
  owned (no state, no ring to rebuild); a request without the key falls back
  to the smooth weighted rotation. `request_mirror = { backend,
  percentage = 1..=100 }` sends a **copy** of the matching request to a
  shadow backend on a detached task — the client keeps the primary answer,
  a mirror that is down or slow changes nothing (`requests_mirrored`,
  `mirror_failures`, `mirror_skipped` in METRICS), the copy carries the
  same forwarded head (and body, up to a 256 KiB budget — larger is not
  mirrored and counted, never truncated). The config gate names field,
  cause and fix for a hash policy without a split, with fewer than two live
  targets or with an unknown key, and for a mirror to a missing backend,
  with a percentage outside 1..=100 or on a local action. `config explain`
  shows `(hash cookie:session …)` and `mirror 100% -> shadow`. Verified end
  to end: stickiness, spread and consistency under target removal, a real
  copy observed on the shadow socket, a dead shadow backend without client
  impact, and the same through the real binary.
- Public JSON Schema of the configuration (Q1/CE1): `eqproxy config schema
  [--output FILE]` prints or writes a draft 2020-12 schema generated from
  the same Rust types the parser deserializes (so it cannot drift from the
  accepted format), published as
  [`eqproxy.schema.json`](eqproxy.schema.json). `eqproxy.toml.example`
  starts with the `#:schema ./eqproxy.schema.json` directive, which gives
  Taplo/Even Better TOML users completion and inline validation — including
  `additionalProperties: false` (from `deny_unknown_fields`), so a typo is
  flagged before `config validate` rejects it. Three gates keep it honest:
  the generated schema must match the repository file byte for byte, the
  documented example must satisfy it (and the real gate), and a typo plus a
  numeric duration must be rejected by it.
- Filter equivalence table (B-E4) in [docs/equivalences.md](docs/equivalences.md):
  CORS, `ext_authz` and `rate_limit` mapped from Envoy, nginx, HAProxy and
  ingress-nginx to EQProxy, with the semantics that differ stated explicitly
  (fail-closed auth without `failure_mode_allow`, a per-instance token
  bucket, HTTP-only `ext_authz`) and what still needs WASM.

### Changed

- Container image runtime: `scratch` with a **static musl** binary instead of
  `debian:bookworm-slim`. Docker Scout scanned the previous image with 4
  critical + 13 high findings, every one of them in packages inherited from
  the Debian base (perl, util-linux, openssl, zlib) and none in EQProxy; the
  fix removes that surface rather than patching it: the image now carries
  **0 packages** (binary + `/etc/ssl/certs/ca-certificates.crt` only, 15.8 MB
  locally vs 164 MB), reports `0C 0H 0M 0L` and passes the non-root and
  copyleft policies. The builder stage fails if the binary stops being
  statically linked, and it now copies `eqproxy.schema.json` before compiling
  (`eqproxy-config` embeds it with `include_str!`, so the image build was
  broken by the Q1/CE1 increment and this fixes it).
- Release pipeline: the image is scanned with Docker Scout (`critical,high`,
  `--exit-code`) **before** the push, builds use `--pull` so the recorded
  base digest is current, and the pushed manifest carries provenance
  (`mode=max`) plus an SPDX SBOM.

### Verification (this release)

- `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D
  warnings` (0 warnings) and `cargo test --workspace` green: 23 suites,
  327 passed, 0 failed, 2 ignored (the two Docker-gated harnesses, last
  measured 23/23 differential and 65/65 migration on the v0.6.0 tree; this
  patch does not touch those paths).
- `veyra audit . --profile standard`: ACCEPTED, plus the Rust Audit static
  scan and an EvoForge `mcp_submit_eval` on a real slice.
- Image scanned with Docker Scout **before** publishing (see the image
  section of the release evidence).
- Parity of the two runtimes measured on the released artifacts over both
  architectures and both transports (S-H1-04, 16 reps per cell): arm64 HTTP
  +1.6 % (p 0.51) and arm64 TLS +2.0 % (p 0.68) for the container, amd64 HTTP
  +6.2 % (p 0.062) and amd64 TLS +6.0 % (p 0.027), with p50/p95 within a few
  percent, RSS at parity (5.3–7.2 MiB both sides) and every response a real
  `200` in all 128 measured reps. The sign flips between campaigns, so the
  supported reading is "no meaningful regression", not "musl is faster".
  Report: [`docs/evidence/v0.6.1-parity/`](docs/evidence/v0.6.1-parity/README.md)
  (it also records the correction of the first version, which bind-mounted the
  glibc binary and produced virtiofs TLS outliers and a false −40 % RSS).

## [v0.6.0] — 2026-10-20

«Rules, routing and traffic» (Phase 4), complete: requests are routed by
typed rules, a request can be shaped on the way up and back, traffic is
balanced, split, limited, pinned and authenticated per rule, DNS changes
in hot, and migrations from the four reference implementations are
demonstrated case by case. The version gate closes with every criterion
measured (below). `v0.6.0-alpha` published the first slice of this same
phase; everything in the next section is part of this release.

### Added

- Typed routing rules per listener (B-H3/B-H4/B-N2/B-N3): ordered
  first-match-wins conditions — `host`/`host_prefix`/`host_regex`
  (case-insensitive, port-free), `path`/`path_prefix`/`path_regex`
  (literal, no normalization), `methods`, `headers`, `cookies` (RFC 6265),
  `map` (hot data, below), `ip` CIDR blocks — routing to exactly one action;
  the listener's `backend` is the default server when nothing matches.
- Rule actions (B-N5/B-I6/B-I11): `use_backend`, `split` (weighted
  traffic with smooth round-robin shares and `weight = 0` rollback),
  `redirect` (3xx with a `$host`/`$uri`/`$request_uri` template) and
  `direct_response` (local answer, no backend contacted), plus
  `rewrite.path_prefix_rewrite`/`host_rewrite`.
- Request and response header actions (B-N4/B-I4/B-E17): `set_headers`,
  `add_headers`, `del_headers`, `response_headers`, templated with
  `$remote_addr`/`$host`/`$scheme`; the `forwarded_headers` policy is
  applied last so a rule can never spoof it, and framing headers are
  rejected.
- Balancing (B-H5/B-N12/B-E6): `roundrobin`, `leastconn` (weighted
  least-connections with SWRR tie-breaking) and `slow_start` dynamic
  weighting that ramps a recovered server from ~0 to its weight.
- Source and cookie affinity (B-H8/B-N13/B-I8), bounded by construction
  (no stick tables): `mode = "source"` hashes the client IP, `mode =
  "cookie"` inserts a slot token re-issued only when stale.
- Canary and weighted traffic (B-I11; ingress `canary-weight`,
  `canary-by-header`, `canary-by-cookie`; Envoy `weighted_clusters`) and
  hot data maps (C10/PP-02): `[maps.*]` re-read on `reload_interval` and
  swapped atomically **without a config reload and without losing any
  other state**; a bad update is rejected once, the last good data keeps
  serving, `maps[reloads= failures=]` counts it.
- Per-rule rate limiting (B-N8/B-I7/B-E16): token bucket per client IP
  with explicit `429` + `rate_limited` counter, no network in the hot
  path.
- CORS and HSTS (B-I10): local preflight for `OPTIONS`
  (`204` + allow-methods/headers/max-age, the backend never sees it) and
  `access-control-*`/`vary: origin` on rule responses, with `"*"` +
  credentials rejected at the config gate.
- Per-rule authentication (B-N9/B-I9): `type = "basic"` against htpasswd
  (`$apr1$` pinned to `openssl passwd -apr1`, plain allowed, bcrypt/crypt
  rejected by name) and `auth-url` subrequests carrying the client
  headers and `X-Original-Method`/`X-Original-URL`, failing closed
  (`500` for a refusing auth service, `502` when it is down or times out,
  counted in `auth_denied`/`auth_service_errors`).
- Non-blocking dynamic DNS (B-H13/B-N18/B-E15): listeners bind and serve
  immediately whatever DNS does, unresolved slots answer an explicit
  `503` (counted in `no_available_server`), `resolve_interval` re-resolves
  and swaps addresses in hot keeping the last-known one on failure, with
  `dns[ok= failures= updates=]` in METRICS.
- WebSocket upgrades and `CONNECT` tunnels (B-H15/B-I18/B-E11) with
  per-direction idle timeouts, and PROXY protocol v2 send + autodetected
  receive (B-H9/B-E10).
- Timeouts per phase and direction (Q5/B-H11(p)/B-E12):
  `stream_idle_timeout`, `max_stream_duration` (total exchange cap,
  `504` when it fires), `request_headers_timeout`, each documented in
  `config explain` (`timeout_on_fire`).
- Migration matrix (v0.6 gate «migración demostrada»): `docs/migration/`
  holds the same demo deployment written in HAProxy 3.4, operator nginx,
  static Envoy 1.34 and ingress-nginx Kubernetes objects (plus the config
  the controller generates) and its translation to `eqproxy.toml`; the
  harness `eqproxy-cli/tests/migration.rs` runs all four originals in real
  containers next to the EQProxy binary and asserts **13/13 cases** on
  every implementation (**65/65 checks**, no exclusions), covering pool
  choice, canary by header/cookie, method routing, prefix rewrites,
  redirects, local answers and the default backend.
- `schema_version` compatibility policy (Q3, ADR-0002): the binary accepts
  `1..=SCHEMA_VERSION`, rejects unknown fields and versions outside the
  range by name, and version validation moves only with a declared
  transition.

### Changed

- Workspace version and the internal path-dependency pins move to
  `0.6.0` (the release tag must match the workspace version).
- `config validate`, `doctor`, `config explain` and the config gate now
  cover the rules, actions, maps, CORS, rate limit, auth, affinity and
  DNS fields, each error naming the field, the cause and a valid example.

### Fixed

- HTTP health checks complete at the HTTP message boundary (RFC 9112 §6)
  instead of waiting for the origin to close (`Content-Length`, chunked,
  `HEAD`/1xx/204/304 and close-delimited bodies), so a keep-alive origin
  no longer flaps a healthy server to `down`.

### Version gate (all criteria measured)

- Property-test corpus + live fuzzing of the rule evaluator: green
  (26,834 executions, 0 crashes).
- Differential corpus against HAProxy 3.4.6, nginx, the ingress-nginx data
  plane and static Envoy v1.34.2: **23/23 cases**, 0 exclusions
  (`cargo test -p eqproxy-cli --test differential -- --ignored`).
- Migration demonstrated: **13/13 cases × 5 implementations = 65/65
  checks** (`cargo test -p eqproxy-cli --test migration -- --ignored`),
  evidence in `docs/evidence/v06-migration/`.
- `config explain` explains the routing decision per rule; hung-DNS
  startup serves (or answers an explicit `503`); benchmarks S-H1-04/05 on
  amd64 and arm64 with raw data in `docs/evidence/v06-bench{,-arm64}/`.
- `cargo fmt --check`, `cargo clippy --workspace --all-targets` (0
  warnings) and `cargo test --workspace` green.

### Declared gaps (postponed by owner decision, 2026-10-20)

- `hash_policy` (consistent hashing / keyed sessions) and
  `request_mirror` → v0.6.x.
- Multi-certificate TLS per SNI (B-I2/B-H10/B-E9) → v0.6.x/v0.7.
- Public JSON Schema / editor autocompletion (Q1/CE1) → v0.6.x.
- The B-E4 native-filter equivalence table (CORS, ext_authz, rate_limit
  already exist under their own names) → v0.6.x.
- Map values are consumed through `equals` matching only (not as backend
  names or header values), and map files must be written atomically.

## [v0.6.0-alpha] — 2026-10-19

Prerelease slice of v0.6 «Reglas, enrutado y tráfico»: typed routing rules,
rule actions and the differential harness; superseded by **v0.6.0** above,
which carries the complete feature set. Published as a **prerelease** (the
`:latest` image tags kept pointing at v0.5.0).

### Added

- Typed routing rules per listener (B-H3/B-H4, first slice):
  `[[listener.*.rules]]` evaluates ordered, first-match-wins conditions
  per request — `host`/`host_prefix`/`host_regex` (case-insensitive,
  compared port-free), `path`/`path_prefix`/`path_regex` (literal,
  case-sensitive, no normalization: `/v1` also matches `/v10`),
  `methods` (case-sensitive tokens), `headers` (exact byte-for-byte /
  unanchored regex / presence, all ANDed) and `ip` (effective source in
  one of the CIDR blocks) — and routes the match to `use_backend`; the
  listener's `backend` remains the fallback when no rule matches. The
  semantics are defined once in `eqproxy-core::rules` and pinned by
  property tests and fuzzing (Q8: defined once, never silently changed).
- Actionable rule validation (Q1/CE1): a bad rule is rejected naming its
  field, the cause and a concrete valid example
  (`listener.web.rules[0].host_regex`); at most one host and one path
  variant per rule, and at least one condition is required (the
  catch-all case is the listener's default backend, not a rule).
- `config explain` traces routing per rule (H4): every rule with why it
  matched or not (`rule[0] "api": no match (host: expected …)`), then
  `route_decision` naming the chosen backend — never a bare backend
  without the path to it.
- Rule actions (B-N5/B-I6, second slice; Envoy `prefix_rewrite`/
  `host_rewrite`, `redirect`, `direct_response`): each rule carries
  exactly one action — `use_backend` (optionally with a
  `[listener.*.rules.rewrite]` subtable: `path_prefix_rewrite` replaces
  the rule's matched `path_prefix` in the forwarded target (literal;
  `""` strips it) and `host_rewrite` sets the upstream `Host`),
  `redirect` (that 3xx with `Location` rendered per request from a
  template with `$host`, `$uri` and `$request_uri`; statuses
  301/302/303/307/308) or `direct_response` (that status, `content_type`
  and `body`, served locally). The local actions never contact a backend
  and drain the request body to keep keep-alive aligned (else close);
  they are counted in the new `redirects_served` /
  `direct_responses_served` metrics. `config explain` reports each
  action (`redirect 301 -> "/new"`, `direct_response 200 …`,
  `use_backend … (rewrite: …)`) and labels local responses
  `no backend contacted`.
- Action validation (Q1): `rewrite` is accepted only on `use_backend`
  rules and needs the rule's `path_prefix`; redirect templates reject
  unknown `$…` placeholders; every error names its field
  (`listener.web.rules[0].redirect.status`) with a concrete example.
- Differential test harness for the v0.6 gate (declared corpus in
  `docs/differential-corpus.md`): the same 16 shared-semantics cases run
  against EQProxy (the built binary), HAProxy 3.4.6, the ingress-nginx
  data plane and static Envoy v1.34.2 in real containers, comparing the
  normalized status, `Location` and body. Run 2026-10-19: 16/16 cases
  agree across the four implementations
  (`cargo test -p eqproxy-cli --test differential -- --ignored`).
- Header cases in the differential corpus (the B-N4/B-I4 executable
  spec): `h1` XFF append, `h2` XFF/X-Real-IP anti-spoofing, `h4`
  X-Forwarded-Proto, `h5`–`h8` set/add/del-header on the way up and a
  response marker on the way back — each on an `append` and an
  `anti-spoofing` endpoint per implementation, with declared
  expectations. The client address is calibrated at run time (the
  `CLIENT` token) and comma-joined header values are normalized. Run
  2026-10-19: 23/23 cases agree across their applicable implementations
  — `h1`/`h2` (implemented)  agree on all four columns; `h4`–`h8` ran as spec ahead of the
  EQProxy implementation with `PENDING` skips, removed when the header
  slice landed in this release.

- Header actions and variables (B-N4/B-I4/B-E17; nginx
  `proxy_set_header`/`add_header`/`proxy_hide_header`, HAProxy
  `set-header`/`del-header`/`add-header`, Envoy
  `request_headers_to_add/remove`): per-rule `set_headers` (replace or
  insert), `add_headers` (append, keeping the client's), `del_headers`
  (remove before forwarding) and `response_headers` (on the response
  the client sees, proxied or local). Values are templates with
  `$remote_addr`, `$host` and `$scheme`, validated at the config gate
  (unknown placeholders and CR/LF rejected naming the field).
  Request-side actions require `use_backend`; the `forwarded_headers`
  policy is applied last and a rule can never override it;
  `content-length`/`transfer-encoding` are rejected (the proxy owns
  framing). `forwarded_headers` now also sets `X-Forwarded-Proto` to
  the client-facing scheme (a single-value header: replaced, never
  chained). `config explain` shows each action. Differential corpus:
  23/23 cases with all four columns asserted, 0 exclusions.
- Advanced balancing (B-H5/B-N12/B-E6, first slice) + slow start (B14):
  `balance = "leastconn"` (aliases `least_conn` (nginx) and
  `least_request` (Envoy `LEAST_REQUEST`)) is weighted
  least-connections — the pick minimizes `active exchanges / effective
  weight`, ties smoothed by the SWRR rotation. Slow start is the
  dynamic-weighting engine: with `slow_start = "30s"` (`"0s"` = off,
  maximum `"1h"`) the *effective weight* ramps linearly from ~0 to
  `weight` over the window after every transition to operational
  (startup or recovery after `rise`), so a cold or recovered server is
  never hammered with full traffic. The in-flight slot is taken under
  the same lock as the pick (no pick/lease race) and released by an RAII
  guard at exchange end. Out of this slice (explicitly open): `source`
  (≈ affinity `mode = "source"`), `uri`/`hdr()` hashing and consistent
  hashing (RING_HASH/MAGLEV). E2E over real sockets (leastconn routes to
  the idle server; a 2:1 weighted backend splits 4:2 in flight; the
  recovered server ramps and then gets exactly 1:1) and against the real
  binary (`run_leastconn_sends_new_requests_to_the_idle_server`,
  `run_slow_start_ramps_the_recovered_server_up`, plus the config gate:
  aliases accepted, `slow_start` bounded, unknown algorithms rejected by
  name).
- Non-blocking dynamic DNS (B-H13/B-N18/B-E15) + startup with hung DNS
  (CE7): `servers = [{ addr = "HOSTNAME:PORT" }]` are resolved in a
  background task started after `bind` — listeners serve from the first
  moment whatever DNS does, unresolved slots answer an explicit 503
  (counted in `no_available_server`) instead of blocking, and
  `resolve_interval` (default `"30s"`, `"0s"` = resolve once at startup,
  maximum `"24h"`) re-resolves periodically and swaps addresses in hot
  (nginx `resolver valid=` / Envoy `dns_refresh_rate` semantics; the raw
  DNS TTL is not visible through `getaddrinfo`). A failed, empty or
  timed-out round keeps the last-known address (nginx `valid=` /
  HAProxy `init-addr last`) and counts in `dns_resolution_failures`; a
  changed address restarts the health machine and the slow-start ramp.
  New `dns[ok= failures= updates=]` cluster in METRICS. E2E: hot
  re-resolution and hung DNS at dataplane level (injected resolver seam,
  never the request path) plus the real binary with the OS resolver (a
  broken `.invalid` name → immediate listener + counted 503; a
  `localhost` backend → traffic + periodic rounds counted). Limitations
  declared: multi-A records use the first address (nginx `server
  name:port` semantics; STRICT_DNS-style expansion is a gap); affinity
  tokens are stable slot indexes across re-resolutions.
- Canary and weighted traffic (B-I11; ingress-nginx `canary`,
  `canary-weight`, `canary-by-header`, `canary-by-cookie`; Envoy
  `weighted_clusters`): the `split` rule action fans requests out
  across backends by weight — smooth weighted round-robin with exact
  shares in rotation (3:1 = 3 of every 4 requests), deterministic per
  request order; `weight = 0` disables a target without touching the
  rest (canary rollback). Canary-by-header is a rule with a `headers`
  condition and canary-by-cookie a new `cookies` condition (RFC 6265
  pair parsing in the `Cookie` header: `;`-separated, pairs without `=`
  ignored, first occurrence wins, names case-insensitive; exact /
  unanchored regex / presence). `split` is mutually exclusive with the
  other actions; `rewrite` and header actions apply to the forwarded
  request whatever target wins. E2E against the real binary
  (`run_canary_split_routes_by_weight_with_header_and_cookie_overrides`:
  3:1 over 8 requests = 6:2, both overrides route 100 % to the canary,
  `config explain` shows `split [stable w=3, canary w=1]` and the
  cookie gate offline) and over real sockets
  (`split_traffic_shares_requests_by_weight_across_backends`,
  `canary_by_cookie_and_header_overrides_route_to_the_canary`, plus the
  weight-0 rollback). Selection is deterministic SWRR (documented
  difference: Envoy's `weighted_clusters` selects randomly).
- Hot data maps (C10/PP-02): named `key → value` tables consulted by
  the new `map` rule condition and updatable **in hot**. `[maps.*]`
  sections hold `file` maps (line format `key value`, `#` comments at
  line start, duplicate keys rejected; optional `default` like nginx
  `map`) or static inline `entries`; file maps are re-read every
  `reload_interval` (default `"5s"`, `"0s"` = load once) and the new
  data swaps in atomically **without a config reload and without losing
  any other state** — counters, buckets, pools and live connections
  survive (the PP-02 success criterion). A malformed or oversized
  update is rejected once (counted in the new `maps[reloads=
  failures=]` METRICS cluster) and the last good data keeps serving.
  The `map` condition selects its lookup key from the request
  (`key = "ip" | "host" | "path" | "method"`, or `header = "name"`) and
  matches on presence or `equals` (the mapped value). E2E against the
  real binary (`run_hot_maps_swap_under_traffic_without_config_reload`:
  a 100 000-entry map updated under traffic — the modified entries
  change, the untouched ones keep working, a held keep-alive connection
  survives the swap and METRICS shows `maps[reloads=1 failures=1]` with
  `cfg[reloads=0`) and over real sockets
  (`map_condition_consults_hot_data_and_swaps_in_hot`). Caveat: write
  map files atomically (write + rename) so the watcher never sees a
  torn file; map values are not yet usable as backend names or header
  values (only via `equals` matching).

### Changed

- HTTP listeners route each request through the listener's rule list
  before falling back to the default backend (TCP mode is unaffected).
- Repository layout (owner decision 2026-10-19): `scripts/` (release and
  benchmark harnesses) is maintainer-local and no longer published; the
  release pipeline is self-contained in `.github/workflows/release.yml`
  (it absorbed `scripts/release.sh`), so CI builds and verifies every
  artifact without the folder.

### Fixed

- HTTP health checks complete at the HTTP message boundary (RFC 9112 §6)
  instead of waiting for the origin to close: `Content-Length` bodies end
  at the declared length, chunked bodies at the terminal chunk,
  `HEAD`/1xx/204/304 carry no body whatever the headers announce, and
  only close-delimited bodies (no framing header) are read to EOF. A
  keep-alive origin that holds the socket open no longer times every
  check out and flaps a healthy server to `down` (interop pinned by E2E
  tests against never-closing origins, Content-Length and chunked, at
  library and real-binary level).

Verified against the built binary (E2E: multi-backend routing, rule
order, fallback and negative cases; the rewrite/redirect/direct_response
actions end to end and their actionable errors) with a property-test
corpus and a live fuzz target for the evaluator (26,834 executions, 0
crashes). The v0.6 benchmark campaign (S-H1-04/05, BENCHMARK_PLAN §3)
was repeated on the second supported architecture (linux/arm64,
oracle-quasar, 4 vCPU): S-H1-04's gaps replicate within noise (rps
ratio 1.150 vs 1.141 on amd64, e2e p95 1.38× vs 1.33×), while S-H1-05
narrows from 4.51× to 1.30× rps because HAProxy's S-H1-05 throughput is
host-dependent; EQProxy leads on both architectures and both scenarios
(raw data + cross-arch comparison in `docs/evidence/v06-bench-arm64/`).

## [v0.5.0] — 2026-10-18

«Operabilidad y confianza» (completa Phase 3). The two blocks that sat
under `Unreleased` (planned as 0.4.6 — hot reload and release
automation) fold into this release.

### Added

- HTTP health checks with `expect` matching (B-H6/B-N11/B-I19/B-E5):
  `type = "http"` with `http_path`, `http_method`, `http_host`,
  `expect_status` (ranges like `"200-299"`) and `expect_rstring`
  (regex over the body). One real exchange per probe with a hard
  timeout; E2E-verified (a backend answering 500 is marked DOWN and
  traffic moves to the healthy server).
- Passive failure detection (B-N10): with `passive = true` on the health
  check, live-traffic verdicts feed the same fall/rise machine —
  connect-phase failures and HTTP 5xx responses count as failures, other
  completed exchanges as success. Passive marks only apply when an
  active checker exists that can bring the server back (safe restart).
- Safe connect-phase retries and bounded backend queues (B-H7/B-E7):
  `retries` (extra dials, max 5) with the documented replay rule
  (idempotent methods only unless `retry_non_idempotent = true` opts in;
  the failed server is excluded from redials), and `maxqueue` +
  `timeout_queue` (never more than `maxqueue` waiters, never unbounded
  waits). A full queue is rejected immediately with 503 and an expired
  waiter with 503 — never a silent hang. Counters: `queue_full`,
  `queue_timeout`, `retry_attempts`.
- Incoming PROXY protocol v1 with an origin allowlist (B-H9/B-E10):
  `proxy_receive = true` + `proxy_allow = ["10.0.0.0/8", …]` turns the
  listener into a strict front door — non-allowlisted origins and
  malformed or timed-out headers are closed without a byte forwarded
  (`proxy_protocol_denied`, `proxy_protocol_invalid`). The claimed
  client address becomes the peer for logs, forwarded headers and
  outgoing PROXY.
- mTLS (A15): `client_ca` under `[listener.*.tls]` requires client
  certificates issued by that CA (verified E2E: no cert and foreign
  certs are rejected, the right cert round-trips).
- Forwarded headers (B-N4, first step): `forwarded_headers =
  "off" | "append" | "replace"` handles `X-Forwarded-For` /
  `X-Real-IP` on the forwarded copy of the head — `append` keeps the
  chain and grows it, `replace` drops spoofed hops. Off by default.
- Custom local responses (C9 minimal): `local_response` (status,
  content_type, body) serves the "no server available" class with the
  configured body; counted in `local_responses_served`.
- Hot certificates (D7): a reload now applies new TLS material on kept
  sockets (verified E2E: after rotation the old root fails and the new
  one works on the same socket), and the swap latency is measured and
  published (`cfg[… last_swap_us=N]`, PP-04/05 — measured, never
  assumed).
- `config explain` documents what each timeout does when it fires
  (Q4/H5/CE5): `timeout_on_fire` maps every phase to its client-visible
  outcome (408/502/504/close), plus the queue, retry and local-response
  policy of the backend.
- Soak harness (`scripts/soak.py`) with published budgets (BENCHMARK_PLAN
  §9): the real binary under sustained load with RSS/CPU sampled from
  `/proc`, and an honest verdict (no measurement, no PASS). The 24h gate
  itself passed on netcup-bench (2026-10-18): 17.28M requests, 0 errors,
  0 bad status, steady RSS 8.86 MiB (budget 64), peak 9.32 MiB (budget
  128), clean SIGINT shutdown (exit 0).

### Changed

- Keep-alive pool hardening (A16): before pooling, the connection is
  probed for EOF — a backend that closed (even without announcing
  `Connection: close`) is dropped instead of handed to the next
  exchange, which used to fail with 502 on its first write.
- Metrics snapshot rendering groups counters by failure origin
  (client/proxy/network/backend/phases; Q4/H5/CE5) with bounded
  cardinality (CE4: fixed counter set, no labels).

### Added (folded from the planned 0.4.6)

- Hot config reload (S-CFG-01): `kill -HUP` re-reads the config file and
  applies it to the running proxy. The candidate goes through the same
  gate as startup (parse + validate + resolve); a rejected one logs
  `config reload rejected` with the cause and the running config keeps
  serving (fail-closed). Accepted swaps match listeners by name: same
  name + address keeps the socket (no rejection window for new
  connections), missing addresses are bound before anything mutates
  (all-or-nothing), removed listeners stop, and established connections
  drain with the config they were accepted with. Counters never reset
  (PP-03) and the new `cfg[reloads=N reload_failures=N]` metrics group
  makes reloads alertable.

- Release automation (`.github/workflows/release.yml`): pushing a `v*`
  tag runs the exact `scripts/release.sh` stages on the runners that can
  execute them (macos-15 for darwin, ubuntu + containers for linux),
  E2E-verifies every artifact (real CLI journeys and live proxied
  traffic) before anything is published, then creates the GitHub release
  (binaries + SHA256SUMS + SBOM) and builds, verifies and pushes the
  multi-arch image to ghcr. `release.sh` gained stages (`darwin`, `linux`,
  `sbom`, `sums`, `verify-image`) so local runs and CI share one verified
  pipeline; the image artifact itself is verified (version, config gate
  and live proxied traffic through the container).

### Fixed

- Release-pipeline E2E backend no longer starts Python's `http.server`
  CLI: on Python 3.14 `HTTPServer.server_bind` resolves reverse DNS
  (`socket.getfqdn()`) between `bind()` and `listen()`, which hung on the
  macOS runners and left the probe bound but never listening. The
  verification backend is now a raw socket with zero name resolution,
  and the loopback wait in CI reports what actually blocked.

## [v0.4.5] — 2026-10-15

### Fixed

- HTTP/1.1 interim responses (1xx) no longer desync a keep-alive client or a
  pooled backend connection. Before, a `100`/`103` head from the backend was
  mistaken for the final response: the client saw the interim as its only
  answer and the real response stayed queued for the next exchange. Interim
  responses are now forwarded (RFC 9112 §6.2) and the loop keeps reading
  until the final message; a redundant backend `100` after the proxy's own
  is consumed exactly once. `101 Switching Protocols` is refused with 502
  (upgrade tunneling is unsupported) and 1xx floods are bounded (8 max).
- `Expect: 100-continue` deadlocked until the inactivity timeout: the client
  waited for an interim response that never came while the proxy waited for
  the body. The proxy now releases the client with a real `100 Continue`
  (RFC 9112 §10.1.2) once the request head has reached the backend.
- Unsupported `Expect` values are rejected explicitly with 417 instead of
  being silently forwarded (RFC 9112 §10.1.2). HTTP/1.0 requests ignore the
  `100-continue` expectation as the RFC requires.
- Malformed backend status lines (`HTTP/1.1 999 …`, `016`, …) are rejected
  with 502; status codes outside 100–599 were previously accepted.
- Backend bytes sent past the end of a response were silently discarded and
  the connection returned to the keep-alive pool, breaking the A16
  byte-alignment contract (the next exchange could consume the stale tail).
  The connection is now dropped instead of pooled, the bytes are never
  forwarded to the client, and the drop increments the new bounded
  `backend_connections_discarded` counter (metrics snapshot) so operators
  can alert on it (audit finding on the interim-response change; also
  reachable before it via `response_carry`).
- `100 Continue` is only generated when the request actually expects a body
  (a bodiless request with `Expect: 100-continue` gets no interim).
- Upstream failures are now diagnosable: invalid response heads, refused
  protocol switches (101) and interim floods log a WARN with listener,
  backend and peer (no secrets); pool drops are counted in the metrics
  (`backend_connections_discarded`).

## [v0.4.4] — 2026-10-15

### Added

- `eqproxy doctor [--config <file>]`: pre-flight environment diagnostics
  (Phase 3). With a config it gates exactly like `run`, then reports one
  `ok:`/`warn:`/`err:` line per check: a momentary TCP bind per listener
  (proves the port is free and permitted), the TLS state per listener
  (material already parsed by the gate), and the FD budget from SPEC §7.3
  and T07 (2 FDs per connection across all `maxconn` plus one per
  listener with 10 % margin, against the soft `NOFILE` limit; a short
  budget warns, never fails). Verdict line last (`doctor: PASS/FAIL` with
  counts); exit 0 unless the gate fails or any check errors. With no
  `--config`, environment only (FD limit + pointer to `--config`).
  Backend reachability is deliberately not probed: a down backend is not
  a config error, and dialing would pollute backends. New dependency:
  `rlimit` 0.10 (safe `NOFILE` reads; `unsafe` stays forbidden).

## [v0.4.3] — 2026-10-15

### Fixed

- `config apply` consumed `/dev/stdin` (or any pipe) on its first read
  and then failed gating on the empty second read. It now reads the
  candidate once and gates from those bytes (found by the Veyra audit's
  `apply-stores-first-configuration` scenario; no released file-based
  workflow was affected).
- Two Clippy lints in the new code (`collapsible_if` in history listing,
  `needless_borrow` in the SIGINT-shutdown test helper).

## [v0.4.2] — 2026-10-15

### Added

- `config apply` / `config rollback` (offline versioned state): `apply`
  gates the candidate exactly like `run` (load, validate, resolve; exit 1
  leaves the state untouched), pushes the previous `current.toml` to
  `history/` (capped at 32, oldest pruned) and installs the candidate via
  atomic rename; re-applying identical bytes is a no-op report.
  `rollback` re-gates the newest backup (relative cert paths resolve
  against the apply-time directory recorded in its header) and pops it
  into current, so walking back takes one rollback per apply. State lives
  in `./.eqproxy` (`EQPROXY_STATE_DIR` overrides it). Hot-apply to a
  running process stays pending (S-CFG-01).

### Changed

- Dependencies: `equivalent` 1.0.2 → 1.0.3 (transitive, semver-compatible).

## [v0.4.1] — 2026-10-15

### Added

- `config plan`: dry run of `run` — loads, validates and resolves (real
  certificate reads, address parsing, backend assembly), then reports the
  full activation inventory (listeners, timeouts, backends, servers)
  without binding or dialing. Exit 1 carries the same actionable errors
  `run` would fail with.

## [v0.4.0] — 2026-10-14

First distributable release: containers and binaries, English-only docs.

### Added

- Backend keep-alive pool (A16): per-server idle pool with a reuse-safety
  contract (clean exchanges only), reuse/dial counters.
- `config explain`: offline simulation of one routing decision (listener,
  backend, selected server with health state), no side effects (SPEC §8).
- `config diff`: offline comparison of two configurations (`+`/`-`/`~`
  vocabulary) for the pre-apply safety workflow.
- Official multi-arch container image (`docker/Dockerfile`, linux/amd64 +
  linux/arm64): locked release build, `debian:bookworm-slim` runtime as
  `nobody`, `ca-certificates` for `ca_file` against the system bundle.
- Reproducible release pipeline (`scripts/release.sh`): four binaries +
  SHA256SUMS + SBOM, every artifact E2E-verified before checksums are
  written.

### Changed

- **Documentation is English-only** from this release (code, messages,
  comments and all published docs). ADRs renamed to English slugs.

### Scope honesty

- This release is **not declared production ready** (Phase 9 gate pending):
  no hot config reload, no rollback, HTTP/1.1 + TCP only, no HTTP/2/3.
  The verified scope per phase is tracked in the maintainer's plan.

## [v0.3.0] — 2026-10-13

- Real HTTP/1.1 proxy with strict framing (smuggling rejected pre-backend),
  TLS termination and verified backend TLS, weighted round-robin, TCP health
  checks, PROXY v1 send, per-phase timeouts, framing fuzz corpus.

## [v0.2.0] — 2026-10-12

- Real minimal TCP proxy with validated TOML config, resource budgets,
  graceful shutdown, basic metrics.

## [v0.1.0] — 2026-10-12

- Research and architecture: SPEC, threat model, parity matrix, ADRs,
  benchmark plan.
