# Changelog — EQProxy

Language: **English**. Format follows "Keep a Changelog" (Added / Changed /
Fixed); versions are `vMAJOR.MINOR.PATCH` git tags.

## [Unreleased]

Nothing yet.

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
