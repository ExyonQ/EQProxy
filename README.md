# ExyonQ Proxy (EQProxy)

Language: **English**.

Reverse proxy and load balancer written in Rust, targeting progressive
functional parity with the reference proxy together with verifiable improvements in
diagnostics, configuration, administration, extensibility and security.

> **Status: v0.8.5 (2026-10-31) — extensions, conversion and no debt in the
> 0.8.x line: request-filter plugins as WASM with deny-by-default capabilities
> (no WASI, no network, no filesystem to grant), a per-listener HTTP response
> cache with `Vary`, ETag/304 revalidation and cache-lock, per-listener message
> limits and stream buffers, hot TLS secrets in both directions, per-server
> `maxconn`, and the official `eqproxy config import` converter for nginx,
> HAProxy, ingress-nginx and Envoy — plus the v0.8 administration HTTP API with
> roles, audit and a server-rendered web panel, hot configuration without a
> control plane, per-server failover (`priority` ladders, `allbackups` pools,
> `drain`/`maintenance`) and opt-in metrics, each with published raw
> evidence.**
> A real TCP and HTTP/1.1 proxy (crates
> `eqproxy-core/config/net/cli`) with **typed routing rules per listener** —
> host/path/method/header/cookie/map/IP
> conditions, first match wins — and four rule actions: `use_backend`,
> `split` (weighted canary with `weight = 0` rollback, optionally pinned by
> `hash_policy` so a key keeps its target, and optionally **mirrored** to a
> shadow backend), `redirect` and `direct_response`. On top of the v0.5 dataplane (strict framing,
> per-phase timeouts, **TLS termination and backend TLS, ALPN h1, mTLS,
> multi-certificate SNI**, **active TCP/HTTP health checks, passive failure detection, safe
> idempotent retries, bounded queues, PROXY protocol v1/v2,
> hot config + certificate reload under traffic**, backend keep-alive pool):
> **set/add/del request headers and response headers with `$remote_addr`/
> `$host`/`$scheme` templates, weighted round-robin + leastconn + slow
> start, source/cookie affinity, non-blocking dynamic DNS, canary by
> header/cookie/weight, hot data maps updated without a config reload,
> per-rule rate limiting, CORS/HSTS, basic + subrequest authentication,
> WebSocket/`CONNECT` tunnels, `max_stream_duration`**, certificates selected
> by SNI (exact name, then wildcard, then the listener default), and the `eqproxy`
> CLI (`validate`, `explain` with per-rule trace and `timeout_on_fire`,
> `schema` — the public JSON Schema for editor completion, `diff`, `plan`,
> offline `apply`/`rollback`, `doctor`), backup server tiers (`backup = true`)
> with a `priority` failover ladder and optional backup pooling
> (`all_backups = true`, HAProxy's `option allbackups`), and an
> **administration plane of its own**
> ([ADR-0017](docs/adr/0017-read-only-admin-plane.md)): a bearer-gated
> `GET /api/v1/status` + `GET /metrics`, hot backend/listener writes under
> `If-Match` ([ADR-0019](docs/adr/0019-hot-config-writes-via-admin-api.md)),
> per-server `drain`/`maintenance`
> ([ADR-0018](docs/adr/0018-first-write-path-server-state.md),
> [ADR-0028](docs/adr/0028-maintenance-closes-the-idle-pool.md)), certificate
> renewal without a restart
> ([ADR-0025](docs/adr/0025-certificate-renewal-without-restart.md)) and an
> **opt-in server-rendered panel** with bearer sessions, a per-session CSRF
> token and a write audit line, no JavaScript
> ([ADR-0029](docs/adr/0029-panel-sessions-and-csrf.md)), with **559 tests**
> across 30 targets green on the tier-1 platform (558 on macOS, where one
> test is Linux-only; `cargo test --workspace`, 2026-10-27) plus two Docker-gated
> harnesses (evidence from the v0.6 gate, not re-run since):
> [differential corpus](docs/differential-corpus.md) **23/23** cases against
> HAProxy 3.4.6, nginx, the ingress-nginx data plane and static Envoy
> v1.34.2, and the [migration matrix](docs/migration/README.md) **65/65
> checks** (four real source configs and their `eqproxy.toml` translation
> routing identically; evidence in
> [docs/evidence/v06-migration/](docs/evidence/v06-migration/)). HTTP/2 is
> terminated on client listeners and — when the backend TLS handshake
> negotiates `h2` (`[backend.X.tls] alpn = ["h2"]`) — spoken to the backend
> too, with **one session per backend server shared by concurrent
> exchanges**, so an h2 client reaches an h2 origin through real HTTP/2 on
> both sides and concurrent requests multiplex instead of queueing. Sessions
> close when idle, a `GOAWAY` drains their in-flight streams, and a stream
> the peer refused before processing is replayed once on a fresh session
> (never after processing). **gRPC streams are relayed end to end**: both
> directions stay open at once, `grpc-status` travels in trailers, routing,
> auth and header rules apply through the same decision path, and
> `idle_timeout`/`max_stream_duration` cut a stream explicitly instead of
> hanging it. **WebSockets over HTTP/2** use an RFC 8441 extended CONNECT
> (`:protocol = websocket`): the proxy translates the stream into the real
> h1 handshake (with its own `Sec-WebSocket-Key`), answers the h2 client with
> `200` (never `101`, and never the internal `Sec-WebSocket-Accept`) and
> relays bytes with flow control as the only buffer; routing, auth and header
> rules apply through the same h1 decision path, a refused upgrade is relayed
> as a normal response, and a silent tunnel is cut by `idle_timeout`.
> **HTTP/3 over QUIC** is served by a listener with `quic = true` and TLS, on
> the same `IP:PORT` over UDP (TLS 1.3, ALPN `h3`, same certificate/SNI/mTLS);
> each h3 request becomes one h1 exchange through the same engine, so routing,
> auth, limits, header actions, mirroring, retries and compression decide
> exactly once. Request bodies without a length stream upstream as chunked,
> trailers cross in both directions, `CONNECT` answers `501`, QUIC connections
> count in `maxconn`, and a TLS change on a live QUIC endpoint needs a restart
> (the reload is rejected, never half-applied). Verified with a real `h3`
> client and with two independent implementations, `aioquic` 1.2.0 and
> `quic-go` 0.64.1, through the release binary.
> Responses can be **gzip- or Brotli-compressed**
> per listener when the client accepts it (streamed, never buffered,
> negotiated from `Accept-Encoding`; wire bytes for both codings published in
> [the raw benchmark](docs/evidence/v07-compression/bench.md)). Request bodies
> are **never decompressed**: a client's `Content-Encoding` is forwarded
> untouched, so there is no decompression surface for a zip bomb
> ([THREAT_MODEL](THREAT_MODEL.md) T09).
> (design in [ADR-0006](docs/adr/0006-http2-termination.md),
> [ADR-0007](docs/adr/0007-http2-backend.md),
> [ADR-0008](docs/adr/0008-http2-backend-multiplexing.md),
> [ADR-0009](docs/adr/0009-http2-session-lifecycle.md),
> [ADR-0010](docs/adr/0010-response-compression.md), evidence
> [v07-http2](docs/evidence/v07-http2.md),
> [v07-http2-backend](docs/evidence/v07-http2-backend.md),
> [v07-http2-multiplexing](docs/evidence/v07-http2-multiplexing.md),
> [v07-http2-session-lifecycle](docs/evidence/v07-http2-session-lifecycle.md),
> [v07-compression](docs/evidence/v07-compression.md),
> [v07-grpc](docs/evidence/v07-grpc.md),
> [v07-ws](docs/evidence/v07-ws.md) and
> [v07-http3](docs/evidence/v07-http3.md), with the soak in
> [v07-grpc-soak-24h](docs/evidence/v07-grpc-soak-24h.md); [ADR-0011](docs/adr/0011-grpc-http2-passthrough.md)
> covers gRPC, [ADR-0012](docs/adr/0012-websockets-over-h2.md) covers
> WebSockets over h2 and [ADR-0013](docs/adr/0013-http3-quic.md) covers
> HTTP/3 over QUIC).
> The v0.8 administration surface has its own pages:
> [authorization matrix](docs/evidence/v08-endpoint-authorization.md),
> [hot configuration](docs/evidence/v08-admin-config-hot-apply.md),
> [panel](docs/evidence/v08-panel.md),
> [maintenance window](docs/evidence/v08-maintenance.md),
> [priority ladder](docs/evidence/v08-priority.md) and
> [backup pool](docs/evidence/v08-allbackups.md).
> Release v0.8.5 (tag `v0.8.5`, release run 41165822327 green on all six
> jobs, image index `sha256:bf1a06cd…` scanned 0 critical / 0 high on both
> architectures and promoted unchanged to `:0.8.5` and `:latest` on GHCR and
> Docker Hub — [artifact gate](docs/evidence/v085-published.md); binaries for
> darwin/linux amd64+arm64 and multi-arch image, see Install). Performance vs 3.4.6 on netcup-bench (amd64, medians
> of 5): the v0.6 HTTP/1.1 scenarios S-H1-04 (10 listeners, 100 backends,
> 20 rules) **18 207 vs 15 957 rps** (p95 4.45 vs 5.92 ms) and S-H1-05
> (500 backends + health checks) **15 624 vs 3 466 rps** (p95 5.16 vs
> 31.4 ms) ([evidence](docs/evidence/v06-bench/)), with the arm64 campaign
> ([evidence](docs/evidence/v06-bench-arm64/)) leading in both and S-H1-04
> gaps within noise. The v0.7 gate scenarios, with h2/h3 active on both
> sides, are published including the losses: S-H2-02 **1.081×** (Better),
> S-H2-01 **0.742×** (Worse, up from 0.099× once the pool stopped churning),
> and with HTTP/3 active S-H3-01 **0.668×** and S-H3-02 **0.768×**, both
> Worse ([pool sizing](docs/evidence/v07-h2-pool-sizing.md),
> [offload](docs/evidence/v07-h3-profile.md),
> [close fix](docs/evidence/v07-h3-close.md)).
>
> **Scope honesty:** v0.8.5 is not declared production ready (Phase 9 gate
> pending). Its own gate is met: 22/22 boxes of the v0.8.5 roadmap, including
> the artifact gate — tag == `Cargo.toml`, every binary and both image
> architectures built with `1.99.1`, the scanned digest promoted unchanged, and
> the published image re-pulled and replayed
> ([published](docs/evidence/v085-published.md)). It keeps the v0.8
> administration guarantees: the route×role authorization matrix with the
> dataplane serving when the admin task dies, a backend applied under traffic
> in under a second, and the metrics budget refusing what exceeds it. The
> latest 24-hour soak remains
> the v0.7 gRPC bidi run **PASS** (2026-10-23: 86 400 s, 4 267 messages, 0 broken
> streams, 0 failed probes), and HTTP/3 interop with two independent clients
> (`aioquic` 1.2.0 and `quic-go` 0.64.1) is unchanged. HTTP/3 stays **experimental**:
> browsers and `curl` over h3 are unverified and the QUIC adversarial tests
> of THREAT_MODEL T19 are not executed. Outside this version by design and
> listed in the [CHANGELOG](CHANGELOG.md): FastCGI, uwsgi and scgi
> ([ADR-0032](docs/adr/0032-fastcgi-uwsgi-scgi-decision.md)), the cache's
> `stale-while-revalidate` / `stale-if-error`
> ([ADR-0034](docs/adr/0034-http-response-cache.md)), and maps consumed through
> `equals` matching only.
> The v0.6 24h soak gate **passed** on
> netcup-bench (2026-10-18: 17.28M requests, 0 errors, steady RSS
> 8.86 MiB / peak 9.32 MiB, clean SIGINT shutdown; budgets in
> [BENCHMARK_PLAN.md](BENCHMARK_PLAN.md) §9).

> **Docs language:** documentation is published in English only.

## Quick start

```bash
cargo run -p eqproxy-cli -- config validate --config eqproxy.toml.example
cargo run -p eqproxy-cli -- run --config eqproxy.toml.example
```

## Install from release v0.8.5

Binaries and checksums live on the
[release page](https://github.com/ExyonQ/EQProxy/releases/tag/v0.8.5).

Every release carries **four prebuilt binaries**: `eqproxy-darwin-arm64`,
`eqproxy-darwin-amd64`, `eqproxy-linux-arm64` and `eqproxy-linux-amd64`. The
Linux ones are **statically linked against musl** (`file` reports `static-pie
linked` on amd64 and `statically linked` on arm64, no `NEEDED` entries, no
interpreter), so they need no libc, no glibc version and no packages at all:
they run on any Linux distribution of that architecture, and also on
`FROM scratch`. Each release ships the Docker Scout report of both image
architectures (`SCOUT-<version>-linux-amd64.md`, `…-arm64.md`) and the
matching sources as `eqproxy-<version>-src.tar.gz` (the tagged tree, exported
with `git archive`), whose digest is a line in the same `SHA256SUMS.txt`.
Building from them is `cargo build --release --locked` with nothing else.

```bash
# Pick your platform artifact:
#   eqproxy-darwin-arm64 | eqproxy-darwin-amd64
#   eqproxy-linux-arm64  | eqproxy-linux-amd64   (static, musl)
curl -sSLO https://github.com/ExyonQ/EQProxy/releases/download/v0.8.5/eqproxy-linux-amd64
curl -sSLO https://github.com/ExyonQ/EQProxy/releases/download/v0.8.5/SHA256SUMS.txt
shasum -a 256 -c SHA256SUMS.txt --ignore-missing   # Linux: sha256sum -c --ignore-missing SHA256SUMS.txt
chmod +x eqproxy-linux-amd64
./eqproxy-linux-amd64 --version

# Smoke test with a minimal config (validate is offline, binds nothing):
cat > eqproxy.toml <<'EOF'
schema_version = 1
[listener.web]
listen = "127.0.0.1:8080"
mode = "http"
backend = "api"
[backend.api]
server = "127.0.0.1:9000"
EOF
./eqproxy-linux-amd64 config validate --config eqproxy.toml
```

Docker (linux/amd64 + linux/arm64, Wolfi base), same digests on both registries:

```bash
docker pull exyonq/eqproxy:0.8.5           # Docker Hub (docs + examples on the repo page)
docker pull ghcr.io/exyonq/eqproxy:0.8.5   # GitHub Container Registry
docker run --rm exyonq/eqproxy:0.8.5 --version
```

## Documentation

| Document | Contents |
|---|---|
| [SPEC.md](SPEC.md) | Specification: goals, priorities, architecture, state taxonomy |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Threat model and non-protections statement |
| [BENCHMARK_PLAN.md](BENCHMARK_PLAN.md) | Honest benchmark plan and operator-task study |
| [docs/differential-corpus.md](docs/differential-corpus.md) | Declared shared-semantics corpus vs HAProxy, nginx, ingress-nginx and Envoy |
| [docs/migration/README.md](docs/migration/README.md) | Migration matrix: the same deployment in the four source formats and in EQProxy |
| [docs/adr/](docs/adr/) | Architecture decision records |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to build, test, document and submit a change, including the audit stack a change must pass |

## Key decisions

- **Comparison reference:** versions 3.4.6 LTS (primary) + 3.0.29 LTS (legacy
  deployed) of the reference proxy. See
  [ADR-0003](docs/adr/0003-multiversion-reference.md).
- **Production platform:** Linux x86_64 (glibc). See
  [ADR-0001](docs/adr/0001-production-platform.md).
- **Configuration format:** study in
  [ADR-0002](docs/adr/0002-configuration-format.md), decision pending approval.
- **Network stack:** tokio + hyper 1.x + rustls, and quinn + h3 for HTTP/3;
  **HTTP/3 is mandatory scope** (Phase 5; two-client interop passed on
  2026-10-23, still experimental pending the QUIC adversarial tests). See
  [ADR-0004](docs/adr/0004-network-stack-and-crate-layout.md).
- **Performance goal:** match or beat the reference proxy 3.4.6 LTS on
  connections, memory,
  CPU and P50/P95/P99 latencies in the scenarios of
  [BENCHMARK_PLAN.md](BENCHMARK_PLAN.md). First measurements
  (S-TCP-01/S-H1-01/S-TLS-01, [evidence](docs/evidence/phase2c/bench.md)):
  **Comparable** after the A16 keep-alive pool; the rest of the matrix is
  **Not measured** (no data, no claim).
- **Code:** 100 % safe Rust (`#![forbid(unsafe_code)]`, no exceptions);
  extensions WASM-only (Lua discarded due to FFI `unsafe`).
- **Parity scope:** the OSS edition of the reference proxy only.
- **Migration:** configuration converter from the reference proxy to EQProxy
  (CLI `eqproxy config import`) with its own parser for the reference
  configuration format and a conversion report; directives are never silently
  dropped.

## License

Dual: [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE), at the recipient's
choice.
