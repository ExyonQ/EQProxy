# ExyonQ Proxy (EQProxy)

Language: **English**.

Reverse proxy and load balancer written in Rust, targeting progressive
functional parity with the reference proxy together with verifiable improvements in
diagnostics, configuration, administration, extensibility and security.

> **Status: v0.6.3 (2026-10-21) — patch over v0.6.2: the config gate rejects
> ALPN h2/h2c where the HTTP/1.1 dataplane cannot serve it, and the image can
> run `config apply`/`rollback` (writable state directory).** A real TCP and HTTP/1.1 proxy (crates
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
> offline `apply`/`rollback`, `doctor`), with **368 tests**
> green plus two Docker-gated harnesses run before the release:
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
> (never after processing).
> (unreleased, on top of v0.6.3: [ADR-0006](docs/adr/0006-http2-termination.md),
> [ADR-0007](docs/adr/0007-http2-backend.md),
> [ADR-0008](docs/adr/0008-http2-backend-multiplexing.md),
> [ADR-0009](docs/adr/0009-http2-session-lifecycle.md), evidence
> [v07-http2](docs/evidence/v07-http2.md),
> [v07-http2-backend](docs/evidence/v07-http2-backend.md),
> [v07-http2-multiplexing](docs/evidence/v07-http2-multiplexing.md) and
> [v07-http2-session-lifecycle](docs/evidence/v07-http2-session-lifecycle.md)); gRPC
> end to end and HTTP/3 (QUIC) remain v0.7 work. Release v0.6.3 (binaries for darwin/linux amd64+arm64 and multi-arch
> image, see Install). Performance vs 3.4.6 on netcup-bench (amd64, medians
> of 5, [evidence](docs/evidence/v06-bench/)): S-H1-04 (10 listeners, 100
> backends, 20 rules) **18 207 vs 15 957 rps** (p95 4.45 vs 5.92 ms),
> S-H1-05 (500 backends + health checks) **15 624 vs 3 466 rps** (p95 5.16
> vs 31.4 ms); the arm64 campaign
> ([evidence](docs/evidence/v06-bench-arm64/)) leads in both scenarios with
> S-H1-04 gaps within noise.
>
> **Scope honesty:** v0.6.3 is not declared production ready (Phase 9 gate
> pending). The whole v0.6 roadmap is delivered (32/32 scope boxes, 6/6
> version-gate criteria); what remains is outside this version by design
> and listed in the [CHANGELOG](CHANGELOG.md): the reference filters that
> only exist as WASM (v0.9, so ecosystem extension stays WASM-only), maps
> consumed through `equals` matching only, and HTTP/2 (termination and
> upstream h2 landed on main after v0.6.3; gRPC and QUIC are still ahead).
> The 24h soak gate **passed** on
> netcup-bench (2026-10-18: 17.28M requests, 0 errors, steady RSS
> 8.86 MiB / peak 9.32 MiB, clean SIGINT shutdown; budgets in
> [BENCHMARK_PLAN.md](BENCHMARK_PLAN.md) §9).

> **Docs language:** documentation is published in English only.

## Quick start

```bash
cargo run -p eqproxy-cli -- config validate --config eqproxy.toml.example
cargo run -p eqproxy-cli -- run --config eqproxy.toml.example
```

## Install from release v0.6.3

Binaries and checksums live on the
[release page](https://github.com/ExyonQ/EQProxy/releases/tag/v0.6.3).

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
curl -sSLO https://github.com/ExyonQ/EQProxy/releases/download/v0.6.3/eqproxy-linux-amd64
curl -sSLO https://github.com/ExyonQ/EQProxy/releases/download/v0.6.3/SHA256SUMS.txt
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

Docker (linux/amd64 + linux/arm64), same digests on both registries:

```bash
docker pull exyonq/eqproxy:0.6.3           # Docker Hub (docs + examples on the repo page)
docker pull ghcr.io/exyonq/eqproxy:0.6.3   # GitHub Container Registry
docker run --rm exyonq/eqproxy:0.6.3 --version
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

## Key decisions

- **Comparison reference:** versions 3.4.6 LTS (primary) + 3.0.29 LTS (legacy
  deployed) of the reference proxy. See
  [ADR-0003](docs/adr/0003-multiversion-reference.md).
- **Production platform:** Linux x86_64 (glibc). See
  [ADR-0001](docs/adr/0001-production-platform.md).
- **Configuration format:** study in
  [ADR-0002](docs/adr/0002-configuration-format.md), decision pending approval.
- **Network stack:** tokio + hyper 1.x + rustls; **HTTP/3 is mandatory scope**
  (Phase 5, experimental until interop is passed). See
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
