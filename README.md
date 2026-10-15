# ExyonQ Proxy (EQProxy)

Language: **English**.

Reverse proxy and load balancer written in Rust, targeting progressive
functional parity with the reference proxy together with verifiable improvements in
diagnostics, configuration, administration, extensibility and security.

> **Status: Phase 3 (2026-10-15).** A real TCP and HTTP/1.1 proxy exists
> (crates `eqproxy-core/config/net/cli`): strict framing, per-phase timeouts,
> signal cancellation, **TLS termination and backend TLS (verification on by
> default), ALPN h1, weighted round-robin with TCP health checks and PROXY
> protocol v1 send**, backend keep-alive pool, typed TOML configuration with
> actionable errors and the `eqproxy` CLI (`validate`, `explain`, `diff`,
> `plan` dry run, offline `apply`/`rollback` with versioned state), with
> 129 tests green (including E2E over real sockets,
> the real binary, and a framing fuzz corpus). No HTTP/2 yet. Release v0.4.1
> published (binaries and multi-arch image, see Install). Performance (first runs vs
> 3.4.6, [evidence](docs/evidence/phase2c/bench.md)): after the A16 backend
> keep-alive pool landed, S-TCP-01, S-H1-01 and S-TLS-01 measure
> **Comparable** (zero non-2xx; tails comparable, H1/TLS at or below the
> reference).
>
> **Scope honesty:** v0.4.1 is not declared production ready (Phase 9 gate
> pending): TCP + HTTP/1.1 only; `apply`/`rollback` manage versioned files
> offline, hot config reload under traffic stays pending (S-CFG-01).

> **Docs language:** documentation is published in English only.

## Quick start

```bash
cargo run -p eqproxy-cli -- config validate --config eqproxy.toml.example
cargo run -p eqproxy-cli -- run --config eqproxy.toml.example
```

## Install from release v0.4.1

Binaries and checksums live on the
[release page](https://github.com/ExyonQ/EQProxy/releases/tag/v0.4.1).

```bash
# Pick your platform artifact:
#   eqproxy-darwin-arm64 | eqproxy-darwin-amd64
#   eqproxy-linux-arm64  | eqproxy-linux-amd64
curl -sSLO https://github.com/ExyonQ/EQProxy/releases/download/v0.4.1/eqproxy-linux-amd64
curl -sSLO https://github.com/ExyonQ/EQProxy/releases/download/v0.4.1/SHA256SUMS.txt
shasum -a 256 -c SHA256SUMS.txt --ignore-missing
chmod +x eqproxy-linux-amd64
./eqproxy-linux-amd64 config validate --config eqproxy.toml.example
```

Docker (linux/amd64 + linux/arm64):

```bash
docker pull ghcr.io/exyonq/eqproxy:0.4.1
docker run --rm ghcr.io/exyonq/eqproxy:0.4.1 --version
```

## Documentation

| Document | Contents |
|---|---|
| [SPEC.md](SPEC.md) | Specification: goals, priorities, architecture, state taxonomy |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Threat model and non-protections statement |
| [ROADMAP.md](ROADMAP.md) | Phases 0–9 with verifiable exit criteria |
| [BENCHMARK_PLAN.md](BENCHMARK_PLAN.md) | Honest benchmark plan and operator-task study |
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
  [BENCHMARK_PLAN.md](BENCHMARK_PLAN.md). Goal, not result: no measurements yet.
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
