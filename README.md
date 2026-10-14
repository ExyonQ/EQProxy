# ExyonQ Proxy (EQProxy)

Language: **English**.

Reverse proxy and load balancer written in Rust, targeting progressive
functional parity with the reference proxy together with verifiable improvements in
diagnostics, configuration, administration, extensibility and security.

> **Status: Phase 2c (2026-10-14).** A real TCP and HTTP/1.1 proxy exists
> (crates `eqproxy-core/config/net/cli`): strict framing, per-phase timeouts,
> signal cancellation, **TLS termination and backend TLS (verification on by
> default), ALPN h1, weighted round-robin with TCP health checks and PROXY
> protocol v1 send**, typed TOML configuration with actionable errors and the
> `eqproxy` CLI, with 96 tests green (including E2E over real sockets, the
> real binary, and a framing fuzz corpus). No HTTP/2 yet. Release v0.3.0
> published (binaries and multi-arch image). Performance (first runs vs
> 3.4.6, [evidence](docs/evidence/phase2c/bench.md)): after the A16 backend
> keep-alive pool landed, S-TCP-01, S-H1-01 and S-TLS-01 measure
> **Comparable** (zero non-2xx; tails comparable, H1/TLS at or below the
> reference).

> **Docs language:** from v0.3.0, documentation is published in English only.
> Frozen Spanish sections below are kept as of v0.2.0 and are not updated.

## Quick start

```bash
cargo run -p eqproxy-cli -- config validate --config eqproxy.toml.example
cargo run -p eqproxy-cli -- run --config eqproxy.toml.example
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
