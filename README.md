# ExyonQ Proxy (EQProxy)

Language: **English** · [Español](#español)

Reverse proxy and load balancer written in Rust, targeting progressive
functional parity with the reference proxy together with verifiable improvements in
diagnostics, configuration, administration, extensibility and security.

> **Status: Phase 2b (2026-10-13).** A real TCP and HTTP/1.1 proxy exists
> (crates `eqproxy-core/config/net/cli`): strict framing, per-phase timeouts,
> signal cancellation, **TLS termination and backend TLS (verification on by
> default), ALPN h1, weighted round-robin with TCP health checks and PROXY
> protocol v1 send**, typed TOML configuration with actionable errors and the
> `eqproxy` CLI, with 93 tests green (including E2E over real sockets and the
> real binary). No HTTP/2 yet. Release v0.2.0 published (binaries and
> multi-arch image). Performance: **not measured** — the only valid sentence
> about benchmarks is "Not measured".

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
  [ADR-0003](docs/adr/0003-referencia-multiversion.md).
- **Production platform:** Linux x86_64 (glibc). See
  [ADR-0001](docs/adr/0001-plataforma-produccion.md).
- **Configuration format:** study in
  [ADR-0002](docs/adr/0002-formato-configuracion.md), decision pending approval.
- **Network stack:** tokio + hyper 1.x + rustls; **HTTP/3 is mandatory scope**
  (Phase 5, experimental until interop is passed). See
  [ADR-0004](docs/adr/0004-stack-red-y-layout-crates.md).
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

---

# Español

Idioma: [English](#exyonq-proxy-eqproxy) · **Español**

Proxy inverso y balanceador de carga escrito en Rust, con objetivo de paridad
funcional progresiva frente al proxy de referencia y mejoras verificables en
diagnóstico,
configuración, administración, extensibilidad y seguridad.

> **Estado: Fase 2b (2026-10-13).** Existe un proxy TCP y HTTP/1.1 real
> (crates `eqproxy-core/config/net/cli`): framing estricto, timeouts por fase,
> cancelación por señal, **TLS termination y TLS a backends (verificación
> activada por defecto), ALPN h1, roundrobin ponderado con health checks TCP y
> envío de PROXY protocol v1**, configuración TOML tipada con errores
> accionables y CLI `eqproxy`, con 93 tests en verde (incl. E2E con sockets
> reales y el binario real). Sin HTTP/2 aún. Release v0.2.0 publicada
> (binarios e imagen multi-arquitectura). Rendimiento: **no medido** — la
> única frase válida sobre benchmarks es «No medido».

## Uso rápido

```bash
cargo run -p eqproxy-cli -- config validate --config eqproxy.toml.example
cargo run -p eqproxy-cli -- run --config eqproxy.toml.example
```

## Documentación

| Documento | Contenido |
|---|---|
| [SPEC.md](SPEC.md) | Especificación: objetivos, prioridades, arquitectura, taxonomía de estados |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Modelo de amenazas y declaración de no-protecciones |
| [ROADMAP.md](ROADMAP.md) | Fases 0–9 con criterios de salida verificables |
| [BENCHMARK_PLAN.md](BENCHMARK_PLAN.md) | Plan de benchmarks honestos y estudio de tareas operativas |
| [docs/adr/](docs/adr/) | Registros de decisiones de arquitectura |

## Decisiones clave

- **Referencia de comparación:** versiones 3.4.6 LTS (primaria) y 3.0.29 LTS
  (legacy desplegada) del proxy de referencia. Ver
  [ADR-0003](docs/adr/0003-referencia-multiversion.md).
- **Plataforma de producción:** Linux x86_64 (glibc). Ver [ADR-0001](docs/adr/0001-plataforma-produccion.md).
- **Formato de configuración:** estudio en [ADR-0002](docs/adr/0002-formato-configuracion.md),
  decisión pendiente de aprobación.
- **Stack de red:** tokio + hyper 1.x + rustls; **HTTP/3 es alcance obligatorio**
  (Fase 5, experimental hasta superar interoperación). Ver [ADR-0004](docs/adr/0004-stack-red-y-layout-crates.md).
- **Objetivo de rendimiento:** igualar o superar al proxy de referencia 3.4.6
  LTS en
  conexiones, memoria, CPU y latencias P50/P95/P99 en los escenarios de
  [BENCHMARK_PLAN.md](BENCHMARK_PLAN.md). Objetivo, no resultado: sin
  mediciones aún.
- **Código:** 100 % safe Rust (`#![forbid(unsafe_code)]`, sin excepciones);
  extensiones solo WASM (Lua descartado por FFI `unsafe`).
- **Alcance de paridad:** solo la edición OSS del proxy de referencia.
- **Migración:** conversor de configuración del proxy de referencia → EQProxy
  (CLI `eqproxy config import`) con parser propio del formato de configuración
  de referencia e informe de conversión; nunca se omiten directivas en silencio.

## Licencia

Dual: [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE), a elección del receptor.
