# ExyonQ Proxy (EQProxy)

Proxy inverso y balanceador de carga escrito en Rust, con objetivo de paridad
funcional progresiva frente a ref y mejoras verificables en diagnóstico,
configuración, administración, extensibilidad y seguridad.

> **Estado actual: Fase 1 completada (2026-10-12).** Existe un proxy TCP real
> (crates `eqproxy-core/config/net/cli`), configuración TOML tipada con errores
> accionables y CLI `eqproxy`, con 30 tests en verde (incl. E2E con sockets
> reales y el binario real). Sin TLS/HTTP aún (Fase 2). Rendimiento: **no
> medido** — la única frase válida sobre benchmarks es «No medido».

## Uso rápido

```bash
cargo run -p eqproxy-cli -- config validate --config eqproxy.toml.example
cargo run -p eqproxy-cli -- run --config eqproxy.toml.example
```

## Documentación

| Documento | Contenido |
|---|---|
| [SPEC.md](SPEC.md) | Especificación: objetivos, prioridades, arquitectura, taxonomía de estados |
| [PARITY_MATRIX.md](PARITY_MATRIX.md) | Matriz de paridad frente a ref 3.4 LTS + 3.0 LTS |
| [USER_PAIN_POINTS.md](USER_PAIN_POINTS.md) | Dolores de usuario documentados y requisitos derivados |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Modelo de amenazas y declaración de no-protecciones |
| [ROADMAP.md](ROADMAP.md) | Fases 0–9 con criterios de salida verificables |
| [BENCHMARK_PLAN.md](BENCHMARK_PLAN.md) | Plan de benchmarks honestos y estudio de tareas operativas |
| [docs/adr/](docs/adr/) | Registros de decisiones de arquitectura |

## Decisiones clave

- **Referencia de comparación:** ref 3.4.6 LTS (primaria) + 3.0.29 LTS
  (legacy desplegada). Ver [ADR-0003](docs/adr/0003-referencia-multiversion.md).
- **Plataforma de producción:** Linux x86_64 (glibc). Ver [ADR-0001](docs/adr/0001-plataforma-produccion.md).
- **Formato de configuración:** estudio en [ADR-0002](docs/adr/0002-formato-configuracion.md),
  decisión pendiente de aprobación.
- **Stack de red:** tokio + hyper 1.x + rustls; **HTTP/3 es alcance obligatorio**
  (Fase 5, experimental hasta superar interoperación). Ver [ADR-0004](docs/adr/0004-stack-red-y-layout-crates.md).
- **Objetivo de rendimiento:** igualar o superar a ref 3.4.6 LTS en RPS,
  conexiones, memoria, CPU y latencias P50/P95/P99 en los escenarios de
  [BENCHMARK_PLAN.md](BENCHMARK_PLAN.md). Objetivo, no resultado: sin
  mediciones aún.
- **Código:** 100 % safe Rust (`#![forbid(unsafe_code)]`, sin excepciones);
  extensiones solo WASM (Lua descartado por FFI `unsafe`).
- **Alcance de paridad:** solo ref OSS; Enterprise y ref One excluidos
  ([PARITY_MATRIX.md](PARITY_MATRIX.md) §E).
- **Migración:** conversor de configuración ref → EQProxy (CLI `eqproxy
  config import ref`) con parser propio de `config-de-referencia` e informe de
  conversión; nunca se omiten directivas en silencio.

## Licencia

Dual: [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE), a elección del receptor.
