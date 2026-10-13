# ADR-0004: Network stack and crate layout

Language: **English** · [Español](#español)

- State: **Accepted for Phases 0–2** (mandatory review when Phase 5 opens)
- Date: 2026-10-12
- Related: [SPEC.md](../../SPEC.md) §Architecture, [ROADMAP.md](../../ROADMAP.md)

## Context

The brief (section 5) proposes a modular workspace of up to 14 crates, but
requires merging modules if splitting crates introduces complexity without
benefit, and forbids assuming a library solves proxy semantics. Stack and
layout must be chosen attending to maintenance, licenses, security and
operational cost (researched in Phase 0, Oct-2026).

## Decision: stack

| Layer | Choice | Researched version | License | Justification / known limit |
|---|---|---|---|---|
| Runtime | tokio | 1.53.2 (2026-09-30) | MIT | Declared LTS until 2027 (1.51/1.53 lines). MSRV 1.85. |
| HTTP/1–2 | hyper | 1.12.0 | MIT | Low-level client/server; **it is not a proxy**: pooling, timeouts and backpressure are our responsibility. No integrated HTTP/3. |
| Bodies | http-body / http-body-util | 1.1.0 / 0.1.5 | MIT | Streaming abstraction; size limits are enforced in our layer. |
| TLS | rustls + `aws-lc-rs` | 0.23.45 (2026-09-14) | Apache-2.0 OR MIT OR ISC | No own cryptography. FIPS only at the validated AWS-LC module level, not automatic. Explicit client certificate verification (mTLS); never disable hostname validation. |
| TLS adapter | tokio-rustls | 0.26.5 | MIT OR Apache-2.0 | Active; `tokio-openssl` only if a concrete need demands it (no releases since 2024-09). |
| Sockets | socket2 | 0.6.5 | MIT OR Apache-2.0 | `SO_REUSEPORT`, keepalive, `TCP_NODELAY`, pre-bind options. `SO_REUSEPORT` is not a portable load-balancing guarantee (stated in docs). |
| QUIC/H3 | quinn + `h3`/`h3-quinn` | quinn 0.11.12; h3-quinn 0.0.10 | MIT OR Apache-2.0 | **HTTP/3 is a product requirement (user decision, 2026-10-12)**. Implemented in Phase 5 with quinn + `h3`, labelled experimental until it passes interoperability tests: `h3` declares itself "still very experimental" in its repo and hyper exposes no H3 API, so the integration and hardening cost is high and explicitly assumed. |
| DNS | hickory-dns (stub resolver) | 0.26.3 | Apache-2.0 OR MIT | Stub role validated by Prossimo; the recursive role is not used. DNS discovery in Phase 4. |
| Config | serde + toml + serde_path_to_error (+ schemars) | 1.0.x | MIT OR Apache-2.0 | See ADR-0002. Own semantic validation separate. |
| Observability | tracing + tracing-subscriber; `metrics` or `prometheus-client` (pick one, not both) | tracing 0.1.44 | MIT OR Apache-2.0 | Metric cardinality bounded by design. The exporter's exact version is pinned in Cargo.lock (still unverified). |
| Plugins (Phase 7) | wasmtime (fuel/epoch + limiters) | 49.0.2 | Apache-2.0 | **Single plugin route** (user decision, 2026-10-12: 100 % safe code). Lua/mlua is **discarded** (C FFI with substantial `unsafe`); future Lua compatibility only in an isolated process and with a new ADR. |
| Testing | cargo-fuzz/libFuzzer + proptest | (pin in Phase 1) | — | Fuzzing of own parsers, config and rules. |

**Cross-cutting rule:** no "latest" version is left unpinned in `Cargo.lock`
and unaudited (`cargo deny`/equivalent) at implementation time. The versions in
this table are the researched state of Oct-2026.

**Code rule (user decision, 2026-10-12):** all our own Rust code is safe —
`#![forbid(unsafe_code)]` in every crate, **no exceptions**. `unsafe` and FFI
live only inside dependencies (tokio, hyper, rustls and wasmtime contain them
internally); they are inventoried and audited (`cargo-geiger` or equivalent) as
documented residual risk.

## Decision: crate layout

Phase 1 starts with **4 crates** (the minimum that separates responsibilities
with real isolation cost):

```
eqproxy/            (workspace)
├── eqproxy-core    # shared types, errors, config snapshots, graceful shutdown
├── eqproxy-config  # EQProxy config parsing and validation, plan/diff
├── eqproxy-net     # dataplane: listeners, connections, TLS, TCP/HTTP proxy
└── eqproxy-cli     # binary: config validate/explain/diff/plan/apply/rollback/doctor
```

Rule for creating new crates (applies every phase): a module is split into its
own crate **only if** (a) it has an API boundary we want to stabilize (e.g.
`eqproxy-control` for the admin API), (b) heavy dependencies we do not want in
the dataplane (e.g. `eqproxy-plugins` with wasmtime), or (c) tests that must be
able to fail without taking down the workspace. Foreseen cases:
`eqproxy-observability` (Phase 3), `eqproxy-control` + `eqproxy-plugins`
(Phases 6–7), `eqproxy-config-import` (Phase 8: **reference proxy
configuration parser** + **converter**, the reference proxy → EQProxy migration
tool). The rest of the brief's names (http/routing/balancer/health/state/
testkit) start as **modules** inside `eqproxy-net`/`eqproxy-core`.

## Alternatives considered

1. **The brief's 14 crates from day 1:** rejected; premature API boundaries,
   compile and coordination cost with no measurable benefit.
2. **A single crate:** rejected for the dataplane: it would mix the CLI binary,
   config validation and the dataplane, and prevent keeping control
   dependencies (wasmtime, panel) out of the traffic process.
3. **Pingora as a base (framework):** evaluated (0.9.0, Apache-2.0, real
   Cloudflare pedigree). Rejected as a base because it is a programming
   framework, not a configurable proxy, and its cache and rustls are declared
   experimental; used as a design reference. **Revisit if the roadmap
   prioritizes time-to-market over dataplane control.** Also, Pingora offers no
   integrated HTTP/3, which is now a mandatory requirement.
4. **OpenSSL instead of rustls:** rejected by default (FFI and C supply
   chain); it would only be reopened for a concrete FIPS/compatibility
   requirement.

## Semver policy (pre-1.0)

- The crates are `0.1.0` **unpublished**: there is no API stability until the
  first publication; the only consumer is this workspace.
- Public types likely to grow carry `#[non_exhaustive]` from now on (e.g.
  `ResolvedListener`) and are built with public constructors: adding fields
  does not break consumers. This is the fix for the semver violation detected
  by `cargo-semver-checks` against the git baseline (fields added to an
  exhaustive struct).
- `cargo-semver-checks` is SKIPPED justified while there is no published
  version to serve as baseline; from the first publication the baseline is the
  registry and public API review is mandatory on every release.

## Consequences

- Phases 1–2 on 4 crates; every future split must satisfy the rule above and
  record it in a short ADR.
- HTTP/3 is **mandatory scope** (client, over QUIC); it arrives in Phase 5 and
  stays labelled experimental until it passes the test plan's interoperability
  tests. HTTP/3 to backends remains an experimental extension (the reference
  proxy has only offered it as experimental since 3.3+, see ADR-0003).
- The performance goal (match or beat the reference proxy 3.4.6 on RPS,
  connections, memory, CPU and P50/P95/P99 latencies in the scenarios of
  BENCHMARK_PLAN.md) is a **product goal with an acceptance criterion**, not an
  asserted result: it is only declared reached when reproducible measurements
  exist; a loss is recorded and profiled before optimizing (brief, section 12).
- Proxy semantics (safe retries, cancellation, backpressure, per-phase
  timeouts) are explicitly implemented and tested on top of hyper; using hyper
  does not guarantee them.

---

# Español

Idioma: [English](#adr-0004-network-stack-and-crate-layout) · **Español**

- Estado: **Aceptado para Fases 0–2** (revisión obligatoria al abrir Fase 5)
- Fecha: 2026-10-12
- Relacionado: [SPEC.md](../../SPEC.md) §Arquitectura, [ROADMAP.md](../../ROADMAP.md)

## Contexto

El brief (sección 5) propone un workspace modular con hasta 14 crates, pero
exige agrupar módulos si separar crates introduce complejidad sin beneficio, y
prohíbe asumir que una biblioteca resuelve la semántica del proxy. Hay que
elegir stack y layout atendiendo a mantenimiento, licencias, seguridad y
coste operativo (investigados en Fase 0, oct-2026).

## Decisión: stack

| Capa | Elección | Versión investigada | Licencia | Justificación / límite conocido |
|---|---|---|---|---|
| Runtime | tokio | 1.53.2 (2026-09-30) | MIT | LTS declarado hasta 2027 (líneas 1.51/1.53). MSRV 1.85. |
| HTTP/1–2 | hyper | 1.12.0 | MIT | Cliente/servidor de bajo nivel; **no es un proxy**: pooling, timeouts y backpressure son nuestra responsabilidad. Sin HTTP/3 integrado. |
| Cuerpos | http-body / http-body-util | 1.1.0 / 0.1.5 | MIT | Abstracción streaming; los límites de tamaño se aplican en nuestra capa. |
| TLS | rustls + `aws-lc-rs` | 0.23.45 (2026-09-14) | Apache-2.0 OR MIT OR ISC | Sin criptografía propia. FIPS solo a nivel de módulo AWS-LC validado, no automático. Verificación de certificados cliente (mTLS) explícita; nunca deshabilitar validación de hostname. |
| Adaptador TLS | tokio-rustls | 0.26.5 | MIT OR Apache-2.0 | Activo; `tokio-openssl` solo si una necesidad concreta lo exige (sin releases desde 2024-09). |
| Sockets | socket2 | 0.6.5 | MIT OR Apache-2.0 | `SO_REUSEPORT`, keepalive, `TCP_NODELAY`, opciones pre-bind. `SO_REUSEPORT` no es una garantía portable de balanceo (se declara en docs). |
| QUIC/H3 | quinn + `h3`/`h3-quinn` | quinn 0.11.12; h3-quinn 0.0.10 | MIT OR Apache-2.0 | **HTTP/3 es requisito de producto (decisión del usuario, 2026-10-12)**. Se implementa en Fase 5 con quinn + `h3`, etiquetado experimental hasta superar pruebas de interoperación: `h3` se declara "still very experimental" en su repo y hyper no expone API H3, por lo que el coste de integración y hardening es alto y se asume explícitamente. |
| DNS | hickory-dns (stub resolver) | 0.26.3 | Apache-2.0 OR MIT | Rol stub validado por Prossimo; el rol recursivo no se usa. Descubrimiento DNS en Fase 4. |
| Config | serde + toml + serde_path_to_error (+ schemars) | 1.0.x | MIT OR Apache-2.0 | Ver ADR-0002. Validación semántica propia aparte. |
| Observabilidad | tracing + tracing-subscriber; `metrics` o `prometheus-client` (elegir uno, no ambos) | tracing 0.1.44 | MIT OR Apache-2.0 | Cardinalidad de métricas acotada por diseño. Versión exacta del exporter se fija en Cargo.lock (sin verificar aún). |
| Plugins (Fase 7) | wasmtime (fuel/epoch + limiters) | 49.0.2 | Apache-2.0 | **Única vía de plugins** (decisión del usuario, 2026-10-12: código 100 % safe). Lua/mlua queda **descartado** (FFI C con `unsafe` sustancial); compatibilidad Lua futura solo en proceso aislado y con ADR nuevo. |
| Pruebas | cargo-fuzz/libFuzzer + proptest | (fijar en Fase 1) | — | Fuzzing de parsers propios, config y reglas. |

**Regla transversal:** no se fija ninguna versión "latest" sin fijarla en
`Cargo.lock` y auditar (`cargo deny`/equivalente) en la fase de implementación.
Las versiones de esta tabla son el estado investigado en oct-2026.

**Regla de código (decisión del usuario, 2026-10-12):** todo el código Rust
propio es safe — `#![forbid(unsafe_code)]` en cada crate, **sin excepciones**.
El `unsafe` y la FFI viven solo dentro de dependencias (tokio, hyper, rustls y
wasmtime los contienen internamente); se inventarían y auditan (`cargo-geiger`
o equivalente) como riesgo residual documentado.

## Decisión: layout de crates

Fase 1 arranca con **4 crates** (el mínimo que separa responsabilidades con
coste real de aislamiento):

```
eqproxy/            (workspace)
├── eqproxy-core    # tipos compartidos, errores, snapshots de config, apagado gradual
├── eqproxy-config  # parseo y validación de config EQProxy, plan/diff
├── eqproxy-net     # dataplane: listeners, conexiones, TLS, proxy TCP/HTTP
└── eqproxy-cli     # binario: config validate/explain/diff/plan/apply/rollback/doctor
```

Regla de creación de crates nuevos (aplica en cada fase): un módulo se separa
en crate propio **solo si** (a) tiene una frontera de API que queremos estabilizar
(p. ej. `eqproxy-control` para la API de administración), (b) dependencias
pesadas que no queremos en el dataplane (p. ej. `eqproxy-plugins` con wasmtime),
o (c) pruebas que deben poder fallar sin tumbar el workspace. Casos previstos:
`eqproxy-observability` (Fase 3), `eqproxy-control` + `eqproxy-plugins`
(Fases 6–7), `eqproxy-config-import` (Fase 8: **parser de configuración del
proxy de referencia** + **conversor**, la herramienta de migración del proxy de referencia → EQProxy). Resto de nombres del brief (http/routing/balancer/health/state/
testkit) empiezan como **módulos** dentro de `eqproxy-net`/`eqproxy-core`.

## Alternativas consideradas

1. **Los 14 crates del brief desde el día 1:** rechazado; fronteras de API
   prematuras, coste de compilación y de coordinación sin beneficio medible.
2. **Un solo crate:** rechazado para el dataplane: mezclaría el binario CLI,
   la validación de config y el dataplane, e impediría mantener dependencias
   de control (wasmtime, panel) fuera del proceso de tráfico.
3. **Pingora como base (framework):** evaluado (0.9.0, Apache-2.0, pedigree
   real en Cloudflare). Rechazado como base porque es un framework de
   programación, no un proxy configurables, y su caché y rustls se declaran
   experimentales; se usa como referencia de diseño. **Revisar si el roadmap
   prioriza tiempo-al-mercado sobre control del dataplane.** Además, Pingora
   no ofrece HTTP/3 integrado, que ahora es requisito obligatorio.
4. **OpenSSL en vez de rustls:** rechazado por defecto (FFI y cadena de
   suministro C); se reabriría solo ante un requisito FIPS/compatibilidad
   concreto.

## Política semver (pre-1.0)

- Los crates son `0.1.0` **sin publicar**: no hay estabilidad de API hasta la
  primera publicación; el único consumidor es este workspace.
- Los tipos públicos susceptibles de crecer llevan `#[non_exhaustive]` desde
  ya (p. ej. `ResolvedListener`) y se construyen con constructores públicos:
  añadir campos no rompe a los consumidores. Es la corrección de la violación
  de semver detectada por `cargo-semver-checks` contra el baseline git
  (campos añadidos a struct exhaustivo).
- `cargo-semver-checks` queda SKIPPED justificado mientras no exista una
  versión publicada que sirva de baseline; a partir de la primera publicación
  el baseline es el registro y la revisión de API pública es obligatoria en
  cada release.

## Consecuencias

- Fases 1–2 sobre 4 crates; cada separación futura exige cumplir la regla
  anterior y dejar constancia en un ADR breve.
- HTTP/3 es **alcance obligatorio** (cliente, sobre QUIC); llega en Fase 5 y
  se mantiene etiquetado experimental hasta superar las pruebas de
  interoperación del plan de pruebas. HTTP/3 hacia backend queda como
  extensión experimental (el proxy de referencia solo lo ofrece como experimental desde
  3.3+, ver ADR-0003).
- El objetivo de rendimiento (igualar o superar al proxy de referencia 3.4.6 en RPS,
  conexiones, memoria, CPU y latencias P50/P95/P99 en los escenarios de
  BENCHMARK_PLAN.md) es un **objetivo de producto con criterio de aceptación**,
  no un resultado afirmado: solo se declara alcanzado cuando existan
  mediciones reproducibles; una pérdida se registra y se perfila antes de
  optimizar (brief, sección 12).
- La semántica de proxy (reintentos seguros, cancelación, backpressure,
  timeouts por fase) se implementa y prueba explícitamente sobre hyper; el
  hecho de usar hyper no la garantiza.
