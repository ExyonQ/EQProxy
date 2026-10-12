# ADR-0004: Stack de red y layout de crates

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
(Fases 6–7), `eqproxy-ref-import` (Fase 8: **parser de configuración de
ref** + **conversor**, la herramienta de migración ref → EQProxy). Resto de nombres del brief (http/routing/balancer/health/state/
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
  extensión experimental (ref solo lo ofrece como experimental desde
  3.3+, ver ADR-0003).
- El objetivo de rendimiento (igualar o superar a ref 3.4.6 en RPS,
  conexiones, memoria, CPU y latencias P50/P95/P99 en los escenarios de
  BENCHMARK_PLAN.md) es un **objetivo de producto con criterio de aceptación**,
  no un resultado afirmado: solo se declara alcanzado cuando existan
  mediciones reproducibles; una pérdida se registra y se perfila antes de
  optimizar (brief, sección 12).
- La semántica de proxy (reintentos seguros, cancelación, backpressure,
  timeouts por fase) se implementa y prueba explícitamente sobre hyper; el
  hecho de usar hyper no la garantiza.
