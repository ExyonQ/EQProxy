# SPEC.md — ExyonQ Proxy (EQProxy) Specification

Language: **English** · [Español](#español)

- Document version: 0.1 (Phase 0)
- Date: 2026-10-12
- Project state: **Phase 0 — Research and scope. No code exists.**

## 1. Purpose

EQProxy is a reverse proxy and load balancer in Rust with two goals:

1. **Progressive functional parity** with the OSS reference proxy (pinned
   reference: 3.4.6 LTS primary, 3.0.29 LTS legacy — see
   [ADR-0003](docs/adr/0003-referencia-multiversion.md)).
2. **Verifiable improvements** in diagnostics, configuration experience,
   administration, extensibility and security.

"Beating the reference proxy" is a **hypothesis validated with reproducible
tests**, not a conclusion (brief, section 15). Explicit product goal (user
decision, 2026-10-12): **match or beat the reference proxy 3.4.6 LTS on RPS,
connections, memory, CPU and P50/P95/P99 latencies** in the scenarios of
[BENCHMARK_PLAN.md](BENCHMARK_PLAN.md). This is a goal with an acceptance
criterion, **not an asserted result**: no measurements yet.

## 2. State taxonomy (mandatory)

Every artifact in this project uses exactly these states, in this order:

| State | Meaning |
|---|---|
| **Designed** | Decided and documented. No code that runs it. |
| **Implemented** | Code that does it exists, in the tree. |
| **Compiled** | `cargo build --release` passes on the tier 1 platform. |
| **Tested** | Automated tests (unit + integration with real sockets) pass. |
| **Validated under load** | Measured with the BENCHMARK_PLAN.md protocol; raw data published. |
| **Production ready** | All of the above + hardening, long-running tests and external review (Phase 9). |

Rules:
- "Designed (scope)" = designed only at scope level in this phase; the detailed
  design comes with its phase.
- A state is never promoted without the corresponding evidence. If a test
  cannot be run, it is marked **pending** with its exact command.
- Forbidden: mocks as evidence of real network, TLS or storage behaviour (unit
  test mocks are labelled as such).

## 3. Goals

1. Efficient and reliable dataplane (priority: correctness first).
2. Typed, validatable and understandable configuration (see §7 and [ADR-0002](docs/adr/0002-formato-configuracion.md)).
3. Diagnostics that explain traffic decisions (explain/trace mode, §8).
4. Safe and atomic configuration updates with respect to the visible view.
5. Accessible administration: CLI, API and web panel (the proxy never depends
   on the panel to run).
6. Extensions with explicit permissions and limits (WASM, §10).
7. Integrated observability (metrics, structured logs, tracing).
8. Recovery and rollback.
9. Reproducible tests (brief section 11 → [BENCHMARK_PLAN.md](BENCHMARK_PLAN.md) and ROADMAP).
10. Documentation oriented to real tasks.
11. **HTTP/3 (QUIC) to clients: mandatory requirement** (user decision,
    2026-10-12), implemented in Phase 5 and labelled experimental until it
    passes interoperability tests.

## 4. Non-goals (explicit)

- It is not a WAF. It does not promise total DDoS protection (rate limiting is
  not anti-DDoS).
- We do not implement our own cryptography; we do not parse complex protocols
  with our own code if maintained libraries exist.
- All our own Rust code is **safe**: `#![forbid(unsafe_code)]` in every crate,
  **no exceptions** (user decision, 2026-10-12). `unsafe` and FFI live only
  inside dependencies, inventoried and audited as residual risk
  ([THREAT_MODEL.md](THREAT_MODEL.md) §5).
- There is no parity with the commercial editions of the reference proxy
  (Enterprise, the One platform, ALOHA, Fusion): **excluded from parity scope**
  by decision (2026-10-12); the exclusion is only documented in the parity
  matrix (internal documentation) §E.
- There is no full compatibility with the reference proxy's config syntax.
  Migration is done with the **configuration converter** (migration tool; CLI
  `eqproxy config import --input reference-config --output eqproxy.toml`,
  `eqproxy-config-import` crate), which converts compatible directives, reports
  those needing review and **explicitly rejects** those that cannot be
  translated without altering behaviour. Directives are never silently
  dropped: "file generated correctly" ≠ "functionally equivalent migration".
- Distributed "atomic" multi-instance updates are not promised without a
  protocol that guarantees them.

## 5. Priorities (inviolable)

**correctness → security → operability → performance → feature breadth.**

Isolation, resource limits or correct semantics are never sacrificed to win a
benchmark. If EQProxy loses a scenario, the loss is recorded and profiled
before optimizing.

## 6. Support platform

See [ADR-0001](docs/adr/0001-plataforma-produccion.md): tier 1 production on
**Linux x86_64 glibc**; experimental tier 2 (aarch64, macOS, musl); Windows
unsupported.

## 7. Architecture

### 7.1 Plane separation

- **Dataplane** (`eqproxy-net`): client traffic. It does not depend on the
  panel or on admin storage to serve already-configured traffic. A control
  plane failure does **not** stop configured traffic.
- **Control plane** (`eqproxy-config`, `eqproxy-cli`, later `eqproxy-control`):
  validation, planning, application and administration.

### 7.2 Configuration snapshots

- Each config application produces an **immutable, coherent snapshot** (shared
  `Arc`) that the dataplane reads without per-request locking.
- No per-request storage accesses when not needed.
- Activation is **atomic with respect to the visible configuration**: either
  the complete new config is visible, or the complete previous one (transition
  by snapshot swap). Change classification: hot-applicable / require draining /
  require process replacement / unsupported (classification table in phase 3;
  the API and the CLI share the same validation).
- If preparing a change fails, nothing is activated (prior resource
  compilation: listeners, pools, certs). Irreversible external effects (e.g. an
  already-issued drain order) are **not promised to be revertible**.

### 7.3 Resource budgets (design; to be validated by measurement)

Visible assumptions: HTTP/1.1 proxying, 16 KiB buffers per direction, active
connections without compression or caching.

| Scenario | Design budget (unmeasured) | Assumption | Validated in |
|---|---|---|---|
| TCP proxy connection | ≤ 36 KiB/connection (2 × 16 KiB buffers + ~4 KiB state) | bidirectional streaming | Phase 2c (measured ~37.8 KiB on darwin/arm64, +5% allocator rounding; Linux re-measurement pending) |
| HTTP/1.1 connection | ≤ 48 KiB/connection (2 buffers + state + parser) | keep-alive to backend | Phase 2c (measured ~15.1 KiB idle keep-alive on darwin/arm64) |
| FDs | 2 FDs per proxied connection + listeners + admin. E.g. maxconn 100 000 → ≥ 200 000 FDs + 10 % margin | `ulimit -n` limit documented in `eqproxy doctor` | Phase 1 |
| Queues | Bounded queue per backend (`maxqueue`); rejection with 503/explicit timeout when full; **never unlimited queues** | burst traffic | Phase 3 |
| Tasks | 1 task per connection (not per request on keep-alive); task cap = connection cap | — | Phase 1 |
| Metric cardinality | Labels bounded by config (frontend/backend/server); labelling with URLs, client IPs or tokens is forbidden | — | Phase 3 |

Behaviour on exhaustion: exhausting FDs, memory or queues produces explicit
rejection (clear error + metric + log), never a process that "returns simulated
success". The numbers above are design targets; they are revised with profiling
data (no "optimization" without evidence).

### 7.4 Crate workspace

See [ADR-0004](docs/adr/0004-stack-red-y-layout-crates.md): 4 initial crates
(`eqproxy-core`, `eqproxy-config`, `eqproxy-net`, `eqproxy-cli`); new crates
only under the documented separation rule.

### 7.5 TLS, balancing and health checks (Phase 2b)

- **TLS termination (A11):** per-listener certificate chain + private key
  (PEM); the handshake is part of the client phase (`client_header_timeout`).
  Min TLS 1.2; ALPN explicit per listener (A14).
- **Backend TLS (A12):** per-backend; certificate **and hostname verified by
  default** (Mozilla roots + `ca_file` for private CAs). The SNI/verified name
  defaults to the server's IP literal, overridable with `server_name`.
  The handshake is bounded by `connect_timeout`.
- **Balancing (B1/B7):** one shared balancer per backend (also shared between
  listeners referencing it): smooth weighted round-robin, `weight` 0..=256.
- **Health checks (B11 TCP):** one task per backend with checks configured;
  `interval`/`timeout`/`fall`/`rise`. Servers start up; `fall` consecutive
  failures take a server down, `rise` consecutive successes bring it back.
- **No servers available:** HTTP answers 503 before touching any server; TCP
  closes the connection immediately. Both count `no_available_server`.
- **PROXY protocol v1 (A9 send):** header written to the chosen server before
  the payload (inside the TLS stream when backend TLS is on).

## 8. Explainable diagnostics (explain/trace mode)

Designed (scope); implementation in Phases 3–4. The explain mode for a request
(real, sampled, or **simulated with no external effects**) must show:

1. Listener and frontend used.
2. Rules evaluated, in order; rules that matched and why.
3. Selected backend and reason; selected server and its state (UP/DOWN/DRAIN/MAINT).
4. Per-phase timings (accept, TLS handshake, request, backend connect, TTFB, transfer).
5. Retries and redistributions.
6. The concrete timeout that fired (client, connect, server, tunnel…).
7. Error origin when determinable: client, proxy, network or backend.
8. Explicit difference between *successful health check* and *functional
   application success*.

Requirements of the diagnostic mode:
- Off or sampled by default; bounded in memory and time.
- Protected by permissions (authenticated control plane).
- Redacted: no tokens, cookies or personal data in the clear.
- **Simulation ≠ execution**: rule simulation issues no requests and has no
  external effects, and is labelled as a simulation in its output.

Associated observability: structured logs (JSON), correlation identifiers,
operational events, metrics exportable in a standard format (Prometheus),
`tracing` integration where it helps. Diagnostics propose concrete actions
without asserting undemonstrated causes.

## 9. Administration and web panel

Designed (scope); implementation in Phase 6. The panel exposes: listener/backend
state, server health, connections/queues/latencies, change history, diffs
between configurations, validation before applying, certificate management,
drain/maintenance, authorised request diagnostics, alerts and multi-instance
management (desired vs applied revisions, drift).

Panel security (detail in [THREAT_MODEL.md](THREAT_MODEL.md)):
authentication, RBAC, write auditing, session and CSRF protection, strict
separation between public endpoint and administration, minimal permissions,
concurrency control on write operations (optimistic concurrency with revision),
forbidden to expose secrets, documented data retention policy. **The panel is
not a requirement to operate the proxy.**

Multi-instance: nothing that is not atomic is declared "atomic"; behaviour
under network partitions and partial failures is documented.

## 10. Extensions (WASM)

Designed (scope); implementation in Phase 7. Single route:

- **WASM (wasmtime)** for untrusted plugins: fuel/epoch interruption, per-store
  memory limits, deadlines.
- **Lua is discarded** by the 100 % safe code policy (user decision,
  2026-10-12): mlua is C FFI with substantial `unsafe`, and Lua is not a
  sandbox for hostile code. If compatibility with the reference proxy's Lua API
  is ever needed, it would be in an isolated process outside the binary and
  with a new ADR.

For each plugin (plugin template) is defined: extension points (fetch,
converter, action, service, task — equivalent to the reference proxy's),
execution model (never arbitrary blocking tasks on dataplane workers; a timeout
does **not** magically cancel a block; isolation in another process when the
plugin may block), allowed capabilities (network and files **denied by
default**), instruction budget, deadlines, cancellation, fail-open/fail-closed
policy **per extension**, plugin API versioning, pre-activation validation and
isolation tests.

Rules: plugins do not run on every request by default; the cost with and
without plugins is measured (BENCHMARK_PLAN.md, scenario S-PLG-01). WASM is
not presented as perfect isolation: host capabilities, residual risks and
runtime dependency are documented.

## 11. Security

See [THREAT_MODEL.md](THREAT_MODEL.md). Cross-cutting principles: per-phase and
per-protocol limits, consistent HTTP message normalization, safe rejection of
ambiguous messages (request smuggling: ambiguous framing is rejected, never
"guessed"), secret protection, dependency and license inventory, vulnerability
reporting procedure.

## 12. Testing and verification

Full strategy in [ROADMAP.md](ROADMAP.md) §Invariants and
[BENCHMARK_PLAN.md](BENCHMARK_PLAN.md): unit, integration with real sockets,
end-to-end, property-based, fuzzing (own parsers, config, rules), differential
tests against the reference proxy where semantics must match, protocol
conformance, sustained load, fault injection, certificate renewal, config
changes under traffic, slow clients/backends, backend failures, long streaming,
changing DNS, resource exhaustion, restart/recovery, plugins exceeding limits.

Tools and their declared limits: `cargo fmt`, `cargo clippy`,
`cargo test`, dependency and license audit (`cargo-deny` or equivalent), Miri
**only** for compatible components (it does not prove the absence of bugs in
the whole service), sanitizers/concurrency tools where appropriate.

## 13. Semantic difference log vs the reference proxy

- Every capability in the parity matrix declares the semantics it preserves and
  the known differences. "Similar feature" ≠ "compatible".
- Documented semantic differences (initial selection, to grow):
  1. **Configuration reload:** the reference proxy spawns a new process and
     inherits sockets; EQProxy applies hot snapshots within the process.
     Metrics are **not** reset on a config application (intentional
     difference; see PP-03). "Process replacement" is only contemplated for
     changes that require it.
  2. **Configuration format:** canonical TOML (proposed, ADR-0002), not the
     reference proxy's syntax; the reference proxy → EQProxy converter
     translates a subset with a per-directive equivalence report (pipeline:
     `reference-config` → lossless reference proxy parser → structured
     representation → translation → validation and generation → `eqproxy.toml`
     + conversion report).
  3. **Server state DRAIN vs MAINT:** own explicit semantics, documented by
     comparison with `set server ... state drain/maint`.
  4. **HTTP framing (Phase 2a):** EQProxy rejects every ambiguous message
     (CL+TE, duplicates, TE ≠ `chunked`, absolute-form, obs-fold) instead of
     normalizing it as the reference proxy may do in some cases;
     `CONNECT`/`Upgrade` answer 501 until Phase 4. Trailers only empty or
     without framing headers.
  5. **TLS and ALPN (Phase 2b):** only TLS 1.2/1.3 (TLS 1.0/1.1 never);
     ALPN offers only the configured protocols (only `http/1.1` in this phase)
     and the handshake **fails** when there is no common protocol instead of
     negotiating nothing silently. Backend TLS verifies certificate **and
     hostname by default** (Mozilla roots + `ca_file`); `verify = false` is an
     explicit opt-out with documented risk (THREAT_MODEL).
  6. **Load balancing (Phase 2b):** smooth weighted round-robin (deterministic;
     ties broken by configuration order) instead of the reference proxy's WRR
     variant; `weight = 0` means drained (never picked, still health-checked).
  7. **Health checks (Phase 2b, TCP):** a check is a TCP connect; check OK ≠
     functional success (§8.8). HTTP checks with `expect` come in Phase 3.
  8. **PROXY protocol (Phase 2b):** send-only v1 (header before the payload;
     `PROXY UNKNOWN` for mixed families); reception and its trust policy come
     in Phase 3 (never trust PROXY from unauthorized sources).
  9. (Living log: each matrix row extends it.)

## 14. Project state and evidence

| Area | State | Evidence |
|---|---|---|
| Phase 0 research (the reference proxy, user pain, Rust ecosystem) | Tested* | Sources with URL in docs; *verified by reading sources, not by execution |
| Specification and scope | Designed | This document |
| Parity matrix | Designed | Internal documentation (incomplete by design, gaps declared) |
| Phase 1 code (TCP proxy, TOML config, CLI) | **Tested** (2026-10-12) | 30 tests green: 19 unit + 6 E2E with real sockets + 5 E2E through the real `eqproxy` binary (incl. SIGINT). fmt/clippy `-D warnings` green; 0 own `unsafe` (`forbid(unsafe_code)`); cargo-deny and cargo-machete green; SBOM in `sbom/` |
| Phase 2a code (strict HTTP/1.1, T01–T03, per-phase timeouts, streaming) | **Tested** (2026-10-12) | 47 tests green: 27 unit + 14 E2E with real sockets (6 TCP + 8 HTTP) + 6 E2E through the real binary (incl. smuggling rejected with 400 and SIGINT). fmt/clippy `-D warnings` green |
| Phase 2b code (TLS termination/backend TLS/ALPN, weighted RR, TCP health checks, PROXY v1 send) | **Tested** (2026-10-13) | 93 tests green: 57 unit + 26 E2E with real sockets (6 TCP + 8 HTTP + 12 Phase 2b) + 10 E2E through the real `eqproxy` binary (incl. real TLS traffic via `openssl s_client`). Veyra audit ACCEPTED + EvoForge slice eval F=1. Details in the 0.2.0 delivery |
| Phase 2c code (framing fuzz corpus + live fuzz, first benchmarks, measured budgets) | **Tested** (2026-10-14) | 3 new corpus tests (~10k parser mutants, no-panic + explicit statuses); live cargo-fuzz `framing` 3.83M execs, 0 crashes; S-TCP-01 Comparable, S-H1-01/S-TLS-01 Worse under sustained concurrency (verified EADDRNOTAVAIL root cause, pool in Phase 3); RSS/conn measured (TCP ~37.8, HTTP ~15.1 KiB). Evidence in `docs/evidence/phase2c/bench.md` |
| Benchmarks | **Measured (Phase 2 scope)** | First runs S-TCP-01, S-H1-01, S-TLS-01 vs 3.4.6 with raw data ([docs/evidence/phase2c/bench.md](docs/evidence/phase2c/bench.md)); full matrix remains Phase 9 |

---

# Español

Idioma: [English](#specmd--exyonq-proxy-eqproxy-specification) · **Español**

- Versión del documento: 0.1 (Fase 0)
- Fecha: 2026-10-12
- Estado del proyecto: **Fase 0 — Investigación y alcance. No existe código.**

## 1. Propósito

EQProxy es un proxy inverso y balanceador de carga en Rust con dos objetivos:

1. **Paridad funcional progresiva** con el proxy de referencia OSS (referencia fijada:
   3.4.6 LTS primaria, 3.0.29 LTS legacy — ver [ADR-0003](docs/adr/0003-referencia-multiversion.md)).
2. **Mejoras verificables** en diagnóstico, experiencia de configuración,
   administración, extensibilidad y seguridad.

“Superar al proxy de referencia” es una **hipótesis que se valida con pruebas
reproducibles**, no una conclusión (brief, sección 15). Objetivo de producto
explícito (decisión del usuario, 2026-10-12): **igualar o superar al proxy de referencia
3.4.6 LTS en RPS, conexiones, memoria, CPU y latencias P50/P95/P99** en los
escenarios de [BENCHMARK_PLAN.md](BENCHMARK_PLAN.md). Esto es un objetivo con
criterio de aceptación, **no un resultado afirmado**: sin mediciones aún.

## 2. Taxonomía de estados (obligatoria)

Todo artefacto de este proyecto usa exactamente estos estados, en este orden:

| Estado | Significado |
|---|---|
| **Diseñado** | Decidido y documentado. Sin código que lo ejecute. |
| **Implementado** | Existe código que lo hace, en el árbol. |
| **Compilado** | `cargo build --release` pasa en la plataforma tier 1. |
| **Probado** | Tests automatizados (unitarios + integración con sockets reales) pasan. |
| **Validado bajo carga** | Medido con el protocolo de BENCHMARK_PLAN.md; datos brutos publicados. |
| **Listo para producción** | Todo lo anterior + hardening, pruebas prolongadas y revisión externa (Fase 9). |

Reglas:
- “Diseñado (alcance)” = diseñado solo a nivel de alcance en esta fase; el
  diseño detallado llega con su fase.
- Nunca se promueve un estado sin evidencia correspondiente. Si una prueba no
  se puede ejecutar, se marca **pendiente** con su comando exacto.
- Prohibido: mocks como evidencia de funcionamiento real de red, TLS o
  almacenamiento (los mocks de tests unitarios se etiquetan como tales).

## 3. Objetivos

1. Dataplane eficiente y fiable (prioridad: corrección primero).
2. Configuración tipada, validable y comprensible (ver §7 y [ADR-0002](docs/adr/0002-formato-configuracion.md)).
3. Diagnóstico que explique las decisiones de tráfico (modo explain/trace, §8).
4. Actualizaciones de configuración seguras y atómicas respecto a la vista.
5. Administración accesible: CLI, API y panel web (el proxy nunca depende del panel para funcionar).
6. Extensiones con permisos y límites explícitos (WASM, §10).
7. Observabilidad integrada (métricas, logs estructurados, tracing).
8. Recuperación y rollback.
9. Pruebas reproducibles (sección 11 del brief → [BENCHMARK_PLAN.md](BENCHMARK_PLAN.md) y ROADMAP).
10. Documentación orientada a tareas reales.
11. **HTTP/3 (QUIC) hacia clientes: requisito obligatorio** (decisión del
    usuario, 2026-10-12), implementado en Fase 5 y etiquetado experimental
    hasta superar las pruebas de interoperación.

## 4. No objetivos (explícitos)

- No es un WAF. No promete protección DDoS total (el rate limiting no es anti-DDoS).
- No implementamos criptografía propia; no parseamos protocolos complejos con
  código propio si hay bibliotecas mantenidas adecuadas.
- Todo el código Rust propio es **safe**: `#![forbid(unsafe_code)]` en cada
  crate, **sin excepciones** (decisión del usuario, 2026-10-12). El `unsafe` y
  la FFI viven solo dentro de dependencias, inventariados y auditados como
  riesgo residual ([THREAT_MODEL.md](THREAT_MODEL.md) §5).
- No hay paridad con las ediciones comerciales del proxy de referencia
  (Enterprise, plataforma One, ALOHA, Fusion):
  **excluidos del alcance de paridad** por decisión (2026-10-12); solo se
  documenta la exclusión en la matriz de paridad (documentación interna) §E.
- No hay compatibilidad total con la sintaxis de config del proxy de referencia. La
  migración se hace con el **conversor de configuración** (herramienta de
  migración; CLI `eqproxy config import --input config-de-referencia --output
  eqproxy.toml`, módulo `eqproxy-config-import`), que convierte las
  directivas compatibles, informa de las que requieren revisión y **rechaza
  explícitamente** las que no se pueden traducir sin alterar el comportamiento.
  Nunca se omiten directivas en silencio: «archivo generado correctamente» ≠
  «migración funcionalmente equivalente».
- No se prometen actualizaciones distribuidas “atómicas” multi-instancia sin un
  protocolo que lo garantice.

## 5. Prioridades (inviolables)

**corrección → seguridad → operabilidad → rendimiento → amplitud funcional.**

Nunca se sacrifica aislamiento, límites de recursos ni semántica correcta para
ganar un benchmark. Si EQProxy pierde un escenario, se registra la pérdida y se
perfila antes de optimizar.

## 6. Plataforma de soporte

Ver [ADR-0001](docs/adr/0001-plataforma-produccion.md): producción tier 1 en
**Linux x86_64 glibc**; tier 2 experimental (aarch64, macOS, musl); Windows no
soportado.

## 7. Arquitectura

### 7.1 Separación de planos

- **Dataplane** (`eqproxy-net`): tráfico de clientes. No depende del panel ni
  del almacenamiento de administración para servir el tráfico ya configurado.
  Un fallo del control plane **no** detiene el tráfico configurado.
- **Control plane** (`eqproxy-config`, `eqproxy-cli`, más adelante
  `eqproxy-control`): validación, planificación, aplicación y administración.

### 7.2 Snapshots de configuración

- Cada aplicación de config produce un **snapshot inmutable y coherente**
  (Arc compartido) que el dataplane lee sin bloqueos por petición.
- Sin accesos a almacenamiento por petición cuando no sean necesarios.
- La activación es **atómica respecto a la configuración visible**: o se ve la
  config nueva completa, o la anterior completa (transición por swap de
  snapshot). Clasificación de cambios: aplicables en caliente / requieren
  drenaje / requieren reemplazo de proceso / no soportados (tabla de
  clasificación en la fase 3; la API y la CLI comparten la misma validación).
- Si la preparación de un cambio falla, no se activa nada (compilación de
  recursos previa: listeners, pools, certs). Efectos externos irreversibles
  (p. ej. ordenar un drenaje ya emitido) **no se prometen revertibles**.

### 7.3 Presupuestos de recursos (diseño; a validar con medición)

Supuestos visibles: HTTP/1.1 proxying, buffers de 16 KiB por dirección,
conexiones activas sin compresión ni caché.

| Escenario | Presupuesto de diseño (sin medir) | Supuesto | Se valida en |
|---|---|---|---|
| Conexión proxy TCP | ≤ 36 KiB/conexión (2 buffers 16 KiB + estado ~4 KiB) | streaming bidireccional | Fase 2 (bench memoria) |
| Conexión HTTP/1.1 | ≤ 48 KiB/conexión (2 buffers + estado + parser) | keep-alive a backend | Fase 2 (bench memoria) |
| FDs | 2 FDs por conexión proxyada + listeners + admin. Ej.: maxconn 100 000 → ≥ 200 000 FDs + 10 % margen | límite `ulimit -n` documentado en `eqproxy doctor` | Fase 1 |
| Colas | Cola acotada por backend (`maxqueue`); rechazo con 503/timeout explícito al llenarse; **nunca colas ilimitadas** | tráfico en ráfaga | Fase 3 |
| Tareas | 1 tarea por conexión (no por petición en keep-alive); cap de tareas = cap de conexiones | — | Fase 1 |
| Cardinalidad de métricas | Etiquetas acotadas por config (frontend/backend/server); prohibido etiquetar con URLs, IPs de cliente ni tokens | — | Fase 3 |

Comportamiento ante agotamiento: agotar FDs, memoria o colas produce rechazo
explícito (error claro + métrica + log), nunca un proceso que “devuelve éxito”
simulado. Los números anteriores son objetivos de diseño; se revisan con datos
de profiling (no se “optimiza” sin evidencia).

### 7.4 Workspace de crates

Ver [ADR-0004](docs/adr/0004-stack-red-y-layout-crates.md): 4 crates iniciales
(`eqproxy-core`, `eqproxy-config`, `eqproxy-net`, `eqproxy-cli`); nuevos crates
solo bajo la regla de separación documentada.

### 7.5 TLS, balanceo y health checks (Fase 2b)

- **TLS termination (A11):** cadena de certificados + clave privada por
  listener (PEM); el handshake vive en la fase cliente
  (`client_header_timeout`). Mínimo TLS 1.2; ALPN explícito por listener (A14).
- **TLS a backends (A12):** por backend; certificado **y nombre verificados por
  defecto** (raíces Mozilla + `ca_file` para CAs privadas). El nombre
  verificado/SNI por defecto es la IP del servidor, configurable con
  `server_name`. El handshake está acotado por `connect_timeout`.
- **Balanceo (B1/B7):** un balancer compartido por backend (también entre
  listeners que lo referencian): roundrobin ponderado suave, `weight` 0..=256.
- **Health checks (B11 TCP):** un task por backend con checks configurados;
  `interval`/`timeout`/`fall`/`rise`. Los servidores arrancan operativos; `fall`
  fallos consecutivos derriban un servidor y `rise` éxitos consecutivos lo
  levantan.
- **Sin servidores disponibles:** HTTP responde 503 antes de tocar ningún
  servidor; TCP cierra la conexión al instante. Ambos cuentan
  `no_available_server`.
- **PROXY protocol v1 (A9 envío):** cabecera escrita al servidor elegido antes
  del payload (dentro del stream TLS si el backend usa TLS).

## 8. Diagnóstico explicable (modo explain/trace)

Diseñado (alcance); implementación en Fases 3–4. El modo explain de una
petición (real, muestreada, o **simulada sin efectos externos**) debe mostrar:

1. Listener y frontend utilizados.
2. Reglas evaluadas, en orden; reglas que coincidieron y por qué.
3. Backend seleccionado y motivo; servidor seleccionado y su estado (UP/DOWN/DRAIN/MAINT).
4. Tiempos por fase (accept, TLS handshake, request, connect a backend, TTFB, transferencia).
5. Reintentos y redistribuciones.
6. Timeout concreto que actuó (cliente, connect, server, tunnel…).
7. Origen del error cuando puede determinarse: cliente, proxy, red o backend.
8. Diferencia explícita entre *health check exitoso* y *éxito funcional de la aplicación*.

Requisitos del modo de diagnóstico:
- Desactivado o muestreado por defecto; acotado en memoria y tiempo.
- Protegido por permisos (control plane autenticado).
- Redactado: sin tokens, cookies ni datos personales en claro.
- **Simulación ≠ ejecución**: la simulación de reglas no genera peticiones ni
  efectos externos, y se etiqueta como simulación en su salida.

Observabilidad asociada: logs estructurados (JSON), identificadores de
correlación, eventos operativos, métricas exportables en formato estándar
(Prometheus), integración de tracing (`tracing`) donde aporte. Los
diagnósticos proponen acciones concretas sin afirmar causas no demostradas.

## 9. Administración y panel web

Diseñado (alcance); implementación en Fase 6. El panel expone: estado de
listeners/backends, salud de servidores, conexiones/colas/latencias, historial
de cambios, diffs entre configuraciones, validación antes de aplicar, gestión
de certificados, drenaje/mantenimiento, diagnóstico de peticiones autorizado,
alertas y gestión multi-instancia (revisiones deseadas vs aplicadas, drift).

Seguridad del panel (detalle en [THREAT_MODEL.md](THREAT_MODEL.md)):
autenticación, RBAC, auditoría de escritura, protección de sesiones y CSRF,
separación estricta entre endpoint público y administración, permisos mínimos,
control de concurrencia en operaciones de escritura (optimistic concurrency
con revisión), prohibición de exponer secretos, política de retención de datos
documentada. **El panel no es requisito para operar el proxy.**

Multi-instancia: no se declara “atómico” nada que no lo sea; se documenta el
comportamiento ante particiones de red y fallos parciales.

## 10. Extensiones (WASM)

Diseñado (alcance); implementación en Fase 7. Vía única:

- **WASM (wasmtime)** para plugins no confiables: fuel/epoch interruption,
  límites de memoria por store, deadlines.
- **Lua queda descartado** por la política de código 100 % safe (decisión del
  usuario, 2026-10-12): mlua es FFI C con `unsafe` sustancial y Lua no es un
  sandbox para código hostil. Si algún día se necesita compatibilidad con la
  API de Lua del proxy de referencia, sería en un proceso aislado fuera del binario y con un
  ADR nuevo.

Para cada plugin se define (plantilla de plugin): puntos de extensión (fetch,
converter, action, service, task — equivalentes a los del proxy de referencia), modelo de
ejecución (nunca tareas bloqueantes arbitrarias en workers del dataplane; un
timeout **no** cancela mágicamente un bloqueo; aislamiento en otro proceso
cuando el plugin pueda bloquear), capacidades permitidas (red y archivos
**denegados por defecto**), presupuesto de instrucciones, deadlines,
cancelación, política fail-open/fail-closed **por extensión**, versionado de
API de plugin, validación antes de activación y pruebas de aislamiento.

Reglas: plugins no se ejecutan en todas las peticiones por defecto; se mide el
coste con y sin plugins (BENCHMARK_PLAN.md, escenario S-PLG-01). WASM no se
presenta como aislamiento perfecto: se documentan capacidades del host, riesgos
residuales y dependencia del runtime.

## 11. Seguridad

Ver [THREAT_MODEL.md](THREAT_MODEL.md). Principios transversales: límites por
fase y protocolo, normalización consistente de mensajes HTTP, rechazo seguro
de mensajes ambiguos (request smuggling: framing ambiguo se rechaza, nunca se
“adivina”), protección de secretos, inventario de dependencias y licencias,
procedimiento de reporte de vulnerabilidades.

## 12. Pruebas y verificación

Estrategia completa en [ROADMAP.md](ROADMAP.md) §Invariantes y
[BENCHMARK_PLAN.md](BENCHMARK_PLAN.md): unitarias, integración con sockets
reales, end-to-end, property-based, fuzzing (parsers propios, config, reglas),
pruebas diferenciales frente al proxy de referencia donde la semántica deba coincidir,
conformidad de protocolos, carga sostenida, inyección de fallos, renovación de
certificados, cambios de config bajo tráfico, clientes/backends lentos, caídas
de backends, streaming largo, DNS cambiante, agotamiento de recursos,
reinicio/recuperación, plugins que exceden límites.

Herramientas y sus límites declarados: `cargo fmt`, `cargo clippy`,
`cargo test`, auditoría de dependencias y licencias (`cargo-deny` o
equivalente), Miri **solo** para componentes compatibles (no prueba la
ausencia de bugs del servicio completo), sanitizers/herramientas de
concurrencia cuando proceda.

## 13. Registro de diferencias semánticas vs el proxy de referencia

- Toda capacidad de la matriz de paridad declara la semántica
  que preserva y las diferencias conocidas. “Función parecida” ≠ “compatible”.
- Las diferencias semánticas documentadas (selección inicial, a crecer):
  1. **Recarga de configuración:** El proxy de referencia crea un proceso nuevo y hereda
     sockets; EQProxy aplica snapshots en caliente dentro del proceso. Las
     métricas **no** se reinician en una aplicación de config (diferencia
     intencionada; ver PP-03). El “reemplazo de proceso” se contempla solo
     para cambios que lo requieran.
  2. **Formato de configuración:** TOML canónico (propuesto, ADR-0002), no la
     sintaxis del proxy de referencia; el conversor del proxy de referencia → EQProxy traduce un subconjunto
     con informe de equivalencia por directiva (pipeline: `config-de-referencia` →
     parser del proxy de referencia sin pérdidas → representación estructurada →
     traducción → validación y generación → `eqproxy.toml` + informe de
     conversión).
3. **Estado de servidor DRAIN vs MAINT:** semántica explícita propia,
   documentada por comparación con `set server ... state drain/maint`.
4. **Framing HTTP (Fase 2a):** EQProxy rechaza todo mensaje ambiguo (CL+TE,
   duplicados, TE ≠ `chunked`, absolute-form, obs-fold) en lugar de
   normalizarlo como puede hacer el proxy de referencia en algunos casos; `CONNECT`/`Upgrade`
   responden 501 hasta Fase 4. Trailers solo vacíos o sin cabeceras de framing.  5. **TLS y ALPN (Fase 2b):** solo TLS 1.2/1.3 (TLS 1.0/1.1 nunca); ALPN
     ofrece solo los protocolos configurados (solo `http/1.1` en esta fase) y
     el handshake **falla** cuando no hay protocolo común en vez de negociar
     nada en silencio. El TLS a backends verifica certificado **y nombre por
     defecto** (raíces Mozilla + `ca_file`); `verify = false` es un opt-out
     explícito con riesgo documentado (THREAT_MODEL).
  6. **Balanceo (Fase 2b):** roundrobin ponderado suave (determinista; empates
     en orden de configuración) en lugar de la variante WRR del proxy de
     referencia; `weight = 0` significa drenado (nunca seleccionado, sí
     comprobado).
  7. **Health checks (Fase 2b, TCP):** un check es una conexión TCP; check OK ≠
     éxito funcional (§8.8). Los checks HTTP con `expect` llegan en Fase 3.
  8. **PROXY protocol (Fase 2b):** solo envío v1 (cabecera antes del payload;
     `PROXY UNKNOWN` para familias mixtas); la recepción y su política de
     confianza llegan en Fase 3 (nunca confiar en PROXY de fuentes no
     autorizadas).
  9. (Registro vivo: cada fila de la matriz lo amplía.)

## 14. Estado y evidencia del proyecto

| Área | Estado | Evidencia |
|---|---|---|
| Investigación Fase 0 (el proxy de referencia, dolor usuario, ecosistema Rust) | Probado* | Fuentes con URL en docs; *verificado por lectura de fuentes, no por ejecución |
| Especificación y alcance | Diseñado | Este documento |
| Matriz de paridad | Diseñado | Documentación interna (incompleta por diseño, huecos declarados) |
| Código Fase 1 (proxy TCP, config TOML, CLI) | **Probado** (2026-10-12) | 30 tests en verde: 19 unit + 6 E2E con sockets reales + 5 E2E por el binario real `eqproxy` (incl. SIGINT). fmt/clippy `-D warnings` en verde; 0 `unsafe` propios (`forbid(unsafe_code)`); cargo-deny y cargo-machete en verde; SBOM en `sbom/` |
| Código Fase 2a (HTTP/1.1 estricto, T01–T03, timeouts por fase, streaming) | **Probado** (2026-10-12) | 47 tests en verde: 27 unit + 14 E2E con sockets reales (6 TCP + 8 HTTP) + 6 E2E por el binario real (incl. smuggling rechazado con 400 y SIGINT). fmt/clippy `-D warnings` en verde |
| Benchmarks | **No medidos** | Solo plan (BENCHMARK_PLAN.md) |
