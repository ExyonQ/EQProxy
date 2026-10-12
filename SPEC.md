# SPEC.md — Especificación de ExyonQ Proxy (EQProxy)

- Versión del documento: 0.1 (Fase 0)
- Fecha: 2026-10-12
- Estado del proyecto: **Fase 0 — Investigación y alcance. No existe código.**

## 1. Propósito

EQProxy es un proxy inverso y balanceador de carga en Rust con dos objetivos:

1. **Paridad funcional progresiva** con ref OSS (referencia fijada:
   3.4.6 LTS primaria, 3.0.29 LTS legacy — ver [ADR-0003](docs/adr/0003-referencia-multiversion.md)).
2. **Mejoras verificables** en diagnóstico, experiencia de configuración,
   administración, extensibilidad y seguridad.

“Superar a ref” es una **hipótesis que se valida con pruebas
reproducibles**, no una conclusión (brief, sección 15). Objetivo de producto
explícito (decisión del usuario, 2026-10-12): **igualar o superar a ref
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
- No hay paridad con ref Enterprise ni **ref One** (ALOHA, Fusion):
  **excluidos del alcance de paridad** por decisión (2026-10-12); solo se
  documenta la exclusión en [PARITY_MATRIX.md](PARITY_MATRIX.md) §E.
- No hay compatibilidad total con la sintaxis de config de ref. La
  migración se hace con el **conversor de configuración** (herramienta de
  migración; CLI `eqproxy config import ref --input config-de-referencia --output
  eqproxy.toml`, módulo `eqproxy-ref-import`), que convierte las
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
  API de Lua de ref, sería en un proceso aislado fuera del binario y con un
  ADR nuevo.

Para cada plugin se define (plantilla de plugin): puntos de extensión (fetch,
converter, action, service, task — equivalentes a los de ref), modelo de
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
pruebas diferenciales frente a ref donde la semántica deba coincidir,
conformidad de protocolos, carga sostenida, inyección de fallos, renovación de
certificados, cambios de config bajo tráfico, clientes/backends lentos, caídas
de backends, streaming largo, DNS cambiante, agotamiento de recursos,
reinicio/recuperación, plugins que exceden límites.

Herramientas y sus límites declarados: `cargo fmt`, `cargo clippy`,
`cargo test`, auditoría de dependencias y licencias (`cargo-deny` o
equivalente), Miri **solo** para componentes compatibles (no prueba la
ausencia de bugs del servicio completo), sanitizers/herramientas de
concurrencia cuando proceda.

## 13. Registro de diferencias semánticas vs ref

- Toda capacidad de [PARITY_MATRIX.md](PARITY_MATRIX.md) declara la semántica
  que preserva y las diferencias conocidas. “Función parecida” ≠ “compatible”.
- Las diferencias semánticas documentadas (selección inicial, a crecer):
  1. **Recarga de configuración:** ref crea un proceso nuevo y hereda
     sockets; EQProxy aplica snapshots en caliente dentro del proceso. Las
     métricas **no** se reinician en una aplicación de config (diferencia
     intencionada; ver PP-03). El “reemplazo de proceso” se contempla solo
     para cambios que lo requieran.
  2. **Formato de configuración:** TOML canónico (propuesto, ADR-0002), no la
     sintaxis ref; el conversor ref → EQProxy traduce un subconjunto
     con informe de equivalencia por directiva (pipeline: `config-de-referencia` →
     parser de ref sin pérdidas → representación estructurada →
     traducción → validación y generación → `eqproxy.toml` + informe de
     conversión).
3. **Estado de servidor DRAIN vs MAINT:** semántica explícita propia,
   documentada por comparación con `set server ... state drain/maint`.
4. **Framing HTTP (Fase 2a):** EQProxy rechaza todo mensaje ambiguo (CL+TE,
   duplicados, TE ≠ `chunked`, absolute-form, obs-fold) en lugar de
   normalizarlo como puede hacer ref en algunos casos; `CONNECT`/`Upgrade`
   responden 501 hasta Fase 4. Trailers solo vacíos o sin cabeceras de framing.
5. (Registro vivo: cada fila de la matriz lo amplía.)

## 14. Estado y evidencia del proyecto

| Área | Estado | Evidencia |
|---|---|---|
| Investigación Fase 0 (ref, dolor usuario, ecosistema Rust) | Probado* | Fuentes con URL en docs; *verificado por lectura de fuentes, no por ejecución |
| Especificación y alcance | Diseñado | Este documento |
| Matriz de paridad | Diseñado | PARITY_MATRIX.md (incompleta por diseño, huecos declarados) |
| Código Fase 1 (proxy TCP, config TOML, CLI) | **Probado** (2026-10-12) | 30 tests en verde: 19 unit + 6 E2E con sockets reales + 5 E2E por el binario real `eqproxy` (incl. SIGINT). fmt/clippy `-D warnings` en verde; 0 `unsafe` propios (`forbid(unsafe_code)`); cargo-deny y cargo-machete en verde; SBOM en `sbom/` |
| Código Fase 2a (HTTP/1.1 estricto, T01–T03, timeouts por fase, streaming) | **Probado** (2026-10-12) | 47 tests en verde: 27 unit + 14 E2E con sockets reales (6 TCP + 8 HTTP) + 6 E2E por el binario real (incl. smuggling rechazado con 400 y SIGINT). fmt/clippy `-D warnings` en verde |
| Benchmarks | **No medidos** | Solo plan (BENCHMARK_PLAN.md) |
