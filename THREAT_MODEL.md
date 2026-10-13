# THREAT_MODEL.md — EQProxy threat model

Language: **English** · [Español](#español)

- Document version: 0.1 (Phase 0)
- Date: 2026-10-12
- Scope: dataplane, control plane, panel, extensions and supply chain.

## 1. Assets and trust boundaries

**Assets:** client traffic (data in transit), secrets (TLS keys, admin tokens,
backend credentials), configuration, session state (stick-tables, cookies),
metrics/logs (sensitive metadata), service availability.

**Trust boundaries:**

| Boundary | Untrusted side | Rule |
|---|---|---|
| F1 | Clients (Internet) | Every message is hostile until validated: framing, size, rate |
| F2 | Backends | They may fail, return garbage or attack (malformed responses) |
| F3 | Network between proxy and backends/DNS | MITM, DNS cache poisoning, partitions |
| F4 | Admin panel/API | Authenticated operators only; RBAC; audited writes |
| F5 | Plugins (Lua/WASM) | **Untrusted code**; capability denied by default |
| F6 | Config and files (certs, maps) | Validated origin; no path traversal; no plaintext secrets in diffs |
| F7 | Supply chain (crates, toolchain) | Audit and pin versions; no unnecessary own `unsafe` |

**Actors:** remote attacker without credentials; malicious authenticated
client; least-privilege operator; malicious or buggy plugin; compromised
dependency provider.

## 2. Design principles (cross-cutting)

1. **Safe rejection of ambiguous messages:** given two possible
   interpretations of an HTTP message (framing, duplicated lengths, obs-fold,
   spaces in header names), the request is **rejected** (4xx) and counted.
   Never "pick one interpretation".
2. **Consistent normalization:** a single header/URI normalization, applied
   before evaluating rules and before forwarding, identical on all routes
   (avoids parsing desynchronization = smuggling).
3. **Limits everywhere:** per phase and protocol (request line size, header
   size, header count, body size, handshake duration, timeouts, concurrency,
   queues). No unlimited queues (SPEC §7.3).
4. **Least privilege:** plugins without network/files by default; panel with
   RBAC; the dataplane does not read admin storage.
5. **Secrets never in:** logs, diffs, metrics, error responses, panels,
   repository. By reference only (ADR-0002 §C8).
6. **Explicit fail:** everything not implemented fails or is switched off;
   never a stub that returns success.

## 3. Threat table

State: *Designed* (mitigation specified) / *Designed (scope)* (mitigation
defined at high level; detail in its phase) / *Pending* (no mitigation yet).

| # | Threat | Vector | Impact | Mitigation | Phase | State |
|---|---|---|---|---|---|---|
| T01 | Request smuggling (CL/TE, duplicates, malformed chunked) | F1 | Rule bypass, connection poisoning | Rejection of ambiguous messages (§2.1); a single parser shared between analysis and forwarding; differential tests + framing parser fuzzing | 2 | **Tested** (2026-10-12, Phase 2a: smuggling corpus rejected before the backend, `http1::tests::smuggling_corpus_is_rejected` + `e2e_http1.rs::http1_smuggling_corpus_is_rejected_before_backend` ✓; **parser fuzzing pending**, Phase 2c) |
| T02 | HTTP framing ambiguities (obs-fold, spaces in names, duplicated hop headers) | F1 | Same as T01 | Strict normalization + rejection; published and tested normalization rule list | 2 | **Tested** (2026-10-12, Phase 2a: rejection of obs-fold, spaces in names, loose CR/LF and absolute-form; rules published in `eqproxy-net/src/http1.rs` ✓) |
| T03 | Malformed / extreme headers (thousands of headers, giant lines) | F1 | CPU, memory | Per-message limits (header count, total size) with 431/400 and a metric | 2 | **Tested** (2026-10-12, Phase 2a: `MAX_HEADERS`=100, `MAX_HEAD_BYTES`=16 KiB, `MAX_LINE_BYTES`=8 KiB → 431 + `http_requests_rejected`; `http1::tests::too_many_headers_is_431` ✓) |
| T04 | Slowloris / slow clients | F1 | Connection exhaustion | Per-phase (accept→headers→body) and idle timeouts; `maxconn` limit; slow-client tests | 1–2 | Designed (scope) |
| T05 | Memory exhaustion | F1/F2 | Crash | Per-connection budgets (SPEC §7.3); streaming bodies by default; buffer limits; explicit rejection on exhaustion | 1–2 | Designed (scope) |
| T06 | CPU exhaustion (complex headers, regex, compression) | F1 | Degradation | Rule evaluation time limits; regex only with a bounded engine (no catastrophic backtracking); compression with ratio limit | 4–5 | Designed (scope) |
| T07 | Connection exhaustion (run out of FDs) | F1 | Denial | Connection caps; FD reservation for admin and draining; `eqproxy doctor` warns on `ulimit` | 1 | Designed |
| T08 | Unlimited queues (memory bloat from waiting requests) | F1 | Crash | Bounded queues per backend (`maxqueue`) with timeout and explicit 503 | 3 | Designed (scope) |
| T09 | Abusive decompression (zip bombs) | F2 (if decompression is supported) | CPU/memory | If implemented: ratio and decompressed-size limits; **if unsupported, stated explicitly** | 5–8 | Pending (depends on compression scope) |
| T10 | Invalid TLS/certificates (to client or backend) | F1/F3 | MITM, interruption | Strict chain and hostname validation when loading certs (fail to start with an invalid cert); backend verification on by default; atomic rotation (PARITY D7) | 2–3 | **Tested** (2026-10-13, Phase 2b: invalid cert/key PEM → startup error with field and example; backend TLS verifies certificate **and hostname by default** (Mozilla roots + `ca_file`); untrusted backend cert rejected and counted (`e2e_phase2b.rs::tls_backend_verification_failure_is_counted_and_rejected` + `cli_e2e.rs::validate_reports_missing_cert_file_with_actionable_error` ✓; **rotation/hot-reload pending**, D7) |
| T11 | PROXY protocol misuse (client IP spoofing) | F1 | IP-based rule bypass, rate-limit evasion | PROXY accepted only on declared endpoints (typically internal network); authorised origins by configuration; no ambiguous auto-detection | 2–3 | **Tested** (2026-10-13, send-only: the v1 header is built **from the real socket addresses**, never from client-supplied data — no spoofing surface in send (`e2e_phase2b.rs::proxy_protocol_v1` ✓); **reception pending Phase 3** with the declared-endpoint trust policy) |
| T12 | SSRF via configuration, DNS discovery or plugins | F4/F5/F3 | Access to internal networks, cloud metadata | Destination allowlist for backends by default in safe mode; URL validation in config; plugins without network access (§2.4); DNS with result validation (rebind: minimum TTL + bounded re-resolution) | 4–7 | Designed (scope) |
| T13 | Control plane exposure (panel/API) | F4 | Full proxy control | Listener separation (admin only on a management interface or with TLS+auth); mandatory authentication; RBAC; protected CSRF/sessions; login rate limit; no secrets in responses | 6 | Designed (scope) |
| T14 | Authorization bypass (IDOR, escalation via API) | F4 | Escalation | Per-resource and per-operation authorization; per-endpoint authorization tests; write auditing | 6 | Designed (scope) |
| T15 | Dependency attacks (supply chain) | F7 | Total compromise | `cargo deny`/equivalent (licenses + advisories); pinned `Cargo.lock`; SBOM inventory; `unsafe` review in critical dependencies (FFI); documented periodic updates | 1+ | Designed (scope) |
| T16 | Tenant isolation errors (multi-instance/panel) | F4/F5 | Data leakage between clients | Data model with explicit tenant in the control plane; process isolation for hostile plugins; permission fuzzing review | 6–8 | Designed (scope) |
| T17 | Secret leakage in logs/diffs/errors | F4/F6 | Exposure | Structured redaction of sensitive fields (no ad-hoc regex); `config export` with `***`; log review in tests | 1–3 | Designed (scope) |
| T18 | Attacks on explain/trace diagnostics (data leakage, resource abuse) | F4 | Leakage / degradation | Dedicated permissions; sampling; bounded memory/time; redaction (SPEC §8) | 3–4 | Designed (scope) |
| T19 | HTTP/3-QUIC specific (UDP amplification, state exhaustion, handshake DoS) | F1 | Degradation | QUIC path validation before responding; connection/half-open limits; address validation cookies; tested in Phase 5 with QUIC adversaries | 5 | Designed (scope) |
| T20 | DNS advertisements / rebinding to backends | F3 | SSRF, theft | See T12; DNS cache with bounded TTL; private range blocking in safe mode | 4 | Designed (scope) |

## 4. Secret handling

- By reference (`file://`, `env:`, or the system secret provider), never as
  literals in canonical config if validation detects them (warning or error,
  depending on mode).
- Guaranteed exclusion from: logs, errors, `config diff`, `config export`,
  metrics, panel responses.
- Restart-free rotation (certs and CAs: PARITY D7).
- Log and audit retention policy documented when the panel is implemented.

## 5. Supply chain and inventory

- Component and license inventory generated from `Cargo.lock` (SBOM in a
  standard format, tool to be pinned in Phase 1).
- Allowed licenses: MIT, Apache-2.0, ISC, BSD; anything else requires an ADR.
- Updates: dependencies audited on each release; RustSec advisories monitored;
  documented cadence.
- **Own code 100 % safe Rust:** `#![forbid(unsafe_code)]` in every crate, **no
  exceptions** (user decision, 2026-10-12; tightens the brief). The `unsafe`
  and FFI of dependencies (tokio, hyper, rustls, wasmtime) are inventoried and
  audited (`cargo-geiger` or equivalent) as residual risk (ADR-0004).

## 6. Vulnerability reporting procedure

1. Private channel (to be defined with the project: security email +
   GitHub/GitLab advisories) — **pending setup in Phase 1** (we do not invent a
   channel that does not exist).
2. Acknowledged within ≤ 5 working days; assessment and fix plan within ≤ 30 days.
3. Disclosure coordination with the reporter; advisory publication with CVE
   when applicable.
4. Affected versions and the fix are documented in the changelog.

## 7. Non-protections (explicit)

- **EQProxy is not a WAF.** It does not inspect application payloads for
  exploits (SQLi, XSS, etc.).
- **Rate limiting is not total DDoS protection.** It mitigates rates per key;
  it does not absorb distributed volumetric attacks. Network protection (SYN
  cookies, anycast, scrubbing) lives outside this project.
- No resistance is promised to physical/ICMP-layer attacks nor to link
  bandwidth exhaustion.

## 8. Known residual risk

- The internal `unsafe` of dependencies (including wasmtime, the only plugin
  runtime) does not disappear by writing our own safe code: the audited
  inventory is maintained and, if a plugin's instruction budget is not enough,
  it is isolated in another process (SPEC §10). Lua/mlua is **discarded**
  (C FFI with substantial `unsafe`).
- HTTP/3 adds a new protocol surface (T19); its "experimental" label is kept
  until the Phase 5 adversarial tests are completed.
- Config semantic validation may not detect every dangerous configuration (e.g.
  contradictory rules): it warns, it does not guarantee.

---

# Español

Idioma: [English](#threat_modelmd--eqproxy-threat-model) · **Español**

- Versión del documento: 0.1 (Fase 0)
- Fecha: 2026-10-12
- Alcance: dataplane, control plane, panel, extensiones y cadena de suministro.

## 1. Activos y fronteras de confianza

**Activos:** tráfico de clientes (datos en tránsito), secretos (claves TLS,
tokens de administración, credenciales de backend), configuración, estado de
sesión (stick-tables, cookies), métricas/logs (metadatos sensibles),
disponibilidad del servicio.

**Fronteras de confianza:**

| Frontera | Lado no confiable | Regla |
|---|---|---|
| F1 | Clientes (Internet) | Todo mensaje es hostil hasta validarse: framing, tamaño, ritmo |
| F2 | Backends | Pueden fallar, devolver basura o atacar (respuestas malformadas) |
| F3 | Red entre proxy y backends/DNS | MITM, cache-poisoning de DNS, particiones |
| F4 | Panel/API de administración | Solo operadores autenticados; RBAC; escrituras auditadas |
| F5 | Plugins (Lua/WASM) | **Código no confiable**; capacidad denegada por defecto |
| F6 | Config y archivos (certs, mapas) | Origen validado; sin path traversal; sin secretos en claro en diffs |
| F7 | Cadena de suministro (crates, toolchain) | Auditar y fijar versiones; sin `unsafe` innecesario propio |

**Actores:** atacante remoto sin credenciales; cliente autenticado malicioso;
operador con privilegios mínimos; plugin malicioso o con bug; proveedor de
dependencia comprometido.

## 2. Principios de diseño (transversales)

1. **Rechazo seguro de mensajes ambiguos:** ante dos interpretaciones posibles
   de un mensaje HTTP (framing, longitudes duplicadas, obs-fold, espacios en
   nombres de cabecera), se **rechaza** la petición (4xx) y se contabiliza.
   Nunca se “elige una interpretación”.
2. **Normalización consistente:** una única normalización de cabeceras/URI,
   aplicada antes de evaluar reglas y antes de reenviar, idéntica en todas las
   rutas (evita desincronización de parsing = smuggling).
3. **Límites en todo:** por fase y protocolo (tamaño de línea de petición, de
   cabeceras, número de cabeceras, tamaño de cuerpo, duración de handshake,
   timeouts, concurrencia, colas). Sin colas ilimitadas (SPEC §7.3).
4. **Principio de mínimo privilegio:** plugins sin red/archivos por defecto;
   panel con RBAC; el dataplane no lee almacenamiento de administración.
5. **Secretos nunca en:** logs, diffs, métricas, respuestas de error, paneles,
   repositorio. Solo por referencia (ADR-0002 §C8).
6. **Fail explícito:** todo lo no implementado falla o queda desactivado;
   jamás un stub que devuelve éxito.

## 3. Tabla de amenazas

Estado: *Diseñado* (mitigación especificada) / *Diseñado (alcance)* (mitigación
definida a alto nivel; detalle en su fase) / *Pendiente* (sin mitigación aún).

| # | Amenaza | Vector | Impacto | Mitigación | Fase | Estado |
|---|---|---|---|---|---|---|
| T01 | Request smuggling (CL/TE, duplicados, chunked malformado) | F1 | Bypass de reglas, envenenamiento de conexiones | Rechazo de mensajes ambiguos (§2.1); parser único compartido entre análisis y reenvío; tests diferenciales + fuzzing del parser de framing | 2 | **Probado** (2026-10-12, Fase 2a: corpus de smuggling rechazado antes del backend, `http1::tests::smuggling_corpus_is_rejected` + `e2e_http1.rs::http1_smuggling_corpus_is_rejected_before_backend` ✓; **fuzzing del parser pendiente**, Fase 2c) |
| T02 | Ambigüedades de framing HTTP (obs-fold, espacios en nombres, cabeceras duplicadas de salto) | F1 | Idem T01 | Normalización estricta + rechazo; lista de reglas de normalización publicada y testeada | 2 | **Probado** (2026-10-12, Fase 2a: rechazo de obs-fold, espacios en nombres, CR/LF suelto y absolute-form; reglas publicadas en `eqproxy-net/src/http1.rs` ✓) |
| T03 | Cabeceras malformadas / extremas (miles de cabeceras, líneas gigantes) | F1 | CPU, memoria | Límites por mensaje (nº cabeceras, tamaño total) con 431/400 y métrica | 2 | **Probado** (2026-10-12, Fase 2a: `MAX_HEADERS`=100, `MAX_HEAD_BYTES`=16 KiB, `MAX_LINE_BYTES`=8 KiB → 431 + `http_requests_rejected`; `http1::tests::too_many_headers_is_431` ✓) |
| T04 | Slowloris / clientes lentos | F1 | Agotamiento de conexiones | Timeouts por fase (accept→headers→body) y de inactividad; límite `maxconn`; tests de cliente lento | 1–2 | Diseñado (alcance) |
| T05 | Agotamiento de memoria | F1/F2 | Caída | Presupuestos por conexión (SPEC §7.3); cuerpos con streaming por defecto; límite de buffers; rechazo explícito al agotar | 1–2 | Diseñado (alcance) |
| T06 | Agotamiento de CPU (cabeceras complejas, regex, compresión) | F1 | Degradación | Límites de tiempo de evaluación de reglas; regex solo con motor acotado (sin backtracking catastrófico); compresión con límite de ratio | 4–5 | Diseñado (alcance) |
| T07 | Agotamiento de conexiones (agotar FDs) | F1 | Denegación | Caps de conexiones; reserva de FDs para administración y drenaje; `eqproxy doctor` advierte `ulimit` | 1 | Diseñado |
| T08 | Colas ilimitadas (memory-bloat por peticiones en espera) | F1 | Caída | Colas acotadas por backend (`maxqueue`) con timeout y 503 explícito | 3 | Diseñado (alcance) |
| T09 | Descompresión abusiva (zip bombs) | F2 (si se soporta descompresión) | CPU/memoria | Si se implementa: límite de ratio y de tamaño descomprimido; **si no se soporta, se declara explícitamente** | 5–8 | Pendiente (depende de alcance de compresión) |
| T10 | TLS/certificados inválidos (a cliente o backend) | F1/F3 | MITM, interrupción | Validación estricta de cadenas y hostnames al cargar certs (fallo al arrancar con cert inválido); verificación de backend activada por defecto; rotación atómica (PARITY D7) | 2–3 | **Probado** (2026-10-13, Fase 2b: PEM de cert/clave inválido → error de arranque con campo y ejemplo; TLS de backend verifica certificado **y nombre por defecto** (raíces Mozilla + `ca_file`); cert de backend no confiable rechazado y contado (`e2e_phase2b.rs::tls_backend_verification_failure_is_counted_and_rejected` + `cli_e2e.rs::validate_reports_missing_cert_file_with_actionable_error` ✓; **rotación/recarga pendiente**, D7) |
| T11 | Uso indebido de PROXY protocol (spoofing de IP de cliente) | F1 | Bypass de reglas por IP, evasión de rate limit | PROXY solo se acepta en endpoints declarados (típicamente de red interna); orígenes autorizados por configuración; sin autodetección ambigua | 2–3 | **Probado** (2026-10-13, solo envío: la cabecera v1 se construye **con las direcciones reales del socket**, nunca con datos del cliente — sin superficie de spoofing en envío (`e2e_phase2b.rs::proxy_protocol_v1` ✓); **recepción pendiente Fase 3** con la política de confianza de endpoints declarados) |
| T12 | SSRF vía configuración, descubrimiento DNS o plugins | F4/F5/F3 | Acceso a redes internas, cloud metadata | Allowlist de destinos para backends por defecto en modo seguro; validación de URLs en config; plugins sin acceso a red (§2.4); DNS con validación de resultados (rebind: TTL mínimo + re-resolución acotada) | 4–7 | Diseñado (alcance) |
| T13 | Exposición del control plane (panel/API) | F4 | Control total del proxy | Separación de listeners (admin solo en interfaz de gestión o con TLS+auth); autenticación obligatoria; RBAC; CSRF/sesiones protegidas; rate limit de login; sin secretos en respuestas | 6 | Diseñado (alcance) |
| T14 | Bypass de autorización (IDOR, escalada vía API) | F4 | Escalada | Autorización por recurso y operación; pruebas de autorización por endpoint; auditoría de escritura | 6 | Diseñado (alcance) |
| T15 | Ataques mediante dependencias (supply chain) | F7 | Compromiso total | `cargo deny`/equivalente (licencias + advisories); `Cargo.lock` fijado; inventario SBOM; revisión de `unsafe` en dependencias críticas (FFI); actualizaciones periódicas documentadas | 1+ | Diseñado (alcance) |
| T16 | Errores de aislamiento entre tenants (multi-instancia/panel) | F4/F5 | Fuga de datos entre clientes | Modelo de datos con tenant explícito en control plane; aislamiento de procesos para plugins hostiles; revisión de fuzzing de permisos | 6–8 | Diseñado (alcance) |
| T17 | Fuga de secretos en logs/diffs/errores | F4/F6 | Exposición | Redacción estructurada de campos sensibles (no regex ad-hoc); `config export` con `***`; revisión de logs en tests | 1–3 | Diseñado (alcance) |
| T18 | Ataques al diagnóstico explain/trace (fuga de datos, abuso de recursos) | F4 | Fuga / degradación | Permisos dedicados; muestreo; acotado en memoria/tiempo; redacción (SPEC §8) | 3–4 | Diseñado (alcance) |
| T19 | HTTP/3-QUIC específico (amplificación UDP, state exhaustion, DoS de handshake) | F1 | Degradación | Validación de path de QUIC antes de responder; límite de conexiones/half-open; cookies de validación de dirección; probar en Fase 5 con adversarios QUIC | 5 | Diseñado (alcance) |
| T20 | Anuncios DNS / rebinding hacia backends | F3 | SSRF, robo | Ver T12; DNS cache con TTL acotado; bloqueo de rangos privados en modo seguro | 4 | Diseñado (alcance) |

## 4. Manejo de secretos

- Referenciados (`file://`, `env:`, o proveedor de secretos del sistema), nunca
  literales en config canónica si la validación lo detecta (advertencia o error,
  según modo).
- Exclusión garantizada de: logs, errores, `config diff`, `config export`,
  métricas, respuestas del panel.
- Rotación sin reinicio (certs y CAs: PARITY D7).
- Política de retención de logs y auditoría documentada al implementar el panel.

## 5. Cadena de suministro e inventario

- Inventario de componentes y licencias generado desde `Cargo.lock` (SBOM en
  formato estándar, herramienta a fijar en Fase 1).
- Licencias permitidas: MIT, Apache-2.0, ISC, BSD; cualquier otra requiere ADR.
- Actualizaciones: dependencias auditadas en cada release; advisories de
  RustSec monitorizados; cadencia documentada.
- **Código propio 100 % safe Rust:** `#![forbid(unsafe_code)]` en todo crate,
  **sin excepciones** (decisión del usuario, 2026-10-12; endurece el brief). El
  `unsafe` y la FFI de las dependencias (tokio, hyper, rustls, wasmtime) se
  inventarían y auditan (`cargo-geiger` o equivalente) como riesgo residual
  (ADR-0004).

## 6. Procedimiento de reporte de vulnerabilidades

1. Canal privado (a definir con el proyecto: email de seguridad + advisories de
   GitHub/GitLab) — **pendiente de configurar en Fase 1** (no inventamos un
   canal que no existe).
2. Aviso acusado en ≤ 5 días laborables; evaluación y plan de fix en ≤ 30 días.
3. Coordinación de divulgación con el reporter; publicación de advisory con
   CVE cuando aplique.
4. Las versiones afectadas y el fix se documentan en el changelog.

## 7. No-protecciones (explícito)

- **EQProxy no es un WAF.** No inspecciona payloads de aplicación contra
  exploits (SQLi, XSS, etc.).
- **El rate limiting no es protección DDoS total.** Mitiga tasas por clave; no
  absorbe ataques de volumen distribuidos. La protección de red (SYN cookies,
  anycast, scrubbing) vive fuera de este proyecto.
- No se promete resistencia a ataques de capa física/ICMP ni a agotamiento de
  ancho de banda del enlace.

## 8. Riesgo residual conocido

- El `unsafe` interno de las dependencias (incluido wasmtime, único runtime de
  plugins) no desaparece por escribir código safe propio: se mantiene el
  inventario auditado y, si el presupuesto de instrucciones de un plugin no
  basta, se aísla en otro proceso (SPEC §10). Lua/mlua está **descartado**
  (FFI C con `unsafe` sustancial).
- HTTP/3 añade una superficie de protocolo nueva (T19); su etiqueta
  «experimental» se mantiene hasta completar las pruebas adversariales de Fase 5.
- La validación semántica de config puede no detectar toda configuración
  peligrosa (p. ej. reglas contradictorias): se advierte, no se garantiza.
