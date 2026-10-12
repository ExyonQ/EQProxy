# THREAT_MODEL.md — Modelo de amenazas de EQProxy

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
| T10 | TLS/certificados inválidos (a cliente o backend) | F1/F3 | MITM, interrupción | Validación estricta de cadenas y hostnames al cargar certs (fallo al arrancar con cert inválido); verificación de backend activada por defecto; rotación atómica (PARITY D7) | 2–3 | Diseñado (alcance) |
| T11 | Uso indebido de PROXY protocol (spoofing de IP de cliente) | F1 | Bypass de reglas por IP, evasión de rate limit | PROXY solo se acepta en endpoints declarados (típicamente de red interna); orígenes autorizados por configuración; sin autodetección ambigua | 2–3 | Diseñado |
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
