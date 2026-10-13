# BENCHMARK_PLAN.md — Honest benchmark plan and operator-task study

Language: **English** · [Español](#español)

- Document version: 0.1 (Phase 0) — **plan, not results. Nothing has been measured.**
- Date: 2026-10-12
- Pinned opponent: **the reference proxy 3.4.6 OSS** (reference build, ADR-0003);
  the real binary is recorded with `-vv` on every run.

## 0. Product goal (user decision, 2026-10-12)

Match or beat the reference proxy 3.4.6 LTS in the scenarios of this plan on:
**RPS, connections (sustained/accepted), memory, CPU and P50, P95 and P99
latencies** (P99.9 is added as a long-tail metric). This is a **goal with an
acceptance criterion**, not a result: it is only declared reached when
reproducible measurements of this plan exist. Every loss is recorded and
profiled before optimizing (brief §12); favourable scenarios are never
cherry-picked.

## 1. Honesty principles

1. **Functionally equivalent** configurations before comparing; if they are
   not, the result is classified "Not comparable" with a reason.
2. Raw data published next to every result; without data there is no claim.
3. Minimum **5** repetitions per scenario; median and spread (min–max) are
   reported, never the single best run.
4. Both products on the same hardware, same OS, same CPU affinity, with no
   parasitic load measured during the run.
5. A result is classified only as: **Better / Comparable / Worse / Not
   comparable / Not measured**. "Comparable" = differences within the variation
   observed between repetitions.

## 2. Disclosure template (mandatory per run)

```
EQProxy date and commit:              <sha> / state (Phase X)
Reference proxy:                      3.4.6 + `-vv` output
Hardware:                             CPU (model, cores, SMT, frequency/turbo),
                                      RAM, disk, NIC
OS and kernel:                        distro, exact version, cmdline, governor,
                                      irqbalance/numa isolation
CPU affinity:                         taskset/cpuset for generator, EQProxy, the reference proxy, backends
Network limits:                       ulimit -n, somaxconn, rmem/wmem, ephemeral ports
Versions and build flags:             EQProxy: cargo profile + flags; the reference proxy: -vv
Full configuration:                   pasted in full (EQProxy and the reference proxy)
TLS:                                  version, ciphers, key size, test cert, session tickets on/off
Generator:                            tool + version + exact flags
Dataset:                              payload size/distribution, route mix, % keep-alive
Duration and repetitions:             warm-up + duration + number of runs
Raw data:                             path to the results directory (histograms, CSV, CPU/RSS)
```

## 3. Scenarios

Mandatory equivalence: same backends (our own versioned echo/origin server),
same topology (separate generator/proxy/backend machines where possible; if
not, the limitation is declared).

| ID | Scenario | Objective | Target metrics (≥ the reference proxy) | Notes |
|---|---|---|---|---|
| S-TCP-01 | TCP passthrough, new connections, high rate | A1 | RPS/connections, CPU, P50/P95/P99 latency | — |
| S-TCP-02 | TCP, long connections with bidirectional streaming | A1, A19 | Sustained connections, memory/connection, CPU | — |
| S-H1-01 | HTTP/1.1 keep-alive, 1 KiB payload | A2 | RPS, P50/P95/P99 latencies, CPU, memory | — |
| S-H1-02 | HTTP/1.1 keep-alive, 1 MiB payload | A2 | Throughput, CPU, memory | — |
| S-H1-03 | HTTP/1.1 new connection per request | A2 | Connections/s, RPS, CPU | Includes the TCP handshake |
| S-H1-04 | HTTP/1.1 with complex rules (20 ACLs, rewrites, headers) | C1–C5 | RPS, latencies, CPU | Semantically identical rules on both |
| S-H1-05 | HTTP/1.1 with 500 backends and active health checks | B1, B11 | RPS, CPU, memory, latencies | — |
| S-TLS-01 | TLS termination, keep-alive, 1 KiB payload | A11 | RPS, latencies, CPU, memory | Identical cipher and cert |
| S-TLS-02 | TLS, new connections (massive handshake) | A11 | Handshakes/s, CPU, memory | — |
| S-H2-01 | HTTP/2 multiplexed (100 streams/connection) | A3 | RPS, latencies, CPU, memory | h2 over TLS |
| S-H2-02 | HTTP/2 large payload | A3 | Throughput, CPU | — |
| S-H3-01 | HTTP/3 (QUIC) 1 KiB payload | A4 | RPS, latencies, CPU, memory | Only if both support H3 in the comparison |
| S-H3-02 | HTTP/3 massive handshake (0-RTT on/off documented) | A4 | Handshakes/s, CPU | — |
| S-STR-01 | Prolonged streaming (upload+download) | A19 | Memory/connection, CPU, stability | 10 minutes minimum |
| S-FAIL-01 | Backend failure and recovery | B8, B17 | Recovery time, errors | Identical health-check interval |
| S-CFG-01 | Config application under traffic | D9 | P99 latency impact, errors, metric resets | PP-04/PP-05 metric |
| S-OVL-01 | Sustained overload (>maxconn) | A18, T08 | Correct errors, memory, queues | — |
| S-PLG-01 | With and without plugins loaded | SPEC §10 | Δ RPS/latency/CPU | Phase 7+ only |

## 4. Metrics

| Metric | How it is measured | Target |
|---|---|---|
| RPS / throughput | Generator (full histogram published) | ≥ the reference proxy (Better or Comparable) |
| Connections (accepted/s and sustained) | Generator + `ss`/counters | ≥ the reference proxy |
| P50/P95/P99 latency (+P99.9) | Generator histograms, corrected for coordinated omission | ≥ the reference proxy (lower is better) |
| CPU | `perf stat`/cgroup: cycles, instructions, % per process | ≤ the reference proxy |
| Memory | Peak and steady RSS, + `heaptrack` when investigating | ≤ the reference proxy |
| Errors | By class (timeout, 5xx, rejections) | 0 unexplained differences |
| Queues and timeouts | Both products' internal metrics | Comparable |
| Recovery | Time until p99 recovers after S-FAIL-01 | ≤ the reference proxy |
| Reload impact | Δ p99 and errors during S-CFG-01 | Documented and bounded (PP-04/05) |

Product goal (user): Better or Comparable on **all** the metrics above (RPS,
connections, memory, CPU, P50/P95/P99) for scenarios S-TCP-01, S-H1-01,
S-H1-02, S-TLS-01, S-H2-01 and S-H3-01 at minimum; the rest are reported too
(losing scenarios are published as well).

## 5. Bias controls

1. **Generator bottleneck:** the generator is calibrated against a local sink
   before each series; if the generator saturates its CPU, the series is
   invalid (discarded and declared).
2. **Coordinated omission:** tools that do not correct it (or do not document
   it) are flagged; for latencies a correcting generator is preferred (e.g.
   wrk2 for HTTP/1.1 — version to be pinned) and the full histogram is
   published.
3. **Non-equivalent configurations:** per-scenario equivalence checklist
   (timeouts, keep-alive, compression, buffers) attached to the data.
4. **Variability:** ≥ 5 repetitions; median + range; environment variation
   (frequency, thermal) is reported.
5. **Different work:** if EQProxy does more work (e.g. structured logs,
   sampled explain), it is also measured with that feature off and both
   figures are published.
6. **Scenario selection:** every ID in §3 is run and published, including the
   unfavourable ones.

## 6. Tools (exact version to be pinned when running)

| Use | Candidates (state: unverified) | Requirement |
|---|---|---|
| HTTP/1.1 | wrk2, vegeta, fortio | CO correction or full histograms |
| HTTP/2 | h2load (nghttp2), fortio | Configurable multiplexed streams |
| HTTP/3 | **pending selection** (open risk: PARITY §F3) | QUIC/H3 support, documented CO, no self-saturation |
| TLS/certs | openssl s_client, cert generation scripts | Versioned test certs |
| System | perf, pidstat, ss, cgroup v2 | CPU/RSS/connections per process |
| Conformance | h2spec (HTTP/2); H3 conformance tooling to be selected | Correct protocol ≠ fast |

## 7. Operator-task study (UX, brief §13)

Compare EQProxy vs the reference proxy 3.4.6 on real tasks; results are **not**
generalized to "all users" from internal tests.

| ID | Task | Metrics |
|---|---|---|
| T-01 | Create a basic proxy | time, errors, documentation lookups, success |
| T-02 | Add a backend | same |
| T-03 | Configure TLS | same |
| T-04 | Diagnose a 502/503 | time to correct cause, perceived clarity (scale), accuracy |
| T-05 | Identify a timeout | time to the concrete timeout, accuracy |
| T-06 | Apply a change | time, errors, perceived risk |
| T-07 | Revert the change | time, recovery success |
| T-08 | Drain a server | time, mistake made, success |
| T-09 | Detect a wrong rule | time, use of `explain`/stats, accuracy |
| T-10 | Migrate a reference-proxy-compatible config | time, unsupported directives identified, success |

Methodology: participants with declared experience (novices/experts),
counterbalanced tool order, timed tasks, short clarity questionnaire;
participants, prior experience and sample limitations are recorded (small n ⇒
exploratory conclusions, not market metrics).

## 8. Expected results vs commitments

- This plan does **not** anticipate results. The classification is published in
  Phase 9 with raw data.
- If EQProxy loses a scenario: it is recorded ("Worse"), profiled (perf/flame
  graphs) and a decision is made to optimize or accept the gap with an ADR.
  Regressions are never hidden and an unfavourable scenario is never withdrawn.
- While there is no data, the only valid sentence about performance is:
  **"Not measured"**.

---

# Español

Idioma: [English](#benchmark_planmd--honest-benchmark-plan-and-operator-task-study) · **Español**

- Versión del documento: 0.1 (Fase 0) — **plan, no resultados. No se ha medido nada.**
- Fecha: 2026-10-12
- Oponente fijado: **el proxy de referencia 3.4.6 OSS** (build de referencia, ADR-0003);
  binario real registrado con `-vv` en cada ejecución.

## 0. Objetivo de producto (decisión del usuario, 2026-10-12)

Igualar o superar al proxy de referencia 3.4.6 LTS en los escenarios de este plan en:
**RPS, conexiones (sostenidas/aceptadas), memoria, CPU y latencias P50, P95 y
P99** (se añade P99.9 como métrica de cola larga). Esto es un **objetivo con
criterio de aceptación**, no un resultado: solo se declara alcanzado cuando
existan mediciones reproducibles de este plan. Toda pérdida se registra y se
perfila antes de optimizar (brief §12); nunca se eligen solo escenarios
favorables.

## 1. Principios de honestidad

1. Configuraciones **funcionalmente equivalentes** antes de comparar; si no lo
   son, se clasifica «No comparable» con motivo.
2. Datos brutos publicados junto a cada resultado; sin datos, no hay afirmación.
3. Repeticiones mínimas **5** por escenario; se reportan mediana y dispersión
   (min–max), nunca el mejor run aislado.
4. Ambos productos en el mismo hardware, mismo SO, misma afinidad de CPU, sin
   carga parásita medida durante la ejecución.
5. Un resultado se clasifica solo así: **Mejor / Comparable / Peor / No
   comparable / No medido**. “Comparable” = diferencias dentro de la variación
   observada entre repeticiones.

## 2. Plantilla de divulgación (obligatoria por ejecución)

```
Fecha y commit de EQProxy:            <sha> / estado (Fase X)
Proxy de referencia:                3.4.6 + salida de `-vv`
Hardware:                             CPU (modelo, núcleos, SMT, frecuencia/turbo),
                                      RAM, disco, NIC
SO y kernel:                          distro, versión exacta, cmdline, governor,
                                      aislamiento irqbalance/numa
Afinidad de CPU:                      taskset/cpuset para generador, EQProxy, el proxy de referencia, backends
Límites de red:                       ulimit -n, somaxconn, rmem/wmem, ephemeral ports
Versiones y flags de compilación:     EQProxy: cargo profile + flags; el proxy de referencia: -vv
Configuración completa:               pegada íntegra (EQProxy y el proxy de referencia)
TLS:                                  versión, cifrados, tamaño de clave, cert de prueba, sesión tickets on/off
Generador:                            herramienta + versión + flags exactos
Dataset:                              tamaño/distribución de payloads, mix de rutas, % keep-alive
Duración y repeticiones:              warm-up + duración + nº de runs
Datos brutos:                         ruta al directorio de resultados (histogramas, CSV, CPU/RSS)
```

## 3. Escenarios

Equivalencia obligatoria: mismos backends (servidor de eco/origen propio,
versionado), misma topología (máquinas separadas generador/proxy/backend cuando
sea posible; si no, se declara la limitación).

| ID | Escenario | Objetivo | Métricas objetivo (≥ el proxy de referencia) | Notas |
|---|---|---|---|---|
| S-TCP-01 | TCP passthrough, conexiones nuevas, alta tasa | A1 | RPS/conexiones, CPU, latencia P50/P95/P99 | — |
| S-TCP-02 | TCP, conexiones largas con streaming bidireccional | A1, A19 | Conexiones sostenidas, memoria/conexión, CPU | — |
| S-H1-01 | HTTP/1.1 keep-alive, payload 1 KiB | A2 | RPS, latencias P50/P95/P99, CPU, memoria | — |
| S-H1-02 | HTTP/1.1 keep-alive, payload 1 MiB | A2 | Throughput, CPU, memoria | — |
| S-H1-03 | HTTP/1.1 conexión nueva por petición | A2 | Conexiones/s, RPS, CPU | Incluye handshake TCP |
| S-H1-04 | HTTP/1.1 con reglas complejas (20 ACLs, rewrites, headers) | C1–C5 | RPS, latencias, CPU | Reglas idénticas en semántica en ambos |
| S-H1-05 | HTTP/1.1 con 500 backends y health checks activos | B1, B11 | RPS, CPU, memoria, latencias | — |
| S-TLS-01 | TLS termination, keep-alive, payload 1 KiB | A11 | RPS, latencias, CPU, memoria | Cifrado y cert idénticos |
| S-TLS-02 | TLS, conexiones nuevas (handshake masivo) | A11 | Handshakes/s, CPU, memoria | — |
| S-H2-01 | HTTP/2 multiplexado (100 flujos/conexión) | A3 | RPS, latencias, CPU, memoria | h2 sobre TLS |
| S-H2-02 | HTTP/2 payload grande | A3 | Throughput, CPU | — |
| S-H3-01 | HTTP/3 (QUIC) payload 1 KiB | A4 | RPS, latencias, CPU, memoria | Solo si ambos soportan H3 en la comparación |
| S-H3-02 | HTTP/3 handshake masivo (0-RTT on/off documentado) | A4 | Handshakes/s, CPU | — |
| S-STR-01 | Streaming prolongado (subida+descarga) | A19 | Memoria/conexión, CPU, estabilidad | 10 min mínimo |
| S-FAIL-01 | Caída de backend y recuperación | B8, B17 | Tiempo de recuperación, errores | Health check interval idéntico |
| S-CFG-01 | Aplicación de config bajo tráfico | D9 | Impacto latencia P99, errores, resets de métricas | Métrica PP-04/PP-05 |
| S-OVL-01 | Sobrecarga sostenida (>maxconn) | A18, T08 | Errores correctos, memoria, colas | — |
| S-PLG-01 | Con y sin plugins cargados | SPEC §10 | Δ de RPS/latencia/CPU | Solo Fase 7+ |

## 4. Métricas

| Métrica | Cómo se mide | Objetivo |
|---|---|---|
| RPS / throughput | Generador (histograma completo publicado) | ≥ el proxy de referencia (Mejor o Comparable) |
| Conexiones (aceptadas/s y sostenidas) | Generador + `ss`/contadores | ≥ el proxy de referencia |
| Latencia P50/P95/P99 (+P99.9) | Histogramas del generador, corregido de coordinated omission | ≥ el proxy de referencia (menor es mejor) |
| CPU | `perf stat`/cgroup: ciclos, instrucciones, % por proceso | ≤ el proxy de referencia |
| Memoria | RSS máx y en régimen, + `heaptrack` si se investiga | ≤ el proxy de referencia |
| Errores | Por clase (timeout, 5xx, rechazos) | 0 diferencias injustificadas |
| Colas y timeouts | Métricas internas de ambos productos | Comparables |
| Recuperación | Tiempo hasta recuperar p99 tras S-FAIL-01 | ≤ el proxy de referencia |
| Impacto de recargas | Δ p99 y errores durante S-CFG-01 | Documentado y acotado (PP-04/05) |

Objetivo de producto (usuario): Mejor o Comparable en **todas** las métricas
anteriores (RPS, conexiones, memoria, CPU, P50/P95/P99) para los escenarios
S-TCP-01, S-H1-01, S-H1-02, S-TLS-01, S-H2-01 y S-H3-01 como mínimo; el resto
se reporta igualmente (se publican también los escenarios que pierdan).

## 5. Controles contra sesgos

1. **Cuello de botella del generador:** se calibra el generador contra un sink
   local antes de cada serie; si el generador satura su CPU, la serie es
   inválida (se descarta y se declara).
2. **Coordinated omission:** herramientas que no lo corrijen (o no lo documentan)
   se marcan; para latencias se prefiere generador con corrección (p. ej. wrk2
   para HTTP/1.1 — versión a fijar) y se publica el histograma completo.
3. **Configuraciones no equivalentes:** checklist de equivalencia por escenario
   (timeouts, keep-alive, compresión, buffers) adjunta a los datos.
4. **Variabilidad:** ≥ 5 repeticiones; mediana + rango; se reporta la variación
   del entorno (frecuencia, termal).
5. **Trabajo distinto:** si EQProxy hace más trabajo (p. ej. logs estructurados,
   explain con muestreo), se mide también con esa función desactivada y se
   publican ambas cifras.
6. **Selección de escenarios:** todos los IDs de §3 se ejecutan y publican,
   incluidos los desfavorables.

## 6. Herramientas (a fijar versión exacta al ejecutar)

| Uso | Candidatos (estado: sin verificar) | Requisito |
|---|---|---|
| HTTP/1.1 | wrk2, vegeta, fortio | Corrección de CO o histogramas completos |
| HTTP/2 | h2load (nghttp2), fortio | Flujos multiplexados configurables |
| HTTP/3 | **pendiente de selección** (riesgo abierto: PARITY §F3) | Soporte QUIC/H3, CO documentado, sin auto-saturación |
| TLS/certs | openssl s_client, scripts de generación de certs | Certs de prueba versionados |
| Sistema | perf, pidstat, ss, cgroup v2 | CPU/RSS/conexiones por proceso |
| Conformidad | h2spec (HTTP/2); tooling de conformidad H3 por seleccionar | Protocolo correcto ≠ rápido |

## 7. Estudio de tareas operativas (UX, brief §13)

Comparar EQProxy vs el proxy de referencia 3.4.6 en tareas reales; **no** se generaliza a
“todos los usuarios” desde pruebas internas.

| ID | Tarea | Métricas |
|---|---|---|
| T-01 | Crear un proxy básico | tiempo, errores, consultas a documentación, éxito |
| T-02 | Añadir un backend | idem |
| T-03 | Configurar TLS | idem |
| T-04 | Diagnosticar un 502/503 | tiempo hasta causa correcta, claridad percibida (escala), acierto |
| T-05 | Identificar un timeout | tiempo hasta el timeout concreto, acierto |
| T-06 | Aplicar un cambio | tiempo, errores, percepción de riesgo |
| T-07 | Revertir el cambio | tiempo, éxito de recuperación |
| T-08 | Drenar un servidor | tiempo, error cometido, éxito |
| T-09 | Detectar una regla incorrecta | tiempo, uso de `explain`/stats, acierto |
| T-10 | Migrar una config compatible con el proxy de referencia | tiempo, directivas no soportadas identificadas, éxito |

Metodología: participantes con experiencia declarada (novatos/expertos),
orden de herramientas contrarrestado, tareas cronometradas, cuestionario corto
de claridad; se registran participantes, experiencia previa y limitaciones de
la muestra (n pequeño ⇒ conclusiones exploratorias, no métricas de mercado).

## 8. Resultados esperados vs compromisos

- Este plan **no** anticipa resultados. La clasificación se publica en la Fase 9
  con datos brutos.
- Si EQProxy pierde un escenario: se registra («Peor»), se perfila (perf/flame
  graphs) y se decide optimizar o aceptar el gap con ADR. Nunca se ocultan
  regresiones ni se retira un escenario desfavorable.
- Mientras no haya datos, la única frase válida sobre rendimiento es:
  **«No medido»**.
