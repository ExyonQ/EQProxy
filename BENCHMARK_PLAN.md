# BENCHMARK_PLAN.md — Plan de benchmarks honestos y estudio de tareas operativas

- Versión del documento: 0.1 (Fase 0) — **plan, no resultados. No se ha medido nada.**
- Fecha: 2026-10-12
- Oponente fijado: **ref 3.4.6 OSS** (build de referencia, ADR-0003);
  binario real registrado con `ref -vv` en cada ejecución.

## 0. Objetivo de producto (decisión del usuario, 2026-10-12)

Igualar o superar a ref 3.4.6 LTS en los escenarios de este plan en:
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
ref:                              3.4.6 + salida de `ref -vv`
Hardware:                             CPU (modelo, núcleos, SMT, frecuencia/turbo),
                                      RAM, disco, NIC
SO y kernel:                          distro, versión exacta, cmdline, governor,
                                      aislamiento irqbalance/numa
Afinidad de CPU:                      taskset/cpuset para generador, EQProxy, ref, backends
Límites de red:                       ulimit -n, somaxconn, rmem/wmem, ephemeral ports
Versiones y flags de compilación:     EQProxy: cargo profile + flags; ref: -vv
Configuración completa:               pegada íntegra (EQProxy y ref)
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

| ID | Escenario | Objetivo | Métricas objetivo (≥ ref) | Notas |
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
| RPS / throughput | Generador (histograma completo publicado) | ≥ ref (Mejor o Comparable) |
| Conexiones (aceptadas/s y sostenidas) | Generador + `ss`/contadores | ≥ ref |
| Latencia P50/P95/P99 (+P99.9) | Histogramas del generador, corregido de coordinated omission | ≥ ref (menor es mejor) |
| CPU | `perf stat`/cgroup: ciclos, instrucciones, % por proceso | ≤ ref |
| Memoria | RSS máx y en régimen, + `heaptrack` si se investiga | ≤ ref |
| Errores | Por clase (timeout, 5xx, rechazos) | 0 diferencias injustificadas |
| Colas y timeouts | Métricas internas de ambos productos | Comparables |
| Recuperación | Tiempo hasta recuperar p99 tras S-FAIL-01 | ≤ ref |
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

Comparar EQProxy vs ref 3.4.6 en tareas reales; **no** se generaliza a
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
| T-10 | Migrar una config ref compatible | tiempo, directivas no soportadas identificadas, éxito |

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
