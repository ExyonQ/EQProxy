# ADR-0001: Plataforma de producción y niveles de soporte

- Estado: **Aceptado** (Fase 0)
- Fecha: 2026-10-12

## Contexto

EQProxy debe elegir una plataforma de producción antes de diseñar el dataplane
(brief, sección 5: "Primero elige una plataforma de producción. Declara por
separado soporte experimental para otras plataformas"). El stack elegido
(tokio/hyper/rustls, ver ADR-0004) es portable, pero las opciones de socket
(`SO_REUSEPORT`, `TCP_FASTOPEN`, `TCP_DEFER_ACCEPT`), los límites de
descriptores y el comportamiento de `recvmmsg`/buffer UDP varían por SO.

## Decisión

- **Plataforma de producción (tier 1): Linux x86_64 con glibc** (kernel ≥ 5.10,
  una distribución con soporte activo). Toda la validación de rendimiento,
  seguridad y operación se realiza aquí.
- **Soporte experimental (tier 2):** Linux aarch64, macOS (desarrollo y tests),
  musl (binarios estáticos). Compilan y pasan tests funcionales, sin garantía
  de rendimiento ni de semántica de socket.
- **No soportado de momento:** Windows. Ninguna afirmación de compatibilidad.

## Alternativas consideradas

1. **musl como tier 1** (binarios estáticos, despliegue trivial): rechazado
   porque el rendimiento del allocator y el soporte de algunas dependencias TLS
   lo hacen más arriesgado como base de benchmarks comparativos.
2. **Multiplataforma tier 1 desde el día 1:** rechazado; multiplica la matriz
   de pruebas sin aportar a la corrección. La regla del proyecto es
   corrección → seguridad → operabilidad → rendimiento.
3. **aarch64 tier 1** (instancias Graviton/Ampere): aplazado; se añadirá como
   tier 1 solo cuando exista presupuesto de benchmarks dedicado.

## Consecuencias

- Los benchmarks de BENCHMARK_PLAN.md declaran Linux x86_64 glibc; cualquier
  resultado en otra plataforma se etiqueta como no comparable.
- La detección de plataforma se hace en compilación (`cfg`), con fallo
  explícito en funciones no implementadas (nunca stubs que devuelvan éxito).
- Los ADR de fases posteriores pueden promover plataformas con evidencia
  (tests + benchmarks) pero nunca degradar tier 1 sin nuevo ADR.
