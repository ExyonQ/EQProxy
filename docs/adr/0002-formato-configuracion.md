# ADR-0002: Formato canónico de configuración

- Estado: **Propuesta — pendiente de aprobación** (el estudio cierra en Fase 0;
  la decisión final se presenta al responsable del proyecto)
- Fecha: 2026-10-12
- Relacionado: [SPEC.md](../../SPEC.md) §Configuración

## Contexto

El brief (sección 6) exige un formato canónico, tipado y validable, con errores
que incluyan archivo, línea, campo, causa y ejemplo de corrección; prohíbe
parsers de protocolos complejos escritos desde cero si existen bibliotecas
mantenidas. Se debe elegir **un** formato canónico (no varios equivalentes),
evaluando alternativas primero.

## Criterios de evaluación (medibles)

| # | Criterio | Cómo se mide |
|---|---|---|
| C1 | Tipado estático del modelo | ¿serde puede representar el modelo sin `Value` dinámico en el camino feliz? |
| C2 | Errores con archivo/línea/campo | ¿El parser devuelve spans de error con offset/línea? ¿Campo con `serde_path_to_error`? |
| C3 | Sin parser propio | ¿Existe crate mantenida (MIT/Apache) que haga el parsing? |
| C4 | Ambigüedad semántica | ¿Dos textos distintos producen significados distintos, o hay coerciones/alias ocultos? |
| C5 | Comentarios y ergonomía de edición | ¿El formato soporta comentarios para operadores humanos? |
| C6 | Migración desde ref | ¿La estructura sección→tabla mapea sin fricción? |
| C7 | Ecosistema y herramientas | Editores, linters, generación de esquema (schemars/jsonschema). |
| C8 | Secretos | ¿Se pueden referenciar/aislar secretos sin exponerlos en diffs? |

## Alternativas evaluadas

### A) TOML (crate `toml` + serde + serde_path_to_error) — **propuesto**
- C1 sí (structs serde). C2 sí: `toml::de::Error` expone spans con línea/columna;
  `serde_path_to_error` aporta el camino del campo. C3 sí. C4 sí: gramática
  no ambigua, sin coerciones de tipo sorprendentes, sin anclas. C5 sí
  (comentarios `#`). C6 alta: `[frontend.web]`, `[[backend.api.server]]`
  mapean directamente a las secciones tipo ref. C7 alto (estándar Rust).
  C8 resolvible con `secret_ref = "file:///..."` / variables de entorno
  referenciadas, nunca literales (validación semántica lo haría fallar).
- Contra: arrays-de-tablas anidados son verbosos para listas de reglas largas.

### B) YAML
- C5/C7 altos (ecosistema K8s), pero **C4 negativo**: tipado implícito
  (`no`, `on`, `1.0` como float/str), anclas y alias con expansión difícil de
  trazar, "Norway problem". Choca con el requisito de "rechazo seguro de
  mensajes ambiguos" del modelo de amenazas. C2 posible pero los errores
  semánticos post-parse siguen siendo difíciles de ubicar. Rechazado.

### C) DSL tipo ref (texto `frontend x / mode tcp / ...`)
- C6 máxima, pero **C3 negativo**: exige escribir y mantener un parser propio,
  que el brief desaconseja explícitamente. Rechazado como formato canónico.
  **Nota:** la migración desde archivos ref se cubre mediante el
  **conversor de configuración** (herramienta de migración ref → EQProxy,
  Fase 8), que usa un **parser de configuración de ref** como etapa interna
  (gramática de líneas; parser propio justificado porque no existe una
  biblioteca mantenida estándar para esa gramática; sujeto a fuzzing) y traduce
  a TOML con clasificación ternaria de directivas e informe de conversión. Eso
  no convierte el DSL en canónico.

### D) RON (Rusty Object Notation)
- C1/C2/C5 buenos (serde nativo, comentarios, spans). C7 bajo: pocas
  herramientas de editor, poco conocimiento operativo. No aporta ventaja sobre
  TOML para este dominio. Rechazado.

### E) JSON
- C2/C3 excelentes, pero sin comentarios (C5 negativo) y con coste de edición
  alto para operadores. Útil solo como formato de **intercambio** (API),
  no como formato de autoría. Rechazado como canónico.

## Propuesta de decisión

**TOML como formato canónico**, con:

1. `schema_version = 1` obligatorio (esquema versionado; migraciones explícitas).
2. Modelo tipado en `eqproxy-config` (structs serde) + **validación semántica**
   aparte (referencias inexistentes, reglas inaccesibles/contradictorias cuando
   sea viable, advertencias de configuraciones peligrosas, estimación de
   recursos con supuestos visibles).
3. Errores con archivo, línea, campo, causa y ejemplo de corrección
   (spans TOML + `serde_path_to_error`).
4. Secretos solo por referencia; `config export` los sustituye por `***`.
5. JSON Schema derivable con schemars para editores y CI.

## Qué queda pendiente de aprobación

- Confirmar TOML frente a YAML (el único criterio a favor de YAML sería una
  restricción organizativa de ecosistema, no técnica).
- Límite de tamaño de config y número de reglas (presupuesto de recursos).

## Consecuencias

- Si se aprueba: la Fase 1 implementa `eqproxy-config` sobre TOML y el
  conversor ref → EQProxy (Fase 8) traduce a TOML clasificando cada
  directiva: convertida / requiere revisión / rechazada explícitamente (nunca
  omitida en silencio; «archivo generado» ≠ «migración funcionalmente
  equivalente»).
- Si se rechaza: este ADR se sustituye por otro y se rehace el §Configuración
  de SPEC.md; el trabajo de la Fase 1 aún no iniciado queda sin coste.
