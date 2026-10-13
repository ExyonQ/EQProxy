# ADR-0002: Canonical configuration format

Language: **English** · [Español](#español)

- State: **Accepted** (2026-10-12, decision delegated to the project lead:
  "You solve it")
- Date: 2026-10-12
- Related: [SPEC.md](../../SPEC.md) §Configuration

## Context

The brief (section 6) requires a canonical, typed and validatable format, with
errors that include file, line, field, cause and a correction example; it
forbids writing complex protocol parsers from scratch when maintained libraries
exist. **One** canonical format must be chosen (not several equivalent ones),
evaluating alternatives first.

## Evaluation criteria (measurable)

| # | Criterion | How it is measured |
|---|---|---|
| C1 | Static typing of the model | Can serde represent the model without dynamic `Value` on the happy path? |
| C2 | Errors with file/line/field | Does the parser return error spans with offset/line? Field with `serde_path_to_error`? |
| C3 | No own parser | Does a maintained crate (MIT/Apache) do the parsing? |
| C4 | Semantic ambiguity | Do two different texts produce different meanings, or are there hidden coercions/aliases? |
| C5 | Comments and editing ergonomics | Does the format support comments for human operators? |
| C6 | Migration from the reference proxy | Does the section→table structure map without friction? |
| C7 | Ecosystem and tooling | Editors, linters, schema generation (schemars/jsonschema). |
| C8 | Secrets | Can secrets be referenced/isolated without exposing them in diffs? |

## Alternatives evaluated

### A) TOML (`toml` crate + serde + serde_path_to_error) — **proposed**
- C1 yes (serde structs). C2 yes: `toml::de::Error` exposes spans with
  line/column; `serde_path_to_error` provides the field path. C3 yes. C4 yes:
  unambiguous grammar, no surprising type coercions, no anchors. C5 yes
  (`#` comments). C6 high: `[frontend.web]`, `[[backend.api.server]]` map
  directly to reference-proxy-like sections. C7 high (Rust standard).
  C8 solvable with `secret_ref = "file:///..."` / referenced environment
  variables, never literals (semantic validation would make it fail).
- Against: nested arrays-of-tables are verbose for long rule lists.

### B) YAML
- C5/C7 high (K8s ecosystem), but **C4 negative**: implicit typing (`no`,
  `on`, `1.0` as float/str), anchors and aliases with hard-to-trace expansion,
  the "Norway problem". It clashes with the threat model's "safe rejection of
  ambiguous messages" requirement. C2 possible but post-parse semantic errors
  remain hard to locate. Rejected.

### C) Reference-configuration-like DSL (text `frontend x / mode tcp / ...`)
- C6 maximum, but **C3 negative**: it requires writing and maintaining our own
  parser, which the brief explicitly discourages. Rejected as canonical format.
  **Note:** migration from reference proxy files is covered by the
  **configuration converter** (reference proxy → EQProxy migration tool,
  Phase 8), which uses a **reference proxy configuration parser** as an
  internal stage (line grammar; own parser justified because no maintained
  standard library exists for that grammar; subject to fuzzing) and translates
  to TOML with ternary directive classification and a conversion report. That
  does not make the DSL canonical.

### D) RON (Rusty Object Notation)
- C1/C2/C5 good (native serde, comments, spans). C7 low: few editor tools,
  little operational knowledge. It brings no advantage over TOML for this
  domain. Rejected.

### E) JSON
- C2/C3 excellent, but no comments (C5 negative) and a high editing cost for
  operators. Useful only as an **exchange** format (API), not as an authoring
  format. Rejected as canonical.

## Proposed decision

**TOML as the canonical format**, with:

1. Mandatory `schema_version = 1` (versioned schema; explicit migrations).
2. Typed model in `eqproxy-config` (serde structs) + separate **semantic
   validation** (nonexistent references, unreachable/contradictory rules where
   feasible, warnings for dangerous configurations, resource estimation with
   visible assumptions).
3. Errors with file, line, field, cause and correction example (TOML spans +
   `serde_path_to_error`).
4. Secrets by reference only; `config export` replaces them with `***`.
5. JSON Schema derivable with schemars for editors and CI.

## Decision (2026-10-12)

- **TOML confirmed** over YAML: the only criterion in YAML's favour would be
  an organizational ecosystem constraint, not a technical one, and none exists.
- **Resource budget approved and verified with tests:**
  - Maximum config size: **1 MiB** (`MAX_CONFIG_BYTES`); rejected before
    parsing, with an actionable error (file + cause + example).
  - Maximum combined `[listener.*]` + `[backend.*]` sections: **1024**
    (`MAX_SECTIONS`); rejected in semantic validation with the reason
    "too many sections" and a correction example.
  - Limits live in `eqproxy-config` (`load`/`parse_str`/`check`), not only in
    documentation; tests: `oversized_source_is_rejected_with_actionable_error`,
    `source_at_the_limit_is_accepted`,
    `too_many_sections_are_rejected_with_budget_reason`,
    `sections_at_the_budget_are_accepted`.

## Consequences

- If approved: Phase 1 implements `eqproxy-config` over TOML and the reference
  proxy → EQProxy converter (Phase 8) translates to TOML classifying each
  directive: converted / needs review / explicitly rejected (never silently
  dropped; "file generated" ≠ "functionally equivalent migration").
- If rejected: this ADR is replaced by another and SPEC.md §Configuration is
  redone; Phase 1 work not yet started costs nothing.

---

# Español

Idioma: [English](#adr-0002-canonical-configuration-format) · **Español**

- Estado: **Aceptado** (2026-10-12, decisión delegada al responsable del
  proyecto: «Solucionalo tú»)
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
| C6 | Migración desde el proxy de referencia | ¿La estructura sección→tabla mapea sin fricción? |
| C7 | Ecosistema y herramientas | Editores, linters, generación de esquema (schemars/jsonschema). |
| C8 | Secretos | ¿Se pueden referenciar/aislar secretos sin exponerlos en diffs? |

## Alternativas evaluadas

### A) TOML (crate `toml` + serde + serde_path_to_error) — **propuesto**
- C1 sí (structs serde). C2 sí: `toml::de::Error` expone spans con línea/columna;
  `serde_path_to_error` aporta el camino del campo. C3 sí. C4 sí: gramática
  no ambigua, sin coerciones de tipo sorprendentes, sin anclas. C5 sí
  (comentarios `#`). C6 alta: `[frontend.web]`, `[[backend.api.server]]`
  mapean directamente a las secciones tipo las del proxy de referencia. C7 alto
  (estándar Rust).
  C8 resolvible con `secret_ref = "file:///..."` / variables de entorno
  referenciadas, nunca literales (validación semántica lo haría fallar).
- Contra: arrays-de-tablas anidados son verbosos para listas de reglas largas.

### B) YAML
- C5/C7 altos (ecosistema K8s), pero **C4 negativo**: tipado implícito
  (`no`, `on`, `1.0` como float/str), anclas y alias con expansión difícil de
  trazar, "Norway problem". Choca con el requisito de "rechazo seguro de
  mensajes ambiguos" del modelo de amenazas. C2 posible pero los errores
  semánticos post-parse siguen siendo difíciles de ubicar. Rechazado.

### C) DSL tipo configuración de referencia (texto `frontend x / mode tcp / ...`)
- C6 máxima, pero **C3 negativo**: exige escribir y mantener un parser propio,
  que el brief desaconseja explícitamente. Rechazado como formato canónico.
  **Nota:** la migración desde archivos del proxy de referencia se cubre mediante el
  **conversor de configuración** (herramienta de migración del proxy de referencia → EQProxy,
  Fase 8), que usa un **parser de configuración del proxy de referencia** como etapa interna
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

## Decisión (2026-10-12)

- **TOML confirmado** frente a YAML: el único criterio a favor de YAML sería
  una restricción organizativa de ecosistema, no técnica, y no existe.
- **Presupuesto de recursos aprobado y verificado con tests:**
  - Tamaño máximo de config: **1 MiB** (`MAX_CONFIG_BYTES`); se rechaza antes
    de parsear, con error accionable (archivo + causa + ejemplo).
  - Máximo de secciones `[listener.*]` + `[backend.*]` combinadas: **1024**
    (`MAX_SECTIONS`); se rechaza en la validación semántica con el motivo
    «demasiadas secciones» y ejemplo de corrección.
  - Límites vivos en `eqproxy-config` (`load`/`parse_str`/`check`), no solo en
    documentación; tests: `oversized_source_is_rejected_with_actionable_error`,
    `source_at_the_limit_is_accepted`,
    `too_many_sections_are_rejected_with_budget_reason`,
    `sections_at_the_budget_are_accepted`.

## Consecuencias

- Si se aprueba: la Fase 1 implementa `eqproxy-config` sobre TOML y el
  conversor del proxy de referencia → EQProxy (Fase 8) traduce a TOML clasificando cada
  directiva: convertida / requiere revisión / rechazada explícitamente (nunca
  omitida en silencio; «archivo generado» ≠ «migración funcionalmente
  equivalente»).
- Si se rechaza: este ADR se sustituye por otro y se rehace el §Configuración
  de SPEC.md; el trabajo de la Fase 1 aún no iniciado queda sin coste.
