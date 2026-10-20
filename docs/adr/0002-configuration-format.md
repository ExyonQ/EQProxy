# ADR-0002: Canonical configuration format

Language: **English**.

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
   **Declared compatibility policy (Q3, 2026-10-19):** a binary accepts
   every schema version it knows (`1..=SCHEMA_VERSION`, backward
   compatible: an older config keeps loading) and rejects newer ones —
   or the invalid `0` — naming the supported range. Unknown fields are
   rejected at the gate (`deny_unknown_fields`), and validation
   hardening only lands together with a `schema_version` transition,
   never silently inside a version. The upgrade path has a way back:
   `config apply` keeps `history/` and `config rollback` re-gates and
   restores the previous config (v0.4.2).
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
