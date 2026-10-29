# v0.8.5 — dylint, cargo-semver-checks y cargo-geiger: decisión registrada

**Objetivo.** Cerrar la casilla de deuda de la v0.8.5 que prohibía un
`SKIPPED`/`INCONCLUSIVE` perpetuo: las tres herramientas salían del audit de
Veyra sin una decisión que dijera si aplican. La respuesta es el
[ADR-0030](../adr/0030-audit-tool-applicability.md), con la evidencia de esta
página.

**Entorno.** macOS arm64, rustc 1.99.1 (`rust-toolchain.toml`), `veyra` 0.7.0,
`cargo-semver-checks` 0.50.0, `cargo-geiger` 0.14.0, `cargo-dylint` 6.0.4
(`dylint-link` no está en `PATH`). Crudo:
[`raw/20261028T212819Z/`](v085-audit-tools-decision/raw/20261028T212819Z/).

## 1. Punto de partida

Veyra `20261028T201726Z` (el audit del incremento anterior) cierra ACCEPTED y
nombra las tres entradas así:

| Herramienta | Estado | Motivo de Veyra |
|---|---|---|
| `dylint` | SKIPPED | «no Dylint configuration or lint libraries found; refusing to invent lints» |
| `cargo-semver-checks` | SKIPPED | «no baseline for unpublished crates (no registry version to diff)» |
| `cargo-geiger` | INCONCLUSIVE | «completed the scan but reported coverage warning(s) in 4 run(s) … this is not a pass» |

Ninguna bloquea el veredicto, pero ninguna tenía decisión. Eso es la deuda.

## 2. `dylint` — no aplica

`dylint` es un marco para **escribir y cargar crates de lints**: su valor
empieza cuando el proyecto posee reglas que Clippy no implementa, y se paga con
una toolchain fijada aparte (las librerías de lints se compilan contra un rustc
concreto). En este árbol:

```text
$ command -v dylint
dylint: not on PATH
$ cargo dylint --version
cargo-dylint 6.0.4
$ ls dylint.toml .dylint.toml
ls: .dylint.toml: No such file or directory
ls: dylint.toml: No such file or directory
$ grep -n "workspace.metadata.dylint\|package.metadata.dylint" Cargo.toml eqproxy-*/Cargo.toml
no [*metadata.dylint] table
```

No hay librería que cargar ni configuración que la declare. Instalar un juego de
lints de terceros fijaría una toolchain más y activaría reglas que nadie eligió:
un modo de fallo nuevo, no una red de seguridad. Lo que sí cubre el terreno es
Clippy bloqueante (`-D warnings`, OK en Veyra) sobre
`[workspace.lints]`, heredado por los cuatro crates con `[lints] workspace =
true`.

**Decisión:** NOT APPLICABLE. Se reconsidera solo si aparece una regla que
Clippy no pueda expresar; entonces el primer paso es un crate de lint con un
fixture que falle, no instalar `dylint` a secas.

## 3. `cargo-semver-checks` — no aplica sin librería publicada

```text
$ cargo semver-checks check-release
error: failed to retrieve index of crate versions from registry
Caused by:
    eqproxy-config not found in registry (crates.io).
exit: 101
```

Los cuatro crates son internos: `cargo metadata` los declara `publish=null`
([`publish-flag.txt`](v085-audit-tools-decision/raw/20261028T212819Z/publish-flag.txt))
y el pipeline publica un **binario** y una imagen, nunca un crate. No hay
baseline de registro que comparar.

**Configuración probada y rechazada.** Añadí `publish = false` a los cuatro
manifiestos para hacer explícita la no-publicación. El resultado fue peor que el
skip:

```text
$ cargo semver-checks check-release -v
    Skipping eqproxy-config v0.8.0 (current)
    Skipping eqproxy-core v0.8.0 (current)
    Skipping eqproxy-net v0.8.0 (current)
exit: 0
```

Tres líneas, una por crate con librería (`eqproxy-cli` es solo bin), y sale 0
sin comparar una sola API; la ejecución sin `-v` no imprime nada
([`semver-checks-plain-empty.txt`](v085-audit-tools-decision/raw/20261028T212819Z/semver-checks-plain-empty.txt)).
Veyra mapea exit 0 a «semver-checks passed»: un pase vacío, exactamente la
confianza falsa que el contrato prohíbe, así que **revertí los cuatro manifiestos**: `git diff` vacío
([`manifests-diff.txt`](v085-audit-tools-decision/raw/20261028T212819Z/manifests-diff.txt))
y `publish` de vuelta a `null`. El transcript queda en
[`semver-checks-verbose.txt`](v085-audit-tools-decision/raw/20261028T212819Z/semver-checks-verbose.txt).

Un baseline por git (`--baseline-rev v0.8.0`) también sería teatro: compararía
APIs internas que cambian juntas en un commit y cuyo resultado no dice nada
sobre la compatibilidad del producto. Los contratos externos reales son la CLI
(`run`, `config validate|plan|explain|apply|rollback|import`, `doctor`; e2e de
`cli_e2e` y escenarios de `veyra.toml`) y el documento de configuración
(`schema_version = 1`, rechazo explícito de otra versión y schema JSON con gate
de deriva).

**Decisión:** NOT APPLICABLE mientras ningún crate se publique. Si alguno se
publica, esta decisión queda anulada y el baseline es obligatorio **antes** de
la primera publicación.

## 4. `cargo-geiger` — informativo, nunca gate

La pregunta «¿usa EQProxy `unsafe`?» la responde el compilador, no un conteo:
`[workspace.lints.rust] unsafe_code = "forbid"` llega a los cuatro crates por
`[lints] workspace = true`. Control negativo real: añadí un bloque
`unsafe { 0 }` a `eqproxy-core/src/lib.rs` y

```text
error: usage of an `unsafe` block
  --> eqproxy-core/src/lib.rs:27:5
error: could not compile `eqproxy-core` (lib) due to 1 previous error
exit: 101
```

El fichero se restauró byte a byte: sha256 `7836a1ac…` antes y después,
`git diff` de 0 líneas
([`unsafe-control.txt`](v085-audit-tools-decision/raw/20261028T212819Z/unsafe-control.txt),
[`lib-before.sha`](v085-audit-tools-decision/raw/20261028T212819Z/lib-before.sha),
[`lib-after.sha`](v085-audit-tools-decision/raw/20261028T212819Z/lib-after.sha)).

El INCONCLUSIVE es una propiedad del **escaneo de dependencias**:

```text
warning lines: 4417            (4 runs: 1082, 1087, 1120 y 1128)
unique files:  1130
unique registry crates: 87     (libm 560, icu_properties_data 556, jsonschema 344, …)
workspace .rs files: 0
workspace non-rs files: eqproxy.schema.json   (include_str!, no es código)
target generated files: 7
```

Cero fuentes Rust del workspace sin escanear. Lo que geiger no puede leer son
ficheros de terceros que no se compilan en esta configuración o que no son
Rust, así que sus conteos de `unsafe` en dependencias son una cota inferior:
sale 1 con `Found N warnings` y Veyra lo llama INCONCLUSIVE con razón.
Silenciar ese exit o tratar el escaneo parcial como PASS sería la misma
confianza falsa que el caso anterior. El riesgo de dependencias lo cubren
`cargo-audit` y `cargo-deny` (OK en el mismo audit, avisos y licencias), que es
la herramienta que responde esa pregunta.

**Decisión:** se queda como información, no como gate. Un hallazgo nuevo de
geiger se lee igual; lo que no hace es bloquear una release mientras su
cobertura sea parcial. Si upstream completa el escaneo, se puede promover a
gate con otra decisión.

## 5. Verificación

- **Manifiestos:** `git diff` de 0 líneas tras el experimento; `publish=null` en
  los cuatro.
- **Control del lint:** rojo con el `unsafe` inyectado (exit 101), verde al
  restaurar; sha256 idéntico.
- **Sin cambios de código, tests ni `veyra.toml`:** no se relajó ninguna
  aserción.
- **Veyra final:** ver §6.
- **Rust Audit, CodeGraph y Hindsight:** ver §6.

## 6. Auditorías del incremento

- **Veyra**: `veyra audit . --profile standard` → **ACCEPTED**, exit 0,
  evidencia `.veyra/evidence/20261028T213104Z/`, 566/566 tests de nextest
  pasados y 2 skipped, 639,36 s. Las tres entradas
  siguen con el mismo estado (dylint SKIPPED, semver-checks SKIPPED, geiger
  INCONCLUSIVE): eso es la herramienta siendo honesta; la decisión es el ADR.
  Cero hallazgos bloqueantes.
- **Rust Audit** 0.2.7: exit 0, **0 critical / 0 high**, 242 medium y 83 low,
  `report/rust-audit-20261028-223319.md`.
  Sin hallazgos nuevos: no cambió ningún `.rs` en este incremento; el `R08` del
  deadline de `wait_for_counter` sigue siendo el falso positivo ya explicado.
- **CodeGraph**: índice de 65 ficheros, 62 547 líneas, 7 073 nodos, 12 782
  edges, `graph_complete: true`, `vector_index_ready: true`, 49 656 ms
  (`/tmp/cg-index-v085-late.json`). `agent context` **falla** igualmente con
  `entry point element 1946 has no vector`, y `agent impact` no encuentra
  símbolo porque el incremento es solo documentación: los `file:line` del ADR se
  comprobaron contra el fuente (workspace lints, `Cargo.toml`, evidencia de
  geiger), no contra el grafo. CodeGraph no se usa como prueba de
  comportamiento; su consulta queda **NOT EXECUTED** por el índice vectorial
  inconsistente.
- **Hindsight**: nota guardada, 8 ids (primera `5ee5e136…`).

## 7. Límites

- `dylint` **NOT EXECUTED** de verdad: no hay librería de lints que ejecutar; la
  decisión es no inventarla.
- `cargo-semver-checks` **NOT EXECUTED** contra un baseline publicado: no existe
  crate publicado. El experimento con `publish = false` sí se ejecutó y se
  rechazó.
- `cargo-geiger` **NOT EXECUTED** con cobertura completa: el escaneo parcial es
  de upstream y afecta a 87 crates de terceros; no se puede arreglar desde este
  repositorio.
- CI y tier root **NOT EXECUTED** en este incremento (solo macOS arm64 uid 501),
  igual que en las casillas anteriores.
