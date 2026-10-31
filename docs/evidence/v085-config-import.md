# v0.8.5 — conversor oficial `eqproxy config import` (CE6 · Q9 · CE8)

**Fecha:** 2026-10-30 · **Casilla:** §1 «Conversor oficial `eqproxy config
import` (Phase 8a)» y §2 **CE6** / **Q9 · CE8** del
[roadmap 0.8.5](../../ROADMAP%20EQPROXY/ROADMAP/Roadmap%200.8.5.md).
**Estado:** implementado en Rust dentro del binario (`eqproxy config import`),
verificado con sockets y ficheros reales. El conversor Python
([`eqproxy_migrate.py`](../../ROADMAP%20EQPROXY/eqproxy_migrate.py)) queda como
referencia del maintainer; el producto ya no depende de él.

## 1. Qué hace

`eqproxy config import` lee una configuración de **nginx**, **HAProxy**,
**ingress-nginx** o **Envoy** (el dialecto se detecta o se fuerza con `--from`),
escribe `eqproxy.toml` y un informe Markdown que clasifica **cada** directiva
del origen en tres cubos: **convertido / revisar / rechazado**.

Dos propiedades no se prometen, se imponen en el código
(`eqproxy-config/src/import/mod.rs`):

1. **Nada se descarta en silencio.** Cada directiva recorrida debe producir al
   menos una clasificación; si una rama olvida hacerlo, la conversión falla en
   vez de dejar un hueco. El informe imprime las directivas **leídas** y las
   **clasificadas**, y el test `import::tests::every_walked_directive_must_be_classified`
   lo comprueba.
2. **El resultado es una configuración válida de EQProxy.** El TOML generado se
   parsea y se valida con el propio parser y validador del producto
   (`crate::parse_str` + `crate::validate::check`) antes de escribirlo: el
   conversor no puede devolver un fichero que el binario rechace.

Códigos de salida (contrato del comando):

| Código | Significado |
|---|---|
| `0` | conversión limpia: fichero válido y **0** directivas rechazadas |
| `2` | fichero válido, pero con directivas sin equivalente (el informe las nombra) |
| `1` | no se pudo leer el origen, el dialecto no se reconoce, no hay listener o no se pudo escribir; **no se escribe nada** |

## 2. Corpus y ejecución

Cuatro configuraciones reales en
[`raw/`](v085-config-import/raw/): un `haproxy.cfg`, un `nginx.conf` con
upstreams y vhosts, un manifiesto ingress-nginx multi-documento y un bootstrap
Envoy v3. Se convierten con el binario real:

```bash
for f in haproxy.cfg nginx.conf ingress-nginx.yaml envoy.yaml; do
  target/debug/eqproxy config import \
    --input "docs/evidence/v085-config-import/raw/$f" \
    --output "docs/evidence/v085-config-import/raw/${f%%.*}.eqproxy.toml" \
    --report "docs/evidence/v085-config-import/raw/${f%%.*}.report.md"
done
```

Salida exacta en [`raw/cli-run.txt`](v085-config-import/raw/cli-run.txt)

| Origen | Detectado | Convertidas | A revisar | Rechazadas | Exit |
|---|---|---|---|---|---|
| `haproxy.cfg` | haproxy | 41 | 30 | 7 | 2 |
| `nginx.conf` | nginx | 18 | 30 | 5 | 2 |
| `ingress-nginx.yaml` | ingress | 23 | 22 | 2 | 2 |
| `envoy.yaml` | envoy | 16 | 19 | 3 | 2 |

Los cuatro son `2` por diseño: cada corpus usa algo que EQProxy no tiene (syslog,
Lua, `ssl-passthrough`, xDS…) y el informe debe nombrarlo. Un `0` aquí sería una
señal de que algo se está perdiendo, no una mejora.

### 2.1 El TOML generado pasa el validador del producto

`config validate` vuelve a parsear y a validar **y además resuelve las rutas**
(certificados, `ca_file`, mapas) contra el disco:

| Fichero | Resultado | Exit |
|---|---|---|
| `ingress-nginx.eqproxy.toml` | `config OK: 2 listener(s), 5 backend(s)` | 0 |
| `haproxy.eqproxy.toml` | falla al resolver `/etc/haproxy/certs/ejemplo.pem` (no existe en esta máquina) | 1 |
| `nginx.eqproxy.toml` | falla al resolver `/etc/ssl/certs/ejemplo.pem` | 1 |
| `envoy.eqproxy.toml` | falla al resolver `/etc/envoy/certs/ca.pem` | 1 |

Los tres fallos son de **resolución de rutas**, no de esquema: el origen apunta
a certificados del host de origen, que el operador copiará a su máquina. Se
declara así en lugar de esconderlo. Salida íntegra y códigos reales (capturados
sin tubería, para que `$?` sea el del binario) en
[`raw/validate.txt`](v085-config-import/raw/validate.txt).

## 3. E2E real: convertir → validar → servir tráfico

Script: [`scripts/evidence/v085-config-import/journey.sh`](../../scripts/evidence/v085-config-import/journey.sh)
(harness local; los datos quedan en
[`raw/e2e/`](v085-config-import/raw/e2e/)). Con el binario real y un origen HTTP
real:

```
origin=51840 proxy=51841
import: …/nginx.conf (nginx) → …/eqproxy.toml: 3 converted, 1 to review, 0 rejected
import exit=0
warning: listener "web__sin_server_name" listens on 0.0.0.0:51841 without TLS: …
config OK: 1 listener(s), 1 backend(s) in …/eqproxy.toml
served: converted-and-serving
with the origin down: HTTP 502
OK
```

Es decir: la configuración **convertida** se sirve con `eqproxy run`, un cliente
HTTP real recibe el cuerpo del origen, y cuando el origen muere el proxy
responde **502** —el tráfico cruzó de verdad la configuración generada, no solo
el parser.

## 4. Límites declarados

- La conversión es **estática**: no ejecuta nada del origen ni compara tráfico.
  La equivalencia de comportamiento de estas cuatro configuraciones no se ha
  medido; lo que se prueba es la forma del artefacto y la honestidad del informe.
- Los ficheros de certificado del origen no se copian: quien migra los coloca y
  `config validate` los resuelve en su máquina.
- Directivas globales (syslog, `lua-load`, `userlist`, xDS…) quedan
  **rechazadas** con nombre y motivo; no se inventan equivalentes.

## 5. Fuzz

Objetivo nuevo [`fuzz/fuzz_targets/config_import.rs`](../../fuzz/fuzz_targets/config_import.rs)
(libFuzzer + ASAN, nightly). Oráculo: `convert` no entra en pánico con texto
arbitrario en los cuatro dialectos; si devuelve `Ok`, el TOML **re-parsea** y
declara al menos un listener; la conversión es determinista (TOML y informe) y
las cifras de la cabecera del informe (leídas / clasificadas / tres cubos)
coinciden con `Outcome::counts` y con el número de directivas listadas.

```
cargo +nightly fuzz run --fuzz-dir fuzz config_import -- \
  -seed_inputs=docs/evidence/v085-config-import/raw -runs=20000 -max_total_time=120
Done 20000 runs in 18 second(s)     # exit 0, 0 artefactos de crash
```

Ejecución del **2026-10-30T23:28:34Z** sobre el árbol de `ad0050a` con
`cargo 1.101.0-nightly (15be64aa0 2026-10-20)`: 20 000 runs, 18 s, `exit 0` y
cero ficheros en `fuzz/artifacts/config_import`. Registro completo en
[`raw/fuzz.log`](v085-config-import/raw/fuzz.log) y resumen en
[`raw/fuzz-summary.txt`](v085-config-import/raw/fuzz-summary.txt). No es una
campaña de horas: es una ejecución real con semillas del corpus, y así se
declara.

## 6. Tests

| Comando | Resultado |
|---|---|
| regeneración del corpus (§2) con el binario de `ad0050a` | 4 ficheros, **0 diferencias de bytes** frente a `raw/` (TOML e informe) |
| `cargo test -p eqproxy-config --test import_corpus` | 5 pasan (4 corpus + detección de dialecto) |
| `cargo test -p eqproxy-config` | 91 + 4 (schema) pasan |
| `cargo test -p eqproxy-cli --test cli_e2e config_import` | 1 pasa (los tres códigos de salida) |
| `cargo test --workspace` | **652 pasan, 0 fallan** |
| `cargo fmt --all -- --check` | exit 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| `cargo build --workspace --release` | exit 0 |

El test `import_corpus` re-parsea el TOML **por su cuenta** (no confía en
`convert`), comprueba que «leídas = clasificadas», que las directivas sin
equivalente aparecen como rechazadas y que convertir dos veces da los mismos
bytes.

## 7. Reproducir

```bash
cargo build --workspace            # binario real
for f in haproxy.cfg nginx.conf ingress-nginx.yaml envoy.yaml; do …; done   # §2
bash scripts/evidence/v085-config-import/journey.sh                          # §3
cargo test -p eqproxy-config --test import_corpus                            # §6
cargo +nightly fuzz run --fuzz-dir fuzz config_import -- -runs=20000 …       # §5
```

## 8. Auditorías del incremento

Sobre el árbol final (`ad0050a` más los cambios sin commitear; el contenido es
el mismo que auditaron ambas legs, comprobado después de una reescritura de
mtime a las 22:54):

- **Veyra Proof — ejecutada y verde.** `/Users/toni/.veyra/.venv/bin/veyra audit .
  --profile standard` (veyra 0.7.0, macOS aarch64, toolchain 1.99.1):
  **ACCEPTED, exit 0**, 11 herramientas en `OK`, 1485.7 s de wall y `cargo-test`
  con **652 passed / 0 failed / 2 ignored**. Evidencia:
  [`.veyra/evidence/20261030T225104Z/report.md`](../../.veyra/evidence/20261030T225104Z/report.md).
  `cargo-geiger` sale **INCONCLUSIVE** y `dylint`/`cargo-semver-checks`
  **SKIPPED**, los tres con decisión registrada en
  [ADR-0030](../adr/0030-audit-tool-applicability.md).
- **CodeGraph Rust — ejecutado sobre el árbol final.** 79 ficheros, 76 889
  líneas, 8 406 nodos, 14 816 aristas, `graph_complete: true`,
  `vector_index_ready: true`, 0 errores (4 266 ms la pasada incremental; la
  completa, 1 675 035 ms). `agent impact` sobre `haproxy::convert` y
  `agent context` sobre el mapeo de `server … maxconn`: cada `file:line` citado
  se comprobó en el fuente (dispatcher en
  [`mod.rs:738`](../../eqproxy-config/src/import/mod.rs#L738), cap en
  [`haproxy.rs:909`](../../eqproxy-config/src/import/haproxy.rs#L909), emisión
  en [`report.rs:40`](../../eqproxy-config/src/import/report.rs#L40)). Ambas
  respuestas son advisory: no prueban comportamiento.
- **Rust Audit — ejecutado, con revisión de sus 7 hallazgos `high`.**
  `python3.13 /Volumes/Lexar/Cursor/rust-ai-audit/scripts/rust_audit.py scan .
  --format md --out report --fail-on high` (rust-ai-audit **0.2.7**, engine
  sha256 `84b5ba5b…`): **exit 1** por la política `--fail-on high`, con
  **critical 0 · high 7 · medium 397 · low 107**. Informe local-only:
  `report/rust-audit-20261031-003019.md`. Los siete `high` se revisaron uno a
  uno y **ninguno es un defecto**:
  - **R09 ×4** (`fuzz/fuzz_targets/config_import.rs:43,55,85,95`,
    `panic!`/`.expect(`): es el **oráculo del objetivo de fuzz**, no código de
    producto — el fichero es `#![no_main]` + `fuzz_target!`, vive en el
    workspace aparte de `fuzz/` (fuera de `cargo test --workspace`) y no se
    enlaza en el binario; el `panic` es exactamente cómo un invariante roto
    se hace visible a libFuzzer.
  - **R16 ×3** (`eqproxy-net/src/cache.rs:421` en `refresh`, `:559` en
    `insert`, `:624` en `remove`, «`Mutex` síncrono cruzando `.await`»):
    falso positivo del heurístico. En las tres el guard vive en un bloque
    interno (`{ let mut inner = self.lock(); … }`, o el `let stored =
    self.lock()…;` que lo suelta al final de la sentencia) y se libera
    **antes** del `.await` de `spawn_blocking`/`persist_variant`; además
    `complete` se ejecuta dentro de `tokio::spawn`
    ([`http1.rs:1915`](../../eqproxy-net/src/http1.rs#L1915)), y un
    `MutexGuard` es `!Send`: si cruzara un `.await` ahí, el crate **no
    compilaría**. No se tocó el código.
- **Hindsight: ejecutado** — nota de cierre en el banco `eqproxy` del proyecto
  (comando y resultado en la entrega del incremento).

## 9. Sin verificar

- Equivalencia de tráfico frente a nginx/HAProxy reales (A/B con las mismas
  cargas): **NO EJECUTADO**; el corpus no trae los orígenes de cada fichero.
  El journey de §3 demuestra que el tráfico cruza la configuración convertida,
  no que sea equivalente a la del origen.
