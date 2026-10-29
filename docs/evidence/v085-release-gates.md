# v0.8.5 — los tres gates de la línea en el pipeline de release

**Objetivo.** Que un tag no pueda construir (ni publicar) antes de que pasen
los tres gates de la línea 0.8.x: citas de evidencia, probes de salud
sub-segundo y skips por uid. Un `push` de tag **no dispara CI**, así que hasta
ahora el release confiaba en que alguien hubiera corrido los gates en otro
sitio.

**Cambio.** `.github/workflows/release.yml`, job `guard` (antes solo citas y
versión):

- instala la toolchain fijada y cachea Cargo;
- corre el **self-test** y el veredicto de cada gate, en ese orden, para que un
  detector roto no pase por no encontrar nada;
- corre la suite **sin privilegios** y **como root** con `--nocapture` (el gate
  de uid lee logs, no fuente) y aplica `check-uid-skips.py` a cada log;
- deja la comprobación de versión del tag al final.

`darwin` y `linux` siguen con `needs: guard`; `image` necesita ambos y
`release` a los tres. La ruta de tag ejecuta el mismo `guard`; la de rama es un
`workflow_dispatch` que, por diseño (`ref_type != tag`), no crea release ni
empuja imagen.

## 1. Control negativo: el gate bloqueó el release (run rojo)

- Run: [40775542855](https://github.com/ExyonQ/EQProxy/actions/runs/40775542855)
- Commit: `0c3bd77`
- Evento/ref: `workflow_dispatch` sobre `ci/release-gates-dryrun`
- Resultado: `guard` **failure**; `darwin`, `linux`, `image`, `release` y
  `dockerhub_page` **skipped**. Ningún build empezó.

El paso que falló fue la suite sin privilegios, en
`run_admin_plane_enforces_group_mode_and_uid_allowlist`:

```text
assertion `left == right` failed: clean shutdown must exit with 0
  left: None
 right: Some(0)
test result: FAILED. 77 passed; 1 failed
```

`None` es `status.code()` de un proceso terminado por señal: el test manda
`SIGINT` en cuanto el socket admin responde, y el handler se instalaba
**después** de anunciar el listener y el plano admin. En esa ventana, la acción
por defecto de SIGINT mata el proceso. Era una carrera real de arranque, no un
fallo del gate; el gate la encontró porque corre la suite en el commit del tag.

## 2. Fix

`eqproxy-cli/src/main.rs`: los canales de shutdown y de configuración se crean
antes de `bind`, y los handlers de **SIGINT y SIGHUP** se instalan antes de
enlazar o anunciar nada. `tokio::signal::unix::signal` registra el handler de
OS de forma síncrona al llamarlo; los `spawn` tardíos desaparecen. Un SIGHUP
que llegue antes de que arranque el applier espera en la cola acotada.

Verificación local del fix:

```text
cargo test -p eqproxy-cli --test cli_e2e   # 78 passed, 0 failed
30 ejecuciones del test exacto con los 10 núcleos saturados (load ~284)
  → 30/30 verdes
cargo clippy -p eqproxy-cli --all-targets -- -D warnings → exit 0
```

## 3. Run 2: gates verdes antes de construir (y el bug del dry-run de imagen)

- Run: [40776942154](https://github.com/ExyonQ/EQProxy/actions/runs/40776942154)
- Commit: `a79c27c`
- Evento/ref: `workflow_dispatch` sobre `ci/release-gates-dryrun`
- `guard`: **success**, 22:03:26 → 22:09:57 UTC (6 min 31 s)
- `darwin`: empieza 22:10:01; `linux`: empieza 22:10:00 — **después** de que
  `guard` termine, que es la prueba de orden que pide la casilla.

| Paso de `guard` | Inicio → fin (UTC) | Duración |
|---|---:|---:|
| Self-test citas + veredicto | 22:03:40 → 22:03:40 | < 1 s |
| Self-test probes + veredicto | 22:03:40 → 22:03:40 | < 1 s |
| Self-test uid | 22:03:40 → 22:03:40 | < 1 s |
| Suite sin privilegios | 22:03:40 → 22:06:36 | 176 s |
| Gate uid (sin privilegios) | 22:06:36 → 22:06:36 | < 1 s |
| Suite como root | 22:06:36 → 22:09:49 | 193 s |
| Gate uid (root) | 22:09:49 → 22:09:49 | < 1 s |
| Comprobación de versión | 22:09:49 | **skipped** (`ref_type != tag`) |

Los 60 binarios de test de las dos pasadas terminaron en `test result: ok`
(0 `FAILED`). El paso de versión es el único que se salta en la rama: en un
tag se ejecuta, y sigue siendo la última comprobación antes de construir.

**Resultado del run: `failure` en el job de imagen, no en los gates.** Los dos
jobs de binarios pasan (linux 22:10:00→23:08:35, 58 min 35 s de job con el
build bajo QEMU; darwin 22:10:01→22:14:28) y su E2E de binario también. El paso
`Build multi-arch image (dry run, no push)` falló al instante:

```text
ERROR: failed to build: invalid tag
"ghcr.io/exyonq/eqproxy:ci/release-gates-dryrun": invalid reference format
```

El modo dry-run derivaba el tag de `GITHUB_REF_NAME`; una rama con `/` no es un
tag Docker válido. Es un bug preexistente del dry-run, **no de los gates ni de
la ruta de tag** (un tag no lleva `/`). Corregido en el workflow:
`VERSION="dryrun-${GITHUB_SHA::12}"`, un tag válido y explícitamente no de
release; verificado que `dryrun-<sha12>` cumple la gramática de tag de Docker.
El fix se re-ejecutó en el run 3: la cadena completa, con el job de imagen
incluido, terminó **verde**. Detalle en la sección 4.

## 4. Run 3: el dry-run completo, verde

- Run: [40788226400](https://github.com/ExyonQ/EQProxy/actions/runs/40788226400)
- Commit: `cbabc2a` (el fix del tag, sobre `a79c27c`)
- Evento/ref: `workflow_dispatch` sobre `ci/release-gates-dryrun`
- Resultado: **success**, 23:33:50 → 01:02:33 UTC (1 h 28 min 43 s)

| Job | Inicio → fin (UTC) | Duración | Conclusión |
|---|---:|---:|---|
| `guard` | 23:33:55 → 23:39:52 | 5 min 57 s | success |
| `darwin` | 23:39:56 → 23:44:21 | 4 min 25 s | success |
| `linux` | 23:39:55 → 00:31:31 | 51 min 36 s | success |
| `image` (dry-run) | 00:31:34 → 01:02:22 | 30 min 48 s | success |
| `release` (ensamblado) | 01:02:25 → 01:02:33 | 8 s | success |
| `dockerhub_page` | 01:02:33 | — | **skipped** (`ref_type != tag`) |

El paso `Build multi-arch image (dry run, no push)` construyó las dos
plataformas (dos invocaciones de buildx; el log nombra `linux/amd64` 71 veces y
`linux/arm64` 50) y terminó con la comprobación de versión sobre la imagen
cargada:

```text
dry-run image: eqproxy 0.8.0
```

Los quince pasos que publican, escanean o promueven quedaron **skipped** en la
rama, y la comprobación externa lo confirma: el tag del dry-run no existe en el
registro (`ghcr.io/exyonq/eqproxy:dryrun-cbabc2a59912: not found`) y
`gh release list` no tiene ninguna entrada nueva (la última sigue siendo
`v0.8.0`, del 2026-10-27).

El job de release también corrió su ensamblado en seco, que es la parte que un
tag sí usa: exportó el tarball del commit `cbabc2a`
(`eqproxy-0.8.0-src.tar.gz`, 2414 entradas, 2 983 673 bytes, versión 0.8.0),
escribió `SHA256SUMS.txt` con las cuatro líneas de binarios más el tarball y lo
verificó (`eqproxy-0.8.0-src.tar.gz: OK`); solo la creación del release quedó
`skipped`.

Crudo: [`image.log`](v085-release-gates/raw/20261029T0110Z/image.log),
[`release.log`](v085-release-gates/raw/20261029T0110Z/release.log),
[`guard.log`](v085-release-gates/raw/20261029T0110Z/guard.log),
[`jobs.tsv`](v085-release-gates/raw/20261029T0110Z/jobs.tsv),
[`image-steps.tsv`](v085-release-gates/raw/20261029T0110Z/image-steps.tsv),
[`release-steps.tsv`](v085-release-gates/raw/20261029T0110Z/release-steps.tsv),
[`run.json`](v085-release-gates/raw/20261029T0110Z/run.json).

## 5. Salidas de los gates (run verde)

```text
self-test ok: dangling citation detected, real and helper names accepted
evidence citations: 71 documents, 164 cited identifiers, 561 #[test] functions in 60 files
self-test ok: short, multi-line, non-literal, TOML, stale, duplicate and malformed input all rejected
suite health probes: 18 found, 2 sub-second or unproven, 2 declared in short-health-probes.txt
self-test ok: undeclared, missing, duplicated and malformed input all rejected
uid-gated skips in an unprivileged run: 0 printed
ok: the unprivileged run printed no uid-gated skip
uid-gated skips as root: 2 printed, 2 declared in uid-skips.txt
ok: every uid-gated skip of the root run is declared, with its reason
```

Crudo: [`run-40776942154-guard.log`](v085-release-gates/raw/run-40776942154-guard.log),
[`gates-summary.txt`](v085-release-gates/raw/gates-summary.txt),
[`run-40776942154-jobs.json`](v085-release-gates/raw/run-40776942154-jobs.json).
El `guard` del run 3 imprimió los mismos recuentos:
[`guard.log`](v085-release-gates/raw/20261029T0110Z/guard.log).
El run rojo conserva su log y sus jobs:
[`run-40775542855-failed.log`](v085-release-gates/raw/run-40775542855-failed.log),
[`run-40775542855-jobs.json`](v085-release-gates/raw/run-40775542855-jobs.json).

## 6. Auditorías del incremento

- **Veyra**: `veyra audit . --profile standard` → **ACCEPTED**, exit 0,
  `.veyra/evidence/20261028T223602Z/`, 566/566 tests de nextest y 2 skipped,
  631,18 s. Corrió después del fix de `main.rs`; el fix del tag dry-run es solo
  YAML y queda fuera de su alcance. **No se repitió** porque ningún fichero
  Rust cambió después: `find` sobre `*.rs`, `Cargo.toml`, `Cargo.lock` y
  `rust-toolchain.toml` con `-newermt '2026-10-28 22:36:00Z'` devuelve **0**
  ficheros (el `main.rs` del árbol tiene el mismo sha256 que el blob de
  `a79c27c`, commit anterior al audit).
- **Rust Audit** 0.2.7: exit 0, **0 critical / 0 high**, 242 medium y 83 low,
  `report/rust-audit-20261029-021258.md` (re-escaneado sobre el árbol final,
  después del run verde; mismos conteos que el scan previo).
- **CodeGraph**: **NOT EXECUTED**. El reindexado se quedó atascado en
  `Vector index 4 on table chunks cannot be searched: entry point element 1946
  has no vector`; `agent impact` tampoco puede resolver el símbolo. Los hechos
  del fix (`main.rs`, handlers antes de `bind`) se comprobaron en el fuente, no
  en el grafo.
- **Hindsight**: nota guardada, 9 ids (primera `83ef3181…`).

## 7. Límites

- **No se ejecutó un tag real**: publicaría release e imagen. El
  `workflow_dispatch` sobre rama es el modo dry-run documentado por el propio
  workflow y ejecuta el mismo `guard`; la ruta de tag añade solo la
  comprobación de versión y los pasos de publicación ya existentes.
- En el run 3 el dry-run de imagen y el ensamblado del release sí se
ejecutaron y quedaron verdes. Las rutas que **publican** (Scout, promoción del
  digest, espejo a Docker Hub, re-pull y creación del release) quedan **NOT
  EXECUTED** por diseño en una rama (`ref_type != tag`); su código no cambió.
- La ruta de tag real sigue **NOT EXECUTED**: un tag publicaría. La equivalencia
  del `guard` es estructural (el job no tiene `if:`), no medida con un tag.
- La evidencia del run 3 cita 71 documentos porque este documento no existía
  durante el run; el gate local sobre el árbol final da 72 documentos con las
  mismas 164 citas y 561 tests, y pasa.
- CI y tier root del repositorio no se re-ejecutaron aquí: el run de gates
  corre la suite en los dos tiers dentro de `guard`, que es lo que la casilla
  pide.
