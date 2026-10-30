# v0.8.5 — the whole suite ten times under load, in both tiers

Casilla de §4 del [roadmap 0.8.5](../../ROADMAP%20EQPROXY/ROADMAP/Roadmap%200.8.5.md):
**«Suite completa 10× bajo carga en los dos tiers (uid 501 y root) sin un
solo fallo, sin SKIP nuevos sin declarar y con el límite de descriptores
impreso en el log root; los dos tiers cierran con el mismo recuento»**.

Se ejecutó con el binario de tests que construye `cargo` en el árbol
publicado, sobre un host Linux real (no CI) y, como extra, en el macOS del
mantenedor. **30 pasadas completas, 0 fallos.** El par que cierra la casilla
es el de Linux —uid 501 y uid 0, mismo host, mismo kernel, mismo árbol— y sus
dos tiers cierran con el recuento idéntico.

## 1. Método

Por cada tier:

```text
cargo test --workspace -- --nocapture
```

10 repeticiones, con todos los núcleos ocupados por un bucle `yes` (8 en el
host de 8 vCPU; 10 en el macOS de 10 núcleos). En cada repetición se
comprueba, y el script falla si algo no cuadra:

- exit status `0`;
- **32 targets** con línea `test result:` (el recuento de targets del árbol);
- **596 passed, 0 failed, 2 ignored** (recuento base de Linux, medido antes
  del soak con una pasada sin carga);
- cero líneas `test result: FAILED`;
- el gate de skips de su tier: `check-uid-skips.py --user-log` (0 skips
  permitidos) o `--root-log` (los 2 declarados, con su razón, y ninguno más);
- el límite de descriptores impreso en el encabezado de la repetición.

El script vive en `scripts/evidence/v085-suite-10x/run.sh` (local-only, como
el resto de harnesses) y escribe el resumen TSV y los recortes por repetición
(rutas `test result:`, `SKIP`, `FAILED`, `panicked`) en
[`docs/evidence/v085-suite-10x/`](v085-suite-10x/). Los logs completos se
quedan en `/tmp` de cada host; el `sha256` de cada uno está en la cabecera de
su recorte.

## 2. Linux (Netcup) — el par que cierra la casilla

- Host: Netcup AMD64, Ubuntu 24.04.4 LTS, kernel
  `6.8.0-147-generic #147-Ubuntu SMP PREEMPT_DYNAMIC`, **8 vCPU**, 15 GiB.
- Árbol: `d558be2e2732e73ece4662771fd646398fd59a21`, clonado desde
  `github.com/ExyonQ/EQProxy`.
- Toolchain: `rustc 1.99.1 (58cf8f9c3 2026-10-13)` /
  `cargo 1.99.1 (5f94df478 2026-08-27)`, el `channel` de
  [`rust-toolchain.toml`](../../rust-toolchain.toml), usado desde
  `/opt/rust-1.99.1` (copia de la toolchain del host) para que ambos tiers
  compilen con el mismo compilador.
- Tiers: uid **501** (`eqsoak`, creado para la casilla) y uid **0** (root),
  cada uno con su propio `CARGO_TARGET_DIR`; el de root arranca en frío, de
  ahí su primera pasada de 245 s.
- Descriptores: `ulimit -Sn` 1024 y `ulimit -Hn` 1048576 antes de cada tier;
  el script eleva al hard y **cada log, root incluido, imprime
  `fd limit: 1048576`**. No es una precaución decorativa: el test de 400
  streams sostiene ~820 descriptores en un proceso, y el límite bajo de
  `sudo`/PAM ya produjo un 502 en CI (comentario del job `suite-as-root`).
- Carga: 8 `yes`, `load1` entre **8.08 y 9.90** en las 20 pasadas (la primera
  muestra del tier user, 1.38, se tomó en el primer segundo, antes de que los
  spinners acumularan su minuto; las demás, 6.96–9.90).

### Tier uid 501

| Rep | Exit | Targets | Passed | Failed | Ignored | Skips | Elapsed (s) | Load1 |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 0 | 32 | 596 | 0 | 2 | 0 | 92 | 1.38 |
| 2 | 0 | 32 | 596 | 0 | 2 | 0 | 92 | 6.96 |
| 3 | 0 | 32 | 596 | 0 | 2 | 0 | 93 | 8.52 |
| 4 | 0 | 32 | 596 | 0 | 2 | 0 | 93 | 8.73 |
| 5 | 0 | 32 | 596 | 0 | 2 | 0 | 93 | 8.37 |
| 6 | 0 | 32 | 596 | 0 | 2 | 0 | 92 | 8.50 |
| 7 | 0 | 32 | 596 | 0 | 2 | 0 | 92 | 8.53 |
| 8 | 0 | 32 | 596 | 0 | 2 | 0 | 92 | 8.33 |
| 9 | 0 | 32 | 596 | 0 | 2 | 0 | 93 | 8.47 |
| 10 | 0 | 32 | 596 | 0 | 2 | 0 | 94 | 9.25 |

**10/10 verde.** Gate de usuario en cada repetición: `0 printed`, `ok: the
unprivileged run printed no uid-gated skip`.

### Tier root

| Rep | Exit | Targets | Passed | Failed | Ignored | Skips | Elapsed (s) | Load1 |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 0 | 32 | 596 | 0 | 2 | 2 | 245¹ | 8.82 |
| 2 | 0 | 32 | 596 | 0 | 2 | 2 | 92 | 9.90 |
| 3 | 0 | 32 | 596 | 0 | 2 | 2 | 91 | 8.61 |
| 4 | 0 | 32 | 596 | 0 | 2 | 2 | 93 | 8.31 |
| 5 | 0 | 32 | 596 | 0 | 2 | 2 | 91 | 8.36 |
| 6 | 0 | 32 | 596 | 0 | 2 | 2 | 91 | 8.35 |
| 7 | 0 | 32 | 596 | 0 | 2 | 2 | 91 | 8.08 |
| 8 | 0 | 32 | 596 | 0 | 2 | 2 | 92 | 8.25 |
| 9 | 0 | 32 | 596 | 0 | 2 | 2 | 92 | 8.24 |
| 10 | 0 | 32 | 596 | 0 | 2 | 2 | 91 | 8.37 |

¹ incluye el build en frío del target de root.

**10/10 verde.** Gate de root en cada repetición: `2 printed, 2 declared`,
`ok: every uid-gated skip of the root run is declared, with its reason`. Los
dos skips son los bloques que declaran su premisa cuando el proceso es root
(la negativa de `chown(2)` a un grupo ajeno no existe para uid 0); están en
[`.github/scripts/uid-skips.txt`](../../.github/scripts/uid-skips.txt) y
ninguno es nuevo.

**Los dos tiers cierran con el mismo recuento**: 32 targets, **596 passed**,
0 failed, 2 ignored, en las 20 pasadas.

## 3. macOS arm64 (extra, uid 501)

El host de desarrollo, sin root (la elevación se denegó; el tier root de la
casilla es el de Linux, que es la plataforma de despliegue):

- Darwin 25.5.0, arm64, 10 núcleos, uid 501, fd `unlimited` (soft 1048576).
- 10/10 verdes, **32/595/0/2**, 0 skips, **98–116 s** por pasada, carga
  314–424 con 10 spinners (la `load average` de macOS incluye procesos
  ajenos y no es comparable con la de Linux; lo que acredita es que los 10
  núcleos estaban ocupados).
- Un test menos que Linux: el de ACL del socket admin es
  `cfg(target_os = "linux")` y no se compila en macOS (la misma diferencia
  que [v08-linux-e2e-admin](v08-linux-e2e-admin.md) documenta: 559 Linux
  frente a 558 macOS).

## 4. Flakes: el que había y lo que se vio

El incremento llegó con un flake **preexistente** ya diagnosticado y
arreglado en `d558be2`: `pool_sizing_keeps_a_400_stream_burst_without_churn`
falló dos veces en CI (run `40722095133`, job root, y run `40961715245`,
tier-1) con **502 en `e2e_http2.rs:712`** frente al 200 esperado. Los logs no
traían ninguna línea de error de dial para ese origen, así que la conexión de
backend murió antes de la cabeza de respuesta; el fixture escuchaba con el
backlog **128** que `std` fija y la oleada abre **400** conexiones a la vez.
El arreglo sube el backlog del origen de prueba a **4096** (nginx usa 511,
HAProxy 4096) con `socket2`, ya en el grafo, **sin cambiar una sola
aserción**. Atribución honesta: es la explicación que encaja con la firma y
con la mecánica del fixture, no una reproducción aislada del fallo original;
lo que sí está medido es que **no reapareció en 30 pasadas bajo carga** (20 en
Linux con 8 núcleos ocupados, 10 en macOS con 10).

En estas 30 pasadas **no apareció ningún flake nuevo**: ni un `FAILED`, ni un
`SKIP` no declarado, ni un recuento distinto en ningún tier. Los dos únicos
`panicked at` de los recortes son el panic **esperado** de
`await_log_line_times_out_with_the_log`, un `#[should_panic]` que figura como
`ok` en la misma línea de resultado.

## 5. Reproducción

En el servidor (los dos tiers, secuenciales, con la toolchain fijada):

```console
$ git clone https://github.com/ExyonQ/EQProxy.git /srv/eqproxy-soak
$ git -C /srv/eqproxy-soak checkout d558be2
$ useradd -u 501 -m -s /bin/bash eqsoak
$ runuser -u eqsoak -- env HOME=/home/eqsoak CARGO_HOME=/home/eqsoak/.cargo \
    CARGO_TARGET_DIR=/srv/eqproxy-target-user \
    PATH=/opt/rust-1.99.1/bin:/usr/local/bin:/usr/bin:/bin \
    TIER=user REPS=10 LOAD=8 OUT=/srv/eqproxy-soak-evidence/user \
    EXPECT_TARGETS=32 EXPECT_PASSED=596 EXPECT_FAILED=0 EXPECT_IGNORED=2 \
    bash /srv/eqproxy-soak/scripts/evidence/v085-suite-10x/run.sh
$ env HOME=/root CARGO_HOME=/root/.cargo CARGO_TARGET_DIR=/srv/eqproxy-target-root \
    PATH=/opt/rust-1.99.1/bin:/usr/local/bin:/usr/bin:/bin \
    TIER=root REPS=10 LOAD=8 OUT=/srv/eqproxy-soak-evidence/root \
    EXPECT_TARGETS=32 EXPECT_PASSED=596 EXPECT_FAILED=0 EXPECT_IGNORED=2 \
    bash /srv/eqproxy-soak/scripts/evidence/v085-suite-10x/run.sh
```

Las cifras de las tablas se leen de los TSV publicados, no de un resumen
aparte:

```console
$ awk -F'\t' 'FNR>1 {n++; p+=$5; f+=$6; if ($3!=0) bad++} END {print "reps="n" passed="p" failed="f" nonzero_exit="bad+0}' \
    docs/evidence/v085-suite-10x/linux/*-summary.tsv
reps=20 passed=11920 failed=0 nonzero_exit=0
```

## 6. Límites de la evidencia

- **Un host Linux y uno macOS.** Es un soak de 30 pasadas, no una campaña de
  24 h ni un banco reproducible: el host Netcup es el del precedente v0.8 y
  la carga es la del propio host, no una carga sintética contra el proxy.
- **El tier root corre en Linux, no en macOS.** La elevación en macOS se
  denegó y no se insistió; el requisito de la casilla (uid 0) queda cubierto
  donde importa para el despliegue y donde CI ya lo ejerce cada push.
- **arm64 Linux: NOT EXECUTED.** El servidor Oracle es aarch64 pero de 4
  vCPU; el par de la casilla se hizo en el Netcup amd64 para que los dos
  tiers compartieran recuento. La pata arm64 de CI (ACL nativa) es otro
  slice y no sustituye este soak.
- **Los logs completos no se publican** (20 × ~1–2 MB de `--nocapture`): se
  publican los recortes por repetición con sus líneas `test result:`,
  `SKIP` y de fallo, y el `sha256` del log completo en la cabecera de cada
  recorte.
- **La `load average` no es una medida de saturación comparable entre
  kernels**; lo que se afirma es que había un bucle `yes` por núcleo y que
  las 30 pasadas terminaron con el recuento esperado.

## 7. Auditorías del incremento

| Pata | Comando | Resultado | Evidencia |
|---|---|---|---|
| Veyra Proof | `veyra audit . --profile standard` | **ACCEPTED**, exit `0`; 11 herramientas OK (`rustfmt`, `cargo check`, `clippy`, `cargo test`, `cargo-audit`, `veyra-anti-theater`, `cargo-nextest`, `cargo-llvm-cov`, `cargo-deny`, `cargo-machete`, `veyra-e2e`), 626 s; `dylint` y `cargo-semver-checks` no ejecutan por política (ADR-0030) y `cargo-geiger` sale INCONCLUSIVE, también explicado en el ADR | [`.veyra/evidence/20261029T233039Z/`](../../.veyra/evidence/20261029T233039Z/report.md) |
| Rust Audit | `python3.13 <rust-ai-audit>/scripts/rust_audit.py scan . --format md --out report --fail-on high` | exit `0`; **0 critical / 0 high**; 242 medium, 93 low. En la superficie tocada solo un aviso **low** `R02` en [`e2e_http2.rs:707`](../../eqproxy-net/tests/e2e_http2.rs#L707) por los números literales del test (400 streams, 750 ms), que son el contrato que afirma | [`report/rust-audit-20261030-003021.md`](../../report/rust-audit-20261030-003021.md) |
| CodeGraph Rust | `codegraph-rust index . --stats-json … --batch-size 16`, después `agent impact` y `agent context` | exit `0`; 68 ficheros, 65 193 líneas, 7 366 nodos, 13 277 aristas, `graph_complete: true`, `vector_index_ready: true`, `errors: 0`, `index_ms: 900 288`. Las respuestas se contrastaron con el fuente (ver abajo) | [`codegraph/`](v085-suite-10x/codegraph) |
| Hindsight | `hindsight-note --project EQProxy --tags v0.8.5 suite flakes` | nota guardada en el banco `eqproxy`, `memory_id 5ba12e80-b763-4203-bf31-78937f24ee39` | banco `eqproxy` |

Lo que CodeGraph acertó y lo que no, comprobado en el fuente: `agent impact`
localizó el fixture nuevo [`bind_keepalive_origin`](../../eqproxy-net/tests/e2e_http2.rs#L592)
con su `socket.listen(4096)` ([`:601`](../../eqproxy-net/tests/e2e_http2.rs#L601)),
el test ([`:707`](../../eqproxy-net/tests/e2e_http2.rs#L707)), `start_keepalive_origin`
([`:605`](../../eqproxy-net/tests/e2e_http2.rs#L605)) y los unitarios de
`pool.rs`; no pudo responder si otros tests comparten el origen, y el
`grep` dice que **el único llamador es la línea 711**, este mismo test.
`agent context` **no abrió** `start_keepalive_origin` y llamó «backlog» al
`64` posicional de los helpers, que es `maxconn`
([`ResolvedListener::new`](../../eqproxy-net/src/proxy.rs#L886)); el backlog
del proxy no se fija en ese argumento. El hecho que se retiene es el del
fuente, no el de la respuesta del agente.
