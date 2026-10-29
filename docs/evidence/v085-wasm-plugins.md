# v0.8.5 — plugins WASM de filtro de petición (B-I5 · B-E4 · B-N17)

**Fecha:** 2026-10-29 · **Casillas:** §1 «Plugins WASM» y §4 «Plugin que excede
límites…» del [roadmap 0.8.5](../../ROADMAP%20EQPROXY/ROADMAP/Roadmap%200.8.5.md).
**Estado:** implementada y verificada E2E con el binario final; S-PLG-01 medido.
La fase de respuesta y el acceso al cuerpo **no** están en ABI v1 (§6).

Diseño: [ADR-0031](../adr/0031-wasm-plugin-host.md). La decisión sobre
FastCGI/uwsgi/scgi (B-N17) está en
[ADR-0032](../adr/0032-fastcgi-uwsgi-scgi-decision.md).

---

## 1. Qué se puede configurar

`[listener.<name>.plugin]` es opcional y solo se acepta en listeners
`mode = "http"` (h1, cada stream h2 y cada petición h3 pasan por el mismo
motor). El módulo se compila **una vez** al resolver la configuración; cada
petición recibe un `Store` y una instancia nuevos.

| Clave | Default | Rango | Efecto observable |
|---|---:|---:|---|
| `path` | — (obligatorio) | `.wasm` ≤ 4 MiB | Ruta relativa al fichero de configuración. Un módulo inválido, un import no permitido o un export ausente **rechazan la configuración**. |
| `fuel` | 10 000 000 | 1..=100 000 000 | Instrucciones por invocación; agotarlo es un trap `OutOfFuel`. |
| `timeout` | `"50ms"` | 1 ms..=5 s | Deadline de pared por invocación (epoch de 1 ms). Un bucle infinito se interrumpe. |
| `memory_bytes` | 16 MiB | 1..=256 MiB | Memoria lineal por instancia; un `memory.grow` que la cruza trap. |
| `max_header_ops` | 16 | 1..=64 | Mutaciones de cabecera por invocación; superarlo es error de host. |
| `on_error` | `"closed"` | `closed` \| `open` | `closed`: 503 y la petición **no** se reenvía. `open`: se reenvía sin cambios y se cuenta `plugin_errors`. |

ABI v1: el módulo exporta `memory`, `eqproxy_alloc` y
`eqproxy_on_request`, y solo puede importar `eqproxy.set_request_header` y
`eqproxy.remove_request_header`. No hay WASI ni ninguna función de host que
haga I/O: red y sistema de ficheros están denegados **por construcción**, no
por una comprobación en tiempo de ejecución. Cualquier otro import rechaza el
módulo nombrándolo.

Las cabeceras de framing y conexión (`content-length`, `transfer-encoding`,
`connection`, `host`, `upgrade`, `expect`, `te`, `trailer`,
`proxy-connection`) están **reservadas**: un plugin que las toque es error de
host y aplica `on_error`. Dejar que una extensión reescriba el framing después
de que el proxy lo validó reabriría el *request smuggling*.

## 2. Dónde vive

- Esquema: [`PluginConfig`](../../eqproxy-config/src/schema.rs#L1108) y
  [`ListenerConfig::plugin`](../../eqproxy-config/src/schema.rs#L1044).
- Validación de rangos, `mode = "http"` y `max_head_bytes <= 64 KiB`:
  [`validate.rs:660`](../../eqproxy-config/src/validate.rs#L660), con el test
  [`plugin_bounds_are_enforced_and_http_mode_is_required`](../../eqproxy-config/src/validate.rs#L2020).
- Host: [`PluginHost::load`](../../eqproxy-net/src/plugin.rs#L185),
  [`PluginHost::run`](../../eqproxy-net/src/plugin.rs#L241),
  [`check_imports`](../../eqproxy-net/src/plugin.rs#L572),
  [`check_exports`](../../eqproxy-net/src/plugin.rs#L590) y el ticker de epoch
  ([`plugin.rs:162`](../../eqproxy-net/src/plugin.rs#L162)).
- Enganche en el motor: [`http1.rs:2048`](../../eqproxy-net/src/http1.rs#L2048)
  (invocación, deny antes del dial, política de fallo) y
  [`apply_plugin_headers`](../../eqproxy-net/src/http1.rs#L1645) (mutaciones al
  final, sobre la cabeza ya reescrita por reglas y `X-Forwarded-*`).
- Resolución desde el CLI: [`main.rs:2789`](../../eqproxy-cli/src/main.rs#L2789).
- Contadores: [`plugin_requests`, `plugin_denied`, `plugin_errors`](../../eqproxy-core/src/metrics.rs#L146),
  sin etiquetas (cardinalidad acotada).

## 3. E2E con sockets reales (9 tests)

Fixture: módulos `.wasm` versionados junto a su fuente `.wat` en
[`eqproxy-net/tests/fixtures/plugins/`](../../eqproxy-net/tests/fixtures/plugins/).
El test carga **los mismos bytes** que cargaría producción; el `.wat` solo
hace revisable el contenido. El origen es un `TcpListener` real que registra
la cabeza recibida, así que «no se marcó el backend» es un hecho sobre el
socket (`dials == 0`), no un mock.

| Test | Qué demuestra |
|---|---|
| [`plugin_adds_a_header_the_backend_receives`](../../eqproxy-net/tests/e2e_plugins.rs#L179) | El origen recibe `x-plugin: on`; `plugin_requests=1`, 0 denegadas, 0 errores. |
| [`plugin_denial_never_dials_the_backend`](../../eqproxy-net/tests/e2e_plugins.rs#L208) | Un `deny_403.wasm` produce 403, **0 dials** y `plugin_denied=1`. |
| [`plugin_sees_the_request_head_and_can_deny_by_method`](../../eqproxy-net/tests/e2e_plugins.rs#L235) | El plugin ve `GET` real: deniega GET (403) y deja pasar POST (200, 1 dial). |
| [`fuel_exhaustion_fails_closed_by_default`](../../eqproxy-net/tests/e2e_plugins.rs#L259) | `spin.wasm` con fuel 10 000 → 503, 0 dials, `plugin_errors=1`. |
| [`the_deadline_fails_closed_even_with_plenty_of_fuel`](../../eqproxy-net/tests/e2e_plugins.rs#L280) | El mismo bucle con fuel 100 M y deadline 5 ms → 503: interrumpe el reloj, no el fuel. |
| [`fail_open_forwards_the_request_unchanged`](../../eqproxy-net/tests/e2e_plugins.rs#L301) | Con `on_error = "open"`, el trap se reenvía sin `x-plugin` y se cuenta el error. |
| [`memory_growth_over_the_bound_fails_closed`](../../eqproxy-net/tests/e2e_plugins.rs#L323) | `grow.wasm` con 1 MiB de tope → 503, 0 dials. |
| [`a_reserved_framing_header_from_the_plugin_fails_closed`](../../eqproxy-net/tests/e2e_plugins.rs#L344) | `content-length` desde el plugin → 503, nunca se reenvía. |
| [`plugin_denial_is_enforced_on_http2_streams`](../../eqproxy-net/tests/e2e_plugins.rs#L366) | Un cliente `h2` real recibe 403 en su stream y el origen no se marca. |

Unitarios del host (9): operaciones de cabecera, fuel, epoch, import WASI
denegado y nombrado, cabecera reservada, `memory.grow`, y los dos rechazos de
carga (exports ABI ausentes y memoria inicial por encima del tope)
([`plugin.rs:677`](../../eqproxy-net/src/plugin.rs#L677)). Más el gate de
configuración de §2.

## 4. S-PLG-01 — coste medido con y sin plugin

### Montaje

`scripts/evidence/v085-wasm-plugins/run.sh` (local-only), dos brazos que solo
difieren en `[listener.web.plugin]`: origen Go real en `127.0.0.1:18081`,
proxy en `127.0.0.1:18080`, `oha 1.14.0`, 15 s por repetición, 64 conexiones
keep-alive, respuestas de 1 KiB, plugin que añade `x-plugin: on` a cada
petición. Dos tandas con el **mismo binario**
`de585e73239d501c2fa327914b56c21960e4e2878c9a89c714fc5b5c17dc9f25`:
3 repeticiones por brazo ([`raw/20261029T183408Z`](v085-wasm-plugins/raw/20261029T183408Z))
y 7 más ([`raw/20261029T184411Z`](v085-wasm-plugins/raw/20261029T184411Z)),
10 por brazo en total. Entorno: macOS 25.5.0, arm64, 10 núcleos, generador y
proxy co-locados, sin *pinning* de CPU.

### Resultados (mediana de 10 repeticiones por brazo)

| Brazo | RPS | p50 | p99 | CPU del proxy | 200 | 503 |
|---|---:|---:|---:|---:|---:|---:|
| sin plugin | **6369.6** | **8.985 ms** | **30.901 ms** | **118.9 %** | 948 783 | 0 |
| con plugin | **5526.0** | **9.818 ms** | **41.900 ms** | **135.9 %** | 825 272 | **22** |
| Δ | **−13.24 %** | **+9.27 %** | **+35.59 %** | **+17.0 pp** | | |

Rango de RPS por repetición: 5749.9–6662.5 sin plugin y 4258.5–6105.2 con
plugin. Las medianas por tanda: −9.57 % (3 reps) y −14.36 % (7 reps); el
sentido del efecto es el mismo en las dos, la magnitud no es separable con
precisión de esta muestra. El coste de CPU (+17 pp de un núcleo, es decir
~1.7 núcleos de los 10) es la señal más estable. Crudo y cálculo:
[`summary.tsv`](v085-wasm-plugins/raw/20261029T184411Z/summary.tsv),
[`summary.json`](v085-wasm-plugins/raw/20261029T184411Z/summary.json) y
[`pooled-summary.json`](v085-wasm-plugins/raw/20261029T184411Z/pooled-summary.json).

### Los 22 × 503 del brazo con plugin (no ocultos)

Con el `timeout = "50ms"` por defecto, **22 de 825 294** peticiones
(0.0027 %) recibieron 503 de la política `closed`, repartidas en 9 de las 10
repeticiones (1–5 por repetición). No son errores del plugin: la única función
invocada es `set_request_header` con constantes válidas, así que no puede
agotar 10 M de fuel, ni crecer memoria, ni tocar una cabecera reservada. La
causa es el deadline de **reloj de pared** bajo saturación: con los 10 núcleos
ocupados por el generador, un worker puede quedar desplanificado más de 50 ms
entre ticks de epoch.

Diagnóstico reproducible: la misma configuración con `timeout = "500ms"`
responde **0 × 503 en 87 493 peticiones** con un RPS equivalente (5835.4), en
[`raw/20261029T183408Z/diagnostic-timeout-500ms/`](v085-wasm-plugins/raw/20261029T183408Z/diagnostic-timeout-500ms/).
Es la semántica documentada (fail-closed) y a la vez un límite operativo: un
despliegue con SLO de cola debe subir `timeout` o aceptar ese 0.0027 % de 503
en hosts saturados.

Los `errorDistribution` de `oha` (`aborted due to deadline`, 637 sin plugin y
631 con plugin) son del **generador**, no del proxy: todas las respuestas
registradas son 200 salvo los 503 citados.

### Lectura

- El plugin añade ~13 % menos RPS y ~36 % más p99 en este montaje co-locado.
  No se presenta como una cifra universal: es un A/B en el mismo host, con un
  módulo trivial y sin pooling de instancias (decisión consciente, ADR-0031).
- El trigger de revisión 3 del ADR («el coste por instancia domina el
  presupuesto») **no se alcanza**: el proxy sigue entregando >5 500 RPS con
  plugin; si un despliegue necesita el techo, el pooling es una decisión
  nueva con su propio análisis de aislamiento.

## 5. Reproducción

```text
cargo fmt --all -- --check                              → exit 0
cargo clippy --workspace --all-targets -- -D warnings  → exit 0
cargo test --workspace                                 → 595 passed, 0 failed (32 binarios)
cargo test -p eqproxy-net --release --test e2e_plugins → 9 passed, 0 failed
cargo test -p eqproxy-net --release --lib plugin       → 9 passed, 0 failed
cargo test -p eqproxy-config --release plugin_bounds   → 1 passed, 0 failed
REPS=7 bash scripts/evidence/v085-wasm-plugins/run.sh  → exit 0; crudo en raw/20261029T184411Z
```

El binario del benchmark se construyó con `cargo build --release -p
eqproxy-cli`; su sha256 está en `environment.txt` de cada tanda. El montaje no
usa contenedores ni otra máquina: es el mismo host de las pruebas, y por eso
las cifras son indicativas, no una comparación contra HAProxy.

## 6. Límites de la evidencia

- **Fase de respuesta y cuerpo fuera de ABI v1.** Solo se filtran cabeceras de
  petición y el veredicto; un filtro de respuesta o que lea el cuerpo necesita
  ABI v2. Está declarado en ADR-0031 y en la matriz, no implícito.
- **Sin estado persistente.** Un `Store` por petición: el plugin no puede
  recordar nada entre peticiones. Es una decisión de aislamiento, no un
  olvido; estado compartido exigiría otro diseño y revisión de concurrencia.
- **Sin pooling.** La instancia se crea por petición; el coste medido lo
  incluye. El trigger de revisión está en el ADR.
- **El deadline es de pared.** Bajo saturación extrema puede dispararse con
  trabajo trivial (los 22 × 503 de §4). No se corrigió cambiando el default
  después de medir: se documenta y se deja la palanca (`timeout`).
- **No se probó en musl/contenedor** en esta casilla. El runtime se compila
  con `default-features = false` y sin WASI; la imagen se ejercita en la
  casilla de artefactos del roadmap.
- **wasmtime 50 añade Cranelift al grafo de dependencias** (licencia
  `Apache-2.0 WITH LLVM-exception`, permitida); `cargo-deny` y la pata de
  licencias de Veyra son el gate.

## 7. Auditorías del incremento

| Pata | Comando | Resultado | Evidencia |
|---|---|---|---|
| Veyra Proof | `veyra audit . --profile standard` | **ACCEPTED**, exit 0; 11 herramientas OK; `dylint` y `cargo-semver-checks` skipped y `cargo-geiger` INCONCLUSIVE, ambos por la razón del ADR-0030 | [`.veyra/evidence/20261029T190213Z/report.md`](../../.veyra/evidence/20261029T190213Z/report.md) |
| Rust Audit | `python3.13 <rust-ai-audit>/scripts/rust_audit.py scan . --format md --out report --fail-on high` | exit 0; **0 critical / 0 high**; 242 medium, 93 low (0.2.7) | [`report/rust-audit-20261029-195132.md`](../../report/rust-audit-20261029-195132.md) |
| CodeGraph Rust | `codegraph-rust index . --stats-json /tmp/cg-index-fresh.json --batch-size 16` + `agent impact` / `agent context` | exit 0; 68 ficheros, 65 175 líneas, 7 365 nodos, 13 272 aristas, `graph_complete: true`, `vector_index_ready: true`, `index_ms: 1 066 459`; las dos consultas resuelven el módulo y sus líneas se comprobaron en el fuente; **una afirmación refutada** (ver abajo) | [`raw/codegraph-20261029T211650Z/`](v085-wasm-plugins/raw/codegraph-20261029T211650Z) |
| Hindsight | `hindsight-note --title ... --project EQProxy --tags v0.8.5 wasm-plugins` | nota guardada en el banco `eqproxy` (HTTP 200) | banco `eqproxy`, `http://localhost:8888/mcp/eqproxy/` |

La primera pasada de Veyra sobre este árbol salió **REJECTED** en la pata de
licencias (`licenses FAILED`, exit 4): `foldhash 0.2`, que Cranelift introduce
vía `hashbrown`, publica bajo **Zlib** y no estaba en la lista explícita de
`deny.toml`. No se desactivó el gate: se añadió la licencia con
[ADR-0033](../adr/0033-zlib-license-for-foldhash.md) y se repitió la auditoría.
El run rechazado se conserva en `.veyra/evidence/20261029T185152Z/` y **no** se
presenta como aprobado.

La primera pasada de CodeGraph sobre este árbol **no produjo índice utilizable**:
`codegraph-rust index` terminó con exit 1 tras `INDEXING COMPLETE`
(`Vector index idx_chunks_embedding_1024 not ready: {"building":{"compacting":true,…}}`)
y `agent impact` respondió con `Vector index 4 on table chunks cannot be searched:
entry point element 1946 has no vector in this transaction`. No se citó ese
estado como evidencia: se renombró el almacén corrupto
(`.codegraph-broken-20261029/`, local-only) y se indexó de cero. El índice nuevo
sí pasa la validación (`vector_index_ready: true`) y sus cifras son las de la
tabla.

Las dos consultas de CodeGraph son **advisory** y se contrastaron con el
fuente. Aciertan en `PluginHost` ([`plugin.rs:109`](../../eqproxy-net/src/plugin.rs#L109)),
`PluginHost::load` ([`:182`](../../eqproxy-net/src/plugin.rs#L182)),
`PluginOutcome` ([`:82`](../../eqproxy-net/src/plugin.rs#L82)),
`with_plugin` ([`proxy.rs:950`](../../eqproxy-net/src/proxy.rs#L950)) y las
líneas de los tests. Pero `agent impact` concluye que «el único consumidor de
producción es `resolve_with` (main.rs:2426)» y que el resto es código de test;
es **falso**: el punto de invocación en el camino de petición es
[`http1.rs:2053`](../../eqproxy-net/src/http1.rs#L2053) (`plugin.run(&head_bytes)`),
que la propia respuesta declara no haber podido resolver. `agent context`
también se queda en `plugin.rs:241` y recomienda buscar a mano; la búsqueda
confirma que h1, cada stream h2 y cada petición h3 pasan por esa llamada. El
hecho que se retiene es el del fuente, no el de la respuesta del agente.

Rust Audit no marca nada en `plugin.rs`. En `e2e_plugins.rs` deja 9 avisos
**low** `R02` («magic number test») por las aserciones `200`, `403`, `503`,
`0` y `1`: son los códigos HTTP y los dials que el journey debe afirmar
literalmente, no una aserción débil. No hay hallazgos nuevos medium ni high, y
los 242 medium / 93 low del informe son los ya existentes en el resto del
tree.
