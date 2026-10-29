# v0.8.5 — buffers y límites configurables (B-N19 · B-I17 · B-E19 · CE3)

**Fecha:** 2026-10-29 · **Casilla:** §1 «Buffers y límites configurables» y §2
CE3 del [roadmap 0.8.5](../../ROADMAP%20EQPROXY/ROADMAP/Roadmap%200.8.5.md).
**Estado:** implementada y verificada E2E; la memoria por A/B **no medida**
(§6).

---

## 1. Qué se puede configurar y qué significa cada valor

`[listener.<name>.limits]` es opcional y **todos sus defaults son las
constantes que el dataplane ya usaba**: omitir la tabla no cambia ningún
byte del comportamiento anterior.

| Clave | Default | Rango | Efecto observable |
|---|---:|---:|---|
| `max_head_bytes` | 16384 | 1024..=1048576 | Tope de la cabeza **de petición y de respuesta** (sin el `\r\n\r\n`). Un cliente que lo cruza recibe 431; un backend que lo cruza, 502. |
| `max_headers` | 100 | 1..=1000 | Número máximo de campos de cabecera por mensaje, en las dos direcciones (431 / 502). |
| `max_body_bytes` | 0 (ilimitado) | `u64` | Tope del **cuerpo de petición**. Un `Content-Length` por encima se rechaza con 413 **antes de marcar el backend**; un cuerpo `chunked` se rechaza en cuanto el siguiente frame lo cruzaría. |
| `stream_buffer_bytes` | ausente = 64 KiB (16 KiB en h3) | 1024..=1048576 | Buffer de la tubería interna de cada stream h2/h3/WebSocket y de cada exchange h2 de backend, más la tubería del compresor. |

La validación rechaza valores fuera de rango con el campo exacto
(`listener.<name>.limits.max_head_bytes`), para que un `16` pensado como KiB no
se convierta en una caída.

## 2. Dónde vive

- Esquema: [`LimitsConfig`](../../eqproxy-config/src/schema.rs#L1057) y
  [`ListenerConfig::limits`](../../eqproxy-config/src/schema.rs#L1040).
- Validación: [`validate.rs:617`](../../eqproxy-config/src/validate.rs#L617)
  (cabeza), [`validate.rs:629`](../../eqproxy-config/src/validate.rs#L629)
  (campos) y [`validate.rs:641`](../../eqproxy-config/src/validate.rs#L641)
  (buffer).
- Resolución: [`ResolvedLimits`](../../eqproxy-net/src/proxy.rs#L802),
  [`ResolvedListener::limits`](../../eqproxy-net/src/proxy.rs#L867) y
  [`with_limits`](../../eqproxy-net/src/proxy.rs#L939); el CLI copia los
  valores ya validados en `resolve()`
  ([main.rs](../../eqproxy-cli/src/main.rs#L2779)).
- Parser y motor:
  [`HeadLimits`](../../eqproxy-net/src/http1.rs#L65),
  [`read_head`](../../eqproxy-net/src/http1.rs#L1074),
  [`copy_chunked_capped`](../../eqproxy-net/src/http1.rs#L765) y el rechazo
  413 del `Content-Length` en
  [`http1.rs:2058`](../../eqproxy-net/src/http1.rs#L2058).
- Tuberías: h2
  ([http2.rs:271](../../eqproxy-net/src/http2.rs#L271), con
  `max_header_list_size` en
  [http2.rs:181](../../eqproxy-net/src/http2.rs#L181)), h3
  ([http3.rs:331](../../eqproxy-net/src/http3.rs#L331)), WebSocket
  ([ws.rs:114](../../eqproxy-net/src/ws.rs#L114)), exchange h2 de backend
  ([backend_h2.rs:518](../../eqproxy-net/src/backend_h2.rs#L518)) y compresor
  ([http1.rs](../../eqproxy-net/src/http1.rs#L941)).
- h2 y h3 no tienen un segundo motor: traducen la petición a HTTP/1.1 y la
  pasan por `http1::serve_http` con el mismo `ResolvedListener`, así que los
  cuatro límites se aplican una sola vez y del mismo modo en los tres
  protocolos. El `max_header_list_size` del servidor h2 publica además el
  tope real antes de que el cliente envíe el bloque.

## 3. El fallo que encontró el primer E2E

El control `max_head_bytes = 128` contra una respuesta de ~300 bytes devolvió
**200**: `read_head` comprobaba el presupuesto solo cuando aún no había
encontrado el terminador. Si la primera lectura de 2 KiB traía la cabeza
completa, el `if let Some(pos) = find_sub(...)` salía antes de cualquier
comprobación y el límite no existía. Es un defecto del código anterior, no de
la sección nueva: con `MAX_HEAD_BYTES = 16 KiB` ocurría lo mismo por encima de
16 KiB si el terminador llegaba en la misma lectura.

Ahora el tope se comprueba contra `pos` antes de aceptar la cabeza
([http1.rs:1094](../../eqproxy-net/src/http1.rs#L1094)), y el caso tiene su
test: 128 bytes → 502, default → 200
([`response_head_over_the_bound_is_a_502_not_a_forward`](../../eqproxy-net/tests/e2e_limits.rs#L344)).
El mismo arreglo acota el `read_head` de h2/h3/WebSocket y del exchange h2 de
backend, que comparten la función.

## 4. Verificación ejecutada

### Tests nuevos (10)

| Nivel | Test | Qué demuestra |
|---|---|---|
| unit | [`configured_header_count_is_the_bound_in_both_directions`](../../eqproxy-net/src/http1.rs#L2832) | 2 campos pasan, 3 dan 431; el mismo tope da 502 en la respuesta. |
| unit | [`read_head_enforces_the_configured_byte_budget`](../../eqproxy-net/src/http1.rs#L2885) | 200 bytes sin terminador con 100 de presupuesto → `TooLarge`; una cabeza que cabe → `Ok`. |
| unit | [`chunked_cap_refuses_a_max_size_chunk_without_overflowing`](../../eqproxy-net/src/http1.rs#L2859) | Un chunk de `u64::MAX` con tope 16 → 413 lógico (`TooLarge`), sin desbordar el acumulador y sin reenviar el frame. |
| unit | [`limits_bounds_are_enforced_and_the_defaults_are_valid`](../../eqproxy-config/src/validate.rs#L1941) | Tabla vacía y valores válidos pasan; `16`, `0` y buffer `0` fallan con el campo nombrado. |
| E2E | [`header_count_bound_is_configurable_and_explicit`](../../eqproxy-net/tests/e2e_limits.rs#L258) | 3 campos → 200; 4 → 431 y el origen no se marca. |
| E2E | [`declared_body_over_the_cap_is_refused_before_the_dial`](../../eqproxy-net/tests/e2e_limits.rs#L290) | 32 B con tope 16 → 413 y **0** dials; 16 B → 200 y 1 dial. |
| E2E | [`chunked_body_over_the_cap_is_refused_with_413`](../../eqproxy-net/tests/e2e_limits.rs#L318) | 16 B → 200; 17 B → 413. |
| E2E | [`response_head_over_the_bound_is_a_502_not_a_forward`](../../eqproxy-net/tests/e2e_limits.rs#L344) | 300 B con tope 128 → 502; mismo origen con default → 200. |
| E2E | [`request_body_cap_also_holds_for_h2_chunked_translation`](../../eqproxy-net/tests/e2e_limits.rs#L366) | Un POST h2 sin `content-length` (traducido a chunked) de 20 B con tope 16 → 413. |
| E2E | [`one_kib_stream_pipe_relays_large_bodies_under_pressure`](../../eqproxy-net/tests/e2e_limits.rs#L398) | **16 streams × 512 KiB = 8 MiB** por tuberías de **1 KiB**: 16/16 completos, byte a byte. |

### Comandos y resultados

```text
cargo fmt --all -- --check                              → ok
cargo check --workspace --all-targets                   → ok
cargo clippy --workspace --all-targets -- -D warnings  → exit 0
cargo test --workspace                                  → exit 0; 31 binarios, 576 passed, 0 failed
cargo test -p eqproxy-net --test e2e_limits             → 6 passed, 0 failed
cargo test -p eqproxy-net --lib http1::tests            → 13 passed, 0 failed
cargo test -p eqproxy-config --lib validate::tests::limits → 1 passed
```

La suite completa sube de **566 a 576** tests: los 10 nuevos. Se regeneró el
artefacto derivado `eqproxy.schema.json` con el propio binario
(`eqproxy config schema --output eqproxy.schema.json`, +42 líneas) y el test
que compara el fichero publicado con lo que el binario renderiza pasa.

### Presión bajo carga

10 pasadas completas de `e2e_limits` con los **10 núcleos** saturados
(`yes > /dev/null`), 2026-10-29 **15:47:28→15:48:39 UTC**:

```text
10/10 pasadas "test result: ok. 6 passed; 0 failed"
60 ejecuciones de journey, 0 fallos
duración por pasada: 2,86 s – 5,16 s
```

Crudo: [`raw/20261029T154728Z/pressure.txt`](v085-limits/raw/20261029T154728Z/pressure.txt)
y [`window.txt`](v085-limits/raw/20261029T154728Z/window.txt).

## 4 bis. La carrera de h3 que destapó Veyra (y su arreglo)

La primera pasada de Veyra sobre esta casilla salió **REJECTED**
(`nextest:nextest-failure`) por un test **anterior**:
`http3_connect_is_refused_and_a_dead_backend_is_an_explicit_502` recibió
`RemoteTerminate { code: H3_REQUEST_INCOMPLETE }` en lugar del 502.

Diagnóstico: si el FIN del cliente no había llegado al `peek_first_chunk`, la
petición se traducía a `chunked`; el motor marcaba el backend muerto, escribía
el 502 y cerraba su mitad de la tubería. El `BodyEnd` posterior intentaba
escribir el terminador, fallaba y hacía `stop_stream(H3_REQUEST_INCOMPLETE)`
antes de que el relay entregara el 502 ya producido. Carrera real del
servidor, no del test.

Arreglo: un cuerpo que ya no se puede reenviar no aborta una respuesta en
curso. El bucle deja de leer cuerpo (`body_failed`) y sigue esperando el
comando del relay; si llega la respuesta se entrega y se cierra, y solo un
relay desaparecido o un idle sin respuesta cortan el stream
([http3.rs](../../eqproxy-net/src/http3.rs#L362)).

Evidencia de la reproducción y del arreglo:

```text
antes:  cargo nextest run … --stress-count 200  → 1 fallo en 82 iteraciones
        (mismo H3_REQUEST_INCOMPLETE, backend "Connection refused")
después: cargo nextest run … --stress-count 300 → 300/300 passed
```

No se cambió ninguna aserción del test; el arreglo está en el servidor.

## 5. Límites de la evidencia

- **No se midió un A/B de RSS** entre 64 KiB y 1 KiB. El test demuestra el
  efecto funcional (8 MiB en vuelo por 16 tuberías de 1 KiB, sin truncar ni
  bloquear), no una cifra de memoria; afirmar una reducción sin medirla sería
  exactamente lo que este repositorio no acepta. El bufer es configurable y
  cada stream lo respeta; cuánto ahorra en un despliegue concreto queda para
  la campaña de benchmarks de la versión.
- **El cuerpo de respuesta no tiene tope.** `max_body_bytes` es una cota de
  petición (clase `client_max_body_size`); recortar una respuesta cambiaría
  bytes que el cliente ya espera. El tope de respuesta podría añadirse con
  semántica propia (502 antes de la cabeza / corte después) en otra casilla.
- **Un cuerpo `chunked` puede llegar al backend antes del 413**: el tamaño no
  se conoce hasta leer el frame, y el frame que cruza no se reenvía. El
  exchange se abandona y la conexión no vuelve al pool. Un `Content-Length`
  declarado sí se rechaza antes de marcar (test con `dials == 0`).
- h3 no tiene un `max_header_list_size` propio en el builder: el tope lo
  aplica el motor h1 al leer la cabeza traducida, con el 431/502 ya descrito.

## 6. Auditorías del incremento

| Pata | Comando | Resultado | Evidencia |
|---|---|---|---|
| Veyra Proof | `veyra audit . --profile standard` | **ACCEPTED**, exit 0 | [`.veyra/evidence/20261029T165444Z/report.md`](../../.veyra/evidence/20261029T165444Z/report.md) |
| Rust Audit | `python3.13 <rust-ai-audit>/scripts/rust_audit.py scan . --format md --out report --fail-on high` | exit 0; **0 critical / 0 high** (242 medium, 84 low; ninguno en el código nuevo) | [`report/rust-audit-20261029-175443.md`](../../report/rust-audit-20261029-175443.md) |
| CodeGraph Rust | `codegraph-rust index . --stats-json /tmp/cg-index.json --batch-size 16` | **NOT EXECUTED**: el indexado murió en `Ollama embedding request failed` sin escribir `--stats-json`; sin índice fresco no se ejecutó `agent impact/context` | log local `/tmp/cg-index.log` (parse: 7 159 nodos, 23 000 edges; el fallo es del índice vectorial, `entry point element 1946 has no vector` y después el embedder) |
| Hindsight | `hindsight-note --title "v0.8.5 limits: buffers y límites configurables + carrera h3" --project EQProxy --tags v085,limits,buffers,http3` | guardada: 6 ids (`092daf78…`, `f3738d90…`, `d24325bd…`, …) | banco `eqproxy` |

Veyra había salido **REJECTED** antes del arreglo de la carrera h3 (§4 bis);
el veredicto REJECTED y su log se conservan en
`.veyra/evidence/20261029T163452Z/` y no se presentan como aprobados. El
`dylint` y el `cargo-semver-checks` aparecen como *skipped* por la razón ya
decidida en el ADR-0030; `cargo-geiger` sigue **INCONCLUSIVE** por avisos de
cobertura de terceros, también según el ADR-0030.
