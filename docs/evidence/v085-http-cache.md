# v0.8.5 — caché HTTP por listener (B-N7 · H1)

**Fecha:** 2026-10-30 · **Casilla:** §1 «Caché HTTP» y criterio de §4
(«test de sesiones concurrentes + revalidación ETag/304») del
[roadmap 0.8.5](../../ROADMAP%20EQPROXY/ROADMAP/Roadmap%200.8.5.md).
**Estado:** implementada y verificada E2E con sockets reales; cierra además
**H1** (caché honesta). Lo fuera de v1 (`stale-while-revalidate`,
`stale-if-error`, `only-if-cached`, `Pragma`, `If-Modified-Since` de
cliente) está declarado en el ADR, no implícito (§6).

Diseño: [ADR-0034](../adr/0034-http-response-cache.md).

---

## 1. Qué se puede configurar

`[listener.<name>.cache]` es opcional y solo se acepta en listeners
`mode = "http"` (h1, cada stream h2 y cada petición h3 pasan por el mismo
`plan_cache` / `serve_cached`). Ausente = caché desactivada.

| Clave | Default | Rango | Efecto observable |
|---|---|---:|---|
| `default_ttl` | `"60s"` | 1 s..=1 día | Frescura cuando el origen no acota más (`s-maxage`/`max-age` solo acortan; `no-cache` en respuesta la deja en cero). |
| `max_memory_bytes` | 64 MiB | 1 MiB..=1 GiB | Presupuesto RAM; por encima, desalojo LRU primero. |
| `max_entry_bytes` | 1 MiB | 64 KiB..=64 MiB (y `<= max_memory_bytes`) | Cuerpos mayores pasan de largo sin cachearse, nunca truncados. |
| `disk_path` | — (solo memoria) | relativo al fichero de config | Persistencia write-through; ficheros caducados o corruptos se saltan y se cuentan. |

Claves de almacenamiento: solo `GET` (un `HEAD` se sirve de la entrada
`GET`, solo cabeceras); 200/301/308/404/410. Nunca se mira ni se guarda con
`Cookie`, `Authorization`, `Range` o `Cache-Control: no-store` en la
petición, ni con `Set-Cookie`, `206` o `302` en la respuesta. La llave es
método + esquema + host (minúsculas) + target + valores de las cabeceras
listadas en `Vary`; `Vary: *` o un `Vary` sobre `Cookie`/`Authorization`
hace la respuesta no almacenable. Un backend con afinidad por cookie
desactiva la caché en tiempo de ejecución. Solo cuerpos con
`Content-Length` bajo el tope se ensamblan en memoria; `chunked` y cierre
de conexión pasan de largo.

Cada respuesta servida lleva `X-Cache: HIT | MISS | REVALIDATED` (`Age`
junto a `HIT`; un `304` a `If-None-Match` del cliente no lleva `Age`).
Contenido visible en `GET /api/v1/cache` (edad, TTL, hits, tamaño, acotado
a 128 objetos) y contadores `cache_hits`, `cache_misses`,
`cache_bypasses`, `cache_revalidations`, `cache_stores`,
`cache_evictions`, `cache_disk_loads`, `cache_disk_skipped`, sin etiquetas.

## 2. Dónde vive

- Esquema: [`CacheConfig`](../../eqproxy-config/src/schema.rs#L1183) y
  [`ListenerConfig::cache`](../../eqproxy-config/src/schema.rs#L1048).
- Validación de rangos, `mode = "http"` y `entry <= memory`:
  [`validate.rs:751`](../../eqproxy-config/src/validate.rs#L751), con su
  gate de config.
- Almacén: [`Cache::load`](../../eqproxy-net/src/cache.rs#L281),
  [`Cache::lookup`](../../eqproxy-net/src/cache.rs#L333) (hit / revalidate
  / fetch / lock-wait), [`Cache::refresh`](../../eqproxy-net/src/cache.rs#L421)
  (el `304` fusiona cabeceras sin tocar el cuerpo, por reemplazo),
  [`decide`](../../eqproxy-net/src/cache.rs#L862) (exclusiones),
  [`render_head`](../../eqproxy-net/src/cache.rs#L1128) y
  [`client_fresh`](../../eqproxy-net/src/cache.rs#L1143).
- Enganche en el motor: [`plan_cache`](../../eqproxy-net/src/http1.rs#L1790)
  (tras routing/auth/plugin, antes del primer byte al backend),
  [`serve_cached`](../../eqproxy-net/src/http1.rs#L1970) (sirve del almacén,
  marca `HIT`/`REVALIDATED`, aplica cabeceras de regla y compresión),
  revalidación [`http1.rs:3041`](../../eqproxy-net/src/http1.rs#L3041) y
  marcador `MISS` del camino de origen
  [`http1.rs:3284`](../../eqproxy-net/src/http1.rs#L3284).
- Resolución desde la CLI: [`main.rs:2827`](../../eqproxy-cli/src/main.rs#L2827).
- Contenido visible: [`/api/v1/cache`](../../eqproxy-net/src/admin.rs#L1446)
  sobre [`Cache::snapshot`](../../eqproxy-net/src/cache.rs#L523).
- Contadores: [`metrics.rs:154`](../../eqproxy-core/src/metrics.rs#L154).

## 3. E2E con sockets reales (13 tests)

Fixture: un `TcpListener` real que registra cada petición (hits por path,
condicionales recibidas, dials), así que «el origen solo se tocó una vez»
es un hecho sobre el socket, no un mock. Los 13 journeys están en
[`eqproxy-net/tests/e2e_cache.rs`](../../eqproxy-net/tests/e2e_cache.rs).

| Test | Qué demuestra |
|---|---|
| [`miss_then_hit_serves_identical_bytes`](../../eqproxy-net/tests/e2e_cache.rs#L402) | MISS, luego HIT con bytes idénticos; `cache_hits=1`, `misses=1`, `stores=1`. |
| [`sessions_never_share_an_entry`](../../eqproxy-net/tests/e2e_cache.rs#L426) | Dos sesiones (`Cookie` distinta) nunca comparten: sin marcador, 1 fetch por sesión, `bypasses` contados, nada almacenado. |
| [`set_cookie_responses_are_never_stored`](../../eqproxy-net/tests/e2e_cache.rs#L460) | Respuesta con `Set-Cookie`: 2 peticiones, 2 fetches, `stores=0`. |
| [`vary_selects_the_variant`](../../eqproxy-net/tests/e2e_cache.rs#L474) | `Vary: Accept-Language`: una variante por idioma, el idioma ausente es su propia variante, un fetch por variante. |
| [`etag_revalidation_refreshes_without_a_body`](../../eqproxy-net/tests/e2e_cache.rs#L495) | `no-cache` del cliente → condicional al origen → `304` → `REVALIDATED` sin cuerpo (`cache_revalidations=1`); al rotar el origen, el `200` reemplaza y lo siguiente es `HIT`. |
| [`entries_expire_after_their_ttl`](../../eqproxy-net/tests/e2e_cache.rs#L531) | TTL de 1 s: caducada y con validadores, el origen revalida con `304` y el cliente nunca ve la caducidad (`REVALIDATED`, cuerpo intacto). |
| [`concurrent_requests_share_one_origin_fetch`](../../eqproxy-net/tests/e2e_cache.rs#L556) | 10 concurrentes: 1 fetch, 1 dial en una conexión reutilizada, 9 servidas del almacén (cache-lock). |
| [`head_is_served_from_the_get_entry`](../../eqproxy-net/tests/e2e_cache.rs#L581) | `HEAD` tras `GET`: 200, cuerpo vacío, `HIT`, `content-length` del `GET`, 1 solo fetch. |
| [`authorization_and_ranges_bypass`](../../eqproxy-net/tests/e2e_cache.rs#L598) | `Authorization` y `Range` ni miran ni guardan (3 fetches, `bypasses=3`, `stores=0`); lo siguiente normal sí almacena y acierta. |
| [`unstorable_statuses_and_directives_stream_through`](../../eqproxy-net/tests/e2e_cache.rs#L626) | `500` y `no-store` del origen: 2 fetches cada uno, `stores=0`. |
| [`oversized_bodies_stream_through_uncached`](../../eqproxy-net/tests/e2e_cache.rs#L643) | Cuerpo sobre el tope: 2 peticiones, 2 fetches, `MISS` siempre. |
| [`cookie_affinity_disables_the_cache_at_runtime`](../../eqproxy-net/tests/e2e_cache.rs#L664) | Backend con afinidad por cookie: sin marcador siquiera (ni `MISS`), 3 fetches, 3 bypasses. |
| [`disk_entries_survive_a_restart`](../../eqproxy-net/tests/e2e_cache.rs#L686) | Entrada en disco, reinicio con el origen apagado (todo dial falla): 200 con los bytes del disco, `HIT`, `cache_disk_loads >= 1`. |

Unitarios del almacén (`cache.rs`, `#[cfg(test)]`): parseo de hechos,
TTL efectivo, decisión de exclusión, `client_fresh`, el refresh que
conserva el cuerpo y el descarte de ficheros corruptos/caducados. Más el
gate de configuración de §2.

### El E2E encontró un bug real del proxy (no del test)

`etag_revalidation_refreshes_without_a_body` fallaba con `MISS` donde el
diseño exige `REVALIDATED`: el `fetch` condicional nunca llegaba al origen
como condicional. Causa en [`http1.rs:2699`](../../eqproxy-net/src/http1.rs#L2699):
la cabeza reenviada no lleva terminador (se escribe `HEAD_END` aparte), y
el `if-none-match` se añadía con `\r\n` **final** en vez de **inicial**,
quedando pegado a la última cabecera (`host: xif-none-match: …`). El origen
nunca veía el validador y respondía `200` completo en cada revalidación.
Fix: líneas con CRLF inicial. Sin el journey de revalidación, cada entrada
caducada se habría descargado entera para siempre sin que ningún contador
lo delatase (el fetch existía, el `304` no).

## 4. Reproducción

```text
cargo fmt --all -- --check                              → exit 0
cargo clippy --workspace --all-targets -- -D warnings  → exit 0
cargo test --workspace                                 → 615 passed, 0 failed (33 targets)
cargo test -p eqproxy-net --test e2e_cache             → 13 passed, 0 failed
cargo test -p eqproxy-net --release --test e2e_cache   → 13 passed, 0 failed
python3 .github/scripts/check-evidence-test-citations.py → exit 0, `ok: every cited test-shaped identifier exists`
```

CI del commit publicado TBD (se rellena tras el push).

## 5. Límites de la evidencia

- **Sin `stale-while-revalidate` ni `stale-if-error`.** Una entrada caducada
  nunca se sirve mientras otra tarea revalida (los que esperan bloquean en
  el lock); si el origen falla, el error se sirve, no lo caducado. Decisión
  documentada, no silencio.
- **Sin evaluación de `If-Modified-Since` del cliente.** Solo
  `If-None-Match` gana un `304` local; el `304` del origen sí se entiende en
  ambos validadores.
- **`Vary` por igualdad exacta** (recorte de espacios, sin plegado).
- **Sin medición S-CACHE bajo carga** en esta casilla: el criterio de §4
  pedía los journeys (sesiones + ETag/304), no un bench; el coste funcional
  demostrado es un fetch por llave bajo concurrencia (§3, lock).
- **El marcador `X-Cache` es informativo**, no contrato de paridad con otra
  caché: los valores siguen el vocabulario de nginx (`REVALIDATED`), no el
  de HAProxy.

## 6. Auditorías del incremento

| Pata | Comando | Resultado | Evidencia |
|---|---|---|---|
| Veyra Proof | `veyra audit . --profile standard` | **ACCEPTED**, exit 0; sin problems; `dylint` y `cargo-semver-checks` skipped y `cargo-geiger` INCONCLUSIVE, los tres por la razón del ADR-0030 | [`.veyra/evidence/20261030T160420Z/report.md`](../../.veyra/evidence/20261030T160420Z/report.md) |
| Rust Audit | `python3.13 <rust-ai-audit>/scripts/rust_audit.py scan . --format md --out report --fail-on high` (0.2.7) | exit 0; **0 critical / 3 high**; los 3 high son R16 falsos positivos (ver abajo) | [`report/rust-audit-20261030-170843.md`](../../report/rust-audit-20261030-170843.md) |
| CodeGraph Rust | `codegraph-rust index . --stats-json /tmp/cg-index-cache.json --batch-size 16` + `agent impact` / `agent context` | exit 0; 70 ficheros, 68 556 líneas, 7 676 nodos, 13 651 aristas, `graph_complete: true`, `vector_index_ready: true`, `errors: 0`, `index_ms: 1 022 904`; las dos consultas resuelven el módulo y sus líneas se comprobaron en el fuente | [`raw/codegraph-20261030T163000Z/`](v085-http-cache/raw/codegraph-20261030T163000Z) |
| Hindsight | `hindsight-note --title ... --project EQProxy --tags v0.8.5 http-cache` | TBD tras el push (la nota cita el run de CI) | banco `eqproxy` |

La primera pasada de Veyra sobre este árbol salió **REJECTED**
(`.veyra/evidence/20261030T154316Z`, error `RUSTSEC-2026-0422/0423/0424`):
los tres avisos, publicados el 2026-10-29 (después de la auditoría del
incremento de plugins), afectan a `wasmtime 50.0.0` y piden `>=50.0.1`.
Se subió el lockfile a `wasmtime 50.0.1` (`cargo update -p wasmtime`) y se
repitió la auditoría; el run rechazado se conserva y **no** se presenta
como aprobado. Los tres avisos tocan rutas de component-model/GC que este
árbol no compila (`default-features = false`, sin component-model),
pero el proceso manda arreglar, no gatear: se arregló.

Rust Audit marcó primero 9 high R09 (`.expect()` en `serve_http`): eran
los 6 `cfg.cache.as_ref().expect("planned with a cache")` de este
incremento — el único `expect` en código de producción del árbol — y se
eliminaron (cada sitio degrada a la ruta sin caché en vez de abortar el
exchange con panic). Los 3 high restantes son R16 (`refresh:421`, `insert:559`,
`remove:624` en `cache.rs`, «Mutex guard a través de `.await`»): **falsos
positivos**, el heurístico ve `lock()` y `.await` en la misma función sin
seguir el ámbito. En los tres, el guard vive en un bloque léxico que
termina antes del primer `.await` (`refresh`: el bloque cierra tras
`variants.push(entry)` y el `spawn_blocking(...).await` va después;
`insert` y `remove`: idéntico patrón). Los low R02 en `e2e_cache.rs` son
los códigos HTTP/dials que los journeys deben afirmar literalmente, no
aserciones débiles.
