# v0.8 — Rotación de certificados en caliente (D7)

Fecha: **2026-10-25** · ADR: [ADR-0025](../adr/0025-certificate-renewal-without-restart.md) ·
Roadmap: [0.8](../../ROADMAP%20EQPROXY/ROADMAP/Roadmap%200.8.md) (casilla D7) ·
Estado: **verificado E2E contra el binario de release**

## Qué se afirma (y con qué se demuestra)

| Afirmación | Prueba |
|---|---|
| El listener sirve el certificado de los ficheros configurados | `journey.log` fases 1 y 2: el DER que recibe un cliente TLS real (Python `ssl`) es la hoja de `cert.pem` |
| `POST /api/v1/certificates/reload` sustituye el material sin reiniciar | `journey.log`: tras escribir los ficheros de B, `200` con `fingerprint` de B y `changed: true`; un handshake **nuevo** recibe B (`sha256:10e03641…`) |
| La conexión abierta **antes** de la rotación sigue sirviendo | `journey.log`: la misma sesión hace `GET /before` antes y `GET /after` después, `200 hello-cert` |
| Un PEM corrupto no deja el proxy sin certificado | `journey.log`: `400 invalid_config` («no certificates in the PEM»), y un handshake nuevo sigue recibiendo B |
| La rotación alcanza a HTTP/3 sin reiniciar | `eqproxy-net/tests/e2e_http3.rs::http3_reload_applies_new_tls_on_the_same_socket` (incluida la conexión previa) |
| La rotación de un socket TCP conservado no corta el exchange en vuelo | `eqproxy-net/tests/e2e_resilience.rs::hot_reload_swaps_tls_material_on_the_kept_socket` |
| RBAC, `Origin`, cuerpo y auditoría de la acción | `journey.log` (403/401/403/400) + `admin::tests::certificate_reload_*` + líneas `AUDIT` con `"method":"POST"` |
| El journey no es vacuo | `control-reload-disabled.log`: con la recarga anulada el journey termina en `FAIL` (exit 1) |

## Comandos y artefactos

```
$ cargo build --release -p eqproxy-cli
$ shasum -a 256 target/release/eqproxy
e1574f7c1bb53d0f99f02159bc65df621ffa1f1628daefe95c12d1cbb78332c6  target/release/eqproxy
$ python3 scripts/evidence/v08-cert-renewal/journey.py
RESULT: all assertions passed          (37 aserciones, exit 0 → raw/journey.log)
```

Entorno: macOS 26.5.1 arm64 · rustc 1.97.1 · cargo 1.97.1 · `eqproxy 0.7.0`.

## Los ficheros que se rotan

| Material | Fichero | Hoja |
|---|---|---|
| A (inicial) | `eqproxy-net/tests/fixtures/cert.pem` + `key.pem` | `CN=localhost`, autofirmado |
| B (rotación) | `eqproxy-net/tests/fixtures/mtls-server.pem` + `mtls-server.key` | `CN=localhost`, emitido por `mtls-ca.pem` |

Son cadenas distintas para el mismo nombre, que es lo que distingue «mismo
certificado» de «certificado renovado» en un handshake real: el journey
compara el DER recibido con la hoja del fichero, no con una etiqueta.

## Salida completa (extracto del journey)

```
PASS the two fixtures are different certificates: True
PASS the listener serves certificate A: sha256:...
PASS the exchange over TLS: HTTP/1.1 200 OK|hello-cert
PASS status reports certificate A: sha256:...
PASS renewal accepted: 200
{"certificates":[{"changed":true,"fingerprint":"sha256:10e036410d8692c73bfc61cde85f727d1dc3dcc0d9c12944745ba411f9c91f3d","listen":"127.0.0.1:51450","listener":"tls","quic":false}],"elapsed_ms":0,"listeners":[{"listen":"127.0.0.1:51450","name":"tls"}],"revision":"v2","summary":"listeners kept=1 added=0 removed=0"}
PASS reported fingerprint: sha256:10e036410d8692c73bfc61cde85f727d1dc3dcc0d9c12944745ba411f9c91f3d
PASS reported as changed: True
PASS revision advanced: True
PASS pre-renewal connection kept serving: HTTP/1.1 200 OK|hello-cert
PASS the listener serves certificate B: sha256:10e036410d8692c73bfc61cde85f727d1dc3dcc0d9c12944745ba411f9c91f3d
PASS unchanged renewal reports changed=false: False
PASS the read token cannot renew: 403
PASS a browser origin is refused: 403
PASS a body is refused: 400
PASS a corrupt certificate is rejected: 400
{"error":"invalid_config","message":"inconsistent configuration after validation: listener.tls.tls: invalid PEM certificate: no certificates in the PEM"}
PASS the live listener still serves B: sha256:10e03641…
PASS and still proxies: HTTP/1.1 200 OK|hello-cert
PASS status still reports B: sha256:10e03641…
PASS a valid file is accepted again: 200
PASS clean shutdown exit code: 0
PASS every renewal attempt is audited: True
PASS the audited path is the action: True
PASS the audit carries the status it answered: True
PASS no secret in the log: True
PASS the rejected renewal was logged as such: True
RESULT: all assertions passed
```

Las líneas `AUDIT` reales del proceso (8 intentos: 200, 200, 403, 401, 403,
400, 400, 200) están en `raw/journey.log`; ninguna contiene el token.

## Control (el journey no es vacuo)

Con la recarga anulada en el applier (`ConfigChange::Reload` devuelve un
`Applied` vacío), el mismo journey falla:

```
FAIL one TLS listener reported: expected [1], got [0]
control exit=1
```

`raw/control-reload-disabled.log`. Restaurado el código, el journey vuelve a
verde con el mismo binario (`sha256 e1574f7c…`, idéntico al de arriba).

## Suite completa

```
$ cargo fmt --all -- --check                      → exit 0
$ cargo clippy --workspace --all-targets -- -D warnings → exit 0
$ cargo test --workspace                          → 492 passed, 0 failed (29 binarios)
```

`raw/full-suite.txt` es la salida literal, con el exit 0 de cada comando.

## Auditorías (sobre el árbol final)

| Pata | Comando | Resultado |
|---|---|---|
| Veyra Proof | `veyra audit . --profile standard` | **ACCEPTED**, exit 0 · `.veyra/evidence/20261025T185130Z/` · `cargo-test` 492 passed / 0 failed, `cargo-nextest` 492 tests (492 passed, 2 skipped), llvm-cov 89.32 % líneas · INCONCLUSIVE `cargo-geiger` (1128 avisos de cobertura) · SKIPPED `dylint`, `cargo-semver-checks` |
| Rust Audit 0.2.7 | `python3.13 …/rust_audit.py scan . --format md --out report --fail-on high` | exit 0 · **0 critical, 0 high, 221 medium, 69 low** (`report/rust-audit-20261025-185816.md`) |
| CodeGraph Rust | `codegraph-rust index . --stats-json`, `agent impact`, `agent context` | 59 ficheros, 55 526 líneas, **6 233 nodos, 11 265 aristas**, `graph_complete: true`, `vector_index_ready: true`, `errors: 0`, 839 938 ms |
| Hindsight | `hindsight-note` | nota guardada (banco `eqproxy`), exit 0 |

Hallazgos nuevos del incremento en Rust Audit, revisados uno a uno:

- `R10 medium` en `HotCerts::leaf_fingerprint` (`unwrap_or_default`): **falso
  positivo**. `parse_certs` rechaza una cadena sin certificados, así que el
  resolver siempre tiene hoja; el valor vacío es inalcanzable y el comentario
  en el código lo dice.
- `R14 medium` en `ConfigApplier::apply_candidate` (5 `.clone()`): real pero
  acotado — una vez por recarga, no por petición, y los valores son los
  nombres/fingerprints de los listeners configurados.
- 3 `R02 low` en los tests nuevos (literales en aserciones): el mismo idioma
  que el resto de la suite.

CodeGraph acertó las ubicaciones (`adopt_certificates` `tls.rs:113`,
`can_adopt_certificates` `:104`, la llamada en `proxy.rs:1586`, el test
`tls.rs:817-844`) y **declaró su hueco**: no registra llamadas de
`serve_with_reloads` ni del applier hacia `BoundProxy::apply`, que sí existen
(`proxy.rs` y `cli/src/main.rs`), así que su "blast radius" se queda corto.
`certificates()` está en `proxy.rs:1505`, no en `:1492` como dijo.

## Límites de esta evidencia

- El journey corre en **macOS arm64**; la rotación no tiene ruta específica de
  plataforma (un `RwLock` y un hash), pero no lo afirmo para Linux/amd64.
- El journey usa un listener **TCP**; la ruta HTTP/3 se prueba en
  `e2e_http3.rs` (sockets reales, cliente quinn real), no contra el binario.
- No se cubre el caso de un `client_ca`/ALPN/versión mínima cambiados en un
  listener QUIC vivo: se **rechaza** (`QuicTlsReload`) por diseño y está
  probado en el test unitario de `tls.rs`, no con el binario.
- Sin Docker ni gate de release en este incremento.
