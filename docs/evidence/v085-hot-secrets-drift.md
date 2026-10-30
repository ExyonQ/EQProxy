# v0.8.5 — Secretos TLS en caliente y drift multi-instancia (B-E9 · B-H10 fin · D10)

**Fecha:** 2026-10-30 · **Casilla:** §1 «Secretos TLS en caliente
(equivalente a SDS) y multi-instancia con drift» del
[roadmap 0.8.5](../../ROADMAP%20EQPROXY/ROADMAP/Roadmap%200.8.5.md).
**Estado:** implementado y verificado E2E; cierra **B-H10** (fin) y la mitad
de detección de D10. La reconciliación central sigue siendo un no-objetivo
documentado (SPEC §9, ADR-0027).

Diseño: [ADR-0035](../adr/0035-hot-secrets-and-drift-runbook.md).

---

## 1. Qué significa «SDS equivalente» aquí

No hay cliente SDS ([ADR-0027](../adr/0027-xds-bridge-decision.md)): el
equivalente son ficheros + la acción de recarga que ya existe, en las dos
direcciones TLS:

| Dirección | Material | Ruta de recarga | Efecto |
|---|---|---|---|
| Listener (h1/h2/h3) | cert/key/SNI | `SIGHUP` o `POST /api/v1/certificates/reload` | swap atómico tras el resolver (ADR-0025); lo ya establecido no se toca |
| Backend (upstream) | `ca_file`, `verify`, `server_name` | el mismo `SIGHUP` / la misma acción, por el mismo single writer | el swap reconstruye los backends; lo ya establecido drena en su generación |

Fallar es fallar cerrado en ambas: un candidato que no valida responde
`400` y el material anterior sigue sirviendo (`config_reload_failures` +1 y
`ERROR config reload rejected` en el log).

Fuera de alcance declarado (ADR-0035, §2): cipher suites configurables
(rustls+AWS-LC solo negocia suites modernas; exponerlas reabriría la
negociación legacy que el proyecto prohíbe como TLS 1.0/1.1) y OCSP
stapling (fetch sin autenticar + caché por certificado; el gancho de
monitorización es `tls_fingerprint` en el status).

## 2. Dónde vive

- Recarga backend: [`resolve_with`](../../../eqproxy-cli/src/main.rs#L2441)
  re-lee `ca_file` en cada reload; el swap la aplica sin reiniciar.
- Renovación listener: [`HotCerts`](../../../eqproxy-net/src/tls.rs#L263),
  [`fixed_material_fingerprint`](../../../eqproxy-net/src/tls.rs#L480).
- Regla de drift (ADR-0035, §3): comparar topología + `tls_fingerprint`
  entre instancias; la `revision` ordena generaciones en una instancia,
  nunca identifica contenido entre instancias; reparar con `SIGHUP`.

## 3. E2E con sockets reales

### 3.1 Rotación de confianza del backend (1 test Rust)

[`backend_tls_trust_rotation_applies_on_reload_without_restart`](../../../eqproxy-net/tests/e2e_resilience.rs)
(tres fases sobre el **mismo** socket del proxy, sin reinicio):

1. el backend sirve `mtls-server.pem` y el proxy confía en `mtls-ca.pem` →
   el eco llega intacto;
2. reload confiando solo en las raíces de Mozilla → el túnel muere cerrado
   (EOF/RST, cero bytes proxiados), `tls_handshake_failures` = 1, un solo
   swap (`config_reloads` = 1). Reintentos a 0 para que un exchange sea
   exactamente un fallo contado;
3. reload devolviendo la CA → el eco vuelve en el mismo socket y no hay
   ningún fallo nuevo.

### 3.2 Drift multi-instancia (journey contra el binario, 13 checks)

[`journey.py`](../../../scripts/evidence/v085-hot-secrets-drift/journey.py)
(13/13 en verde): dos instancias del binario release con el **mismo**
fichero, un `PUT` divergente solo en A y `SIGHUP` como reparación:

| Fase | Hecho | Resultado |
|---|---|---|
| Acuerdo | mismo fichero | `v1`/`v1`, topologías iguales, ambas sirven `origin-one` |
| Divergencia | `PUT` en A: segundo origen | `200` → `v2`; A sirve los dos orígenes, B solo el del fichero; `v2` vs `v1`, 2 servidores vs 1 |
| Reparación | `SIGHUP` en A | el edit runtime cae, las topologías vuelven a coincidir… pero las revisiones **no** se realinean (`v3` vs `v1`): esa es la regla documentada, no un bug |

## 4. Reproducción

```bash
cargo test --test e2e_resilience backend_tls_trust_rotation
python3 scripts/evidence/v085-hot-secrets-drift/journey.py   # EQPROXY_BIN=… (default: target/release/eqproxy)
```

Salidas del run en [`raw/`](v085-hot-secrets-drift/raw/) (status JSON por
fase; los `.log` de cada instancia quedan junto al journey local).

## 5. Límites de la evidencia

- La reconciliación multi-instancia (aplicar un deseo a N instancias de
  forma atómica) no existe ni se promete: el runbook es detectar (status)
  y converger (mismo fichero + reload). SPEC §9 sigue listándola como
  pendiente.
- Sin persistencia de ediciones runtime, sin identidades por usuario, sin
  sumidero duradero de auditoría: el resto de la lista del SPEC §9.
- `client_ca`/ALPN/versión mínima en un listener QUIC vivo siguen pidiendo
  reinicio (ADR-0025); la expiración de certificados no se alerta (falta
  parseo X.509).

## 6. Auditorías del incremento

| Pata | Comando | Resultado | Evidencia |
|---|---|---|---|
| Veyra Proof | `veyra audit . --profile standard` | **ACCEPTED**, exit 0; `dylint` y `cargo-semver-checks` skipped y `cargo-geiger` INCONCLUSIVE, los tres por la razón del ADR-0030 | [`.veyra/evidence/20261030T170613Z/report.md`](../../.veyra/evidence/20261030T170613Z/report.md) |
| Rust Audit | `python3.13 <rust-ai-audit>/scripts/rust_audit.py scan . --format md --out report --fail-on high` (0.2.7) | exit 0; **0 critical / 3 high**; los 3 high son los R16 ya revisados en `cache.rs` (falsos positivos, guard en bloque léxico antes del `.await`); el incremento no añade ningún high/critical nuevo (el R08 del test nuevo es el `Instant::now` de deadline que usan todos los E2E) | [`report/rust-audit-20261030-180527.md`](../../report/rust-audit-20261030-180527.md) |
| CodeGraph Rust | `codegraph-rust index . --stats-json /tmp/cg-index-secrets.json --batch-size 16` | **NOT EXECUTED**: el índice no completa en el presupuesto de 600 s de la herramienta (el árbol necesita ~11–17 min según las mediciones del ADR-proceso; el fichero de stats quedó vacío y el proceso se mató). Una consulta contra un índice rancio no es evidencia. El slice toca un solo fichero de tests (`e2e_resilience.rs` +163) y sus llamadas se comprobaron en el fuente (§2) | — |
| Hindsight | `hindsight-note --title ... --project EQProxy` | TBD tras el push (la nota cita el run de CI) | banco `eqproxy` |

CI del commit publicado `7058654`
([run 41099054219](https://github.com/ExyonQ/EQProxy/actions/runs/41099054219)):
**verde, cinco jobs**, 17:27:57→17:32:41 UTC.
