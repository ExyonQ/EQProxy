# Informe de conversión nginx → EQProxy

- Entrada: `docs/evidence/v085-config-import/raw/e2e/nginx.conf`
- Salida: `docs/evidence/v085-config-import/raw/e2e/eqproxy.toml`
- Listeners generados: **1** · Backends generados: **1**
- Directivas leídas: **4** · clasificadas: **4** — convertidas **3** · a revisar **1** · rechazadas **0**

«Nunca se descarta en silencio»: cada directiva del origen aparece abajo. El fichero generado se ha parseado y validado con el propio parser de EQProxy (`schema_version = 1`) antes de escribirlo. La conversión es estática: no se ha ejecutado nada de la configuración de origen ni se ha medido tráfico.

## Conversión generada

| listener | escucha | modo | backend | TLS |
|---|---|---|---|---|
| `web__sin_server_name` | 0.0.0.0:62351 | http | `app` | no |

| backend | servidores (peso) | balance | health check | PROXY | TLS backend |
|---|---|---|---|---|---|
| `app` | 127.0.0.1:62350 (1) | roundrobin | — | none | no |

## Detalle de la clasificación

### ❌ no traducible (0)


### ⛔ rechazado (sin equivalente en EQProxy) (0)


### ⚠️ revisar (0)


### ℹ️ informativo (1)

- `listen 62351` — *server (sin server_name)*: binding y TLS del listener: aplicados arriba en [listener.*.tls]

### ✅ convertido (3)

- `server 127.0.0.1:62350` — *upstream app*: servidor 127.0.0.1:62350 (peso 1) en el upstream
- `listen 62351` — *server (sin server_name)*: listener de EQProxy en 62351
- `proxy_pass http://app` — *server (sin server_name) location /*: regla con use_backend = «app»

## Qué no se ha traducido

Ninguna: todas las directivas del origen tienen destino o son informativas.

## Siguiente paso

1. `eqproxy config validate --config <salida>` — el mismo gate que usa el binario.
2. Leer las secciones «revisar» y «rechazado» de arriba y corregir a mano lo que falte.
3. `eqproxy config diff --help` para comparar con la configuración actual antes de `config apply`.
