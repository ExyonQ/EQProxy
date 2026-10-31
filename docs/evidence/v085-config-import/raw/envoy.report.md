# Informe de conversión Envoy → EQProxy

- Entrada: `docs/evidence/v085-config-import/raw/envoy.yaml`
- Salida: `docs/evidence/v085-config-import/raw/envoy.eqproxy.toml`
- Listeners generados: **2** · Backends generados: **3**
- Directivas leídas: **38** · clasificadas: **38** — convertidas **16** · a revisar **19** · rechazadas **3**

«Nunca se descarta en silencio»: cada directiva del origen aparece abajo. El fichero generado se ha parseado y validado con el propio parser de EQProxy (`schema_version = 1`) antes de escribirlo. La conversión es estática: no se ha ejecutado nada de la configuración de origen ni se ha medido tráfico.

## Conversión generada

| listener | escucha | modo | backend | TLS |
|---|---|---|---|---|
| `listener_https` | 0.0.0.0:443 | http | `svc_web` | sí |
| `listener_tcp` | 0.0.0.0:5432 | tcp | `svc_db` | no |

| backend | servidores (peso) | balance | health check | PROXY | TLS backend |
|---|---|---|---|---|---|
| `svc_api` | 10.0.1.20:8080 (1) | leastconn | HTTP 5s/1s/fall 2/rise 2 /healthz | none | sí |
| `svc_db` | 10.0.3.5:5432 (1) | roundrobin | — | none | no |
| `svc_web` | 10.0.0.10:8080 (2), 10.0.0.11:8080 (1) | roundrobin | TCP 2s/1s/fall 3/rise 2 | none | no |

## Detalle de la clasificación

### ❌ no traducible (0)


### ⛔ rechazado (sin equivalente en EQProxy) (3)

- `envoy.filters.http.lua` — *listener listener_https*: filtro Lua: no se ejecuta; el sustituto es un plugin WASM (ADR-0031)
- `listener listener_udp (udp_listener)` — *listener listener_udp*: listener UDP: EQProxy solo habla UDP para QUIC/HTTP3
- `dynamic_resources: {1 claves}` — *bootstrap*: xDS (cds/lds/rds/eds) sin soporte: EQProxy lee un fichero local y recarga con SIGHUP o `config apply` (ADR-0027)

### ⚠️ revisar (13)

- `type: STRICT_DNS` — *cluster svc_web*: DNS del cluster: EQProxy resuelve HOSTNAME:PORT y lo re-resuelve con resolve_interval
- `connect_timeout: 5s` — *cluster svc_web*: EQProxy no tiene connect_timeout por backend: se aplica el de cada listener
- `outlier_detection: {1 claves}` — *cluster svc_web*: detección pasiva: EQProxy reacciona a fallos de conexión con health_check.passive; consecutive_5xx no se evalúa
- `type: EDS` — *cluster svc_api*: EDS (endpoints por xDS): sin plano de control; los endpoints del manifiesto se usan tal cual
- `connect_timeout: 3s` — *cluster svc_api*: EQProxy no tiene connect_timeout por backend: se aplica el de cada listener
- `connect_timeout: 5s` — *cluster svc_db*: EQProxy no tiene connect_timeout por backend: se aplica el de cada listener
- `domain *.ejemplo.com` — *listener listener_https*: host_regex para el comodín de un nivel (*.ejemplo.com)
- `route /api retry_policy` — *listener listener_https*: [backend.*].retries (num_retries = 2)
- `route /api timeout` — *listener listener_https*: [listener.*].max_stream_duration (duración total, no solo inactividad)
- `envoy.filters.http.cors` — *listener listener_https*: [[listener.*.rules]].cors (allow_origin, métodos, max_age)
- `stat_prefix: ingress_https` — *listener listener_https*: ajuste del HCM sin equivalente directo
- `access_log: [1 elementos]` — *listener listener_https*: [access_log] con format = "json"
- `admin: {1 claves}` — *bootstrap*: [admin].listen = "127.0.0.1:9901" necesita además token_file (bearer obligatorio en EQProxy) y allow_remote si no es loopback

### ℹ️ informativo (6)

- `name: svc_web` — *cluster svc_web*: nombre del cluster → nombre del backend
- `name: svc_api` — *cluster svc_api*: nombre del cluster → nombre del backend
- `name: svc_db` — *cluster svc_db*: nombre del cluster → nombre del backend
- `envoy.filters.http.router` — *listener listener_https*: el router de Envoy es implícito en EQProxy
- `node: {2 claves}` — *bootstrap*: identidad del nodo Envoy: sin equivalente (no hay plano de control)
- `static_resources: {2 claves}` — *bootstrap*: contenedores de clusters/listeners ya traducidos arriba

### ✅ convertido (16)

- `lb_policy: ROUND_ROBIN` — *cluster svc_web*: balance = "roundrobin"
- `endpoint 10.0.0.10:8080` — *cluster svc_web*: servidor con peso 2
- `endpoint 10.0.0.11:8080` — *cluster svc_web*: servidor con peso 1
- `health_check TCP` — *cluster svc_web*: health_check (interval 2s, timeout 1s), fall/rise del manifiesto
- `lb_policy: LEAST_REQUEST` — *cluster svc_api*: balance = "leastconn"
- `http2_protocol_options: {0 claves}` — *cluster svc_api*: [backend.*.tls].alpn = ["h2"] (HTTP/2 al backend)
- `transport_socket: {2 claves}` — *cluster svc_api*: [backend.*.tls] (server_name, ca_file, alpn)
- `health_check HTTP /healthz` — *cluster svc_api*: health_check (interval 5s, timeout 1s), fall/rise del manifiesto
- `endpoint 10.0.1.20:8080` — *cluster svc_api*: servidor con peso 1
- `endpoint 10.0.3.5:5432` — *cluster svc_db*: servidor con peso 1
- `transport_socket tls` — *listener listener_https*: [listener.*.tls] (cert, key, alpn, min_version)
- `domain ejemplo.com` — *listener listener_https*: condición host de la regla
- `envoy.filters.network.http_connection_manager` — *listener listener_https*: listener en mode = "http"
- `listener listener_https` — *listener listener_https*: listener «listener_https» (http)
- `envoy.filters.network.tcp_proxy` — *listener listener_tcp*: listener en mode = "tcp" → backend «svc_db»
- `listener listener_tcp` — *listener listener_tcp*: listener «listener_tcp» (tcp)

## Qué no se ha traducido

- filtro Lua: no se ejecuta; el sustituto es un plugin WASM (ADR-0031) (1)
- listener UDP: EQProxy solo habla UDP para QUIC/HTTP3 (1)
- xDS (cds/lds/rds/eds) sin soporte: EQProxy lee un fichero local y recarga con SIGHUP o `config apply` (ADR-0027) (1)

Cada uno de estos puntos es un cambio de comportamiento frente al proxy de origen. Hasta que se resuelvan (o se acepten por escrito), la configuración **no es equivalente**.

## Siguiente paso

1. `eqproxy config validate --config <salida>` — el mismo gate que usa el binario.
2. Leer las secciones «revisar» y «rechazado» de arriba y corregir a mano lo que falte.
3. `eqproxy config diff --help` para comparar con la configuración actual antes de `config apply`.
