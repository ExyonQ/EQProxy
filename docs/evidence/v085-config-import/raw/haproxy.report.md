# Informe de conversión HAProxy → EQProxy

- Entrada: `docs/evidence/v085-config-import/raw/haproxy.cfg`
- Salida: `docs/evidence/v085-config-import/raw/haproxy.eqproxy.toml`
- Listeners generados: **4** · Backends generados: **3**
- Directivas leídas: **78** · clasificadas: **78** — convertidas **41** · a revisar **30** · rechazadas **7**

«Nunca se descarta en silencio»: cada directiva del origen aparece abajo. El fichero generado se ha parseado y validado con el propio parser de EQProxy (`schema_version = 1`) antes de escribirlo. La conversión es estática: no se ha ejecutado nada de la configuración de origen ni se ha medido tráfico.

## Conversión generada

| listener | escucha | modo | backend | TLS |
|---|---|---|---|---|
| `app_tcp` | 0.0.0.0:3306 | tcp | `app_tcp` | no |
| `fe_https` | 0.0.0.0:443 | http | `bk_web` | sí |
| `fe_https_2` | 0.0.0.0:8443 | http | `bk_web` | sí |
| `fe_tcp_ssh` | 0.0.0.0:2222 | tcp | `bk_ssh` | no |

| backend | servidores (peso) | balance | health check | PROXY | TLS backend |
|---|---|---|---|---|---|
| `app_tcp` | 10.0.3.5:3306 (1) | roundrobin | TCP 5s/1s/fall 2/rise 2 | none | sí |
| `bk_ssh` | 10.0.0.30:22 (1), 10.0.0.31:22 (1) | roundrobin | TCP 2s/1s/fall 3/rise 2 | none | no |
| `bk_web` | 10.0.0.10:8080 (100), 10.0.0.11:8080 (50), 10.0.0.12:8080 (1) backup, ejemplocpuerta.local:8080 (1) | leastconn | HTTP 2s/1s/fall 3/rise 2 | v1 | no |

## Detalle de la clasificación

### ❌ no traducible (2)

- `server ssh2 send-proxy-v2` — *backend bk_ssh*: PROXY protocol v2: EQProxy solo emite v1
- `listen stats` — *listen stats*: backend sin servidores traducibles: se omite

### ⛔ rechazado (sin equivalente en EQProxy) (5)

- `option httplog` — *defaults*: opción sin equivalente conocido
- `option dontlognull` — *defaults*: opción sin equivalente conocido
- `option redispatch` — *defaults*: opción sin equivalente conocido
- `timeout queue 30s` — *defaults*: «timeout queue» sin equivalente: idle_timeout es el único plazo de inactividad
- `capture request header Host len 64` — *frontend fe_https*: captura de cabeceras: use el access log estructurado

### ⚠️ revisar (22)

- `log /dev/log local0` — *global*: EQProxy sí lo cubre en [access_log].path con format = "json" | "combined": transcríbalo a mano
- `nbthread 4` — *global*: EQProxy sí lo cubre en runtime multi-hilo de tokio (no configurable): transcríbalo a mano
- `stats socket /run/haproxy/admin.sock mode 660 level admin` — *global*: EQProxy sí lo cubre en [admin].unix_socket + token_file (plano de administración con bearer token): transcríbalo a mano
- `daemon` — *global*: EQProxy sí lo cubre en ejecute bajo systemd/supervisord: transcríbalo a mano
- `mode http` — *defaults*: modo por defecto «http»: el modo real lo fija cada listener
- `log global` — *defaults*: EQProxy sí lo cubre en [access_log].path con format = "json" | "combined": transcríbalo a mano
- `retries 3` — *defaults*: EQProxy sí lo cubre en [backend.*].retries: transcríbalo a mano
- `http-response set-header Server mi-servidor` — *backend bk_web*: EQProxy sí lo cubre en [[listener.*.rules]].response_headers: transcríbalo a mano
- `bind 127.0.0.1:9000` — *listen stats*: directiva de backend sin traducción automática: revísela a mano
- `stats enable` — *listen stats*: EQProxy sí lo cubre en [admin].unix_socket + token_file (plano de administración con bearer token): transcríbalo a mano
- `stats uri /haproxy?stats` — *listen stats*: EQProxy sí lo cubre en [admin].unix_socket + token_file (plano de administración con bearer token): transcríbalo a mano
- `default_backend bk_web` — *listen stats*: directiva de backend sin traducción automática: revísela a mano
- `bind 0.0.0.0:3306` — *listen app_tcp*: directiva de backend sin traducción automática: revísela a mano
- `server db1 verify none` — *listen app_tcp*: verify = false: EQProxy verifica por defecto; desactivarlo tiene riesgo
- `crt /etc/haproxy/certs/ejemplo.pem` — *frontend fe_https*: HAProxy usa un PEM combinado: EQProxy exige cert y key separados — se emite key = «/etc/haproxy/certs/ejemplo.pem.key» y hay que corregirlo
- `http-request set-header` — *frontend fe_https*: sin una condición a la que asociarlo no se emite (una regla necesita condición): añada [[]] a mano en [listener.*.rules] con set_headers name = "X-Forwarded-Proto"
- `crt /etc/haproxy/certs/ejemplo.pem` — *frontend fe_https*: HAProxy usa un PEM combinado: EQProxy exige cert y key separados — se emite key = «/etc/haproxy/certs/ejemplo.pem.key» y hay que corregirlo
- `http-request set-header` — *frontend fe_https*: sin una condición a la que asociarlo no se emite (una regla necesita condición): añada [[]] a mano en [listener.*.rules] con set_headers name = "X-Forwarded-Proto"
- `timeout client/server` — *frontend fe_tcp_ssh*: EQProxy tiene un solo idle_timeout bidireccional: se usa el menor de los dos
- `stats enable` — *listen stats*: EQProxy sí lo cubre en [admin].unix_socket + token_file (plano de administración con bearer token): transcríbalo a mano
- `stats uri /haproxy?stats` — *listen stats*: EQProxy sí lo cubre en [admin].unix_socket + token_file (plano de administración con bearer token): transcríbalo a mano
- `server db1 10.0.3.5:3306 check inter 5s fall 2 rise 2 ssl verify none sni db.interno` — *listen app_tcp*: directiva de frontend sin traducción automática: revísela a mano

### ℹ️ informativo (8)

- `mode http` — *backend bk_web*: el modo (tcp/http) real lo fija cada listener de EQProxy
- `mode tcp` — *backend bk_ssh*: el modo (tcp/http) real lo fija cada listener de EQProxy
- `mode http` — *listen stats*: el modo (tcp/http) real lo fija cada listener de EQProxy
- `mode tcp` — *listen app_tcp*: el modo (tcp/http) real lo fija cada listener de EQProxy
- `mode http` — *frontend fe_https*: modo del listener «http»
- `mode tcp` — *frontend fe_tcp_ssh*: modo del listener «tcp»
- `mode http` — *listen stats*: modo del listener «http»
- `mode tcp` — *listen app_tcp*: modo del listener «tcp»

### ✅ convertido (41)

- `maxconn 50000` — *global*: listener.maxconn = 50000
- `option forwardfor` — *defaults*: [listener.*].forwarded_headers = "append" en cada listener
- `timeout connect 4s` — *defaults*: timeout por defecto «connect»
- `timeout client 30s` — *defaults*: timeout por defecto «client»
- `timeout server 30s` — *defaults*: timeout por defecto «server»
- `timeout http-request 10s` — *defaults*: timeout por defecto «http-request»
- `timeout http-keep-alive 10s` — *defaults*: timeout por defecto «http-keep-alive»
- `timeout check 5s` — *defaults*: timeout por defecto «check»
- `balance leastconn` — *backend bk_web*: balance = "leastconn"
- `option httpchk GET /healthz HTTP/1.1` — *backend bk_web*: health_check con type = "http" (B-H6: status esperado y ruta)
- `cookie SERVERID insert indirect nocache` — *backend bk_web*: [backend.*.affinity] mode = "cookie", cookie = "SERVERID"
- `server web1 send-proxy` — *backend bk_web*: proxy_protocol = "v1"
- `server web1 check` — *backend bk_web*: health_check activo (interval/fall/rise)
- `server web2 send-proxy` — *backend bk_web*: proxy_protocol = "v1"
- `server web2 check` — *backend bk_web*: health_check activo (interval/fall/rise)
- `server web3 backup` — *backend bk_web*: backup = true (solo se usa cuando ningún primario es elegible)
- `server web3 check` — *backend bk_web*: health_check activo (interval/fall/rise)
- `server web4 check` — *backend bk_web*: health_check activo (interval/fall/rise)
- `balance source` — *backend bk_ssh*: [backend.*.affinity] mode = "source" (hash de la IP del cliente)
- `server ssh1 check` — *backend bk_ssh*: health_check activo (interval/fall/rise)
- `server ssh2 check` — *backend bk_ssh*: health_check activo (interval/fall/rise)
- `timeout connect 5s` — *listen app_tcp*: timeout «connect» del backend
- `server db1 ssl` — *listen app_tcp*: [backend.*.tls] (verify, ca_file, server_name, alpn)
- `server db1 check` — *listen app_tcp*: health_check activo (interval/fall/rise)
- `bind 0.0.0.0:443 ssl crt /etc/haproxy/certs/ejemplo.pem alpn h2,http/1.1` — *frontend fe_https*: listener de EQProxy sobre esta dirección
- `bind 0.0.0.0:8443 ssl crt /etc/haproxy/certs/ejemplo.pem` — *frontend fe_https*: listener de EQProxy sobre esta dirección
- `maxconn 20000` — *frontend fe_https*: listener.maxconn = 20000
- `default_backend bk_web` — *frontend fe_https*: backend de respaldo del listener (el `backend` de [listener.*])
- `http-request set-header X-Forwarded-Proto https` — *frontend fe_https*: set_headers += { X-Forwarded-Proto, https }
- `http-request deny if { src 10.9.9.9 }` — *frontend fe_https*: regla [[listener.*.rules]] con direct_response 403 para la condición
- `bind 0.0.0.0:443` — *frontend fe_https*: listener «fe_https» (http) → backend «bk_web»
- `bind 0.0.0.0:8443` — *frontend fe_https*: listener «fe_https_2» (http) → backend «bk_web»
- `bind 0.0.0.0:2222` — *frontend fe_tcp_ssh*: listener de EQProxy sobre esta dirección
- `default_backend bk_ssh` — *frontend fe_tcp_ssh*: backend de respaldo del listener (el `backend` de [listener.*])
- `timeout client 10m` — *frontend fe_tcp_ssh*: timeout del listener
- `bind 0.0.0.0:2222` — *frontend fe_tcp_ssh*: listener «fe_tcp_ssh» (tcp) → backend «bk_ssh»
- `bind 127.0.0.1:9000` — *listen stats*: listener de EQProxy sobre esta dirección
- `default_backend bk_web` — *listen stats*: backend de respaldo del listener (el `backend` de [listener.*])
- `bind 0.0.0.0:3306` — *listen app_tcp*: listener de EQProxy sobre esta dirección
- `timeout connect 5s` — *listen app_tcp*: timeout del listener
- `bind 0.0.0.0:3306` — *listen app_tcp*: listener «app_tcp» (tcp) → backend «app_tcp»

## Qué no se ha traducido

- PROXY protocol v2: EQProxy solo emite v1 (1)
- backend sin servidores traducibles: se omite (1)
- captura de cabeceras: use el access log estructurado (1)
- opción sin equivalente conocido (3)
- «timeout queue» sin equivalente: idle_timeout es el único plazo de inactividad (1)

Cada uno de estos puntos es un cambio de comportamiento frente al proxy de origen. Hasta que se resuelvan (o se acepten por escrito), la configuración **no es equivalente**.

## Siguiente paso

1. `eqproxy config validate --config <salida>` — el mismo gate que usa el binario.
2. Leer las secciones «revisar» y «rechazado» de arriba y corregir a mano lo que falte.
3. `eqproxy config diff --help` para comparar con la configuración actual antes de `config apply`.
