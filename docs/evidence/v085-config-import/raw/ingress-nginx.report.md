# Informe de conversión ingress-nginx → EQProxy

- Entrada: `docs/evidence/v085-config-import/raw/ingress-nginx.yaml`
- Salida: `docs/evidence/v085-config-import/raw/ingress-nginx.eqproxy.toml`
- Listeners generados: **2** · Backends generados: **5**
- Directivas leídas: **47** · clasificadas: **47** — convertidas **23** · a revisar **22** · rechazadas **2**

«Nunca se descarta en silencio»: cada directiva del origen aparece abajo. El fichero generado se ha parseado y validado con el propio parser de EQProxy (`schema_version = 1`) antes de escribirlo. La conversión es estática: no se ha ejecutado nada de la configuración de origen ni se ha medido tráfico.

## Conversión generada

| listener | escucha | modo | backend | TLS |
|---|---|---|---|---|
| `ingress_0_0_0_0_443` | 0.0.0.0:443 | http | `web-svc_80` | no |
| `tcp_9000` | 0.0.0.0:9000 | tcp | `tcp-svc_9000` | no |

| backend | servidores (peso) | balance | health check | PROXY | TLS backend |
|---|---|---|---|---|---|
| `api-svc_8080` | 10.0.1.20:8080 (1) | roundrobin | — | none | no |
| `grpc-svc_50051` | 10.0.2.5:50051 (1) | roundrobin | — | none | no |
| `panel-svc_3000` | panel-svc.default.svc.cluster.local:3000 (1) | roundrobin | — | none | no |
| `tcp-svc_9000` | 10.0.4.5:9000 (1) | roundrobin | — | none | no |
| `web-svc_80` | 10.0.0.10:8080 (1), 10.0.0.11:8080 (1) | roundrobin | — | none | no |

## Detalle de la clasificación

### ❌ no traducible (0)


### ⛔ rechazado (sin equivalente en EQProxy) (2)

- `ssl-passthrough` — *Ingress passthrough*: passthrough TLS: EQProxy no enruta por SNI sin terminar TLS (haría falta ssl_preread); Ingress omitido
- `5353: udp` — *ConfigMap udp-services*: EQProxy no proxifica UDP (solo QUIC/HTTP3 como servidor)

### ⚠️ revisar (21)

- `affinity: cookie` — *Ingress web*: [backend.*.affinity] mode = "cookie" (actívelo en el backend del Ingress)
- `configuration-snippet: more_set_headers "X-App: web";` — *Ingress web*: snippet de nginx: no se ejecuta ni se traduce (sustituto: plugin WASM o reglas)
- `enable-cors: true` — *Ingress web*: regla cors con allow_origin = "*" hasta que cors-allow-origin diga otro
- `force-ssl-redirect: true` — *Ingress web*: la redirección 80 → 443 es un listener aparte con reglas redirect; este conversor genera el listener que sirve tráfico
- `proxy-read-timeout: 30s` — *Ingress web*: listener.server_header_timeout (aproximado: EQProxy solo acota la cabecera de respuesta)
- `session-cookie-name: route` — *Ingress web*: [backend.*.affinity].cookie con este nombre
- `ssl-redirect: true` — *Ingress web*: la redirección 80 → 443 es un listener aparte con reglas redirect; este conversor genera el listener que sirve tráfico
- `tls secretName ejemplo-tls` — *Ingress web*: el secreto de Kubernetes no es un fichero: móntelo y configure [listener.*.tls] cert/key (o [listener.*.tls].certs por host)
- `Service panel-svc:3000` — *Ingress web*: sin Endpoints en el manifiesto: se usa el nombre DNS «panel-svc.default.svc.cluster.local:3000» (EQProxy lo re-resuelve en caliente)
- `backend-protocol: GRPC` — *Ingress grpc*: gRPC: [backend.*.tls].alpn = ["h2"] (el listener habla h2 al backend)
- `ssl-redirect: false` — *Ingress grpc*: la redirección 80 → 443 es un listener aparte con reglas redirect; este conversor genera el listener que sirve tráfico
- `tls secretName grpc-tls` — *Ingress grpc*: el secreto de Kubernetes no es un fichero: móntelo y configure [listener.*.tls] cert/key (o [listener.*.tls].certs por host)
- `allow-snippet-annotations: true` — *ConfigMap*: los snippets no se ejecutan: EQProxy los sustituye por plugins WASM y reglas
- `default-ssl-certificate: ingress-nginx/wildcard-tls` — *ConfigMap*: el secreto de Kubernetes no es una ruta: móntelo y rellene [listener.*.tls]
- `enable-http2: true` — *ConfigMap*: [listener.*.tls].alpn con "h2" cuando el listener tenga TLS
- `enable-metrics: true` — *ConfigMap*: [admin] (GET /metrics con bearer token) en lugar de exponerlo al público
- `keep-alive: 75` — *ConfigMap*: listener.idle_timeout (segundos; nginx habla de keep-alive y EQProxy de inactividad)
- `log-format-upstream: $remote_addr - $remote_user [$time_local]` — *ConfigMap*: [access_log] con format = "json" o "combined"
- `ssl-protocols: TLSv1.2 TLSv1.3` — *ConfigMap*: [listener.*.tls].min_version (EQProxy nunca acepta TLS 1.0/1.1)
- `use-proxy-protocol: false` — *ConfigMap*: [listener.*].proxy_receive + proxy_allow (allowlist obligatoria)
- `0.0.0.0:443` — *listener*: sin certificado montado: rellene [listener.*.tls] con cert/key antes de aplicar (el Ingress declara un secretName, no una ruta de fichero)

### ℹ️ informativo (1)

- `upstream-keepalive-connections: 64` — *ConfigMap*: el pool de EQProxy es fijo: 64 conexiones idle por servidor, 60 s

### ✅ convertido (23)

- `cors-allow-origin: https://ejemplo.com` — *Ingress web*: [[listener.*.rules]].cors.allow_origin
- `enable-hsts: true` — *Ingress web*: response_headers += Strict-Transport-Security: max-age=31536000
- `hsts-max-age: 31536000` — *Ingress web*: response_headers Strict-Transport-Security max-age
- `limit-rps: 20` — *Ingress web*: [[listener.*.rules]].rate_limit rate = 20, per = "1s"
- `load-balance: round_robin` — *Ingress web*: balance = "roundrobin" en los backends del Ingress
- `proxy-body-size: 4m` — *Ingress web*: listener.limits.max_body_bytes = 4194304
- `proxy-connect-timeout: 3s` — *Ingress web*: listener.connect_timeout
- `rewrite-target: /` — *Ingress web*: [[listener.*.rules]].rewrite.path_prefix_rewrite
- `whitelist-source-range: 10.0.0.0/8,192.168.0.0/16` — *Ingress web*: [[listener.*.rules]].ip con los rangos declarados
- `Endpoints web-svc` — *Ingress web*: servidor 10.0.0.10:8080 del backend «web-svc_80»
- `Endpoints web-svc` — *Ingress web*: servidor 10.0.0.11:8080 del backend «web-svc_80»
- `path / → web-svc:80` — *Ingress web*: regla host ejemplo.com → backend «web-svc_80»
- `Endpoints api-svc` — *Ingress web*: servidor 10.0.1.20:8080 del backend «api-svc_8080»
- `path /api → api-svc:8080` — *Ingress web*: regla host ejemplo.com → backend «api-svc_8080»
- `path / → panel-svc:3000` — *Ingress web*: regla host panel.ejemplo.com → backend «panel-svc_3000»
- `Endpoints grpc-svc` — *Ingress grpc*: servidor 10.0.2.5:50051 del backend «grpc-svc_50051»
- `path / → grpc-svc:50051` — *Ingress grpc*: regla host grpc.ejemplo.com → backend «grpc-svc_50051»
- `load-balance: round_robin` — *ConfigMap*: balance por defecto de los backends generados
- `max-connections: 20000` — *ConfigMap*: listener.maxconn = 20000
- `proxy-body-size: 8m` — *ConfigMap*: listener.limits.max_body_bytes
- `0.0.0.0:443` — *listener*: listener «ingress_0_0_0_0_443» con 4 reglas host+path
- `Endpoints tcp-svc` — *ConfigMap tcp-services*: servidor 10.0.4.5:9000 del backend «tcp-svc_9000»
- `9000: default/tcp-svc:9000` — *ConfigMap tcp-services*: listener «tcp_9000» (tcp 0.0.0.0:9000) → backend «tcp-svc_9000»

## Qué no se ha traducido

- EQProxy no proxifica UDP (solo QUIC/HTTP3 como servidor) (1)
- passthrough TLS: EQProxy no enruta por SNI sin terminar TLS (haría falta ssl_preread); Ingress omitido (1)

Cada uno de estos puntos es un cambio de comportamiento frente al proxy de origen. Hasta que se resuelvan (o se acepten por escrito), la configuración **no es equivalente**.

## Siguiente paso

1. `eqproxy config validate --config <salida>` — el mismo gate que usa el binario.
2. Leer las secciones «revisar» y «rechazado» de arriba y corregir a mano lo que falte.
3. `eqproxy config diff --help` para comparar con la configuración actual antes de `config apply`.
