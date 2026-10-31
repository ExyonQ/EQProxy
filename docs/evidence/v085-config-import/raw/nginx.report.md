# Informe de conversión nginx → EQProxy

- Entrada: `docs/evidence/v085-config-import/raw/nginx.conf`
- Salida: `docs/evidence/v085-config-import/raw/nginx.eqproxy.toml`
- Listeners generados: **1** · Backends generados: **2**
- Directivas leídas: **53** · clasificadas: **53** — convertidas **18** · a revisar **30** · rechazadas **5**

«Nunca se descarta en silencio»: cada directiva del origen aparece abajo. El fichero generado se ha parseado y validado con el propio parser de EQProxy (`schema_version = 1`) antes de escribirlo. La conversión es estática: no se ha ejecutado nada de la configuración de origen ni se ha medido tráfico.

## Conversión generada

| listener | escucha | modo | backend | TLS |
|---|---|---|---|---|
| `web_ejemplo_com` | 0.0.0.0:443 | http | `app` | sí |

| backend | servidores (peso) | balance | health check | PROXY | TLS backend |
|---|---|---|---|---|---|
| `api_v2` | 10.0.1.20:9000 (5), 10.0.1.21:9000 (2) | roundrobin | — | none | no |
| `app` | 10.0.0.10:8080 (3), 10.0.0.11:8080 (1), 10.0.0.12:8080 (1) backup | leastconn | — | none | no |

## Detalle de la clasificación

### ❌ no traducible (1)

- `location` — *server ejemplo.com*: el bloque no tiene ninguna location con proxy_pass ni deny: EQProxy no sirve contenido estático

### ⛔ rechazado (sin equivalente en EQProxy) (4)

- `error_log /var/log/nginx/error.log` — *global*: directiva global «error_log» sin equivalente conocido: revísela a mano
- `server (varios en la misma dirección)` — *listen 443*: varios vhosts comparten «443»: se traduce «ejemplo.com» y quedan sin migrar «panel.ejemplo.com». EQProxy enruta por host con [[listener.*.rules]].host, pero cada vhost puede traer su propio certificado y un listener sirve un solo [listener.*.tls]
- `root /var/www` — *server ejemplo.com location /static/*: EQProxy no sirve ficheros estáticos: hace falta un backend de origen
- `expires 30d` — *server ejemplo.com location /static/*: EQProxy no sirve ficheros estáticos: hace falta un backend de origen

### ⚠️ revisar (15)

- `max_fails=3` — *upstream app*: chequeo pasivo de nginx: EQProxy tiene check TCP activo y detección pasiva (health_check.passive)
- `fail_timeout=30s` — *upstream app*: chequeo pasivo de nginx: EQProxy tiene check TCP activo y detección pasiva (health_check.passive)
- `keepalive 32` — *upstream app*: pool de EQProxy: 64 conexiones idle por servidor, expiración 60 s
- `include /etc/nginx/mime.types` — *http*: include no se expande: revise «/etc/nginx/mime.types» a mano y vuelva a convertir
- `log_format main $remote_addr - $remote_user [$time_local] "$request"  $status $body_bytes_sent "$http_referer"` — *http*: [access_log] con format = "json" (campos estables) o "combined" (forma nginx)
- `access_log /var/log/nginx/access.log main` — *http*: [access_log].path (una línea por petición; la ruta y el formato se eligen en el TOML)
- `gzip_types text/css application/json` — *http*: tipos de gzip: EQProxy comprime text/*, application/json y xml por defecto (compression.types)
- `ssl_ciphers HIGH:!aNULL` — *server ejemplo.com*: EQProxy sí lo soporta en selección de cipher suites: fuera por decisión (ADR-0035): transcríbalo a mano
- `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for` — *server ejemplo.com location /*: «$proxy_add_x_forwarded_for» → [listener.*].forwarded_headers = "append" (EQProxy añade la IP de cliente a X-Forwarded-For)
- `proxy_connect_timeout 3s` — *server ejemplo.com location /*: los timeouts se configuran por listener: la directiva de location se aplica al listener generado
- `proxy_read_timeout 30s` — *server ejemplo.com location /*: los timeouts se configuran por listener: la directiva de location se aplica al listener generado
- `limit_req zone=api burst=20` — *server ejemplo.com location /api/*: [[listener.*.rules]].rate_limit (rate/per/burst) por IP: transcríbalo a mano
- `add_header` — *server ejemplo.com*: las cabeceras se emiten en una regla: las peticiones que no casen con ninguna regla no las llevan
- `server_name ejemplo.com www.ejemplo.com` — *server ejemplo.com*: varios server_name (ejemplo.com, www.ejemplo.com): EQProxy enruta por host con [[listener.*.rules]].host, pero el conversor no genera una regla por nombre
- `return 301 https://$host$request_uri` — *server ejemplo.com*: redirección a nivel de server: [[listener.*.rules]].redirect, pero un listener necesita un backend real; si el bloque solo redirige, créelo a mano

### ℹ️ informativo (15)

- `worker_processes auto` — *global*: directiva global sin traducción (no afecta a eqproxy.toml)
- `pid /run/nginx.pid` — *global*: directiva global sin traducción (no afecta a eqproxy.toml)
- `events` — *global*: bloque de infraestructura sin traducción (no afecta a eqproxy.toml)
- `default_type application/octet-stream` — *http*: cosmético de nginx (tipos MIME): EQProxy solo proxifica
- `sendfile on` — *http*: rendimiento interno de nginx sin mando expuesto
- `listen 443 ssl` — *server ejemplo.com*: binding y TLS del listener: aplicados arriba en [listener.*.tls]
- `http2 on` — *server ejemplo.com*: binding y TLS del listener: aplicados arriba en [listener.*.tls]
- `server_name ejemplo.com` — *server ejemplo.com*: nombre del vhost: se usa como etiqueta del listener (el enrutado por host necesita [[listener.*.rules]].host)
- `ssl_certificate /etc/ssl/certs/ejemplo.pem` — *server ejemplo.com*: binding y TLS del listener: aplicados arriba en [listener.*.tls]
- `ssl_certificate_key /etc/ssl/private/ejemplo.key` — *server ejemplo.com*: binding y TLS del listener: aplicados arriba en [listener.*.tls]
- `ssl_protocols TLSv1.2 TLSv1.3` — *server ejemplo.com*: binding y TLS del listener: aplicados arriba en [listener.*.tls]
- `client_header_timeout 10s` — *server ejemplo.com*: timeout del listener: se aplica al listener generado
- `keepalive_timeout 65s` — *server ejemplo.com*: timeout del listener: se aplica al listener generado
- `http2` — *server ejemplo.com*: ALPN h2 en [listener.*.tls] (HTTP/2 nativo)
- `listen 80` — *server ejemplo.com*: binding y TLS del listener: aplicados arriba en [listener.*.tls]

### ✅ convertido (18)

- `least_conn` — *upstream app*: balance = "leastconn" (least-connections ponderado)
- `server 10.0.0.10:8080 weight=3 max_fails=3 fail_timeout=30s` — *upstream app*: servidor 10.0.0.10:8080 (peso 3) en el upstream
- `server 10.0.0.11:8080` — *upstream app*: servidor 10.0.0.11:8080 (peso 1) en el upstream
- `backup` — *upstream app*: backup = true (B8: solo se usa cuando ningún primario es elegible)
- `server 10.0.0.12:8080 backup` — *upstream app*: servidor 10.0.0.12:8080 (peso 1) en el upstream
- `server 10.0.1.20:9000 weight=5` — *upstream api_v2*: servidor 10.0.1.20:9000 (peso 5) en el upstream
- `server 10.0.1.21:9000 weight=2` — *upstream api_v2*: servidor 10.0.1.21:9000 (peso 2) en el upstream
- `gzip on` — *http*: [listener.*.compression].gzip = true en cada listener generado
- `listen 443` — *server ejemplo.com*: listener de EQProxy en 443 con TLS y ALPN h2
- `ssl_certificate / ssl_certificate_key` — *server ejemplo.com*: [listener.*.tls] cert = «/etc/ssl/certs/ejemplo.pem», key = «/etc/ssl/private/ejemplo.key»
- `ssl_protocols TLSv1.2 TLSv1.3` — *server ejemplo.com*: [listener.*.tls].min_version (EQProxy nunca acepta TLS 1.0/1.1)
- `proxy_pass http://app` — *server ejemplo.com location /*: regla con use_backend = «app»
- `proxy_set_header Host $host` — *server ejemplo.com location /*: set_headers += { Host, $host }
- `proxy_set_header X-Real-IP $remote_addr` — *server ejemplo.com location /*: set_headers += { X-Real-IP, $remote_addr }
- `proxy_pass http://api_v2` — *server ejemplo.com location /api/*: regla con use_backend = «api_v2»
- `proxy_set_header Host $host` — *server ejemplo.com location /api/*: set_headers += { Host, $host }
- `add_header X-Frame-Options SAMEORIGIN always` — *server ejemplo.com*: [[listener.*.rules]].response_headers (se emite en la regla que cubre el listener)
- `listen 80` — *server ejemplo.com*: listener de EQProxy en 80

## Qué no se ha traducido

- EQProxy no sirve ficheros estáticos: hace falta un backend de origen (2)
- directiva global «error_log» sin equivalente conocido: revísela a mano (1)
- el bloque no tiene ninguna location con proxy_pass ni deny: EQProxy no sirve contenido estático (1)
- varios vhosts comparten «443»: se traduce «ejemplo.com» y quedan sin migrar «panel.ejemplo.com». EQProxy enruta por host con [[listener.*.rules]].host, pero cada vhost puede traer su propio certificado y un listener sirve un solo [listener.*.tls] (1)

Cada uno de estos puntos es un cambio de comportamiento frente al proxy de origen. Hasta que se resuelvan (o se acepten por escrito), la configuración **no es equivalente**.

## Siguiente paso

1. `eqproxy config validate --config <salida>` — el mismo gate que usa el binario.
2. Leer las secciones «revisar» y «rechazado» de arriba y corregir a mano lo que falte.
3. `eqproxy config diff --help` para comparar con la configuración actual antes de `config apply`.
