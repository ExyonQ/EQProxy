# Equivalencias de filtros nativos (B-E4)

Mapa de los tres filtros nativos de uso masivo entre las referencias
(Envoy, nginx, HAProxy, ingress-nginx) y la configuración de EQProxy. No es
una lista de deseos: cada fila apunta al **test que la respalda** en este
repositorio, y las diferencias de semántica están declaradas, no escondidas
bajo la misma palabra.

Nada de esto necesita WASM (v0.8.5): los tres se resuelven con configuración
tipada dentro del dataplane.

## 1. CORS

| Referencia | Forma en el origen | EQProxy |
|---|---|---|
| Envoy | `envoy.filters.http.cors` (`allow_origin_string_match`, `allow_methods`, `allow_headers`, `expose_headers`, `max_age`, `allow_credentials`) | `[listener.*.rules.cors]` |
| nginx | sin directiva: `add_header Access-Control-*` + `if ($request_method = OPTIONS) { return 204; }` | igual |
| HAProxy | `http-response set-header Access-Control-Allow-Origin …` + `http-request return` del preflight | igual |
| ingress-nginx | `enable-cors`, `cors-allow-origin`, `cors-allow-methods`, `cors-allow-headers`, `cors-expose-headers`, `cors-max-age`, `cors-allow-credentials` | igual |

Semántica EQProxy:

- `allow_origin` es un origen **exacto** (no lista, no regex) y `*` se
  rechaza junto con `allow_credentials` en el gate — la misma combinación
  que el navegador ignora.
- El **preflight** (`OPTIONS` con `Origin` + `Access-Control-Request-Method`)
  lo responde la regla localmente con `204` y nunca llega al backend.
- El resto de respuestas de la regla llevan las cabeceras CORS añadidas
  (incluidas las locales: `redirect`, `direct_response`, preflight).
- `max_age = "0s"` omite la cabecera en vez de mandar cero.

Tests: `eqproxy-net/tests/e2e_rules.rs`
(`cors_preflight_is_local_and_responses_carry_headers`), gate en
`eqproxy-config/src/validate.rs` (`cors_*`).

## 2. ext_authz (autorización por subrequest)

| Referencia | Forma en el origen | EQProxy |
|---|---|---|
| Envoy | `envoy.filters.http.ext_authz` con `http_service` (o gRPC) | `[listener.*.rules.auth] url = "http://HOST[:PORT][/PATH]"` |
| nginx | `auth_request /auth;` + `location = /auth { proxy_pass …; }` | igual |
| HAProxy | `http-request auth` / `http-request deny` con `http-request set-var` desde un `userlist` o servicio externo | igual |
| ingress-nginx | `auth-url`, `auth-type` | `url` + `type = "basic"` |

Semántica EQProxy:

- La subrequest es **HTTP/1.1 GET** al `url`, con las cabeceras del cliente
  (sin framing) más `X-Original-Method` y `X-Original-URL`.
- Decisión: `2xx` permite; `401`/`403` niegan **con la respuesta del
  servicio** hacia el cliente (status + `www-authenticate`, `location`,
  `set-cookie`, `content-type` y cuerpo ≤ 8 KiB); cualquier otro status
  → `500`; servicio caído o timeout → `502`.
- **Fail closed siempre**: no hay `failure_mode_allow` (Envoy sí lo tiene).
- `type = "basic"` (htpasswd: `$apr1$…` o planas) corre **antes** del
  subrequest y es local; bcrypt/crypt/`{SHA}` los rechaza el gate nombrando
  el fix.
- La autenticación puede colgar de **cualquier** acción de la regla y se
  evalúa antes del preflight CORS.

Tests: `eqproxy-net/tests/e2e_rules.rs`
(`auth_basic_rejects_missing_or_wrong_credentials_explicitly`,
`auth_subrequest_allows_on_2xx_and_fails_closed`) y
`eqproxy-cli/tests/cli_e2e.rs` (`run_auth_basic_and_subrequest_gate_requests`).

## 3. rate_limit

| Referencia | Forma en el origen | EQProxy |
|---|---|---|
| Envoy | `envoy.filters.http.local_ratelimit` (bucket en proceso); `envoy.filters.http.ratelimit` (servicio RLS global) | `rate_limit = { rate, per, burst }` |
| nginx | `limit_req zone=api rate=10r/s burst=20 nodelay;` | igual |
| HAProxy | `stick-table type ip size 100k rate(60s)` + `http-request deny deny_status 429` | igual |
| ingress-nginx | `limit-rps`, `limit-rpm`, `limit-burst` | `rate` + `per` + `burst` |

Semántica EQProxy:

- Bucket de tokens **en memoria, por IP de cliente y por regla**: no hay red
  en la ruta caliente, así que el limitador nunca «no puede decidir» (Q6).
- `rate = 10` con `per = "1s"` es 10 req/s; con `per = "60s"`, 10 req/min
  (rpm). `burst` por defecto es `rate`.
- Por encima del límite: `429` explícito + contador `rate_limited`. Nunca se
  encola ni se descarta en silencio.
- **Diferencia declarada:** no hay estado compartido entre procesos (Envoy
  RLS / `limit_req_zone` de nginx con `shared`): el bucket vive en el
  proceso de EQProxy. Un despliegue con varias instancias de EQProxy limita
  **por instancia**.

Tests: `eqproxy-net/tests/e2e_rules.rs`
(`rate_limit_rejects_over_the_limit_explicitly`), gate en `validate.rs`.

## 4. Lo que queda fuera (y por qué)

Estos filtros necesitan WASM (v0.8.5) o un servicio externo; no hay atajo
honesto con configuración:

| Filtro | Motivo |
|---|---|
| `envoy.filters.http.lua` / `ext_proc` | código por petición: WASM |
| `fault` (abort/delay inyectados) | WASM |
| `jwt_authn`, `oauth2` | WASM (o `ext_authz` con un servicio propio) |
| `grpc_web`, `grpc_json_transcoder` | WASM |
| `tap`, `gzip`, `decompressor` | WASM (en v0.8.5) |

`ext_authz` por gRPC y el servicio global de rate limit también esperan a
WASM/HTTP/2: hoy solo existe la variante HTTP de `ext_authz` y el bucket
local.
