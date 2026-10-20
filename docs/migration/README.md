# Migration matrix — real source configs vs the EQProxy translation

Gate criterion of v0.6 («migración demostrada»): the **same demo deployment**
expressed in the four source formats EQProxy migrates, plus its translation to
EQProxy, routing **case by case exactly the same**.

The harness is a Rust integration test:
[tests/migration.rs](../../eqproxy-cli/tests/migration.rs). It starts the four
originals as containers and the freshly built `eqproxy` binary natively, all in
front of the same five echo backends, sends every case of the matrix below to
each one and asserts the declared result. It is `#[ignore]`d (needs Docker) like
the differential corpus.

```bash
cargo test -p eqproxy-cli --test migration -- --ignored --nocapture
```

Last run (13/13 cases × 5 implementations = 65/65 checks): evidence and
environment in [`docs/evidence/v06-migration/`](../evidence/v06-migration/README.md).

## Files

| File | Role |
|---|---|
| [haproxy.cfg](haproxy.cfg) | The deployment as HAProxy 3.4 config |
| [nginx.conf](nginx.conf) | The deployment as operator-written nginx |
| [envoy.yaml](envoy.yaml) | The deployment as a static Envoy 1.34 bootstrap |
| [ingress.yaml](ingress.yaml) | The deployment as Kubernetes objects (ingress-nginx) |
| [ingress-nginx-generated.conf](ingress-nginx-generated.conf) | The controller-shaped config those objects generate (what runs) |
| [eqproxy.toml](eqproxy.toml) | The translation to EQProxy |

## Topology

Five backends echo `<pool> <request_uri>`, so the pool that served a request and
any path rewrite are both visible in the body:

| pool | address in the source configs | role |
|---|---|---|
| `web` | 172.24.0.11:80 | storefront |
| `api` | 172.24.0.12:80 | API |
| `admin` | 172.24.0.13:80 | admin writes |
| `canary` | 172.24.0.14:80 | storefront canary |
| `fallback` | 172.24.0.15:80 | default backend |

Every implementation listens on `:8080`. The harness renders
[eqproxy.toml](eqproxy.toml) with two declared substitutions — nothing else is
touched:

1. `listen = "0.0.0.0:8080"` → `listen = "127.0.0.1:0"` (a free port; the
   containers publish their `:8080` on host loopback instead of holding it).
2. `server = "172.24.0.1x:80"` → `server = "127.0.0.1:<published port>"` for
   each pool (the native binary reaches the backends through host ports; the
   containers reach them at their fixed IP on the same demo network).

Both substitutions change *where* the pools live, not what any rule means.

## Matrix

Each case is sent to all five implementations; the declared outcome is asserted
on each, with no exclusions.

| # | request | Host | expected |
|---|---|---|---|
| m1 | `GET /` | shop.example.com | `200 web /` |
| m2 | `GET /api/x` + `Cookie: canary=on` | shop.example.com | `200 canary /api/x` |
| m3 | `GET /` + `X-Canary: on` | shop.example.com | `200 canary /` |
| m4 | `POST /api/x` | api.example.com | `200 api /api/x` |
| m5 | `POST /admin/x` | shop.example.com | `200 admin /admin/x` |
| m6 | `GET /admin/x` | shop.example.com | `200 web /admin/x` |
| m7 | `GET /reports/x` | shop.example.com | `200 api /reports/x` |
| m8 | `GET /api/v1/users` | api.example.com | `200 api /api/users` (rewrite) |
| m9 | `GET /api/a.json` | api.example.com | `200 api /api/a.json` |
| m10 | `GET /old/blog` | shop.example.com | `301` + `Location: /blog` |
| m11 | `GET /healthz` | shop.example.com | `200 ok` (local answer) |
| m12 | `GET /x` | other.example.com | `200 fallback /x` |
| m13 | `GET /x` | api.example.com | `200 fallback /x` |

## Mapping

| feature | HAProxy | nginx | Envoy | ingress-nginx | EQProxy |
|---|---|---|---|---|---|
| prefix route | `use_backend … path_beg` | `location /prefix/` | route `prefix` | Ingress path `Prefix` | `path_prefix` + `use_backend` |
| exact route | `{ path /x }` | `location = /x` | route `path` | path `Exact` | `path` |
| host route | `hdr(host)` | `server_name` | `virtual_hosts[].domains` | Ingress `host` | `host` |
| method route | `{ method POST }` | `if ($request_method …)` / map | header `:method` | snippet | `methods` |
| canary by cookie | `cook(canary) -m str on` | `map $cookie_…` | header regex on `cookie` | `canary-by-cookie` | `cookies` |
| canary by header | `hdr(x-canary)` | `map $http_x_canary` | header `exact_match` | `canary-by-header` | `headers` |
| prefix rewrite | `http-request set-path` | `rewrite … break` | `prefix_rewrite` | `rewrite-target` | `rewrite.path_prefix_rewrite` |
| redirect | `http-request redirect` | `return 301` | `redirect` | snippet `return 301` | `redirect` |
| local answer | `http-request return` | `return 200` | `direct_response` | snippet `return 200` | `direct_response` |
| default | `default_backend` | `default_server` | `domains: ["*"]` | `defaultBackend` | listener `backend` |

## Declared limitations

- **ingress-nginx runs the config the controller generates**, not the controller
  itself: the object → config translation (and therefore cluster Service
  resolution) is not exercised, only the data plane semantics of the generated
  shapes. Same declared limitation as `docs/differential-corpus.md`.
- **Method routing and local answers in the ingress column** use the standard
  `configuration-snippet` escape hatch, because Ingress cannot express method
  routing or local answers natively; the annotation is part of
  [ingress.yaml](ingress.yaml).
- **TLS, SNI, WebSocket upgrade and HTTP/2** are outside this matrix (they are
  transport concerns covered by their own slices); all five run plain HTTP/1.1.
- **Load balancing across several servers per pool** is out of scope here (one
  server per pool keeps "which pool served it" observable); the balancing
  algorithms are covered by the differential corpus and benchmarks.
