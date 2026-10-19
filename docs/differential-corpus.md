# Differential corpus — shared semantics (v0.6 gate)

The v0.6 acceptance gate requires *differential tests against HAProxy 3.4.6,
ingress-nginx and static Envoy on the cases of shared semantics (declared
corpus)*. This document **is** that declaration: the cases, the
per-implementation mapping, the normalization rules and the limitations. The
harness that executes it is
[`eqproxy-cli/tests/differential.rs`](../eqproxy-cli/tests/differential.rs) —
real containers, real sockets, one config per implementation generated from
the same case list:

```
cargo test -p eqproxy-cli --test differential -- --ignored --nocapture
```

(Docker required; images are pulled on first use. The report is written to
`$CARGO_TARGET_TMPDIR/differential-<pid>/differential-report.md` with the
image digests and the binary hash.)

## Implementations under comparison

| column | what runs | version |
|---|---|---|
| `eqproxy` | the freshly built `eqproxy` binary, native | sha256 recorded in the report |
| `haproxy` | official image, generated `haproxy.cfg` | `haproxy:3.4.6` (HAProxy 3.4.6-56332c5) |
| `ingress-nginx` | the `nginx` binary shipped inside the official controller image, driven by a static config in the shapes the controller generates (like «Envoy estático») | `registry.k8s.io/ingress-nginx/controller:v1.13.0` (nginx/1.27.1) |
| `envoy` | official image, static bootstrap (no xDS) | `envoyproxy/envoy:v1.34.2` |

Backends are identity-echo servers (`nginx:alpine` serving
`return 200 "<id> $request_uri"`), so the target each proxy forwards —
and therefore any rewrite — is observable in the response body.

## Normalization (declared)

- Only the **status code** is compared; the reason phrase legitimately
  differs per implementation (and lowercases in ours).
- **`Location`** is reduced to path + query when absolute: the scheme and
  authority depend on the deployment, the redirect target is the shared
  semantics.
- The **body** is compared only when the case declares one: 3xx bodies
  differ legitimately (nginx sends its error page, the others send none).

## Corpus

Path namespaces are disjoint, so one config per implementation covers the
whole corpus and rule ordering is exercised for real. Every case declares
one outcome; all applicable implementations must produce it.

| id | request (HTTP/1.1, `Connection: close`) | declared outcome | shared semantics |
|---|---|---|---|
| `c1-prefix` | `GET /c1/users` | `200` · `api /c1/users` | `path_prefix` routes to its backend |
| `c1-boundary` | `GET /c10/users` | `200` · `fallback /c10/users` | literal prefix boundary: `/c1/` must not swallow `/c10` |
| `c2-host` | `GET /c2/x` · `Host: Special.Example.com` | `200` · `mgmt /c2/x` | host match is case-insensitive |
| `c2-port` | `GET /c2/x` · `Host: special.example.com:8443` | `200` · `mgmt /c2/x` | host match compares without the `:port` suffix |
| `c2-near` | `GET /c2/x` · `Host: other.example.com` | `200` · `fallback /c2/x` | a host near miss must not route |
| `c3-method` | `POST /c3/x` | `200` · `mgmt /c3/x` | method condition matches |
| `c3-near` | `GET /c3/x` | `200` · `fallback /c3/x` | method near miss must not route |
| `c4-header` | `GET /c4/x` · `x-beta: on` | `200` · `mgmt /c4/x` | header exact match routes |
| `c4-near` | `GET /c4/x` | `200` · `fallback /c4/x` | missing header must not route |
| `c5-first` | `GET /c5/x` · `x-beta: on` | `200` · `mgmt /c5/x` | ordered rules: the first matching rule wins over a later one |
| `c5-second` | `GET /c5/x` | `200` · `api /c5/x` | ordered rules: the later rule catches what the first misses |
| `c6-redirect` | `GET /c6/old` | `301` · `Location: /c6/new` (body not compared) | local 3xx with `Location` |
| `c7-direct` | `GET /c7/ping` | `200` · `pong` | local direct response, no backend contacted |
| `c8-rewrite` | `GET /c8/v1/users` | `200` · `api /c8/api/users` | prefix rewrite: the backend sees the rewritten target |
| `c11-regex` | `GET /c11/data.json` | `200` · `mgmt /c11/data.json` | a path regex over `.json` paths routes |
| `c11-boundary` | `GET /c11/data.jsonx` | `200` · `fallback /c11/data.jsonx` | regex near miss must not route |

### Per-implementation mapping (same observable, different mechanism)

- **Ordered rules (`c5`)**: HAProxy uses an ordered `use_backend` chain,
  Envoy ordered routes, EQProxy ordered `[[listener.*.rules]]`; nginx has
  no ordered rule list, so the same observable is expressed with a `map`
  on the header. The corpus asserts *which backend served*, not the
  mechanism.
- **Host matching (`c2`)**: HAProxy `req.hdr(host),lower,field(1,:)`,
  nginx `server_name` (caseless, port-free by design), EQProxy `host`
  (caseless, port-free per Q8), Envoy `domains` + `strip_any_host_port:
  true` — without that HCM option Envoy would compare `host:port`
  verbatim and `c2-port` would diverge.
- **Regex (`c11`)**: HAProxy `path -m reg \.json$` plus a `path_beg`
  scope and nginx `location ~*` use unanchored PCRE; Envoy `safe_regex`
  and the EQProxy rule use anchored spellings (`^/c11/.*\.json$`) to
  express the same set of paths. (EQProxy compiles unanchored regexes;
  the anchors here are part of the pattern.)
- **Rewrite (`c8`)**: HAProxy `set-path %[path,regsub(...)]` (its
  `http-request` rules always run before `use_backend`), nginx `rewrite …
  break`, Envoy `prefix_rewrite`, EQProxy `[listener.*.rules.rewrite]`
  `path_prefix_rewrite`.
- **Local answers (`c6`, `c7`)**: HAProxy `http-request redirect` /
  `http-request return`, nginx `return`, Envoy `redirect` /
  `direct_response`, EQProxy `redirect` / `direct_response` actions.

## Findings (run 2026-10-19)

16/16 cases agree across the four implementations, with no divergences
and no case needing a per-implementation exclusion. Full matrix with
image digests in the generated report.

## Limitations

- **ingress-nginx is exercised at the data plane** with a static config:
  the controller translation (Ingress/CRD objects → nginx.conf) is NOT
  exercised, by the same decision that covers Envoy with a static
  bootstrap.
- The corpus covers v0.6 rule matching and rule actions. Timeouts,
  retries, error classes (503 vs 502), header manipulation and PROXY
  protocol semantics are NOT in this corpus (their references diverge
  legitimately or belong to later slices).
- Comparison is per-case against the declared outcome; the corpus does
  not fingerprint whole config files or fuzz the references.
