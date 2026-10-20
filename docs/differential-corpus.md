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
and therefore any rewrite — is observable in the response body. Paths
under `/h…` echo the forwarded request headers instead (`xff`, `real`,
`beta`, `gone`, `added`; `/h4…` also echoes `proto`), which is how the
header cases observe what each proxy actually forwarded.

## Normalization (declared)

- Only the **status code** is compared; the reason phrase legitimately
  differs per implementation (and lowercases in ours).
- **`Location`** is reduced to path + query when absolute: the scheme and
  authority depend on the deployment, the redirect target is the shared
  semantics.
- The **body** is compared only when the case declares one: 3xx bodies
  differ legitimately (nginx sends its error page, the others send none).
- **Comma-joined header values** use one canonical separator (`", "`):
  some backends merge duplicate header lines with a comma and no space,
  others with `", "`; the joined value is the same header semantics.
- The **client address** is topology-dependent (host loopback for the
  native binary, docker gateway for the containerized references), so
  the harness calibrates it once per implementation — a probe without
  XFF on the append endpoint echoes it as the sole XFF entry — and
  substitutes it as the `CLIENT` token in bodies.

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

### Header cases — the B-N4/B-I4 executable spec

Header semantics run on **two endpoints**, each with its own config per
implementation: `main` (forwarded headers append) and `replace`
(anti-spoofing). The request headers are sent by the client (including
spoofed `X-Forwarded-For`/`X-Real-IP`); the declared outcome is what the
backend must observe after the proxy. Response-header cases declare the
header the client must observe. `CLIENT` is the calibrated client
address (see normalization).

| id | endpoint | request | declared outcome | shared semantics |
|---|---|---|---|---|
| `h1-xff-append` | `main` | `GET /h1/x` · `X-Forwarded-For: 10.9.9.9` | `xff=[10.9.9.9, CLIENT]` · `real=[]` | XFF grows: client-sent hops are kept, the client is appended |
| `h2-xff-xri-replace` | `replace` | `GET /h2/x` · `X-Forwarded-For: 10.9.9.9` · `X-Real-IP: 1.2.3.4` | `xff=[CLIENT]` · `real=[CLIENT]` | anti-spoofing: both headers carry the real client only |
| `h4-xfp` | `main` | `GET /h4/x` | `proto=[http]` | `X-Forwarded-Proto` carries the client scheme |
| `h5-set-header` | `main` | `GET /h5/x` · `x-beta: off` | `beta=[on]` | set-header replaces the client's value on the forwarded request |
| `h6-del-header` | `main` | `GET /h6/x` · `x-gone: please` | `gone=[]` | del-header removes the client's header before forwarding |
| `h7-add-header` | `main` | `GET /h7/x` · `x-added: base` | `added=[base, extra]` | add-header combines the added value with the client's |
| `h8-response-marker` | `main` | `GET /h8/x` | response header `x-marker: v06` | response headers can be set on the way back |

EQProxy implements the whole table (B-N4/B-I4/B-E17):
`forwarded_headers = "append"/"replace"` covers `h1`/`h2`, both modes
also set `X-Forwarded-Proto` (`h4`), and the rule header actions
(`set_headers`/`add_headers`/`del_headers`/`response_headers`) cover
`h5`–`h8`. Before implementation, `h4`–`h8` ran as spec with
`PENDING` skips asserted on the three references: their agreement is
the evidence that the declared outcome is the shared semantics, not an
EQProxy invention.

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
- **Forwarded headers (`h1`, `h2`)**: HAProxy `http-request set-header`
  with `"%[hdr(x-forwarded-for)], %[src]"` / `"%[src]"`, nginx
  `$proxy_add_x_forwarded_for` / `$remote_addr`, Envoy
  `request_headers_to_add` with `%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%`
  (its own XFF append is disabled with `skip_xff_append` so the header
  ops are the whole story), EQProxy `forwarded_headers =
  "append"/"replace"`.
- **Header actions (`h5`–`h8`)**: HAProxy `set-header` / `del-header` /
  `add-header` + `http-response set-header`, nginx `proxy_set_header` /
  `add_header`, Envoy route-level `request_headers_to_remove` /
  `request_headers_to_add` / `response_headers_to_add`, EQProxy
  `set_headers`/`add_headers`/`del_headers`/`response_headers` on the
  matched rule. In all four the rules are scoped to the `/h` namespace;
  the `h8` marker is a global response rule in HAProxy (present in
  every response, asserted only where declared).
- **X-Forwarded-Proto (`h4`)**: emitted with the client-facing scheme
  by all four (Envoy natively; the others via explicit header rules).
  A single-value header: the client's is replaced, never chained.

## Findings

- **2026-10-19 (routing)**: 16/16 cases agree across the four
  implementations, with no divergences and no case needing a
  per-implementation exclusion.
- **2026-10-19 (headers)**: 23/23 cases agree across their applicable
  implementations. `h1`/`h2` agree on **all four** columns — the B-N4
  slice-1 semantics (append/replace) are shared with the references,
  not invented. `h4`–`h8` agreed on the three references with 5
  documented `PENDING` exclusions in the `eqproxy` column (spec ahead
  of implementation). No divergences. Full matrix with image digests
  in the generated report.
- **2026-10-19 (headers implemented)**: the B-N4/B-I4/B-E17 slice
  implemented in EQProxy (XFP + rule header actions + `$remote_addr`/
  `$host`/`$scheme` values); the `PENDING` skips are gone and the
  corpus closes **23/23 with all four columns asserted and 0
  exclusions**.

## Limitations

- **ingress-nginx is exercised at the data plane** with a static config:
  the controller translation (Ingress/CRD objects → nginx.conf) is NOT
  exercised, by the same decision that covers Envoy with a static
  bootstrap.
- The corpus covers v0.6 rule matching and rule actions and the
  B-N4/B-I4 header semantics (declared here ahead of the EQProxy
  implementation for `h4`–`h8`). Timeouts, retries, error classes
  (503 vs 502) and PROXY protocol semantics are NOT in this corpus
  (their references diverge legitimately or belong to later slices).
- Comparison is per-case against the declared outcome; the corpus does
  not fingerprint whole config files or fuzz the references.
