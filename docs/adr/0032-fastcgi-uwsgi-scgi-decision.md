# ADR-0032: FastCGI, uwsgi and scgi gateways — not adopted

Language: **English**.

- State: **Accepted** (2026-10-29, roadmap v0.8.5, box B-I5/B-E4/B-N17)
- Date: 2026-10-29
- Related: [roadmap v0.8.5, §1](../../ROADMAP%20EQPROXY/ROADMAP/Roadmap%200.8.5.md)
  (the box this decision closes), [nginx.md B-N17](../../ROADMAP%20EQPROXY/nginx.md)
  (the parity gap), [ADR-0031](0031-wasm-plugin-host.md) (the WASM extension
  this box also lands), [v085-wasm-plugins](../evidence/v085-wasm-plugins.md)
  (evidence and the converter's classification)

## Context

nginx can talk to application servers directly:

- `fastcgi_pass` — FastCGI (binary framing, name/value parameter encoding,
  request IDs, multiplexed streams);
- `uwsgi_pass` — the uwsgi protocol (its own 4-byte header and modifier
  variables);
- `scgi_pass` — SCGI (netstring headers, no multiplexing);
- `grpc_pass` — gRPC over HTTP/2.

EQProxy is a reverse proxy: it forwards HTTP messages (HTTP/1.1, h2, h3 and
gRPC streams) and tunnels TCP. It is not an application server and does not
generate request environments for a runtime.

`grpc_pass` is already covered by the gRPC support added in v0.7 (HTTP/2
proxying with streaming, trailers and deadlines), so only the three non-HTTP
gateways are open.

The v0.8.5 roadmap marks B-N17 as a **decision**, not as an implementation
promise: parity means "or equivalent", and a gateway that changes the protocol
is not equivalent to proxying HTTP. The converter must classify these
directives explicitly instead of dropping them.

## Decision

FastCGI, uwsgi and scgi gateways are **not adopted** in the 0.8.x line or in
the v0.9.1 certification scope.

Reasons, in order of weight:

1. **Different protocol, different contract.** These are not HTTP upstreams.
   Implementing them means encoding/decoding their parameter sets, managing
   their request IDs and, for FastCGI, its multiplexing — an application
   gateway with its own conformance surface, not a listener option.
2. **No demonstrated migration need.** The reference configurations this
   project migrates (ingress-nginx, HAProxy, Envoy) target HTTP upstreams;
   ingress-nginx exposes no FastCGI annotation. Adding three protocols for a
   case nobody has brought would be a dependency and test burden without a
   proven user.
3. **The safe, honest alternative exists.** An application behind FastCGI can
   be fronted by its own HTTP server (the normal deployment), and EQProxy
   proxies that HTTP hop. The semantics the user cares about (routing, TLS,
   limits, balancing, observability) are preserved; the FastCGI hop is not
   something this proxy pretends to speak.

The migration path is explicit for the converter (Phase 8a, still pending —
ADR-0030 records that `config import` exits 2 today):

- when it lands, `eqproxy config import` **must** classify `fastcgi_pass`,
  `uwsgi_pass` and `scgi_pass` as **rejected with a cause**
  ("application-server protocol, not supported; front it with an HTTP
  server"), never as converted and never silently omitted;
- `grpc_pass` maps to the existing gRPC/HTTP2 upstream support.

## Consequences

- The parity matrix keeps B-N17 as **not applicable / rejected by decision**,
  not as pending work. The roadmap box cites this ADR and ADR-0031.
- A user who needs FastCGI keeps running nginx (or any FastCGI front end) in
  front of the application and puts EQProxy in front of that HTTP endpoint.
- No protocol implementation, dependency or listener mode is added.
- The converter's report is the place where the gap must be visible once the
  converter exists; a silent conversion would be the failure mode this
  decision forbids. The pending converter box owns that check.

## Revisit triggers

1. A real migration corpus contains `fastcgi_pass`/`uwsgi_pass`/`scgi_pass`
   and the owner accepts the application-gateway scope.
2. A gateway design that preserves the application-server contract (parameters,
   multiplexing, error semantics) is specified with conformance tests.
3. The converter starts reporting these directives as anything other than an
   explicit rejection.
