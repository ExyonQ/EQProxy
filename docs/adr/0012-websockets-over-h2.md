# ADR-0012 — WebSockets over HTTP/2 (RFC 8441 extended CONNECT)

Status: Accepted · 2026-10-23 · v0.7 slice 8 (B-I18)

## Context

HTTP/2 has no `101 Switching Protocols`: a WebSocket starts with an
**extended CONNECT** — a `CONNECT` request carrying `:protocol = websocket`
plus `:scheme`, `:authority` and `:path`, negotiated through
`SETTINGS_ENABLE_CONNECT_PROTOCOL` (RFC 8441). The stream itself becomes the
socket; frames travel as DATA in both directions.

EQProxy already had two halves that matter here:

- an h1 WebSocket/`CONNECT` tunnel with routing, authentication, header
  actions and an idle cap (`http1::serve_http`), and
- an h2 listener that translates each stream into one h1 exchange through a
  bounded in-memory pipe, refusing `CONNECT` with `501`.

The gap (B-I18) was the join: an h2 client could not open a WebSocket.

## Decision

Serve an h2 extended CONNECT with `:protocol = websocket` by translating it
into the **real h1 WebSocket handshake** the same h1 engine already serves.

1. `ws::serve` detects `CONNECT` + `:protocol = websocket`; every other
   `CONNECT` (classic or unknown protocol) keeps the explicit `501`.
2. The h2 request is rendered as the h1 request the same client would have
   sent: `GET <path> HTTP/1.1`, `host: <authority>`, `Upgrade: websocket`,
   `Connection: Upgrade`, `Sec-WebSocket-Version: 13`, a proxy-generated
   `Sec-WebSocket-Key`, and the client's end-to-end headers (subprotocols
   included). Hop-by-hop headers and a client-supplied key/version are
   dropped.
3. That head goes through `http1::serve_http` over a bounded pipe. Routing
   rules, auth, rate limiting, header actions, rewrites, `forwarded_headers`,
   the pool and the tunnel all run in their one implementation; there is no
   second decision engine.
4. A backend `101` becomes an h2 `200` (RFC 8441 §5) carrying the backend's
   end-to-end headers minus `Sec-WebSocket-Accept`. The stream is then a byte
   relay: h2 DATA → backend socket, backend socket → h2 DATA, with the
   client's flow-control window as the only outbound buffer and capacity
   released only after the backend accepted the chunk.
5. A non-`101` answer is relayed as a normal h2 response (status, headers,
   body): a refused handshake is visible, not an empty tunnel.
6. `idle_timeout` cuts a silent tunnel in either direction and counts it in
   `idle_timeouts`; no `max_stream_duration` special case is needed because
   the relay is the same bounded one as the h1 tunnel.

## Alternatives considered

- **Native h2 WebSocket towards the backend** (backend also speaks RFC 8441):
  rejected for this slice because no mainstream origin serves WebSockets over
  h2 yet; it would add a second backend path with no real peer to verify it
  against. The h1 backend path is what every real WebSocket server speaks.
- **A separate h2 tunnel engine** (no h1 pipe): rejected — it would duplicate
  routing, auth, header and tunnel logic, which is exactly the drift the
  existing translation is designed to avoid.
- **Passing `:protocol` through to a backend h2 session**: same as the first
  alternative; deferred, explicitly.

## Consequences

- One code path for WebSocket decisions on h1 and h2 clients; a rule that
  denies `/chat` denies it for both without extra work (verified E2E: the h2
  extended CONNECT to a `direct_response` path is answered locally and the
  backend is never contacted).
- The proxy generates the upstream `Sec-WebSocket-Key`; the client's key (if
  any) is ignored, and the backend's `Sec-WebSocket-Accept` is not forwarded.
- A backend that speaks **only** h2 cannot serve a WebSocket through this
  slice; the h1 WebSocket path remains the requirement for the origin side.
- No `permessage-deflate` negotiation is performed by the proxy: the
  extension headers cross untouched and compression remains end to end.
- Response compression and request mirroring do not apply to a switched
  stream.
- New counters: `ws[tunnels=… failures=…]`; a successful tunnel also counts
  as one proxied request.
- `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` is advertised on every h2
  connection; clients that never send `:protocol` are unaffected.
