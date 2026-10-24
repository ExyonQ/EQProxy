# v0.7 slice 8 — WebSockets over HTTP/2 (RFC 8441)

Language: **English**. Evidence for the eighth v0.7 increment, collected on
2026-10-23 (macOS 26.5.1 arm64 host, `rustc 1.97.1`, `hyper-h2` 4.2.0).
Unreleased: it lands on top of `b93883e` plus the slice 7 working tree.

## 1. Objective

An HTTP/2 client must be able to open a WebSocket. HTTP/2 has no `101`; the
handshake is an **extended CONNECT** (`:protocol = websocket`, RFC 8441) and
the stream becomes the socket (`B-I18`). Before this slice EQProxy answered
every h2 `CONNECT` with `501`, so browsers and h2-only clients could not reach
a realtime endpoint through it.

Not covered: WebSockets to a backend that speaks **only** h2, proxy-side
`permessage-deflate` negotiation, compression or mirroring of a switched
stream, the S-H2/S-H3 scenarios against HAProxy, and the 24-hour soak (a
separate gate, still running).

## 2. Artifact under test

| Item | Value |
|---|---|
| Base commit | `b93883e` (`docs: record the backend HTTP/2 session lifecycle slice`) plus the slice 7 and 8 working tree |
| Binary | `target/release/eqproxy`, sha256 `1c9f040a42ed6c73e68900a2ec7bd4c29168e9e130580f60d9875cea324f27d3` (`cargo build --release -p eqproxy-cli`, rebuilt after the last code change) |
| Toolchain | `rustc 1.97.1 (8bab26f4f 2026-07-14)`, cargo 1.97.1 |
| Independent client | `hyper-h2` 4.2.0 (Python 3.9.6), real TCP socket, `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` |
| Origin | real TCP server speaking the HTTP/1.1 upgrade and echoing bytes (harness) |
| Design | [ADR-0012](../adr/0012-websockets-over-h2.md) |
| Raw run | [`v07-ws/run.txt`](v07-ws/run.txt), harness `scripts/evidence/v07-ws/run.py` (maintainer-local) |

## 3. What the implementation does

`eqproxy-net/src/ws.rs` serves a request when **all** of these hold: method
`CONNECT`, `:protocol = websocket`, and `:authority` plus `:path` present.
Everything else keeps the previous behaviour (`501` for a classic CONNECT or
an unknown protocol).

For a pass-through stream:

1. The h2 request is rendered as the h1 handshake: `GET <path> HTTP/1.1`,
   `host: <authority>`, the client's end-to-end headers (subprotocols
   included), `upgrade: websocket`, `connection: Upgrade`,
   `sec-websocket-version: 13` and a proxy-generated
   `sec-websocket-key` (16 bytes from the nanosecond clock plus a counter,
   base64). Hop-by-hop headers, a client key and a client version are
   dropped; the key only has to be unique per handshake and is not a secret.
2. That head goes through `http1::serve_http` on a bounded 64 KiB pipe, so
   routing rules, auth, rate limiting, header actions, rewrites,
   `forwarded_headers`, the backend pool and the tunnel are the **same**
   implementation the h1 client uses.
3. A backend `101` becomes an h2 `200` (RFC 8441 §5) carrying the backend's
   end-to-end headers minus `Sec-WebSocket-Accept`; the stream is then a byte
   relay with the client's flow-control window as the only outbound buffer.
4. A non-`101` answer is relayed as a normal h2 response (status, headers,
   body) — a refusal is visible, never an empty tunnel.
5. `idle_timeout` cuts a silent tunnel in either direction, counted in
   `idle_timeouts`.
6. New counters: `ws[tunnels=… failures=…]`; a successful tunnel counts one
   proxied request.

`SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` is advertised on every h2 connection
(`http2::serve_h2`), which is what lets a client use `:protocol` at all.

## 4. Journeys and results

### 4.1 Dataplane E2E with real sockets (cargo)

`cargo test -p eqproxy-net --test e2e_ws_h2` — **6 passed, 0 failed**, 10.3 s.
The client is the real `h2` crate over loopback TCP; the origin is a real TCP
server that validates the h1 upgrade and echoes bytes.

| Journey | What it proves | Result |
|---|---|---|
| `ws_extended_connect_tunnels_bytes_both_ways` | `200` (never `101`), `sec-websocket-protocol: chat` returned, no `sec-websocket-accept`, h1 upgrade headers absent from h2; the origin saw `GET /chat?room=7`, `host: ws.test`, `upgrade: websocket`, `connection: Upgrade`, `sec-websocket-version: 13`, a key and the client's subprotocol list; two messages echoed on the same stream; a client half-close closes the backend socket; `ws_tunnels = 1`, `ws_failures = 0` | pass |
| `ws_refused_handshake_is_relayed_as_a_normal_response` | a backend `404` arrives as h2 `404` with its body `no tunnel here`; `ws_tunnels = 0`, `ws_failures = 1` | pass |
| `ws_route_denial_answers_before_any_backend_contact` | a `direct_response` rule on `/blocked` answers `403` on the h2 stream and the backend is never contacted (accepted connections = 0): routing decisions are the h1 engine's | pass |
| `ws_unknown_protocol_is_refused_with_501` | `:protocol = not-a-protocol` → `501`, backend untouched | pass |
| `ws_classic_connect_keeps_its_501` | an authority-form `CONNECT` without `:protocol` → `501`, backend untouched | pass |
| `ws_silent_tunnel_is_cut_by_the_idle_timeout` | with a 250 ms idle window, a silent tunnel is cut — the h2 stream ends (cleanly or with a reset) instead of staying open forever, and the origin sees its socket close | pass |

Unit tests in `eqproxy-net/src/ws.rs` — **4 passed**: base64 RFC vector, the
generated key is 24 base64 characters and differs per handshake, the h1 head
carries the upgrade and drops hop-by-hop/key/version while forwarding
subprotocols, and a target that is not a path defaults to `/` (asterisk-form
refused).

### 4.2 Independent client through the release binary

`python3 scripts/evidence/v07-ws/run.py` — **PASS**. The client is `hyper-h2`
4.2.0 over h2c with `ENABLE_CONNECT_PROTOCOL`; the origin is a real TCP
WebSocket server; the proxy is the release binary with a real config
(`idle_timeout = 30s`, plaintext listener).

| Journey | Observable result |
|---|---|
| `tunnel` | `:status 200`, `sec-websocket-protocol: chat`, 13-byte and 15-byte messages echoed; the origin recorded `GET /chat?room=7 HTTP/1.1`, `host: ws.test`, `sec-websocket-protocol: chat, superchat`, `upgrade: websocket`, `connection: Upgrade`, `sec-websocket-version: 13`, a generated key |
| `refused` | `:status 404` with body `no tunnel here` and END_STREAM |
| `protocol` | `:protocol = not-a-protocol` → `:status 501` and END_STREAM |

Raw output: [`v07-ws/run.txt`](v07-ws/run.txt). The two handshakes the origin
saw, exactly as recorded by the harness:

```text
GET /chat?room=7 HTTP/1.1
host: ws.test
sec-websocket-protocol: chat, superchat
upgrade: websocket
connection: Upgrade
sec-websocket-version: 13
sec-websocket-key: 4IUWHkD+4BgBAAAAAAAAAA==
```

## 5. Test suite

- `cargo fmt --all -- --check` → clean.
- `cargo clippy --workspace --all-targets -- -D warnings` → clean.
- `cargo test --workspace` → **406 passed, 0 failed** (405 before this slice's
  last E2E test: +4 unit and +6 dataplane E2E). The two Docker-gated
  harnesses remain ignored as before.

## 6. Error and boundary cases

- Not `CONNECT`, or no `:protocol` → the previous path (classic CONNECT `501`;
  ordinary requests unchanged).
- `:protocol` other than `websocket` → `501` (RFC 8441 §5), no backend
  contact, counted in `http_requests_rejected`.
- Missing `:authority`/`:path` → `400`.
- Backend answer other than `101` → that answer is relayed (status, headers,
  body), counted as a `ws_failures`.
- Backend closes before or during the handshake → `502` (or the relayed error
  status) and `ws_failures`; the h2 stream is never left half-open.
- Silent tunnel → `idle_timeout` in either direction, counted.
- Client resets the stream → the tunnel task ends, the backend socket is
  closed, the h1 engine finishes.
- Headers with CR/LF/NUL are refused before anything is sent (`400`), even
  though the h2 layer already rejects them; the guard is defensive.

## 7. Verification tooling

- **Veyra Proof**: `veyra audit . --profile standard` → **ACCEPTED**, exit 0,
  evidence in `.veyra/evidence/20261022T234002Z/`. 11 tools OK (rustfmt,
  cargo check, clippy, cargo test, cargo-audit, anti-theater, nextest,
  llvm-cov, deny, machete, veyra-e2e); `dylint` and
  `cargo-semver-checks` were **skipped** (no Dylint configuration; no
  registry baseline for unpublished crates), exactly as the report states.
- **Rust Audit** (`python3.13 scripts/rust_audit.py scan … --fail-on high`):
  **exit 1**, 237 findings, report `rust-audit-20261023-014028.json`. On this
  slice: one **critical** at the base64 test vector
  `AAAAAAAAAAAAAAAAAAAAAA==` (16 zero bytes flagged as a hardcoded secret —
  a false positive), two **medium** `let _ =` on shutdown calls that only
  signal EOF to a stream that is already ending, and test-quality notes
  (wall-clock read, assertions without messages, numeric literals) accepted
  as style debt. Nothing on this list is suppressed in the report.
- **EvoForge** `mcp_submit_eval` on the extended-CONNECT decision and the
  key encoder (host `cargo test --workspace` ran first: 406 passed):
  `fitness_score: 1.0`, `compiles: true`, `tests_pass: true`, 0 failed
  layers (`trace_id d6399b66-d07b-492d-8826-066cbc4b2706`). Two earlier
  attempts scored 0 on `pattern.unchecked_index`/`lossy_cast`/
  `unchecked_rem`; those were real style problems in the encoder, and the
  production code was changed to checked conversions and `get` lookups (the
  slice then matched it exactly), not the eval bent to fit.

## 8. Limits and NOT EXECUTED

- **Backend that speaks only h2**: **NOT EXECUTED / not implemented**. The
  backend side of this slice is the h1 WebSocket handshake (see ADR-0012).
- `permessage-deflate` is not negotiated by the proxy; extension headers cross
  through untouched and compression stays end to end.
- The generated `Sec-WebSocket-Key` is unique but not cryptographically
  random: it exists so the backend can compute its accept digest, and no
  security property depends on it (TLS protects the hop).
- Response compression and request mirroring do not apply to a switched
  stream.
- Docker image and Docker Scout on both architectures: **NOT EXECUTED**.
- S-H2/S-H3 scenarios against HAProxy 3.4.6: **NOT EXECUTED**.
- The 24-hour gRPC soak is a separate gate and is running; see
  [v07-grpc-soak-24h.md](v07-grpc-soak-24h.md).
- Throughput/latency is not measured: the numbers above are correctness
  observations from one loopback host.
