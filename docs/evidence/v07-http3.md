# v0.7 slice 9 — HTTP/3 termination over QUIC (B-H2)

## 1. Objective

Serve **real HTTP/3 (RFC 9114) over QUIC** to clients: TLS 1.3 + ALPN `h3`
on the listener's own `IP:PORT` over UDP, one h3 request stream turning into
one HTTP/1.1 exchange through the existing engine (routing rules, auth, rate
limiting, header actions, mirroring, retries, keep-alive pool and response
compression), with explicit answers for unsupported/error cases and a
lifecycle (startup, hot reload, shutdown, `maxconn`) that cannot silently
diverge from the TCP listener. This closes roadmap **B-H2** (with B-E2 and the
priority note B-E13), the last missing item of the v0.7 parity list.

Design: [ADR-0013](../adr/0013-http3-quic.md).

## 2. Artifact under test

| | |
|---|---|
| Binary | `target/release/eqproxy` (`eqproxy 0.6.3`) |
| SHA-256 | `f1d0aecb0ea1b3fbeec081ddd8661ae786fbeeb08038cee39787b8916ceb3982` |
| Host | `Darwin lex 25.5.0 … arm64` (Apple M2 Max), macOS 26.5 |
| Toolchain | `rustc 1.97.1` / `cargo 1.97.1` (edition 2024) |
| Stack | `quinn 0.11.12` (`rustls-aws-lc-rs`, no `ring`), `h3 0.0.8`, `h3-quinn 0.0.10` |
| Independent client 1 | `aioquic 1.2.0` (Python 3.9.6), QUIC + h3 + QPACK, no TCP fallback |
| Independent client 2 | `quic-go v0.64.1` (Go 1.26.2), its own QUIC + h3 + QPACK stack (source in [`v07-http3/interop-quic-go/`](v07-http3/interop-quic-go/)) |

## 3. What the implementation does

- **Configuration.** `quic = true` per listener. The gate requires
  `mode = "http"` and `[listener.X.tls]`, rejects `alpn = ["h3"]` on the TCP
  side (the QUIC endpoint offers it automatically) and rejects
  `proxy_receive` (no preamble on QUIC). The JSON Schema and
  `eqproxy.toml.example` document the key, and `config plan` renders
  `quic=h3/udp` for a listener that serves it.
- **Transport.** `quinn::Endpoint` bound to the listener's **resolved TCP
  address** over UDP (the `:0` case resolves the TCP port first), with the
  listener's certificates/SNI/mTLS, ALPN forced to `h3`, the listener
  `idle_timeout` as QUIC idle timeout and `max_concurrent_bidi_streams = 128`.
- **h3.** Each request is translated with the same `build_request_head` the
  h2 path uses (`:authority` → `host`, origin-form, hop-by-hop stripped,
  `content-length` preserved / no body → no framing / otherwise `chunked`)
  and handed to `http1::serve_http` on a bounded duplex. A body-less request
  is detected with one stateful `poll_recv_data` peek, so a GET is not
  rewritten as chunked. Two tasks per exchange: one owns the h3 stream and
  applies response commands (head/data/trailers/finish/reset) and forwards
  the request body; the other reads the h1 answer and sends those commands
  through a bounded 4×16 KiB channel. The client's h3 trailers become h1
  trailers; an h1 chunked response's trailers become h3 trailers.
- **Errors/boundaries.** `CONNECT` → `501`; a dead backend → `502` from the
  engine; an invalid request → `400`; a truncated backend body resets the h3
  stream instead of ending it cleanly; a backend `101` resets the stream
  (h3 has no protocol switch); interim 1xx are skipped (h3 0.0.8 has no
  informational frame); `maxconn` refuses the QUIC handshake explicitly.
- **Lifecycle.** `bind` opens TCP and UDP before any loop runs (fail-closed);
  a reload keeps the endpoint of a kept listener, starts/stops QUIC when the
  flag changes, and **rejects a TLS material change on a live endpoint**
  (`QuicTlsReload`) because a quinn endpoint freezes its TLS at creation;
  shutdown triggers CONNECTION_CLOSE and joins the h3 accept task.
- **Interop decision.** h3 0.0.8 greases the stream frame before FIN on the
  first completed stream. The first aioquic run timed out with a complete
  response on the wire: aioquic 1.2.0 leaves its DATA event
  `stream_ended = false` when an unknown frame follows DATA, so the end of
  stream is lost. Grease is optional (RFC 9114 §7.2.8), so the server now
  builds the connection with `send_grease(false)`; the same aioquic harness
  then passed. The Rust `h3` client accepted both behaviours (it is the same
  crate that emitted the grease), which is why the independent client was the
  one that found it.

## 4. Journeys and results

### 4.1 Dataplane E2E with real sockets (`cargo`)

`cargo test -p eqproxy-net --test e2e_http3` — **7 passed, 0 failed**
(0.14 s wall). The client is a real `quinn` endpoint speaking `h3` over
loopback UDP; the origin is a real HTTP/1.1 TCP server.

| Journey | What it proves |
|---|---|
| `http3_get_is_terminated_and_relayed_to_the_h1_origin` | TLS 1.3 + h3 handshake, GET answered `200` with the origin body and header, origin saw `GET /hello HTTP/1.1` with `host: localhost` and no `connection:`; `http_requests_proxied = 1` and one accepted connection |
| `http3_request_body_without_length_streams_as_chunked_upstream` | 256 KiB POST without `content-length` arrives at the origin as `transfer-encoding: chunked`, every byte (and only those) in order, `200` with the byte count |
| `http3_chunked_response_and_trailers_cross_the_translation` | chunked origin response decoded into h3 DATA, `x-origin: yes` trailer delivered as h3 trailers, no `transfer-encoding` in the h3 headers |
| `http3_requests_get_the_h1_engine_decisions_rules_and_compression` | a `direct_response` rule answers `418` without dialing the origin; `accept-encoding: gzip` produces `content-encoding: gzip` and the decoded body is the origin's 8192 bytes |
| `http3_connect_is_refused_and_a_dead_backend_is_an_explicit_502` | `CONNECT` → `501` (counted rejected); a listener whose only server is down answers `502`, not a hang |
| `http3_maxconn_refuses_a_second_quic_connection` | with `maxconn = 1` the second QUIC handshake is refused promptly and `connections_rejected` counts it |
| `http3_reload_rejects_a_tls_change_and_can_turn_quic_off` | same name/address with different TLS → `ProxyError::QuicTlsReload`, the running endpoint keeps serving; `quic = false` is applied in place (endpoint closed, new h3 connection refused) while the TLS TCP listener keeps answering h1 |

### 4.2 Real release binary + first independent client (`aioquic`)

```
python3 -m venv /tmp/h3venv
/tmp/h3venv/bin/pip install aioquic==1.2.0
cargo build --release -p eqproxy-cli
/tmp/h3venv/bin/python docs/evidence/v07-http3/run.py
```

Run `docs/evidence/v07-http3/run-20261023T004518Z/` (`results.json`,
`summary.txt`, `proxy.log`, `plan.txt`, `eqproxy.toml`) — **PASS**, proxy
exit `0`, wall 0.28 s:

| Journey | Result |
|---|---|
| `GET /hello` | `200`, 17 B `hello from origin`; origin saw `GET /hello HTTP/1.1` |
| `POST /echo` 256 KiB without `content-length` | `200`, 12 B `262144 bytes`; origin received exactly 262144 B over chunked framing |
| `GET /trailers` | `200`, 13 B `hello chunked`, trailer `x-origin: yes` |
| `GET /compress` + `accept-encoding: gzip` | `200`, 44 B gzip; decompresses to 8192 × `a` |
| `GET /shed` (direct rule) | `418`, `{"shed":true}`, no origin contact |
| `CONNECT /tunnel` | `501`, 0 B |

Cross-checks in the same run: `plan` exit 0 with
`listener "h3": bind 127.0.0.1:50130 mode=http … quic=h3/udp`; final metrics
`client[accepted=1 completed=1] backend[opened=4 proxied=4]
compression[gzip=1 …] direct=1`, `tls_failures=0`; SIGINT produced a clean
`proxy_exit = 0` and the `(final)` metrics line.

Note on the metrics: `protocol_errors=1` in that run is the deliberate
`CONNECT` refusal (`http_requests_rejected`), not a protocol violation.

### 4.3 Second independent client (`quic-go`)

A second implementation with no shared code with the proxy: `quic-go`
v0.64.1 (its own QUIC transport, h3 framing and QPACK). The client is a
small Go program ([`v07-http3/interop-quic-go/main.go`](v07-http3/interop-quic-go/main.go)) that
only performs requests and prints JSON; every assertion stays in `run.py`,
the same ones the aioquic run uses.

```
cd docs/evidence/v07-http3/interop-quic-go && go mod download
/tmp/h3venv/bin/python docs/evidence/v07-http3/run.py --client quic-go
```

Run `docs/evidence/v07-http3/run-20261023T012403Z-quic-go/` (`results.json`,
`summary.txt`, `go-build.log`, `go-client.log`, `proxy.log`, `eqproxy.toml`;
the client binary is built in a temporary directory and only its hash is kept)
— **PASS**, `go build` exit 0, proxy exit 0, wall 1.67 s, same release binary
sha256 `f1d0aecb…`:

| Journey | Result |
|---|---|
| `GET /hello` | `200`, 17 B `hello from origin`; origin saw `host: localhost` |
| `POST /echo` 256 KiB, unknown length | `200`, 12 B `262144 bytes`; origin received 262144 B over `transfer-encoding: chunked` |
| `GET /trailers` | `200`, 13 B `hello chunked`, trailer `x-origin: yes` |
| `GET /compress` + `accept-encoding: gzip` | `200`, 44 B gzip; decompresses to 8192 × `a` |
| `GET /shed` (direct rule) | `418`, `{"shed":true}`, origin saw no `/shed` request |

Final metrics: `client[accepted=1 completed=1]
backend[opened=4 proxied=4] direct=1 compression[gzip=2 bytes_in=8205
bytes_out=77]`, `tls_failures=0`, clean SIGINT (`proxy_exit = 0`).

Honest notes on this client: (1) Go canonicalizes header names and reports
trailers as lists, so `run.py` normalizes that shape before the shared checks
— two earlier runs in this directory (`run-20261023T012024Z-quic-go` and
`run-20261023T012108Z-quic-go`) failed on that adapter, not on the proxy, and
are kept as evidence of the iteration; (2) `net/http` over h3 does not issue
a plain `CONNECT`, so the `501` check runs on aioquic and in the Rust E2E,
not here; (3) the same run was repeated with `aioquic`
(`run-20261023T012405Z`) after the harness change — **PASS** — so the
orchestrator refactor did not favour either client.

## 5. Test suite

`cargo test --workspace` — **414 passed, 0 failed, 2 ignored** (the two
`miri`-only network tests), 28 suites. This slice added **8 tests**: 7
dataplane E2E (`e2e_http3.rs`) and 1 configuration-gate test
(`quic_requires_tls_http_mode_and_no_proxy_header`, four negative cases plus
the valid one).

## 6. Error and boundary cases

| Case | Behaviour | Where |
|---|---|---|
| `quic = true` without TLS | config error naming `listener.X.quic`, fix suggestion | `validate.rs` unit test |
| `quic` on a `tcp` listener | config error (`mode = "http"`) | same |
| `quic` with `proxy_receive` | config error (no QUIC preamble) | same |
| `alpn = ["h3"]` on the TCP TLS table | config error (reserved for QUIC) | same |
| TLS material changed on a live QUIC listener | `QuicTlsReload`, running config keeps serving | reload E2E |
| UDP port already in use | `ProxyError::QuicBind` aborts startup whole (TCP sockets closed) | code path in `bind`; not exercised with a real port clash |
| QUIC handshake fails/times out | logged, `tls_handshake_failures` counted, no request forwarded | code path; both clients exercise success only |
| Body shorter than declared | h3 stream reset (`H3_REQUEST_INCOMPLETE`), never a clean end | code path |
| Backend 101 | stream reset, logged | code path |
| `CONNECT` | `501`, counted rejected | E2E + binary |
| No server reachable | engine's `502` | E2E |

## 7. Checks run

| Command | Result |
|---|---|
| `cargo fmt --all --check` | clean (below) |
| `cargo build --workspace` / `cargo build --release -p eqproxy-cli` | exit 0 |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean (below) |
| `cargo test --workspace` | 414 passed, 0 failed, 2 ignored |
| `gofmt -l …/interop-quic-go` / `go vet ./…` | clean / exit 0 |
| `/tmp/h3venv/bin/python docs/evidence/v07-http3/run.py` | PASS, exit 0 (`run-20261023T012405Z`) |
| `/tmp/h3venv/bin/python docs/evidence/v07-http3/run.py --client quic-go` | PASS, exit 0 (`run-20261023T012403Z-quic-go`) |
| `veyra audit . --profile standard` | **ACCEPTED**, exit 0, `.veyra/evidence/20261023T012717Z/` (rustfmt, check, clippy, test, audit, anti-theater, nextest, llvm-cov, deny, machete and `veyra-e2e` 17/17 OK; geiger INCONCLUSIVE by its own coverage warning, dylint/semver-checks SKIPPED for lack of config/baseline — no check disabled) |
| Rust Audit `scan . --format terminal,md,json,sarif --fail-on high` | exit 1: 251 findings (3 critical / 25 high / 180 medium / 43 low), triaged below; **none in the new HTTP/3 code** |
| EvoForge `mcp_submit_eval` | **F = 1.0**, 3/3 sandbox tests, clippy clean, exit 0, trace `94fd6088-02f1-4a2f-8cb5-0c2ba308c123`; re-run for the interop increment on the same unchanged h3 translation slice — **F = 1.0**, trace `113d25cd-49e2-40ff-b8eb-4d59e261291b` |

### Rust Audit triage (exit 1, reported as such)

The scan is static and offline; its report is
`report/rust-audit-20261023-033238.json` (local artifact, untracked).
Every high/critical finding was checked against the code, not waved through:

- `R18d` **false positive**: "impossible version requirement `2` for
  `thiserror`" — 2.x is published and `Cargo.lock` resolves `thiserror
  2.0.21`; the tool's major table is stale. The three `eqproxy-*` crates
  flagged as "hallucinated/generic" are this workspace's path dependencies.
- `R20`/`R18c` **false positives**: `h2`, `http`, `h3` and `md-5` are the real
  crates in `Cargo.lock` and in use; the "not popular" / "does not exist,
  near-miss of `h3`" classification comes from the offline popularity data,
  and the message contradicts crates.io (`h2` 0.4.x, `http` 1.x, `h3` 0.0.x,
  `md-5` is RustCrypto's digest crate). The new `h3` dependency is what makes
  `h2`/`http` look like near-misses.
- `R12` **false positive**: `ws.rs:371` is the RFC 4648 base64 alphabet
  (`A–Z a–z 0–9 +/`), a protocol table; the per-connection keys are random,
  no secret is hardcoded.
- `R03` **by design**: the `default_*` functions in `schema.rs` are serde
  defaults — a constant *is* the documented default (`maxconn = 1024`,
  `gzip_level = 6`, ...). `main.rs`'s `not_implemented` returns exit 2 and a
  message for features not shipped: explicit failure, never fake success.
- `R04` **false positive**: the strings in `rules.rs` are error messages
  ("unknown placeholder in value: ..."), not placeholder data.
- `R09` **documented invariants**: `proxy.rs:326` panics on a poisoned
  rate-limiter lock, `proxy.rs:1470` on a phase-1-established entry and
  `main.rs:766` on a backend a listener already references; none of them
  parses external input.
- `R16` **false positive**: `proxy.rs:2204` is `tokio::sync::Mutex::lock()`
  (`connect_gate` returns `Arc<tokio::sync::Mutex<()>>`), deliberately held
  across the await so concurrent exchanges share one handshake; no synchronous
  guard crosses an await.

## 8. Limits and NOT EXECUTED

- **NOT EXECUTED — container gate (Docker on amd64/arm64 + Scout 0
  critical/high).** This slice is not a release/publication increment; the
  container gate stays with the v0.7 release increment, which will carry the
  QUIC endpoint. The new crates (`quinn`, `h3`, `h3-quinn`) are pure Rust and
  use the already-shipped `aws-lc-rs` provider, but that is a build fact, not
  a container verification.
- **Interop gate: two independent clients pass.** aioquic 1.2.0 and
  quic-go 0.64.1 drive the same binary through GET, 256 KiB streaming POST,
  trailers, gzip, a direct rule and clean shutdown. **NOT EXECUTED** — a
  wider interop campaign: browsers (Chrome/Firefox/Safari), `curl` with
  HTTP/3, ngtcp2/quiche. No claim is made for those.
- **NOT EXECUTED — 0-RTT, connection migration, qlog export, HTTP/3 to
  backends, WebSocket/Extended CONNECT over h3, gRPC over h3, interim 1xx.**
  All are out of the slice by design (ADR-0013).
- **NOT EXECUTED — UDP-port collision at startup** (unit path exists; a real
  two-process clash was not staged).
- **Benchmark executed, and it is a loss**: S-H3-01/S-H3-02 against
  HAProxy 3.4.6 with h3 active on both, 5 repetitions, raw data in
  [v07-h3-bench.md](v07-h3-bench.md) and
  [`v07-h3-bench/run-20261023T134656Z/`](v07-h3-bench/run-20261023T134656Z/).
  EQProxy is **Worse** on both (0.341× throughput, 3.38× p50 latency and
  1.77× CPU in S-H3-01; 0.739× handshakes/s in S-H3-02), with lower memory.
  No claim of h3 performance parity is made; the loss is recorded, not
  hidden, and S-H2-01/02 remain pending.
