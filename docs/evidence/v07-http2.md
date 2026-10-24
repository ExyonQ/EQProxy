# v0.7 slice 1 — HTTP/2 termination (`h2` in, HTTP/1.1 out)

> **Superseded in part** by [slice 2](v07-http2-backend.md) (2026-10-22):
> the backend side now speaks HTTP/2 when its TLS ALPN negotiates `h2`, and
> the configuration gate accepts `alpn = ["h2"]` on a backend. The text below
> records what slice 1 actually delivered; its "upstream stays HTTP/1.1"
> limitation no longer applies.
>
> **Benchmark follow-up (2026-10-23):** the S-H2-01/02 campaign against
> HAProxy 3.4.6 with h2 active in both is published in
> [`v07-h2-bench.md`](v07-h2-bench.md). It measures the translation described
> here and finds **Worse** (S-H2-01 0.099×, S-H2-02 0.975×): the backend idle
> pool (64 per server) churns connections once more than 64 h2 streams are in
> flight, exhausts the ephemeral port range and returns 502s. The §9 note
> below ("no benchmark was run for this slice") is true of this slice only.
>
> **Fixed (2026-10-23):** the pool now sizes its idle cap from the peak
> exchanges in flight ([ADR-0015](../adr/0015-backend-idle-pool-sizing.md)),
> and the S-H2-01/02 campaign was re-measured: 0.742× (was 0.099×), 0.55
> backend connections per 1 000 requests (was 192.85) and zero `502`s. See
> [`v07-h2-pool-sizing.md`](v07-h2-pool-sizing.md).

Language: **English**. Evidence for the first v0.7 increment, collected on
2026-10-21/22 (macOS 26 arm64 host, Rust 1.97.1, curl 8.7.1 with nghttp2
1.68.1). Unreleased: it lands on top of v0.6.3.

## 1. Objective

Serve real HTTP/2 to clients and keep the existing HTTP/1.1 dataplane as the
single place where routing, actions and errors are decided. Roadmap rows:
`B-H1`, `B-N1`, `B-I1`, `B-E2` (the "downgrade to h1 / h2⇄h1 translation"
part); `B-I12` (gRPC), `B-H2` (HTTP/3), `B-I18` (WebSockets over h2) and
`B-H6` (compression) are **not** covered by this slice.

## 2. Artifact under test

| Item | Value |
|---|---|
| Commit | `47f5176` (`feat(net): terminate HTTP/2 and translate it to HTTP/1.1 upstream`) |
| Binary | `target/debug/eqproxy` built from that commit, sha256 `96c89250435625ebb32a576cc00ae1f7256117bf9df3069bd0edfb8c21564c9f` (build: `CARGO_TARGET_DIR=/tmp/eqproxy-v07-build cargo build -p eqproxy-cli`) |
| Toolchain | `rustc 1.97.1 (8bab26f4f 2026-07-14)`, cargo 1.97.1 |
| New dependencies | `h2 0.4.20`, `http 1.5.0`, `bytes 1.0` (plus their transitive `tokio-util`, `tracing`, `slab`, `fnv`, `atomic-waker`, `futures-core/sink`) |
| Design | [ADR-0006](../adr/0006-http2-termination.md) |

## 3. Changes

| File | Change |
|---|---|
| `eqproxy-net/src/http2.rs` (new, ~800 lines with tests) | `serve_h2` (h2 handshake + accept loop, 128 concurrent streams), `exchange` (one stream = one h1 exchange on a 64 KiB duplex), `build_request_head` (pseudo-headers → h1 head, framing decision, hop-by-hop stripping), `forward_request_body` (DATA → h1 body with flow-control release), `relay_response` / `relay_chunked` (h1 head/body → HEADERS/DATA/trailers, capacity reserved before every frame), `is_h2c` (preface detection with `peek`) |
| `eqproxy-net/src/proxy.rs` | `handle_connection` keeps the whole stream (`IoStream`) and picks h2 by ALPN `h2` (TLS) or h2c preface (plaintext); `accept_loop` hands an `Arc<ResolvedListener>`; TCP mode never sniffs |
| `eqproxy-net/src/http1.rs` | `read_head`, `read_crlf_line`, `parse_chunk_size`, `parse_header_line`, `Prefixed`, `CopyError`, `FORBIDDEN_TRAILERS` become `pub(crate)` so the translation reuses the same strict parsers instead of duplicating them |
| `eqproxy-net/src/lib.rs`, `Cargo.toml` | module + `h2`/`http`/`bytes` dependencies |
| `eqproxy-config/src/validate.rs` | the client-listener `h2`/`h2c` rejection is removed (it is served now); the backend-side rejection stays |
| `eqproxy-config/src/schema.rs`, `eqproxy.schema.json` | ALPN field docs say what each side supports; schema regenerated |
| `eqproxy-net/tests/e2e_http2.rs` (new) | 6 E2E journeys over real sockets with a real h2 client |
| `eqproxy-cli/tests/cli_e2e.rs` | the rejection test becomes an acceptance test; a new E2E drives the real binary with real `curl` (h2c, TLS h2, TLS http/1.1) |
| `CHANGELOG.md`, `README.md`, `SPEC.md`, `docs/docker-hub-readme.md`, roadmap 0.7 | state, semantics and the documented limits |

## 4. End-to-end journeys against the real binary

Config (`/tmp/h2evid/eqproxy.toml`): one plaintext `mode = "http"` listener,
one TLS listener with `alpn = ["h2", "http/1.1"]`, both to the same backend.
Origin: `python3 -m http.server` (an independent HTTP/1.1 implementation, not
a stub). Script: `/tmp/h2evid/journey.sh`; output
`/tmp/h2evid/journey2.log`. Both listeners announced their addresses, and the
proxy shut down cleanly on SIGINT.

```
=== h2c (curl --http2-prior-knowledge)
HTTP/2 200
server: SimpleHTTP/0.6 Python/3.9.6
content-type: text/html
content-length: 19

h2 through eqproxy
=== TLS (curl --http2)
HTTP/2 200
server: SimpleHTTP/0.6 Python/3.9.6
content-type: text/html
content-length: 19

h2 through eqproxy
=== TLS (curl --http1.1)
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.9.6
Content-Length: 19

h2 through eqproxy
=== origin saw
127.0.0.1 - - [22/Oct/2026 01:10:52] "GET / HTTP/1.1" 200 -
127.0.0.1 - - [22/Oct/2026 01:10:52] "GET / HTTP/1.1" 200 -
127.0.0.1 - - [22/Oct/2026 01:10:53] "GET / HTTP/1.1" 200 -
=== metrics (final)
client[accepted=3 active=0 completed=3 rejected_maxconn=0 protocol_errors=0]
proxy[no_server=0 ...] backend[connect_failures=0 ... opened=3 proxied=3]
shutdown complete
```

What this proves and what it does not:

- `HTTP/2 200` is curl reporting the **negotiated version of the answer**, so
  the proxy really produced HTTP/2 frames (HEADERS with `:status 200`, DATA
  with the body), not an HTTP/1.1 reply that curl accepted. The same run over
  `--http1.1` produced an HTTP/1.x answer, and the origin only ever saw
  HTTP/1.1 requests.
- The HTTP/1.0 status line in the third block is the origin's own version
  line forwarded verbatim (Python's `http.server` answers HTTP/1.0); it is
  pre-existing h1 behaviour and not part of this increment.
- `metrics` counts the three connections and the three proxied exchanges.
  There is no per-protocol counter yet (see §9).

## 5. Dataplane E2E (real sockets, real h2 client)

`cargo test -p eqproxy-net --test e2e_http2` → **6 passed**. The client is the
`h2` crate itself over loopback TCP/TLS, not a mock:

| Test | What it demonstrates |
|---|---|
| `h2c_multiplexes_streams_that_must_advance_together` | Three streams on **one** connection complete only if the origin holds three simultaneous exchanges behind a barrier: a proxy that serialized streams deadlocks and the test times out. Proves real multiplexing. |
| `h2_request_without_content_length_goes_upstream_as_chunked` | A POST with no `content-length` reaches the origin as `transfer-encoding: chunked` with the payload intact; the origin records the exact bytes it received. |
| `h2_decodes_chunked_responses_and_keeps_trailers` | `Transfer-Encoding: chunked` + `x-checksum` trailer upstream becomes DATA `hello world` with no chunk framing visible and an h2 trailer HEADERS; `transfer-encoding` never crosses. |
| `h2_truncated_backend_body_resets_the_stream` | Origin declares 10 bytes, sends 3, closes: the client sees an error/reset, never a clean 3-byte body. |
| `h2_dead_backend_answers_502_and_a_redirect_answers_locally` | Dead backend → `502` on the stream; a rule `308` is rendered locally with the real `Location` and no backend contact. |
| `tls_alpn_h2_terminates_a_real_http2_connection` | TLS handshake negotiates `h2` and the h2 session serves the request; asserts `alpn_protocol() == b"h2"`. |

CLI E2E: `cargo test -p eqproxy-cli --test cli_e2e -- http2` →
**1 passed** (`run_serves_http2_to_real_clients_over_tls_and_cleartext`: real
binary + real curl, h2c and TLS h2, and `HTTP/1.1 200` on the same TLS
listener); the replaced gate test
`validate_accepts_h2_alpn_on_an_http_listener` → **1 passed** (two ALPN
shapes, real fixtures, exit 0, `config OK`).

## 6. Unit tests

`cargo test -p eqproxy-net --lib http2` → **7 passed**: origin-form request
line and `:authority` → `host`; declared `content-length` kept exactly once;
body without a length becomes chunked; hop-by-hop headers never cross;
`OPTIONS *` refused, empty path becomes `/`; response headers lowercased with
hop-by-hop dropped; application framing headers kept; preface bytes.

## 7. Suite, format and lints

| Check | Command | Result |
|---|---|---|
| Format | `cargo fmt --all --check` | exit 0 |
| Lints | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| Tests | `cargo test --workspace` | **349 passed, 0 failed**, 24 result lines, exit 0 (same count in the Veyra run: `.veyra/evidence/20261021T230738Z/tools/cargo-test/stdout.log`) |
| Coverage/nextest/E2E | `veyra audit . --profile standard` | see §8 |

## 8. Audits

- **Veyra Proof**: `veyra audit . --profile standard` → **ACCEPTED**,
  exit **0**, evidence `.veyra/evidence/20261021T230738Z/` (profile
  `standard`, 706 s of tools). `rustfmt`, `cargo check`, `clippy`,
  `cargo test`, `cargo-audit`, `anti-theater`, `nextest`, `llvm-cov`,
  `cargo-deny`, `cargo-machete` and `veyra-e2e` all OK; **no problems**.
  Not executed, reported as such: `dylint` (no configuration/libraries) and
  `cargo-semver-checks` (no registry baseline for unpublished crates).
  `cargo-geiger` **INCONCLUSIVE**: its scan reported coverage warnings in 4
  runs, so unsafe counts are a lower bound, not a pass.
  A first run (`.veyra/evidence/20261021T225524Z`) was **REJECTED** by
  `rustfmt:rustfmt-diff` because it overlapped the last edits; the tree was
  formatted and the audit rerun on the committed tree, which is the ACCEPTED
  run above. The rejected run is kept, not deleted.
- **Rust Audit**: `python3.13 scripts/rust_audit.py scan /Volumes/Lexar/Cursor/EQProxy --format terminal,json,md --fail-on high` → exit **1**,
  **196 findings** (2 critical, 19 high, 145 medium, 30 low), reports
  `report/rust-audit-20261022-005733.{md,json}` and
  `report/not-executed-2026-10-22.md`. The increment adds **three** findings,
  all reviewed:
  - `R18c high` on `http2.rs` "Crate `http` does not exist… near-miss of
    `tap`": false positive (`http` 1.5.0 is the ecosystem crate; the audit's
    online table also lists it as `ok`).
  - `R10 medium` ×2 (`let _ = pipe_write.shutdown()`, `let _ =
    respond.send_response(...)`): deliberate, each with the reason in a
    comment — the shutdown is only the EOF signal, and a refusal cannot be
    delivered to a stream the client already reset. No error is hidden that
    the code could act on.
  - The critical findings are pre-existing/dependency heuristics
    (`thiserror = "2"` "impossible" — 2.x exists; the three `eqproxy-*`
    workspace crates "not on crates.io" — they are path dependencies).
  - `R19` in the `--online` run flagged `webpki-roots@1.0.9`
    (RUSTSEC-2026-0381, distrusted emSign root). Checked against the lock:
    the tree resolves **1.0.10**, which is the fixed release
    (`git show HEAD:Cargo.lock`), so the advisory does not apply; the online
    finding carried a stale version.
- **EvoForge**: `mcp_submit_eval` after the host suite passed, on a std-only
  slice of `build_request_head`/`response_headers` (four tests) →
  `fitness_score 1.0`, `tests_pass true`, `clippy_pass true`, exit 0,
  trace `a6a7e6e5-2dee-4327-83e1-a7bc521688ed`. The slice is a condensed
  replica for the sandbox; it is **not** a substitute for §4–§5.

## 9. Pending and limitations (not claimed)

- **Upstream HTTP/2** is not implemented: the backend side speaks HTTP/1.1,
  and the configuration gate still rejects `alpn = ["h2"]` on a backend used
  by an `http` listener. h2 end-to-end (`http2_protocol_options` parity) is
  the next slice.
- **gRPC (B-I12)** needs end-to-end h2; not covered.
- **WebSockets over h2 / extended CONNECT (B-I18)** and `CONNECT` over h2
  (refused with `501`) are not covered.
- **HTTP/3/QUIC (B-H2)** untouched.
- **Compression (B-H6)** untouched; no compression claim is made.
- **No benchmark** of h2 throughput/latency was run for this slice
  (**NOT EXECUTED**): the per-stream pipe and task cost is documented in
  ADR-0006 as the price of reusing the engine, not as a measured figure.
- **No GOAWAY on graceful shutdown**: established h2 connections drain within
  `shutdown_grace` like keep-alive h1 ones; they are not asked to migrate.
- **No per-protocol metrics**: h2 traffic is visible in the connection and
  exchange counters, but there is no `http2_streams` counter yet.
- **No h2-specific load/soak run** and no interop matrix beyond curl and the
  `h2` client crate.
- A TLS listener configured with `alpn = ["http/1.1"]` rejects an h2-only
  client at the handshake (no common protocol), exactly as before; the h2c
  preface over TLS is not special-cased and the h1 parser rejects it with
  `400`.

## 10. Reproduction

```bash
# unit + dataplane E2E + real-binary E2E
cargo test -p eqproxy-net --lib http2
cargo test -p eqproxy-net --test e2e_http2
cargo test -p eqproxy-cli --test cli_e2e -- http2

# the manual journey of §4 (config + origin + curl), from this repository:
#   see /tmp/h2evid/journey.sh in the run that produced the log
bash /tmp/h2evid/journey.sh </dev/null >/tmp/h2evid/journey.log 2>&1

# audits
veyra audit . --profile standard
python3.13 /Volumes/Lexar/Cursor/rust-ai-audit/scripts/rust_audit.py scan . \
  --format terminal,json,md --fail-on high
```
