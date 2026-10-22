# v0.7 slice 2 — HTTP/2 to the backend

Language: **English**. Evidence for the second v0.7 increment, collected on
2026-10-22 (macOS 26 arm64 host, `rustc 1.97.1`, curl 8.7.1 with nghttp2
1.68.1, hyper-h2 4.2.0 on Python 3.9.6). Unreleased: it lands on top of
v0.6.3, after [slice 1](v07-http2.md).

## 1. Objective

Speak HTTP/2 to the origin instead of only terminating it in front, so an h2
client can reach an h2 backend with HTTP/2 on both sides (`B-H1`, `B-N1`,
`B-I1`, `B-E2` — the `http2_protocol_options` part), and remove the v0.6.3
gate that forbade `alpn = ["h2"]` on a backend used by an `http` listener.
gRPC (`B-I12`), WebSockets over h2 (`B-I18`), HTTP/3 (`B-H2`) and compression
(`B-H6`) are **not** covered.

## 2. Artifact under test

| Item | Value |
|---|---|
| Commit | `727467a` (`feat(net): speak HTTP/2 to a backend that negotiates h2`); this document travels in the follow-up `docs:` commit |
| Binary | `target/release/eqproxy` rebuilt from the committed tree, sha256 `50369b856af41dd09af7d3af5cd80296fed0d1f8891d0d87e5b97aca416dfa09` (`cargo build --release -p eqproxy-cli`, 1 m 01 s) |
| Toolchain | `rustc 1.97.1`, cargo 1.97.1 |
| New dependencies | none: `h2 0.4.20`, `http 1.5.0`, `bytes` were already in the graph from slice 1 |
| Design | [ADR-0007](../adr/0007-http2-backend.md) (extends [ADR-0006](../adr/0006-http2-termination.md)) |

## 3. Changes

| File | Change |
|---|---|
| `eqproxy-net/src/backend_h2.rs` (new, ~450 lines with tests) | `bridge` (h2 client handshake inside the connect phase, then a bounded 64 KiB duplex), `pump` (one h1 message per h2 stream, forever), `exchange`, `build_request` (`:method`/`:path`/`:authority`/`:scheme`, hop-by-hop and `host`/`expect`/`te` stripped, `content-length` only when declared), `forward_request_body` (h1 body → DATA, h1 trailers → trailing HEADERS, flow control honored), `write_response_head` + `relay_response_body` (backend `content-length` preserved, otherwise `chunked`; h2 trailers → h1 trailers) |
| `eqproxy-net/src/proxy.rs` | `connect_backend_to` checks the negotiated ALPN after the TLS handshake and hands an `h2` session to the bridge; `DialTimeouts` keeps name/timeouts together (the signature was over the clippy limit with 8 arguments) |
| `eqproxy-net/src/mirror.rs` | the mirror dials through the same path, so a mirrored copy to an h2 backend goes out as HTTP/2 too |
| `eqproxy-net/src/http2.rs` | `StreamError`, `capacity`, `DATA_CHUNK`, `copy_error`, `is_hop_by_hop` become `pub(crate)`: the backend bridge reuses the same framing helpers instead of copying them |
| `eqproxy-net/src/http1.rs` | `phrase` becomes `pub(crate)` (the h1 status line the bridge synthesizes needs a reason phrase) |
| `eqproxy-config/src/validate.rs` | the backend `h2`/`h2c` rejection (`unserved_alpn`, `http_mode_user`) is removed; the rejection test becomes an acceptance test |
| `eqproxy-config/src/schema.rs`, `eqproxy.schema.json` | the backend ALPN field documents the opt-in; schema regenerated |
| `eqproxy-net/tests/e2e_backend_h2.rs` (new) | 7 E2E journeys with a real h2-over-TLS server |
| `eqproxy-cli/tests/cli_e2e.rs` | `validate_accepts_h2_alpn_on_a_backend` (real binary, exit 0, `config OK`) |
| `CHANGELOG.md`, `README.md`, `SPEC.md` (item 11), `docs/docker-hub-readme.md`, roadmap 0.7 | state, semantics and limits |

## 4. End-to-end journey against the built binary (independent h2 origin)

Artifact: `target/release/eqproxy`, sha256
`50369b856af41dd09af7d3af5cd80296fed0d1f8891d0d87e5b97aca416dfa09`.

- Config (`/tmp/h2be/eqproxy.toml`): plaintext `mode = "http"` listener on
  `127.0.0.1:28081`, one backend `127.0.0.1:28443` with
  `verify = true`, `ca_file` = the repository test CA, `server_name =
  "localhost"` and `alpn = ["h2"]`.
- Gate: `./target/release/eqproxy config validate --config /tmp/h2be/eqproxy.toml`
  → `config OK: 1 listener(s), 1 backend(s)`, exit 0.
- Origin: `python3 /tmp/h2be/origin.py …` — an **independent** implementation
  (hyper-h2 4.2.0 on a real TLS socket, ALPN `h2`), not a mock and not the
  Rust `h2` crate; it records every stream it receives as JSON.
- Client: real `curl --http1.1` (so the *client* side is HTTP/1.1 and the
  *backend* side is HTTP/2 — the translation is what is under test).

```
--- request 1 (POST /echo, X-Test: live, body hello-from-curl)
HTTP/1.1 200 ok
x-origin: python-h2
content-length: 25

python-h2:hello-from-curl

--- origin recorded for it
{"connection": 1, "stream": 1, "method": "POST", "path": "/echo",
 "scheme": "https", "authority": "127.0.0.1:28081",
 "headers": [[":method","POST"], [":scheme","https"],
             [":authority","127.0.0.1:28081"], [":path","/echo"],
             ["user-agent","curl/8.7.1"], ["accept","*/*"],
             ["x-test","live"],
             ["content-type","application/x-www-form-urlencoded"],
             ["content-length","15"]],
 "body": "hello-from-curl", "trailers": null}

--- reuse: two URLs in one curl invocation, then a chunked upload, then /trailers
HTTP/1.1 200 ok (x-origin: python-h2)   # GET /echo
HTTP/1.1 200 ok (x-origin: python-h2)   # GET /echo, same client connection
HTTP/1.1 200 ok                        # POST /echo, Transfer-Encoding: chunked
                                       # → origin headers have NO content-length
                                       #   and body "chunked-by-curl"
HTTP/1.1 200 ok
x-origin: python-h2
transfer-encoding: chunked

7
trailed
0
x-checksum: abc123
```

All five exchanges were recorded on origin **`connection: 1`** with stream ids
1, 3, 5, 7, 9: one h2 session served every request, including the ones from
different curl invocations.

Final metrics from the proxy's clean SIGINT shutdown (`proxy.log`):

```
METRICS client[accepted=4 active=0 completed=4 ...] network[bytes_c2b=30 bytes_b2c=77]
backend[connect_failures=0 tls_failures=0 discarded=0 reused=4 opened=1 proxied=5] ...
INFO shutdown signal received; draining connections
METRICS ... (final)
shutdown complete
```

`opened=1 reused=4 proxied=5` is the pool contract on top of h2: one TLS+h2
session, four reuses, five exchanges, no connect or TLS failure.

What this proves: the backend received real HTTP/2 (`:method/:scheme/
:authority/:path` pseudo-headers, no `host`, no `connection`, no
`transfer-encoding`), the body and application headers survived, a chunked h1
request became DATA with no `content-length`, a chunked h2 answer became an h1
`transfer-encoding: chunked` body whose trailing header arrived as an h1
trailer, and the same session was reused across client connections.

What it does not prove: throughput, latency, multiplexing to the backend (the
pool is exclusive), gRPC, or behaviour under a backend that speaks h2 badly —
see §8.

## 5. Dataplane E2E (real sockets, real h2 server)

`cargo test -p eqproxy-net --test e2e_backend_h2` → **7 passed** (10.15 s).
The backend is the `h2` crate's server over TLS with ALPN `h2`; the client is
either the `h2` crate or raw HTTP/1.1 bytes, never a mock:

| Test | What it demonstrates |
|---|---|
| `h1_client_reaches_an_h2_backend_through_a_real_h2_session` | h1 POST reaches the origin as `HTTP_2` with `:authority` from `Host`, the body and `X-Custom` intact, `host`/`connection` absent, `x-origin` back to the client, `connect_failures = 0`. |
| `h2_client_reaches_an_h2_backend_end_to_end` | h2 on the listener (`alpn = ["h2"]`) and h2 on the backend in the same exchange: HTTP/2 from end to end, body both ways. |
| `one_pooled_h2_session_serves_consecutive_requests` | Two exchanges on one client connection produce **one** accepted backend TCP connection and two streams: the pool reuses the h2 session, and the second answer (418 + body) is intact. |
| `trailers_and_chunked_bodies_cross_in_both_directions` | h2 client → h2 backend: request trailers arrive as trailing HEADERS, response trailers arrive as h2 trailers. Then an h1 chunked request with a trailer crosses too, and the h2 answer's trailer reaches the h1 client as an h1 trailer. |
| `head_keeps_its_declared_length_and_the_session_stays_usable` | `HEAD` keeps `content-length: 5` with no body and the same h2 session still serves the next `GET` (no session lost, no bogus truncation). |
| `connect_through_an_h2_backend_is_refused_not_half_forwarded` | `CONNECT` answers `502` and the origin sees **no stream**: no half-open tunnel. |
| `a_backend_that_cannot_negotiate_h2_is_an_explicit_502` | The opt-in says `h2`, the server only offers `http/1.1`: the handshake fails, `tls_handshake_failures ≥ 1`, the client gets `502`, the origin sees nothing. |

Unit tests in the module: `cargo test -p eqproxy-net --lib backend_h2` →
**4 passed** (h1-only headers never cross; a chunked body carries no length
and a body-less request ends the stream; `CONNECT` and host-less requests are
refused; an absolute-form target keeps its own authority).

CLI E2E: `cargo test -p eqproxy-cli --test cli_e2e validate_accepts_h2_alpn`
→ **2 passed** (listener acceptance from slice 1 + the new backend acceptance
through the real binary).

## 6. Suite, format and lints

| Check | Command | Result |
|---|---|---|
| Format | `cargo fmt --all --check` | exit 0 |
| Lints | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| Tests | `cargo test --workspace` | **361 passed, 0 failed**, 25 result lines, exit 0, run again on the committed tree (`/tmp/h2be/final-test.log`) |
| Coverage/nextest/E2E | `veyra audit . --profile standard` | see §7 |

Suite arithmetic: 349 (slice 1) + 7 E2E + 4 unit + 1 CLI = **361**. One earlier
`cargo test --workspace` run reported `cli_e2e` 54 passed / 1 failed; its
output was not captured, and the suite then passed five consecutive times
(one full workspace run for the count, three standalone `cli_e2e` runs, and
the final `/tmp/worktest.log` run). It is reported as an unexplained flake,
not as a pass.

## 7. Audits

- **Veyra Proof**: `veyra audit . --profile standard` → **ACCEPTED**,
  exit **0** (`.veyra/evidence/20261022T132336Z/manifest.json`,
  `decision.exit_code = 0`), 658 s of tools. OK: `rustfmt`, `cargo check`,
  `clippy`, `cargo test`, `cargo-audit`, `veyra-anti-theater`,
  `cargo-nextest`, `cargo-llvm-cov`, `cargo-deny`, `cargo-machete`,
  `veyra-e2e`. **No problems.** Not executed, reported as such: `dylint` (no
  configuration/libraries) and `cargo-semver-checks` (no registry baseline
  for unpublished crates). `cargo-geiger` **INCONCLUSIVE** (coverage warnings
  in 4 runs): unsafe counts are a lower bound, not a pass.
- **Rust Audit**: `python3.13 scripts/rust_audit.py scan /Volumes/Lexar/Cursor/EQProxy
  --format terminal,json,md --fail-on high` → exit **1**, **200 findings**
  (2 critical, 20 high, 145 medium, 33 low); reports
  `report/rust-audit-20261022-152411.{md,json}` and
  `report/not-executed-2026-10-22.md`. The findings that point at this
  increment are five, all reviewed:
  - `R18c high` ×2 on `backend_h2.rs` (`h2` "does not exist… near-miss of
    `cc`", `http` "… near-miss of `tap`"): false positives — both crates are
    real, already in the graph since slice 1 and used by `http2.rs`.
  - `R02 low` ×3 on `e2e_backend_h2.rs` (magic numbers in assertions): the
    literals are HTTP status codes and stream counts (`200`, `418`, `1`),
    which are the contract under test, not tuning constants.
  - The critical findings are pre-existing heuristics (`thiserror = "2"`
    "impossible"; the three workspace crates "not on crates.io" — they are
    path dependencies), unchanged from the slice-1 audit.
- **EvoForge**: `mcp_submit_eval` after the host suite passed, on a std-only
  condensed replica of `build_request` (scheme/authority, hop-by-hop and
  `content-length` handling, `CONNECT`/host-less refusal, absolute-form) with
  four tests → `fitness_score 1.0`, `tests_pass true`, `clippy_pass true`,
  exit 0, trace `e4a9d015-5b37-46c4-bea7-b4c16749fed6`. The first submission
  compiled and passed its tests but failed clippy (`single_char_add_str`,
  `single_char_pattern`) and scored 0; the fixed slice is the F=1 above. The
  slice is a replica for the sandbox and is **not** a substitute for §4–§5.

## 8. Pending and limitations (not claimed)

- **No benchmark.** Throughput/latency of the h1⇄h2 bridge (one h1 parse + one
  h2 encode per exchange, per direction) is **NOT EXECUTED**: there is no
  measured figure, and none is claimed. ADR-0007 states the cost exists.
- **No h2-to-backend multiplexing.** The pool lends a connection to one
  exchange at a time, so streams on the backend session are serial. Envoy
  multiplexes; EQProxy does not, yet.
- **No h2c to the backend.** Plaintext backends keep speaking HTTP/1.1; there
  is no `h2c`-to-origin option (there is no TLS ALPN to negotiate it).
- **No gRPC (`B-I12`)**: gRPC also needs client-side extended CONNECT/streaming
  semantics and a request body that is not h1-framed end to end.
- **WebSockets over h2 / extended CONNECT (`B-I18`)** and `CONNECT` to an h2
  backend (refused with `502`) are not covered.
- **HTTP/3/QUIC (`B-H2`)** untouched; **compression (`B-H6`)** untouched.
- **h2 interim (`1xx`) responses from a backend are consumed** by the client
  library; `100-continue` is answered by the proxy. Not forwarded.
- **`content-length` + trailers from a backend**: the trailers are dropped
  (h1 cannot express that combination without re-framing). Chunked h2 answers
  do carry them.
- **No Docker image rebuild or container journey** for this slice: **NOT
  EXECUTED**. The image is rebuilt and exercised by the release workflow
  before any tag; this increment is unreleased.
- **No soak, no interop matrix** beyond the `h2` crate server, one Python
  `hyper-h2` origin and `curl`.

## 9. Reproduction

```bash
# unit + dataplane E2E + CLI gate
cargo test -p eqproxy-net --lib backend_h2
cargo test -p eqproxy-net --test e2e_backend_h2
cargo test -p eqproxy-cli --test cli_e2e validate_accepts_h2_alpn

# the manual journey of §4
cargo build --release -p eqproxy-cli
./target/release/eqproxy config validate --config /tmp/h2be/eqproxy.toml
python3 /tmp/h2be/origin.py eqproxy-net/tests/fixtures/cert.pem \
  eqproxy-net/tests/fixtures/key.pem 28443 /tmp/h2be/seen.jsonl &
./target/release/eqproxy run --config /tmp/h2be/eqproxy.toml &
curl --http1.1 -d hello-from-curl http://127.0.0.1:28081/echo
# (SIGINT to the proxy; see proxy.log for the final METRICS line)
```
