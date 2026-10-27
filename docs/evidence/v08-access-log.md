# v0.8 — Structured access log (ADR-0020, B-N14/B-I14/B-E8)

Language: **English**. Raw data: [`v08-access-log/raw/`](v08-access-log/raw/).

## What was proved

A running `eqproxy` writes exactly one access-log line per HTTP request that
reaches its engine, in both configured shapes, without ever blocking the
request path:

1. `format = "json"` under 40 concurrent clients against a real origin: one
   line per request, correct listener/client/protocol/method/status/backend,
   the query string never present, `access_log_dropped` still 0, clean SIGINT.
2. `format = "combined"` with the real binary: one nginx-shaped line, UTC
   date, status and byte count in the documented positions.
3. A configured `path` that cannot be opened **fails startup** (exit 1) with
   `access log cannot be opened`; the proxy never serves without the sink an
   operator asked for.
4. In-process E2E: HTTP/1.1 parsed and unparsed heads (408) are both logged
   with the documented fields, and HTTP/2 requests carry `protocol: http/2`.
5. Unit: JSON field set, combined escaping (a hostile User-Agent cannot inject
   a second line), UTC calendar conversion against known instants, drop
   accounting when the writer stops, and flush of the queued lines on
   shutdown.
6. Manual E2E with the built binary, one real origin and 20 concurrent curl
   clients: 21 lines (1 readiness probe + 20 requests), all `status: 200`,
   `access_log_dropped_total 0`, no `secret` query token in the file, exit 0.

Not proved in this slice: HTTP/3 access-log E2E (the h3 path feeds the same
`http1::serve_http` engine and compiles, but no h3 test asserts a line), and
rotation/sampling/syslog (not implemented, ADR-0020 "Pending").

## Artifact and environment

- Binary: `target/debug/eqproxy` (Cargo debug profile), sha256
  `c4685f36cbe96cd5c47db320abf4fd75a4570c7ab27895144f00b7cea33dc3d7`.
- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, macOS 15 (Darwin),
  Apple silicon (aarch64).
- Real dependencies: the binary itself, a Python `ThreadingHTTPServer` origin
  (manual run), `curl` clients, and the loopback kernel stack. No mock of the
  proxy, the origin or the transport.
- Build: `cargo build -p eqproxy-cli` (debug, exit 0).

## Commands and results

### Format, lint, suite

```console
$ cargo fmt --all --check
(no output, exit 0)
$ cargo clippy --workspace --all-targets -- -D warnings
Finished `dev` profile [unoptimized + debuginfo] target(s) in 2.43s
(exit 0)
$ cargo test --workspace
...
summed over the 29 test binaries: 472 passed, 0 failed, 2 ignored
(exit status 0; full log /tmp/v08-suite.log, not committed)
```

The two ignored tests are the pre-existing miri-only cases
(`#[cfg_attr(miri, ignore)]`); they run under a normal `cargo test` and are not
part of this slice.

### Targeted access-log tests

```console
$ cargo test -p eqproxy-net --lib access::
running 6 tests
access::tests::utc_calendar_matches_known_instants ... ok
access::tests::absent_values_are_dashes_in_combined ... ok
access::tests::combined_is_one_line_and_escapes_injection ... ok
access::tests::json_is_one_line_with_the_documented_fields ... ok
access::tests::a_stopped_writer_counts_dropped_lines ... ok
access::tests::the_writer_flushes_the_queued_lines_on_shutdown ... ok
test result: ok. 6 passed; 0 failed

$ cargo test -p eqproxy-net --test e2e_http1 access
test access_log_records_parsed_and_unparsed_requests ... ok
test result: ok. 1 passed; 0 failed

$ cargo test -p eqproxy-net --test e2e_http2 access
test access_log_marks_h2_requests_and_their_status ... ok
test result: ok. 1 passed; 0 failed

$ cargo test -p eqproxy-cli --test cli_e2e run_writes_one_json_access_line_per_request_under_traffic -- --exact
test run_writes_one_json_access_line_per_request_under_traffic ... ok
test result: ok. 1 passed; 0 failed

$ cargo test -p eqproxy-cli --test cli_e2e run_writes_combined_lines_when_configured -- --exact
test run_writes_combined_lines_when_configured ... ok
test result: ok. 1 passed; 0 failed

$ cargo test -p eqproxy-cli --test cli_e2e access_log
test run_refuses_to_start_when_the_access_log_cannot_be_opened ... ok
test result: ok. 1 passed; 0 failed
```

The CLI tests spawn the real binary (not a library harness), the real origin
and real clients. `run_writes_one_json_access_line_per_request_under_traffic`
issues 40 concurrent requests and asserts 40 lines, one JSON object each, with
`status: 200`, `backend: api`, `bytes: 0`, an RFC 3339 UTC `time`, and the
query string absent; then it sends SIGINT and requires exit 0.
`run_writes_combined_lines_when_configured` asserts the exact nginx positions
(`client - - [dd/Mon/yyyy:HH:MM:SS +0000] "GET /path HTTP/1.1" 200 0 "-" "ua"`).

### Manual E2E (raw output committed)

```console
$ ./target/debug/eqproxy run --config /tmp/eqproxy-access-demo.toml &
$ for i in $(seq 1 20); do curl -s -o /dev/null "http://127.0.0.1:18181/file-$i?token=secret$i" & done
$ curl -s -H "Authorization: Bearer ..." http://127.0.0.1:18182/metrics | grep access_log_dropped
eqproxy_access_log_dropped_total 0
$ kill -INT <proxy>; wait
PROXY_EXIT=0
$ wc -l docs/evidence/v08-access-log/raw/access.jsonl
21
$ grep -c '"status":200' docs/evidence/v08-access-log/raw/access.jsonl
21
$ grep -c secret docs/evidence/v08-access-log/raw/access.jsonl
0
```

First line of the committed log:

```json
{"time":"2026-10-25T03:31:17.518Z","listener":"web","client":"127.0.0.1:51632","protocol":"http/1.1","method":"GET","path":"/probe","host":"127.0.0.1:18181","status":200,"duration_ms":0,"backend":"api","server":"127.0.0.1:18180","user_agent":"curl/8.7.1","bytes":22}
```

The full transcript, config and 5,638-byte log are in
[`v08-access-log/raw/`](v08-access-log/raw/); the log's sha256 is
`2e27838c6544fd821459ddee14f200fb9d80b052a701cdd6bf7497f3a6f58cab`.

## Audits

- **Veyra Proof** — `veyra audit . --profile standard`; decision
  **ACCEPTED**, exit 0, evidence
  `.veyra/evidence/20261025T032220Z/`. OK: rustfmt, cargo check, clippy,
  cargo test, cargo-audit, anti-theater, nextest, llvm-cov, cargo-deny,
  machete, veyra-e2e. `dylint` and `cargo-semver-checks` SKIPPED (no Dylint
  config; no registry baseline for unpublished crates). `cargo-geiger`
  INCONCLUSIVE (coverage warnings in 4 runs; unsafe counts are a lower bound),
  reported as not-a-pass.
- **Rust Audit 0.2.7** — `python3.13 /Volumes/Lexar/Cursor/rust-ai-audit/scripts/rust_audit.py
  scan . --format md --out report --fail-on high`; exit **0**,
  `report/rust-audit-20261025-043135.md`: critical 0, high 0, medium 213,
  low 64. Findings added by this increment are all **low (R02, magic
  numbers in tests)**: `eqproxy-cli/tests/cli_e2e.rs:6605`,
  `eqproxy-net/src/access.rs:506`, `:551`, `:574`,
  `eqproxy-net/tests/e2e_http1.rs:1257`,
  `eqproxy-net/tests/e2e_http2.rs:704`. Reviewed: they are assertion literals
  (status 200, byte counts, line counts), not logic; no critical/high finding
  touches the new code.
- **CodeGraph Rust** — see the closing section; index built after the last
  source edit.
- **Hindsight** — note **“v0.8 access log: bounded sink, JSON/combined,
  fail-closed”** stored (exit 0, bank `eqproxy`, memory ids returned by the
  CLI), with the same commands and results cited here.

## Production conditions

Verified here: real binary, real sockets, real origin, both formats,
fail-closed startup, bounded sink drops counted, clean shutdown flush, no
query string in the output. Pending for release: release-profile build and
container run, 24 h soak with a slow sink, HTTP/3 line assertion, rotation and
syslog (out of scope for this slice).

## CodeGraph Rust (structure only)

`codegraph-rust index . --stats-json /tmp/cg-index-v08.json` finished with
`complete: true`, `graph_complete: true`, `vector_index_ready: true`,
`errors: 0`, index time 524,843 ms: 58 files, 52,278 lines, 5,790 nodes,
10,541 edges, 43 cached files skipped. The index was built after the last
source edit (this evidence page was written afterwards, so the graph covers
the code, not this document).

`agent impact "what breaks if eqproxy-net/src/access.rs changes"` and
`agent context "where is the structured access log emitted for HTTP/2
requests"` both exited 0. The facts used were checked against the source:

- `eqproxy-net/src/lib.rs:10` declares `pub mod access` and `:31-34`
  re-exports `AccessEntry, AccessHandle, AccessLog, AccessLogFormat,
  AccessLogSettings, AccessRecord, ClientProtocol`.
- `eqproxy-net/src/proxy.rs:868` `ResolvedListener::with_access` is the
  injection point; `eqproxy-cli/src/main.rs:1868` (`access_settings`) and
  `:2206` (`resolve_with`) are the CLI consumers.
- The record is created in `eqproxy-net/src/http1.rs:1695` inside
  `serve_http` (`:1607`), and `Drop for AccessRecord`
  (`eqproxy-net/src/access.rs:454-461`) stamps the duration and emits.
  HTTP/2, HTTP/3 and the WebSocket upgrade reach that engine through
  `http2.rs:267`, `http3.rs:335` and `ws.rs:118` with their `ClientProtocol`.

**CodeGraph claim not confirmed:** its `context` answer said the entry is
“created per stream in `eqproxy-net/src/http2.rs` inside the `exchange`
task”. The source contradicts it: `http2.rs` contains no `AccessRecord`; it
only passes `ClientProtocol::Http2` to `http1::serve_http`. The answer is a
pointer, not evidence.
