# Evidence — v0.7 response compression: gzip and Brotli

Language: **English**.

- Date: 2026-10-22
- Scope: `B-N6` (both halves: gzip and Brotli), `H6` / `C11` (compression
  benchmarks with raw data) of roadmap v0.7 (Phase 5, `Roadmap 0.7.md`,
  local-only)
- Design: [ADR-0010](../adr/0010-response-compression.md)
- Artifact under test: `target/release/eqproxy`,
  sha256 `adb6dfffa1587a3f02e5f70dd7ba8383970b19e9fc370444660c042c840c48f2`
- Toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- Host: macOS 26.5.1, `Darwin arm64`; loopback TCP, no TLS in the benchmarks

## 1. Objective

Compress HTTP responses with gzip **and** Brotli per listener, negotiated from
`Accept-Encoding`, streamed (nothing buffered whole), and measure both codings
with published raw data **before** claiming any performance. The same
implementation must serve both client protocols: HTTP/1.1 directly and HTTP/2
through the existing h2⇄h1 translation.

## 2. What was implemented

| Piece | Location |
|---|---|
| Config gate (`gzip`, `level`, `brotli`, `brotli_quality`, `min_size`, `types`), `tcp`-mode refusal, runtime-grammar media types | `eqproxy-config/src/schema.rs`, `eqproxy-config/src/validate.rs` |
| Negotiation (q-values, Brotli on ties, disabled codings never selected) and eligibility | `eqproxy-core/src/compression.rs` |
| Streaming gzip member writer (raw deflate + CRC32/ISIZE), streaming Brotli writer (pure-Rust `brotli` crate, flushed per relayed block), head rewrite for either token | `eqproxy-net/src/compression.rs` |
| h1 relay integration (head rewrite, chunked re-framing, trailers after the compressed stream) | `eqproxy-net/src/http1.rs` |
| Counters `compression[gzip=… brotli=… bytes_in=… bytes_out=…]` | `eqproxy-core/src/metrics.rs`, `eqproxy-net/src/proxy.rs` |
| `config validate` / `config explain` reporting | `eqproxy-cli/src/main.rs` |

The h2 path needs no second implementation: the h1 engine emits a chunked
compressed response and the existing h2 translator turns it into DATA frames
and drops the hop-by-hop framing.

## 3. Commands and results (artifact above, this host)

```
cargo fmt --all -- --check
  → clean, exit 0

cargo clippy --workspace --all-targets -- -D warnings
  → Finished dev profile, exit 0, no warnings

cargo test --workspace
  → passed=384 failed=0 (sum of all `test result:` lines; 7 new in this slice)

cargo test -p eqproxy-net compression
  → 8 passed, 0 failed (eligibility, both encoders, head rewrite, selection)

cargo test --test cli_e2e brotli
  → 2 passed, 0 failed (h1 negotiation/refusals, h2c through curl)
```

`cargo fmt` was run once over the tree before the final check; no test was
skipped, ignored or weakened to obtain these results.

## 4. E2E journeys against the real binary

Every journey spawns the built binary (`eqproxy run`) against an independent
origin process over real loopback sockets, then asserts on the bytes that cross
the wire.

### J1 — gzip over HTTP/1.1 (`run_compresses_gzip_and_respects_every_refusal_case`)

| # | Request | Expected (asserted) |
|---|---|---|
| 1 | `GET /big`, `Accept-Encoding: gzip, deflate` | `200`, `content-encoding: gzip`, `transfer-encoding: chunked`, `vary: accept-encoding`, **no** `content-length`; body starts `1f 8b`, decodes to the origin's exact bytes and is smaller |
| 2 | `gzip;q=0` | identity: no `content-encoding`, the origin's `content-length`, exact bytes |
| 3 | `GET /small` (declared length < `min_size`) | identity, bytes `tiny` |
| 4 | origin sent `Content-Encoding: br` | untouched (`content-encoding: br`), never re-encoded |
| 5 | `application/octet-stream` (PNG) | identity, PNG magic preserved |
| 6 | chunked origin body | gzip re-framing works and the origin trailer `x-checksum: 42` survives after the stream |
| 7 | `Accept-Encoding: *` on JSON | gzip applied, decoded body is JSON |
| 8 | origin sent `Cache-Control: no-transform` | identity, exact bytes |
| 9 | HTTP/1.0 client with `Accept-Encoding: gzip` | identity, exact bytes |
| 10 | real `SIGINT` | clean exit `0`, final `METRICS` reports the gzip counter and `bytes_out < bytes_in` |

### J2 — gzip over h2c (`run_serves_gzip_over_h2c_to_a_real_client`)

`curl --http2-prior-knowledge --compressed` with `-D -`: response line
`HTTP/2 200`, `content-encoding: gzip`, **no** `transfer-encoding` field
(h2 has no chunked framing), body decoded by curl is byte-identical to the
origin's text, clean `SIGINT` exit.

### J3 — Brotli over HTTP/1.1 (`run_compresses_brotli_and_prefers_it_over_gzip`)

| # | Request | Expected (asserted) |
|---|---|---|
| 1 | `Accept-Encoding: gzip, br` | Brotli wins the tie: `content-encoding: br`, `transfer-encoding: chunked`, `vary`, no `content-length`; body decodes (independent `brotli` decoder) to the origin's bytes and is smaller |
| 2 | `Accept-Encoding: gzip` | gzip is still served when Brotli is not offered |
| 3 | `gzip;q=0.9, br;q=0.2` | explicit q-values order the choice: gzip |
| 4 | `br;q=0` | Brotli refused; gzip was not offered, so identity with exact bytes |
| 5 | `/small` with `br` | identity, bytes `tiny` |
| 6 | chunked origin body with `br` | `content-encoding: br`, decodes exactly, trailer `x-checksum: 42` preserved |
| 7 | real `SIGINT` | final `METRICS` reports `brotli=2 gzip=2`, `bytes_out < bytes_in`, clean exit `0` |

### J4 — Brotli over h2c (`run_serves_brotli_over_h2c_to_a_real_client`)

`curl --http2-prior-knowledge -H 'Accept-Encoding: br'` writes the raw body to
a file (this curl has no Brotli support, so `--compressed` would not offer
`br`): response line `HTTP/2 200`, `content-encoding: br`, no
`transfer-encoding`, and the test decodes the file itself with the `brotli`
crate and compares it with the origin's bytes.

### J5 — Config gate (`validate_and_explain_report_the_compression_settings`)

`config validate` accepts gzip-only, Brotli-only and both-enabled blocks;
`config explain` prints `compression: gzip level=6 …`,
`compression: brotli quality=7 …` and
`compression: gzip level=7 brotli quality=4 …` respectively. Rejected with exit
`1` and the field name: either coding on a `tcp` listener, a gzip level outside
1–9, a Brotli quality outside 0–11, an empty type list and a media type outside
`type/subtype`, `type/*`, `*/*`.

## 5. Raw benchmark data (C11 / H6)

`scripts/evidence/v07-compression/bench.py` (maintainer-local, outside the
repository) measured the release binary against the independent Python origin:

```
python3 scripts/evidence/v07-compression/bench.py --binary target/release/eqproxy
```

- 3 corpora (text, JSON, binary) × 7 configurations (identity, gzip levels
  1/6/9, Brotli qualities 1/5/11) × 5 repetitions × 50 requests, plus 3
  warm-ups per cell.
- Every compressed response is decoded with an **independent** decoder (zlib
  for gzip, the Brotli reference Python module for `br`) and compared with the
  origin's bytes; the `Válidos` column is 250/250 for every compressing cell
  and 0/0 for the cells that correctly stayed identity.
- Raw file: [`v07-compression/raw.jsonl`](v07-compression/raw.jsonl)
  (105 lines = 21 cells × 5 repetitions), summary:
  [`v07-compression/bench.md`](v07-compression/bench.md).

Median wire bytes per request at the default settings (gzip level 6, Brotli
quality 5):

| Corpus | Identity | gzip 6 | ratio | Brotli 5 | ratio | Brotli 11 |
|---|---|---|---|---|---|---|
| text (771 214 B) | 771 214 | 49 799 | 0.065 | 12 726 | 0.017 | 11 998 |
| JSON (1 037 124 B) | 1 037 124 | 77 132 | 0.074 | 30 380 | 0.029 | 32 366 |
| binary (262 144 B) | 262 144 | 262 144 | 1.000 | 262 144 | 1.000 | 262 144 |

The binary corpus is `application/octet-stream`, outside the default type
list, so it stays identity even when the client accepts the coding. Request
rates are indicative and published in `bench.md`: one sequential client on a
shared laptop, and Brotli quality 11 is CPU-bound (about 0.5 req/s on the 1 MB
corpus) — which is why the default quality is 5, not 11.

## 6. Boundary and error cases covered

Refused when: `HEAD`, HTTP/1.0 client, 1xx/204/206/304/101, `Content-Encoding`
already present, `Content-Range`, `Cache-Control: no-transform`,
`Content-Type` outside the configured list, declared `Content-Length` below
`min_size`, no `Accept-Encoding` at all, and a coding the listener did not
enable. Malformed `q` values are refusals (`br;q=bogus` → identity). The gate
rejects a Brotli quality above 11 and a gzip level outside 1–9 before the
dataplane sees them; the encoders reject the same values if constructed
directly. Encoder I/O failures propagate as `io::Error` instead of emitting a
truncated stream, and the Brotli writer's final block is flushed in
`finish`.

## 7. Audit and eval

- `veyra audit . --profile standard` → **ACCEPTED**, exit `0`, evidence
  `.veyra/evidence/20261022T212517Z/report.json`. `cargo-geiger` returned
  **INCONCLUSIVE** (dependency coverage warnings: unsafe counts are a lower
  bound, not a pass). `dylint` and `cargo-semver-checks` were **SKIPPED** with
  reasons (no lint libraries configured, no published baseline).
  `veyra-anti-theater` reported no findings above informational level;
  `veyra-e2e` ran 17 scenarios: 17 passed, 0 failed.
- Rust Audit (`scan --format terminal,json --fail-on high --online`) → exit
  `1` (the workspace's pre-existing high/critical baseline is above the
  threshold), 223 findings (5 critical, 26 high, 154 medium, 38 low). **Zero
  findings in the files of this slice** (`compression.rs`, `http1.rs`,
  `schema.rs`, `validate.rs`, `metrics.rs`, `main.rs`, `cli_e2e.rs`). Online
  dependency check: `brotli` resolves on crates.io (9.0.0, docs.rs 200, no
  OSV advisory). Report: `rust-ai-audit/report/rust-audit-20261022-233107.json`,
  not-executed report: `report/not-executed-2026-10-22.md` (mutation testing,
  Miri and the supply-chain pipeline were not run: reported there, not
  counted as passes).
- EvoForge `mcp_submit_eval` (slice copy of `choose_encoding` +
  `coding_quality`, host `cargo test -p eqproxy-net compression` green first):
  **F = 1.0**, 2 tests executed and passed, `compiles=true`,
  `clippy_pass=true`, exit `0`, trace `dd7dc59b-9db4-4744-8835-25bfe6e87c85`.

## 8. Not executed / pending

- **Docker image for this slice: NOT EXECUTED.** No image was built or run for
  the compression slices, so the amd64/arm64 container journeys and the Docker
  Scout gate are not covered here; they run in the release pipeline before a
  tag.
- Comparison against another proxy (nginx/HAProxy/Caddy compression) was not
  performed; the published data is EQProxy against an identity baseline only.
- TLS listeners and concurrent clients are outside this benchmark; h2 was
  exercised as cleartext prior knowledge (J2/J4), not as TLS ALPN.
- gRPC and HTTP/3 remain outside this row (their own roadmap boxes).

## 9. Reproduce

```
cargo build --release
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 scripts/evidence/v07-compression/bench.py --binary target/release/eqproxy
veyra audit . --profile standard
```

The benchmark rewrites `docs/evidence/v07-compression/bench.md` and
`raw.jsonl`; record the binary hash it prints, because a different build
invalidates the comparison.
