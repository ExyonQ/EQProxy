# ADR-0010: Response compression (gzip and Brotli)

Language: **English**.

- State: **Accepted** (2026-10-22, fifth v0.7 slice; Brotli added in the sixth)
- Date: 2026-10-22
- Related: [ADR-0006](0006-http2-termination.md) (h2 termination),
  [ADR-0007](0007-http2-backend.md) (h2 to the backend), SPEC §13 (semantic
  difference log), roadmap v0.7 (`B-N6`, `H6`, `C11`)

## Context

The v0.7 roadmap asks for compression in two steps: **gzip first, measured**
(`B-N6`, `C11`), Brotli later **only when it can be measured** (`H6`). The
fifth slice delivered gzip with published raw numbers; the sixth adds Brotli
to the same negotiation, gate and benchmark, so both codings are measured in
one run and neither is promised without data.

Two constraints shape the design:

1. The engine is streaming: a response body is relayed as it arrives, never
   buffered whole (SPEC §7.5). Compression must not change that.
2. Every h2 stream is already translated through the h1 engine
   ([ADR-0006](0006-http2-termination.md)), so a single implementation at the
   h1 response layer must serve both protocols.

## Decision

### Configuration surface

One opt-in block per **listener** (`http` mode only):

```toml
[listener.web.compression]
gzip = true
level = 6           # gzip, 1–9, default 6
brotli = true
brotli_quality = 5  # Brotli, 0–11, default 5
min_size = 1024     # only when the response declares Content-Length
types = ["text/*", "application/json", "application/javascript",
         "application/xml", "application/xhtml+xml", "application/rss+xml",
         "image/svg+xml"]
```

The gate rejects either coding on a `tcp` listener, a gzip level outside 1–9, a
Brotli quality outside 0–11 and a media type that is not `type/subtype`,
`type/*` or `*/*`. The runtime parses the same grammar
(`eqproxy_core::compression`), so the gate cannot accept something the dataplane
would interpret differently.

### Negotiation

The request's `Accept-Encoding` is evaluated per RFC 9110 §12.5.3 (subset): an
explicit entry decides for its coding, `q=0` refuses it, `*` covers the coding
when no explicit entry exists, malformed q-values are treated as refusals, and
a request without `Accept-Encoding` gets identity. When both codings are
acceptable, the higher q-value wins; on a tie **Brotli** wins (it is smaller at
a comparable quality). A coding the listener did not enable is never selected,
even when the client lists it.

### What is eligible

A response is compressed only when **all** of these hold: the client is
HTTP/1.1 (an HTTP/1.0 client cannot read the chunked framing), the method is
not `HEAD`, the status has a body (not 1xx/204/206/304), there is no
`Content-Encoding`, no `Content-Range`, no `Cache-Control: no-transform`, the
`Content-Type` matches the configured list, and — when `Content-Length` is
present — the declared body is at least `min_size`. A response without a
declared length (chunked or until-EOF) is not filtered by `min_size`, because
its size is unknown when the decision must be made.

### Wire behaviour

- The body is compressed **while it is relayed**. gzip uses `flate2`'s
  raw-deflate stream and this crate writes the member (fixed header with mtime
  0 and OS 255, CRC32 and ISIZE trailer). Brotli uses the pure-Rust `brotli`
  crate's `CompressorWriter`, flushed after every relayed block so a streaming
  response is never held back; the quality is per listener. Nothing is
  buffered whole, and a fresh encoder is created per response.
- The client-facing head is rewritten: `Content-Length`, the old
  `Transfer-Encoding` and `Content-Encoding` are dropped,
  `Content-Encoding: gzip` or `Content-Encoding: br` and
  `Transfer-Encoding: chunked` are added, and `Vary: Accept-Encoding` is added
  once (never duplicated). The status line is presented as `HTTP/1.1` (chunked
  requires it); the backend's bytes are not touched.
- Backend chunked trailers are validated exactly as before and re-emitted
  **after** the compressed stream, where HTTP chunked framing expects them.
- The h2 path needs no second implementation: the h1 engine produces the
  chunked compressed response, the existing translator turns it into DATA
  frames and drops the hop-by-hop framing.
- Counters: `compression_gzip_responses`, `compression_brotli_responses`,
  `compression_bytes_in` (plaintext), `compression_bytes_out` (compressed
  payload), rendered as
  `compression[gzip=… brotli=… bytes_in=… bytes_out=…]`.

### Measurement

`docs/evidence/v07-compression/bench.py` measures the release binary against
an independent Python origin over loopback with three fixed corpora (text,
JSON, binary), five repetitions of fifty requests per cell and seven
configurations (identity, gzip levels 1/6/9, Brotli qualities 1/5/11). Every
compressed response is decoded and compared with the origin's bytes, with two
independent decoders (zlib for gzip, the Brotli reference module for `br`).
The raw JSONL and the summary are committed next to this ADR's evidence
document. Wire bytes are stable and are the only claim made; request rates are
labelled indicative (single sequential client on a shared laptop).

## Consequences

- A listener that does not opt in behaves exactly as before; compression costs
  nothing when disabled.
- Compressed responses are chunked: a client that only understands
  `Content-Length` still reads them, but tooling that inspects the raw head
  sees no length. This is the standard trade-off of streaming compression;
  buffering to keep a length was rejected (it would defeat SPEC §7.5).
- Already-compressed media types are never re-encoded by default; operators
  can add them to `types`, and the eligibility rules still refuse a
  `Content-Encoding` that is already present.
- Brotli costs more CPU per byte than gzip at equal quality; the benchmark
  publishes both so operators can pick. Qualities above 9 are meant for
  precompressed assets, not per-request work, and the default is 5.
- No caching or precompression: every request pays the CPU cost. The published
  numbers are the baseline for deciding whether a cache is worth adding.
