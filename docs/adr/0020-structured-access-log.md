# ADR-0020: Structured, non-blocking access log

Language: **English**.

- State: **Accepted** (2026-10-25, roadmap v0.8 B-N14/B-I14/B-E8)
- Date: 2026-10-25
- Related: [ADR-0002](0002-configuration-format.md) (TOML configuration),
  [ADR-0017](0017-read-only-admin-plane.md) (admin plane and cardinality),
  [SPEC §9](../SPEC.md) (observability), roadmap v0.8 CE4

## Context

EQProxy has counters, stderr diagnostics and an audit line for **writes**, but
no per-request log an operator can ship to a collector. nginx/ingress-nginx
(`access_log`, `log_format`) and Envoy (`access_log`, structured JSON) both
offer one; the roadmap names the gap as **B-N14**, **B-I14** and **B-E8**, and
the migration guides cannot promise parity without it.

Two constraints shape the design:

- **The dataplane must not wait on a log sink.** A blocked disk, a full pipe
  or a slow collector may not add latency to a proxied request, and may not
  consume an unbounded queue under load (CE4).
- **The line is derived from real request facts**, not from a second parser.
  HTTP/2 and HTTP/3 already synthesize an HTTP/1.1 message and hand it to
  `http1::serve_http` (ADR-0004 and the v0.7 slices), so logging near that
  engine covers all three protocols with the same status and duration the
  client actually observed.

## Decision

### Configuration

A new optional top-level section; absent means **off** (never an implicit
sink):

```toml
[access_log]
format = "json"          # "json" (default) or "combined"
path = "/var/log/eqproxy/access.log"   # absent = stdout
```

- `format = "json"` writes one JSON object per line.
- `format = "combined"` writes the nginx combined shape, with `-` for a field
  the exchange does not have.
- `path` is opened once at startup, in append mode. A failure to open it
  aborts startup: a configured sink that silently disappears is worse than
  not starting (same rule as the admin plane in ADR-0017).
- The destination and format are **fixed at startup**. `SIGHUP` and the admin
  API reload the configuration but never swap the sink: changing
  `[access_log]` needs a restart. A reload that edits it logs a warning and
  keeps the running sink, so an operator is never left believing the new file
  is in use.

### Fields

JSON object (stable names, no nested objects):

| Field | Meaning |
|---|---|
| `time` | UTC RFC 3339 timestamp, millisecond precision |
| `listener` | listener name (`[listener.<name>]`) |
| `client` | peer `IP:PORT` as accepted (PROXY protocol included) |
| `protocol` | `http/1.1`, `http/2` or `http/3` |
| `method` | request method, or `-` when the head never parsed |
| `path` | request path **without the query string**, or `-` |
| `host` | effective `Host`/`:authority`, or `-` |
| `status` | final response status; `0` when the exchange ended without one (client abort) |
| `duration_ms` | wall time from request-head start to exchange end |
| `backend` | backend name, when a backend was chosen |
| `server` | backend address that served, when one did |
| `referer`, `user_agent` | request headers verbatim, or omitted |
| `bytes` | response body length when exactly known (local and `Content-Length` answers); omitted otherwise |

`combined` emits:
`client - - [dd/Mon/yyyy:HH:MM:SS +0000] "METHOD path PROTOCOL" status bytes "-" "ua"`,
with `-` for unknown bytes, referer always `-` (it is not part of the nginx
combined field order without a referer), and the same one-line guarantee.
Times are UTC for both formats: a local timezone would make two instances of
the same deployment disagree.

`path` deliberately **excludes the query string**: tokens in query parameters
must not be copied into a log that is shipped off-box (T17). A request whose
head never parsed (408, 431, malformed) is still logged, with `method` and
`path` as `-`.

### Non-blocking sink

Requests do not write. They build one entry and `try_send` it into a **bounded
channel** (4096 entries); a dedicated task owns the file/stdout and writes one
line per entry, flushing after each line so `tail -f` and a collector see it
promptly. If the channel is full the entry is **dropped and counted**
(`access_log_dropped` in the counters and Prometheus), never awaited and never
queued unboundedly. The status shows whether a deployment is losing lines:
silent loss is rejected.

The channel is created in the CLI, shared by every listener and preserved
across SIGHUP swaps. `cargo test` paths that do not start the CLI attach no
sink (`ResolvedListener::access = None`), so no test writes logs by accident.

### Coverage

Every request that reaches `http1::serve_http` is logged exactly once:
plain HTTP/1.1, each HTTP/2 stream, each HTTP/3 request and the HTTP/1.1
WebSocket upgrade path, which all run through that engine. Terminations that
fail **before** a request exists (TLS handshake failure, h2/h3 connection
error, a TCP tunnel) are not access-logged; they remain counters and stderr
diagnostics. An exchange that ends without a response is logged with
`status = 0`, so a truncated log never looks like a missing request.

`duration_ms` runs until the exchange (or the upgraded tunnel) ends, so a
WebSocket entry measures the tunnel, not just the handshake; its `status` is
the `101` that opened it.

## Consequences

- Operators get per-request evidence for all three HTTP versions with one
  configuration, and the proxy's hot path never blocks on the sink.
- The log is not a transaction log: it is best-effort under overload, and the
  drop counter is the signal. `status = 0` and `bytes` absent are honest
  gaps, not errors.
- Sensitive values are bounded by construction: no request or response
  headers other than `Referer`/`User-Agent`, no query string, no
  `Authorization`.
- A restart is required to change the destination or format; this is the same
  model as the admin listener and is stated in the example configuration.

## Pending (not decided here)

- Per-listener overrides, sampling, rotation (`SIGUSR1`/size-based) and
  compression of the sink.
- Tracing correlation (`traceparent`) and a configurable field set.
- A syslog/journald destination; the file/stdout destinations cover the
  roadmap slice.
