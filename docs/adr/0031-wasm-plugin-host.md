# ADR-0031: WASM request-filter plugins — ABI v1, deny-by-default capabilities

Language: **English**.

- State: **Accepted** (2026-10-29, roadmap v0.8.5, box B-I5/B-E4; B-N17 is
  decided in [ADR-0032](0032-fastcgi-uwsgi-scgi-decision.md))
- Date: 2026-10-29
- Related: [roadmap v0.8.5, §1](../../ROADMAP%20EQPROXY/ROADMAP/Roadmap%200.8.5.md)
  (the box this closes), [SPEC §10](../..//SPEC.md#10-extensions-wasm)
  (the extension contract), [ADR-0004](0004-network-stack-and-crate-layout.md)
  (workspace layout), [BENCHMARK_PLAN §3](../../BENCHMARK_PLAN.md) (S-PLG-01),
  [v085-wasm-plugins](../evidence/v085-wasm-plugins.md) (commands, numbers
  and journeys)

## Context

ingress-nginx `*-snippet` annotations and Envoy's Lua/Wasm filters exist
because built-in filters never cover every use case. The first two are an
escape hatch to raw configuration or arbitrary code inside the proxy
(CVE-2021-25742 is the known ingress-nginx example); EQProxy rejects both by
policy. The remaining safe extension point is a WASM module executed by the
proxy under explicit limits.

The roadmap requires: fuel/epoch interruption, per-store memory limits,
deadlines, capabilities denied by default, fail-open/fail-closed **per
extension**, and S-PLG-01 measured with and without plugins. The SPEC also
names the runtime (wasmtime) and warns that a timeout does not cancel a block:
a plugin must not be able to wait on I/O at all.

The first slice must be real and useful, not a placeholder: a request filter
that can inspect the request and either continue it (adding/removing request
headers) or reject it with an explicit status. That covers the common snippet
uses (header injection, access blocks) while staying inside one well-defined
extension point.

## Decision

### 1. Runtime and dependency surface

`wasmtime 50` compiled with `default-features = false` and only
`cranelift`, `runtime` and `std`:

- no `wasi`/`wasi-preview1` host implementation is linked, so a plugin cannot
  open files or sockets through WASI;
- no `async`, `component-model`, `cache`, GC or debug features are compiled;
- the JIT compiles the module once per listener at config resolution; each
  request gets a fresh `Store` and instance.

Test fixtures are committed **binary `.wasm` modules next to their `.wat`
source** (`eqproxy-net/tests/fixtures/plugins/`): the tests load exactly the
bytes production loads, and the WAT file keeps the fixture reviewable. The
`wat` compiler is not a dependency of the workspace; production accepts binary
`.wasm`, never WAT text.

### 2. ABI v1

A plugin module exports:

| Export | Signature | Meaning |
|---|---|---|
| `memory` | linear memory | The only memory the host reads/writes |
| `eqproxy_alloc` | `(len: i32) -> i32` | Returns the guest pointer for `len` input bytes |
| `eqproxy_on_request` | `(ptr: i32, len: i32) -> i32` | Handles one request; `0` = continue, `400..=599` = reject |

The host writes the **client's request head** (request line + header lines,
without the final CRLFCRLF) at the pointer returned by `eqproxy_alloc`, then
calls `eqproxy_on_request`.

The module may import exactly two functions from module `"eqproxy"`:

| Import | Signature | Effect |
|---|---|---|
| `set_request_header` | `(name_ptr, name_len, value_ptr, value_len: i32)` | Replaces every forwarded header with that name (or appends it) |
| `remove_request_header` | `(name_ptr, name_len: i32)` | Drops every forwarded header with that name |

Any other import — WASI, `env.*`, a network shim — makes the module **fail to
load**, with the import named in the configuration error. There is no network
or filesystem capability to grant: the host exposes none. This is
deny-by-default in the strong sense, not a runtime check that can be bypassed.

Mutations are applied to the forwarded head **last**: after rule header
actions, `X-Forwarded-*` and rewrites. A plugin therefore wins over earlier
stages, and the documented order is testable. The plugin sees the original
client head, not the rewritten one; that is stated, not implied.

Framing and connection headers are **reserved** and cannot be set or removed:
`content-length`, `transfer-encoding`, `connection`, `host`, `upgrade`,
`expect`, `te`, `trailer`, `proxy-connection`. A plugin that tries is a host
error (fail policy applies). Allowing them would let an extension reintroduce
request smuggling after the proxy validated framing, which is exactly the
class of bug this project refuses.

Status codes outside `0` and `400..=599` are a host error, never a silent
allow. A rejection is answered with an empty body and `connection: close`.

### 3. Limits

Per invocation, from `[listener.<name>.plugin]`:

| Limit | Default | Bound | Mechanism |
|---|---:|---:|---|
| `fuel` | 10,000,000 | 1..=100,000,000 | `Store::set_fuel`; exhaustion traps `OutOfFuel` |
| `timeout` | 50 ms | 1 ms..=5 s | epoch ticker every 1 ms; `set_epoch_deadline`; traps `Interrupt` |
| `memory_bytes` | 16 MiB | 1..=256 MiB | `StoreLimits::memory_size` + `trap_on_grow_failure`; `memory.grow` beyond the bound traps |
| `max_header_ops` | 16 | 1..=64 | Host counter; exceeding it is a host error |
| module size | — | ≤ 4 MiB | Checked before compilation |
| input head | — | ≤ 64 KiB | A listener with a plugin must keep `limits.max_head_bytes <= 65536`, validated at config time |
| header name/value | — | 64 / 2048 bytes | Host validation per call |
| total mutation bytes | — | 8 KiB | Host counter |

One `Store` per request also bounds instances, tables and memories to one each
and discards all plugin state after the response. Plugins are **stateless
request filters** in v1; persistent state is a separate decision that would
need shared memory or a host store, with its own concurrency review.

### 4. Execution model

The module runs **inline on the dataplane worker**, like Envoy's Wasm filter,
not on a per-request thread. The bound is what makes this honest:

- the host imports cannot block (there is no I/O to wait on), so a plugin can
  only compute;
- fuel bounds instructions and the epoch deadline bounds wall-clock time, and
  wasmtime inserts epoch checks at loop back-edges and calls, so an infinite
  loop **is** interrupted (tested), unlike a blocking syscall;
- the deadline bounds one invocation; it is not a promise to cancel host code,
  because no host code runs long enough to need it.

A plugin that needs to block belongs outside the dataplane, per SPEC §10, and
is not supported by ABI v1.

### 5. Failure policy

Configuration and load errors (unreadable file, invalid module, denied import,
missing export, initial memory over the bound, plugin on a `tcp` listener)
**reject the configuration**: a running proxy keeps its previous snapshot and
`check` exits 1. Nothing is skipped silently.

Runtime errors (trap, fuel, deadline, memory growth, host validation) follow
`on_error`:

- `closed` (default): answer `503 service unavailable`, count
  `plugin_errors`, never forward the request;
- `open`: forward the request **unchanged** (no partial header mutations),
  count `plugin_errors`.

`plugin_requests` counts every invocation, `plugin_denied` counts explicit
rejections. Metrics have fixed names and no labels (bounded cardinality).

A plugin rejection is a normal HTTP response (`403`, `429`, … chosen by the
plugin) and is logged in the access log with that status; it is not a proxy
error.

### 6. Extension point coverage

| Listener protocol | Covered | Why |
|---|---|---|
| HTTP/1.1 | yes | Runs in `serve_http`, before the backend dial |
| HTTP/2 | yes | Each stream is translated to the same `serve_http` engine |
| HTTP/3 | yes | Same engine per request |
| TCP (`mode = "tcp"`) | rejected at config | There is no HTTP request to filter |
| Response phase | **not in v1** | Would need a second ABI and body access; documented gap |

## Consequences

- Snippets get a safe equivalent for request header manipulation and access
  rejection; rewrites, response filters and body access remain gaps, named in
  the parity matrix rather than implied.
- The dependency graph grows by wasmtime's JIT (Cranelift). License policy
  already allows `Apache-2.0 WITH LLVM-exception`; Cranelift's `foldhash` is
  Zlib, allowed by [ADR-0033](0033-zlib-license-for-foldhash.md) after
  `cargo-deny` rejected the first audit. `cargo-deny` and Veyra's license leg
  are the gate. Geiger's dependency coverage stays informational per ADR-0030.
- A per-request `Store` + instance costs more than a pooled instance; S-PLG-01
  measures it. If the cost is unacceptable, pooling is a new decision with its
  own isolation analysis, not an undocumented optimisation.
- No timeout can turn a plugin into an unkillable block: there is no blocking
  import. A CPU-bound plugin is interrupted by fuel/epoch and the request
  fails per policy.

## Revisit triggers

1. Response-phase filters or request-body access are required (ABI v2).
2. Persistent plugin state is required (needs a concurrency and lifetime
   design).
3. S-PLG-01 shows the per-request instance cost dominating the request budget
   (pooling proposal with isolation tests).
4. wasmtime's reduced feature set stops building on the pinned toolchain or
   musl image.
