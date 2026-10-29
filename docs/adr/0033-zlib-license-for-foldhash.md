# ADR-0033: allow the Zlib licence for `foldhash` (wasmtime's Cranelift)

- State: **Accepted** (2026-10-29, v0.8.5 WASM plugin box)
- Date: 2026-10-29
- Related: [ADR-0031](0031-wasm-plugin-host.md) (the wasmtime dependency that
  introduces the crate), [`deny.toml`](../../deny.toml) (the allowlist this
  changes), [v085-wasm-plugins](../evidence/v085-wasm-plugins.md) (the audit
  run that found it)

## Context

ADR-0031 compiles `wasmtime 50` with only `cranelift`, `runtime` and `std`.
Cranelift pulls `hashbrown 0.17`, which pulls `foldhash 0.2`, published under
the **Zlib** licence. `deny.toml` allows the permissive licences already in
use (MIT, Apache-2.0, ISC, BSD, Unicode-3.0, BSL-1.0, CC0-1.0,
CDLA-Permissive-2.0) and states that any other licence requires an ADR.
`cargo-deny` rejected the tree on `foldhash` in the first Veyra run of this
increment (`.veyra/evidence/20261029T185152Z`, `licenses FAILED`, exit 4), and
the audit is right to fail: the licence was not declared.

## Decision

Add `"Zlib"` to `[licenses].allow` in `deny.toml`.

Zlib is a permissive, OSI-approved and FSF Free/Libre licence: it permits use,
modification and redistribution, including in proprietary and Apache-2.0
projects, and imposes no copyleft. It is compatible with the project's
Apache-2.0 licence and with every other licence already allowed.

## Consequences

- The dependency graph stays as designed; no crate is replaced or vendored and
  no check is disabled. `cargo-deny` reviews the whole graph again on every
  run, so a future Zlib crate is still visible, now allowed by policy.
- The allowlist grows by one entry with a named reason (this ADR), not by a
  blanket "allow all permissive" rule.
- If a Zlib-licensed crate ever brings a different obligation (for example a
  modification-notice requirement), that is a new decision; this ADR only
  covers the licence as published by `foldhash 0.2`.
