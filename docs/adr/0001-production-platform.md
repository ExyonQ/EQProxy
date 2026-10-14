# ADR-0001: Production platform and support tiers

Language: **English**.

- State: **Accepted** (Phase 0)
- Date: 2026-10-12

## Context

EQProxy must choose a production platform before designing the dataplane
(brief, section 5: "First choose a production platform. Separately declare
experimental support for other platforms"). The chosen stack (tokio/hyper/rustls,
see ADR-0004) is portable, but socket options (`SO_REUSEPORT`, `TCP_FASTOPEN`,
`TCP_DEFER_ACCEPT`), descriptor limits and `recvmmsg`/UDP buffer behaviour vary
per OS.

## Decision

- **Production platform (tier 1): Linux x86_64 with glibc** (kernel ≥ 5.10, a
  distribution with active support). All performance, security and operational
  validation happens here.
- **Experimental support (tier 2):** Linux aarch64, macOS (development and
  tests), musl (static binaries). They compile and pass functional tests, with
  no guarantee of performance or socket semantics.
- **Unsupported for now:** Windows. No compatibility claim whatsoever.

## Alternatives considered

1. **musl as tier 1** (static binaries, trivial deployment): rejected because
   allocator performance and some TLS dependencies' support make it riskier as
   the basis for comparative benchmarks.
2. **Multi-platform tier 1 from day 1:** rejected; it multiplies the test
   matrix without contributing to correctness. The project rule is
   correctness → security → operability → performance.
3. **aarch64 tier 1** (Graviton/Ampere instances): deferred; it will be added
   as tier 1 only when dedicated benchmark budget exists.

## Consequences

- The BENCHMARK_PLAN.md benchmarks declare Linux x86_64 glibc; any result on
  another platform is labelled not comparable.
- Platform detection is done at compile time (`cfg`), with explicit failure in
  unimplemented functions (never stubs that return success).
- ADRs of later phases may promote platforms with evidence (tests + benchmarks)
  but never demote tier 1 without a new ADR.
