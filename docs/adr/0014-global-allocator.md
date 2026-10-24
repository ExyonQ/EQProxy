# ADR-0014 — mimalloc as the global allocator

- **Status:** Accepted (2026-10-23)
- **Context:** v0.7 gate, scenario S-H3-01 (HTTP/3, 1 KiB, 64 streams in
  flight), EQProxy 0.341× HAProxy 3.4.6.
- **Evidence:** [`docs/evidence/v07-h3-profile.md`](../evidence/v07-h3-profile.md),
  campaign [`v07-h3-bench/run-20261023T134656Z`](../evidence/v07-h3-bench/run-20261023T134656Z/report.json).

## Problem

`perf` on a DWARF build of the exact S-H3-01 artifact attributed **~20 % of
CPU to musl's allocator** (`__lock` 5.6 %, `__libc_free` 4.8 %,
`__libc_malloc_impl` 2.5 %, `alloc_slot` 1.1 %, `calloc` 1.0 %, `__unlock`
2.6 %) and a further **~8 % to the kernel path its lock drives**
(`futex_wake` 2.0 % self plus `__pv_queued_spin_lock_slowpath`,
`_raw_spin_lock` and `__raw_callee_save___pv_queued_spin_unlock`). An
allocation-counting build measured **108 allocations and 34 KiB allocated per
proxied request**, 44 KiB of it zeroed, across eight tokio workers. musl's
malloc serialises those allocations on a group lock; free from a different
worker than the one that allocated wakes waiters with a futex, so a small
1 KiB GET pays for a lock convoy.

The h1 engine, h3 translation and quinn all allocate per request; removing
every allocation would mean rewriting quinn/h3, and the per-request budget
would still be tens of objects.

## Decision

Use **mimalloc 0.1.52** (`default-features = false`) as the process-wide
allocator, installed in `eqproxy-cli/src/main.rs` behind
`#[global_allocator]`. It keeps per-thread free lists, so an allocation and
its free do not contend on one global lock and normally do not leave the
allocating thread.

## Alternatives considered

| Option | Why not |
|---|---|
| Keep musl malloc | Measured cost above; no tuning knob in musl's mallocng. |
| jemalloc / rpmalloc / snmalloc | Same class of change; mimalloc is the smallest integration (one crate, C compiled by `cc` in the existing builder) and was the one measured. |
| Pool buffers per connection | Fixes our own buffers only; quinn, h3 and the h1 engine keep allocating per request. |
| Reduce worker threads | Changes scheduling semantics for all workloads and hides rather than removes the contention. |

## Consequences

- `libmimalloc-sys` is compiled into the static musl binary; image size grows
  by the allocator's text (~200 KiB), and the image stays `scratch` with no
  runtime package.
- Peak RSS is now a mimalloc property (per-thread heaps and retained free
  lists); it is measured by the benchmark probe and reported with the
  results, never assumed.
- The allocator applies to every code path (HTTP/1.1, HTTP/2, HTTP/3,
  control plane), so historical v0.6 numbers are not directly comparable to
  post-ADR builds on CPU/throughput; the v0.7 evidence records the artifact
  hash for each campaign.
- `unsafe_code` stays forbidden in the workspace: `mimalloc::MiMalloc`
  implements `GlobalAlloc` inside the dependency, the binary only names the
  type.

## Verification

Same host, same config, same generator, 12 s runs alternating:

| Build | Throughput | p50 |
|---|---|---|
| musl malloc (v07 image) | 18 815 req/s | 3.00 ms |
| mimalloc (same source + allocator) | **26 190 req/s** | **2.15 ms** |

Zero errors and `sanity = ok` in both. The final S-H3-01 campaign re-run with
the published image is in `v07-h3-profile.md` §7.
