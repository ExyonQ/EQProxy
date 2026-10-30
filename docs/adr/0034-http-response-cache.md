# ADR-0034: per-listener HTTP response cache (B-N7 · H1)

- State: **Accepted** (2026-10-30, roadmap v0.8.5, box B-N7/H1)
- Date: 2026-10-30
- Related: [roadmap v0.8.5](../../ROADMAP%20EQPROXY/ROADMAP/Roadmap%200.8.5.md)
  (§1, §4), [H1 in informe-criticas-haproxy](../../ROADMAP%20EQPROXY/informe-criticas-haproxy.md),
  [v085-http-cache](../evidence/v085-http-cache.md), [ADR-0010](0010-response-compression.md)
  (compression interplay)

## Context

HAProxy ships a small in-memory cache and nginx a larger one; the HAProxy
critique (H1) records the failure mode that blocked migrations: a cache that
stores session responses, keys on cookies, or hides its content turns the
accelerator into a session-leak machine. EQProxy therefore gets a cache only
under an honesty contract: every exclusion must be a tested fact, and the
content must be inspectable at runtime.

The cache sits on the h1 engine path (each h2 stream and each h3 request
passes through the same `plan_cache` / `serve_cached` pair), after routing,
auth and the plugin, before any backend byte.

## Decision

One opt-in cache per `http` listener (`[listener.<name>.cache]`, absent =
disabled):

| Key | Default | Range |
|---|---|---|
| `default_ttl` | `"60s"` | 1 s..=1 day (`s-maxage`/`max-age` shorten, never extend; response `no-cache` forces zero) |
| `max_memory_bytes` | 64 MiB | 1 MiB..=1 GiB, LRU eviction past it |
| `max_entry_bytes` | 1 MiB | 64 KiB..=64 MiB, and `<= max_memory_bytes` |
| `disk_path` | absent | relative to the config file (memory only when absent) |

Storage rules (each a named E2E journey, not a comment):

- Only `GET` is stored; `HEAD` is served headers-only from the `GET` entry.
- A request with `Cookie`, `Authorization`, `Range` or `Cache-Control:
  no-store` never looks up nor stores. A response with `Set-Cookie` is never
  stored. Responses `206` and `302` stream through uncached.
- The key is method + scheme + lowercased host + target + the values of the
  `Vary`-listed request headers. `Vary: *` or a `Vary` over
  `Cookie`/`Authorization` makes the response unstorable — the variant key
  would be session identity.
- Backends with cookie affinity bypass the cache at runtime: a cached answer
  would steal the pinning cookie.
- Only `Content-Length` bodies under the entry bound assemble in memory;
  chunked and close-delimited responses stream through uncached, never
  re-framed. Larger bodies stream through, never truncated.
- Stale entries with validators revalidate with `If-None-Match` /
  `If-Modified-Since`; an origin `304` refreshes the stored headers without
  touching the body (replacement, never mutation: a concurrent serve holds
  the old `Arc` byte-identical). Without validators the entry is refetched.
- Cache-lock: one origin fetch per key at a time; concurrent requests wait
  on the in-flight fetch (bounded `lock_wait`) instead of stampeding.
- Disk persistence is write-through; expired or corrupt files are skipped
  and counted (`cache_disk_skipped`), never trusted.
- Visibility: `GET /api/v1/cache` lists entries (age, TTL, hits, size,
  bounded to 128 objects) and every served response carries `X-Cache:
  HIT | MISS | REVALIDATED` (`Age` beside a `HIT`); `304` answers to a
  client `If-None-Match` carry no `Age`. Counters `cache_hits`,
  `cache_misses`, `cache_bypasses`, `cache_revalidations`,
  `cache_stores`, `cache_evictions`, `cache_disk_loads`,
  `cache_disk_skipped` — label-free.

Deliberately out of v1 (documented in `cache.rs`, not silent):
`stale-while-revalidate`, `stale-if-error`, `only-if-cached`, `Pragma`,
`Vary` folding beyond exact trimmed match, client `If-Modified-Since`
evaluation (only `If-None-Match` earns a client `304`).

## Consequences

- Session leaks are structurally impossible rather than conventionally
  avoided: the bypass lists and the key shape are the mechanism, and the
  E2E proves each exclusion against a real origin.
- Compression applies to served entries through the same eligibility path
  as origin responses; the stored bytes stay canonical.
- A `SIGHUP` reload rebuilds the cache from the new file (same discipline
  as listeners and backends); disk files survive the process restart.
- The next cache work (if any) starts from the out-of-v1 list above, not
  from a rediscovery.
