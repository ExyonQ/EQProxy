# v0.8.5 — counters read after the last head now wait with a deadline

The roadmap's fourth debt box named `backend_connections_opened/reused` and
"any counter incremented when the exchange ends". The source says something
more specific, and the difference matters:

- **`backend_connections_opened` / `_reused` are not end-of-exchange counters.**
  Both are incremented where the connection is dialled or checked out
  ([`proxy.rs:2127`](../../eqproxy-net/src/proxy.rs#L2127),
  [`2165`](../../eqproxy-net/src/proxy.rs#L2165),
  [`2571`](../../eqproxy-net/src/proxy.rs#L2571)), before the request is sent,
  so any test that has read the response cannot beat them. The 200 ms sleeps in
  `e2e_http2` cover the **pool check-in** that wave 2 measures, not a counter
  sample.
- **The counters that do land late** are `http_requests_proxied`
  ([`http1.rs:2522`](../../eqproxy-net/src/http1.rs#L2522), after the body has
  been copied), `backend_connections_discarded`
  ([`http1.rs:2583`](../../eqproxy-net/src/http1.rs#L2583), same tail) and
  `connections_active` (decremented when the connection task ends). A test that
  reads them right after the last head races the proxy by construction.
- **EOF-delimited exchanges are safe**: the proxy increments before it closes
  the client, so a test that reads to EOF cannot read early. That is why
  [`retry_saves_idempotent_get_from_dead_server`](../../eqproxy-net/tests/e2e_resilience.rs#L302)
  and [`http1_post_body_streams_end_to_end`](../../eqproxy-net/tests/e2e_http1.rs#L362)
  keep their shape: the 2026-10-28 control below showed they pass with the
  increment delayed 300 ms.

## 1. The change

[`common::wait_for_counter`](../../eqproxy-net/tests/common/mod.rs#L100) polls
the value until it reaches the expected one, with a 5 s deadline and 5 ms
between reads, and fails with the last value read. It is the same contract as
[`wait_for_proxied`](../../eqproxy-net/tests/e2e_pool.rs#L176) (added after CI
run 40616967835), generalised for the counters above. Seven sites use it; no
assertion changed:

| Test | Counter | Before |
|---|---|---|
| [`http1_get_roundtrip_and_keepalive`](../../eqproxy-net/tests/e2e_http1.rs#L342) | `http_requests_proxied` | `sleep(100ms)` + one sample |
| [`http1_client_abort_cancels_upstream_promptly`](../../eqproxy-net/tests/e2e_http1.rs#L911) | `connections_active` | `sleep(100ms)` + one sample |
| [`expect_100_continue_releases_client_and_streams_body`](../../eqproxy-net/tests/e2e_http1.rs#L1012) | `http_requests_proxied` | `sleep(100ms)` + one sample |
| [`interim_1xx_is_forwarded_and_never_desyncs_keepalive`](../../eqproxy-net/tests/e2e_http1.rs#L1087) | `http_requests_proxied` | `sleep(100ms)` + one sample |
| [`backend_redundant_100_is_consumed_exactly_once`](../../eqproxy-net/tests/e2e_http1.rs#L1144) | `http_requests_proxied` | `sleep(100ms)` + one sample |
| [`oversent_backend_bytes_are_never_forwarded_or_pooled`](../../eqproxy-net/tests/e2e_http1.rs#L1243) | `backend_connections_discarded` | `sleep(100ms)` + one sample |
| [`http3_get_is_terminated_and_relayed_to_the_h1_origin`](../../eqproxy-net/tests/e2e_http3.rs#L406) | `http_requests_proxied` | no wait at all |

## 2. Negative control: the race is real

A temporary, never-committed patch added a 300 ms delay **before** the
`http_requests_proxied` increment in `http1.rs` (backup first, sha256
`b4cc823c…`). With the old tests:

```
[e2e_http1::http1_get_roundtrip_and_keepalive] exit=101
  panicked at eqproxy-net/tests/e2e_http1.rs:341:5: left: 1 right: 2
[e2e_http3::http3_get_is_terminated_and_relayed_to_the_h1_origin] exit=101
  panicked at eqproxy-net/tests/e2e_http3.rs:404:5: left: 0 right: 1
[e2e_resilience::retry_saves_idempotent_get_from_dead_server] exit=0
```

The third line is a **negative result kept on purpose**: that journey reads to
EOF, so the delayed counter still lands before the client sees the close. It
was not changed.

Raw: [`negative-control.txt`](v085-late-counters/raw/20261028T201216Z/negative-control.txt).

## 3. Positive control: the wait absorbs the same delay

With the 300 ms patch still in place and the seven sites waiting:

```
[e2e_http1::http1_get_roundtrip_and_keepalive] exit=0 1 passed
[e2e_http1::http1_client_abort_cancels_upstream_promptly] exit=0 1 passed
[e2e_http1::expect_100_continue_releases_client_and_streams_body] exit=0 1 passed
[e2e_http1::interim_1xx_is_forwarded_and_never_desyncs_keepalive] exit=0 1 passed
[e2e_http1::backend_redundant_100_is_consumed_exactly_once] exit=0 1 passed
[e2e_http1::oversent_backend_bytes_are_never_forwarded_or_pooled] exit=0 1 passed
[e2e_http3::http3_get_is_terminated_and_relayed_to_the_h1_origin] exit=0 1 passed
```

Raw: [`positive-control.txt`](v085-late-counters/raw/20261028T201216Z/positive-control.txt).
The same file also records three first attempts that matched **no** test
(`0 passed`, filtered out) because their names were guessed wrong; the rerun
with the exact names is the one above.
Then `http1.rs` was restored from the backup: sha256
`b4cc823c4e0c57b340473b94b58030ca2da221df9c938bb6774662e87147e0d0`,
`git diff --quiet -- eqproxy-net/src/http1.rs` empty. The shipped tree has no
delay.

## 4. Local verification (macOS arm64, uid 501)

```
$ cargo fmt --all -- --check                                    # exit 0
$ cargo clippy -p eqproxy-net --all-targets -- -D warnings      # exit 0
$ python3 .github/scripts/check-short-health-probes.py          # exit 0 (18 probes, 2 declared)
$ cargo test -p eqproxy-net --test e2e_http1 --test e2e_http3
test result: ok. 20 passed; 0 failed  (e2e_http1)   finished in 1.98s
test result: ok. 13 passed; 0 failed  (e2e_http3)   finished in 0.21s
```

20 repetitions of both targets with the 10 cores saturated: **660 test
executions (33 per pass), 0 failures**, load average 284–288:

```
[rep 1] exit=0 3s load= 284.60 304.02 320.30  :: 2 targets ok
…
[rep 20] exit=0 3s load= 288.60 301.44 318.22  :: 2 targets ok
fail=0/20
```

Raw: [`final-tree.txt`](v085-late-counters/raw/20261028T201611Z/final-tree.txt),
[`load-20x.txt`](v085-late-counters/raw/20261028T201611Z/load-20x.txt).

## 5. Limits and NOT EXECUTED

- **macOS arm64, uid 501 only.** CI and the root tier are **NOT EXECUTED**.
- The 300 ms delay is a **local control only**: it proves the wait tolerates a
  late increment; it does not measure how late the real bookkeeping can be, and
  it is not a production change (`git diff` on `http1.rs` is empty).
- The wait proves the value **arrives**; it does not make a wrong value right.
  Every assertion keeps its expected number and message.
- `wait_for_counter` has a 5 s deadline. A genuinely stuck counter fails with
  the last value read instead of hanging the suite.
- Not every counter read in the suite was converted: only the end-of-exchange
  reads demonstrated above. `ws_tunnels` and `grpc_streams` are incremented
  before the response, and `opened/reused` at dial/checkout, so they need no
  wait; the `e2e_http2` sleeps are pool state, not sampling.

## 6. Audit legs

- **Veyra Proof** — `veyra audit . --profile standard`, verdict **ACCEPTED**,
  exit 0, evidence `.veyra/evidence/20261028T201726Z/`, 646.04 s in tools;
  `cargo-test` OK, nextest **566 passed, 0 failed, 2 skipped**. SKIPPED named:
  `dylint` (no configuration), `cargo-semver-checks` (no baseline);
  `cargo-geiger` INCONCLUSIVE (coverage warnings), as before.
- **Rust Audit** 0.2.7 — exit 0, **0 critical / 0 high**, 242 medium / 83 low;
  report `report/rust-audit-20261028-211923.md`. One finding is new and is
  named here: R08 medium at `tests/common/mod.rs:100` for `wait_for_counter`.
  It is a **false positive for this code**: the `tokio::time::Instant` read is
  the deadline that turns a stuck counter into a test failure with the last
  value instead of a hang, not a wall-clock assertion on behaviour (the
  monotonic clock is the correct one for a deadline).
- **CodeGraph Rust** — index `codegraph-rust index .`: **65 files, 62 547
  lines, 7 073 nodes, 12 782 edges, `graph_complete: true`,
  `vector_index_ready: true`**, `index_ms` 49 656, 0 errors. The **agent
  queries are NOT EXECUTED**: `semantic_code_search` fails with "Vector index
  4 on table `chunks` cannot be searched: entry point element 1946 has no
  vector in this transaction" (24–26 occurrences per impact run).
  `index . --complete-deferred` timed out after 420 s and
  `index . --force` hung at its second pass and was stopped; neither repaired
  the vector index. The advisory answer is therefore not cited as a finding;
  the `file:line` facts in §1 are checked against the source, not taken from
  the graph.
- **Hindsight** — note stored in bank `eqproxy`, exit 0, 8 memory ids; first
  `e9ebe90f-5974-43be-8275-3165cc27b086`.
