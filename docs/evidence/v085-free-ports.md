# v0.8.5 — deterministic test addresses: `free_port()` disappears

The suite reserved its own address in three different ways and the roadmap
carried one of them as "13 calls in 4 files". Measured with
`grep -rn 'free_port' eqproxy-net/tests eqproxy-cli/tests` it is **11 calls in
3 files**: 3 in `e2e_phase2b.rs`, 6 in `e2e_reload.rs`, 2 in `e2e_resilience.rs`
(plus 3 uses of the already-guarded `dead_backend()` at
[`329`](../../eqproxy-net/tests/e2e_resilience.rs#L329),
[`386`](../../eqproxy-net/tests/e2e_resilience.rs#L386) and
[`448`](../../eqproxy-net/tests/e2e_resilience.rs#L448)). The "1 cli" was a test
**name**, [`doctor_passes_for_a_free_port`](../../eqproxy-cli/tests/cli_e2e.rs#L2685),
not a helper call — the count is corrected in the roadmap. The helper is gone
from the tree: every site below now reserves deterministically.

## 1. Two failure modes, three mechanisms

`free_port()` bound `127.0.0.1:0`, read the port and **dropped the listener**.
The port was free at that instant and predictable only until the next bind: a
neighbour test binary (nextest runs them concurrently) could be handed the same
port. As an address that must **refuse**, the neighbour answered and the "dead"
server was alive (run 40724799187: six `200`s with `retry_attempts == 0`). As an
address the proxy must **listen** on, the neighbour held it and the reload
failed with `AddrInUse`. [`tests/common/mod.rs`](../../eqproxy-net/tests/common/mod.rs)
now holds the three answers, each documented with the failure it prevents:

- **[`dead_addr()`](../../eqproxy-net/tests/common/mod.rs#L65)** (7 sites): the
  guard keeps `127.0.0.1:P` bound — the kernel will not hand `P` to another
  `:0` bind — and the handed-out address is `127.0.0.2:P`, where nothing
  listens. One correction measured here: on macOS `127.0.0.2` is connectable
  but **not** a local address, so the SYN is dropped and the connect waits for
  its own timeout; it is *not* an instant refusal. The proxy dial (2 s) and the
  health check (1 s / 50 ms) bound it themselves, and the doc comment no longer
  claims otherwise. `127.0.0.2` cannot be bound on macOS, so it is only ever a
  destination.
- **`BoundProxy::local_addrs()`** (6 reload sites): the listener is configured
  with port 0 and the real address is read back from the socket the kernel
  assigned to *this* proxy. `proxy::apply` keys a kept listener on the
  configured address, so `:0` stays `:0` across a swap
  ([`proxy.rs:1245`](../../eqproxy-net/src/proxy.rs#L1245)). Where the rebind
  test needs a *different* configured address, `[::1]:0` is a distinct key with
  the same guarantee ([`e2e_reload.rs:284`](../../eqproxy-net/tests/e2e_reload.rs#L284)).
- **[`revivable_addr()`](../../eqproxy-net/tests/common/mod.rs#L77)** (1 site,
  [`e2e_phase2b.rs:434`](../../eqproxy-net/tests/e2e_phase2b.rs#L434)): a
  recovery test needs the port closed first (checks fail) and bindable later
  (the origin comes up at the same address). The port comes from below the
  ephemeral range (`20000..20010`), which no `:0` bind can be handed, and the
  **claim is a UDP socket on the same port**: UDP and TCP port spaces are
  independent, so the claim does not open the TCP side the test needs closed,
  and it is exclusive across binaries. The first load run of this increment
  proved the need for it (see §4).

Two contract tests live in the same module so the mechanisms cannot rot
silently: [`dead_addr_never_answers_…`](../../eqproxy-net/tests/common/mod.rs#L90)
(bounded connect must fail, and the guard must reject a second bind of
`127.0.0.1:P`) and
[`revivable_addr_is_closed_and_then_bindable`](../../eqproxy-net/tests/common/mod.rs#L106)
(no TCP answer, two claims get two ports, the test binds it afterwards). They
run in both E2E binaries that include the module.

## 2. The 11 sites, after the change

| Site (before) | Contract | Now |
|---|---|---|
| `e2e_phase2b.rs:438` `healthchecks_e2e` | checks must fail, then the origin rises at the same address | [`revivable_addr`](../../eqproxy-net/tests/e2e_phase2b.rs#L434) |
| `e2e_phase2b.rs:631` `all_servers_down_returns_503_in_http_mode` | dead server | [`dead_addr`](../../eqproxy-net/tests/e2e_phase2b.rs#L627) |
| `e2e_phase2b.rs:683` `all_servers_down_closes_connection_in_tcp_mode` | dead server | [`dead_addr`](../../eqproxy-net/tests/e2e_phase2b.rs#L679) |
| `e2e_reload.rs:111` `hot_swap_…` | proxy listens, reload keeps the socket | [`ephemeral` + read-back](../../eqproxy-net/tests/e2e_reload.rs#L110), kept swap at [`129`](../../eqproxy-net/tests/e2e_reload.rs#L129) |
| `e2e_reload.rs:160` `supervisor_counts_…` | proxy listens; a held port must fail the bad reload | [`169`/`174`](../../eqproxy-net/tests/e2e_reload.rs#L169) |
| `e2e_reload.rs:223-225` `apply_adds_removes_and_rebinds_listeners` | bind, read back, rebind to a new key | [`234`/`239`](../../eqproxy-net/tests/e2e_reload.rs#L234), add [`245`](../../eqproxy-net/tests/e2e_reload.rs#L245), read [`259`](../../eqproxy-net/tests/e2e_reload.rs#L259), rebind [`284`/`298`](../../eqproxy-net/tests/e2e_reload.rs#L284) |
| `e2e_reload.rs:288` `duplicate_addresses_are_rejected_…` | the real address must be a duplicate | [`311`/`316`](../../eqproxy-net/tests/e2e_reload.rs#L311) |
| `e2e_resilience.rs:502` `full_queue_…` | weight-0 server, never dialled | [`dead_addr`](../../eqproxy-net/tests/e2e_resilience.rs#L478) |
| `e2e_resilience.rs:571` `local_response_…` | weight-0 server, never dialled | [`dead_addr`](../../eqproxy-net/tests/e2e_resilience.rs#L549) |
| `dead_backend()` ×3 in `e2e_resilience.rs` | a dial must fail | shared [`dead_addr`](../../eqproxy-net/tests/e2e_resilience.rs#L303) |

No assertion changed. The registry comment of the short-probe gate was updated
to the new mechanism
([`.github/scripts/short-health-probes.txt`](../../.github/scripts/short-health-probes.txt)),
because the two `all_servers_down_*` tests are declared there and their reason
named `free_port()`.

## 3. Local verification (macOS arm64, uid 501)

```
$ cargo fmt --all -- --check                                    # exit 0
$ cargo clippy -p eqproxy-net --all-targets -- -D warnings      # exit 0
$ python3 .github/scripts/check-short-health-probes.py --self-test   # exit 0
$ python3 .github/scripts/check-short-health-probes.py               # exit 0 (18 probes, 2 declared)
$ cargo test -p eqproxy-net --test e2e_phase2b --test e2e_resilience --test e2e_reload
test result: ok. 15 passed; 0 failed  (e2e_phase2b)          finished in 5.07s
test result: ok.  4 passed; 0 failed  (e2e_reload)           finished in 0.09s
test result: ok. 17 passed; 0 failed  (e2e_resilience)       finished in 6.28s
```

Raw: [`final-tree.txt`](v085-free-ports/raw/20261028T191621Z/final-tree.txt)
(the per-target listing, `fmt` and the probe gate in one log) and
[`load-20x.txt`](v085-free-ports/raw/20261028T191621Z/load-20x.txt).

## 4. Under load, and the collision it found

20 repetitions of the three targets with the 10 cores saturated by spinners:
**720 test executions (36 per pass), 0 failures**, load average 300–313
(foreign 200 %-CPU test binaries from another project were also running):

```
[rep 1] exit=0 13s load= 313.29 312.28 316.74  :: 3 targets ok
…
[rep 20] exit=0 14s load= 310.47 310.07 314.57  :: 3 targets ok
fail=0/20
```

Raw: [`load-20x.txt`](v085-free-ports/raw/20261028T191621Z/load-20x.txt).

The first load run of the same tree failed, and the failure is part of the
evidence: repetition 10 died in
`revivable_addr_is_closed_and_then_bindable` with `AddrInUse`, because the
first version of `revivable_addr()` still used probe-and-release and the
`e2e_phase2b` and `e2e_resilience` binaries claimed `20000` at the same time —
the very defect this increment removes, reproduced inside the new helper. The
fix is the UDP claim of §1; the failing raw stays on disk:

```
[rep 10] FAIL 7s load= 304.88 299.38 314.34
panicked at eqproxy-net/tests/common/mod.rs:105:44:
the test must be able to bind it later: Os { code: 48, kind: AddrInUse … }
fail=1/20
```

Raw: [`load-20x-final.txt`](v085-free-ports/raw/20261028T191019Z/load-20x-final.txt).

A second measurement from the same session: the first contract test used an
unbounded `TcpStream::connect` to `127.0.0.2:P` and hung for the macOS default
(75 s) before passing, which is what showed that the "refused at once" wording
was wrong for this platform
([`targets-with-helper-tests.txt`](v085-free-ports/raw/20261028T190649Z/targets-with-helper-tests.txt)).

## 5. Limits and NOT EXECUTED

- **macOS arm64, uid 501 only.** CI, the root tier and Linux behaviour are
  **NOT EXECUTED**: on Linux `127.0.0.2` is a local address, so a connect is
  expected to be refused rather than dropped, but that was not measured here
  and nothing in the tests depends on which of the two happens (both are
  bounded by the caller's timeout).
- **The rebind key needs `[::1]`.** Verified on this machine and on
  `::1`-enabled Linux only in principle; CI runs will confirm. Without an IPv6
  loopback the reload test fails loudly at bind, it does not flake.
- **A foreign process can still take `20000..20010`** before
  `revivable_addr()`'s consumer binds it; the suite cannot, and the panic
  message names the range. Nothing in the tests can stop a non-suite binder.
- **`wait_until_refused` after a listener is removed** (reload tests) still
  asserts a freed port refuses; a foreign binder could theoretically take it in
  that window. It does not use `free_port()` any more; the residual window is
  inherent to asserting a closed socket and is named here rather than hidden.
- No production behaviour changed: the diff is test helpers, three test files
  and one registry comment.

## 6. Audit legs

- **Veyra Proof** — `veyra audit . --profile standard`, verdict **ACCEPTED**,
  exit 0, evidence `.veyra/evidence/20261028T193131Z/`, 811.63 s in tools,
  `cargo-test` OK (562 nextest tests passed, 0 failed, 2 skipped). SKIPPED
  named: `dylint` (no configuration), `cargo-semver-checks` (no baseline);
  `cargo-geiger` INCONCLUSIVE (coverage warnings), as before this increment.
- **Rust Audit** 0.2.7 — exit 0, **0 critical / 0 high**, 241 medium / 85 low;
  report `report/rust-audit-20261028-204604.md`. No finding on
  `tests/common/mod.rs`; the medium findings that mention the touched files are
  the pre-existing `wait_until`/time patterns of `e2e_reload.rs`, unmodified by
  this change.
- **CodeGraph Rust** — `codegraph-rust index . --stats-json
  /tmp/cg-index-v085-ports.json`: **65 files, 62 503 lines, 7 074 nodes,
  12 773 edges, `graph_complete: true`, `vector_index_ready: true`**,
  `index_ms` 212 989, 0 errors. A first attempt hung for more than 10 minutes
  at the embedding step with 0 % CPU while Ollama answered a direct request in
  0.116 s; it was stopped by PID and the retry finished in 213 s — the leg is
  the completed retry, not the hung one. `agent impact` on the two helpers was
  right where checked: 10 call sites (2 of `revivable_addr`, 8 of `dead_addr`)
  across the two binaries and the self-tests, and `mod common` at
  [`e2e_phase2b.rs:22`](../../eqproxy-net/tests/e2e_phase2b.rs#L22) and
  [`e2e_resilience.rs:24`](../../eqproxy-net/tests/e2e_resilience.rs#L24), both
  confirmed in source. `agent context` answered with the **wrong file**
  (`cli_e2e.rs`) and said it could not find the reservation logic; corrected by
  source: the helpers are [`common/mod.rs:65`](../../eqproxy-net/tests/common/mod.rs#L65)
  and [`77`](../../eqproxy-net/tests/common/mod.rs#L77), and the read-backs are
  at [`e2e_reload.rs:117`](../../eqproxy-net/tests/e2e_reload.rs#L117),
  [`174`](../../eqproxy-net/tests/e2e_reload.rs#L174),
  [`239`](../../eqproxy-net/tests/e2e_reload.rs#L239),
  [`259`](../../eqproxy-net/tests/e2e_reload.rs#L259),
  [`298`](../../eqproxy-net/tests/e2e_reload.rs#L298) and
  [`316`](../../eqproxy-net/tests/e2e_reload.rs#L316). Per AGENTS, the advisory
  answer is not repeated as a finding without that check.
- **Hindsight** — note stored in bank `eqproxy`, exit 0, 8 memory ids; first
  `11ea7802-b9b1-40ac-b17d-003c88df2ff4`.
