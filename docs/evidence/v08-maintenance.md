# B8/H3 — the `maintenance` window closes what is ours, v0.8

Language: **English**.

**Increment:** the pending half of [ADR-0018](../adr/0018-first-write-path-server-state.md)
("drain is not maintenance yet") — the third per-server administration state,
`maintenance`, decided in [ADR-0028](../adr/0028-maintenance-closes-the-idle-pool.md).

`drain` removes a server from new selections and lets in-flight exchanges
finish, but it leaves the server's **idle pooled connections** where they are:
EQProxy's keep-alive pool and its backend HTTP/2 session keep sockets parked on
a box that an operator is about to patch. `maintenance` is the same removal
**plus** closing that idle material at the transition, and refusing to park
anything on the slot afterwards. Nothing of ours stays on the server.

| Piece | Where |
|---|---|
| Third state (`ready`/`drain`/`maintenance`, exact wire names) | [balancer.rs:52](eqproxy-net/src/balancer.rs#L52) |
| Selection: a removed slot is never picked | [balancer.rs:1412](eqproxy-net/src/balancer.rs#L1412) |
| Transition closes the h1 pool and the backend h2 session | [admin.rs:1890](eqproxy-net/src/admin.rs#L1890) |
| A finished exchange is never re-parked on a maintenance slot | [http1.rs:2567](eqproxy-net/src/http1.rs#L2567) |
| h2 session removed from the hub, closed when its last stream ends | [backend_h2.rs:413](eqproxy-net/src/backend_h2.rs#L413) |
| Window opening is an event, not a poll | [balancer.rs:336](eqproxy-net/src/balancer.rs#L336) |
| Gauge `eqproxy_backend_servers_maintenance` (label-free) | [admin.rs:1687](eqproxy-net/src/admin.rs#L1687) |
| Unit tests | [admin.rs:2454](eqproxy-net/src/admin.rs#L2454), [balancer.rs:1463](eqproxy-net/src/balancer.rs#L1463) |
| E2E of the h2 session | [e2e_backend_h2.rs:1140](eqproxy-net/tests/e2e_backend_h2.rs#L1140), [:1215](eqproxy-net/tests/e2e_backend_h2.rs#L1215) |
| E2E of the wire route | [e2e_admin.rs:433](eqproxy-net/tests/e2e_admin.rs#L433) (`write_roles_and_bodies_are_enforced_over_the_wire`, real admin socket) |

## Binary under test

- `target/release/eqproxy`, `eqproxy 0.7.0`, sha256
  `47fff1c8cef6193640d3cecbba166b7dbd1f84bf5c5acf392d42b9adb0279c9c`
  (`cargo build --release -p eqproxy-cli`, `--release`, final tree of the
  increment). The journey was first run against the previous build
  (`c532bd1c…`, `raw/run-20261026T230424Z/`) and repeated after the rebuild
  that added the panel wiring; both runs are on disk and agree on every
  phase.
- Host: macOS 26.5.1 arm64 (Darwin), `python3.13`.
- Journey: [`scripts/evidence/v08-maintenance/journey.py`](../../scripts/evidence/v08-maintenance/journey.py)
  (local-only harness, per the `docs/` rule), run from the repository root.
- Raw run: [`docs/evidence/v08-maintenance/raw/run-20261027T003548Z/`](v08-maintenance/raw/run-20261027T003548Z/)
  — `journey.txt` (transcript), `eqproxy.toml` (exact config), `eqproxy.log`
  (the proxy's own log, `AUDIT` lines included), `status.json`, `metrics.txt`.

## Command

```console
$ python3.13 scripts/evidence/v08-maintenance/journey.py
binary: /Volumes/Lexar/Cursor/EQProxy/target/release/eqproxy
version: eqproxy 0.7.0
sha256: 47fff1c8cef6193640d3cecbba166b7dbd1f84bf5c5acf392d42b9adb0279c9c  target/release/eqproxy
dataplane 127.0.0.1:49177 · admin 127.0.0.1:49178
primary 127.0.0.1:49175 · spare 127.0.0.1:49176
```

Exit code **0**, 23 `PASS`, 0 `FAIL`, last line `ALL PASS`.

## What the journey observed (and what it does not prove)

Each line below is from the raw `journey.txt`; the origin is a real HTTP/1.1
server that counts **its own** open connections, so "the pool was closed" is
the server's observation, not the proxy's word.

1. **A connection is parked on the primary before the window.** The client
   keeps one keep-alive connection open; the origin reports `open: 1` for the
   proxy's own socket.

   ```
   PASS the proxy parked a keep-alive connection on the primary: {'open': 1, 'served': 1}
   PASS the slot starts ready and undrained: {'state': 'ready', 'active': 0, 'drained': False, …}
   ```

2. **`maintenance` closes it at the transition** — the interesting half:

   ```
   PASS the idle pooled connection is closed, not left parked: {'open': 0}
   PASS the client connection survives the window: (200, 'spare')
   ```

   The client's connection was never touched; only the freed backend socket
   disappeared. A `drain` leaves it open (ADR-0028's reason to exist).

3. **The slot takes no new exchange**, and the answer says so:

   ```
   PASS the whole tier moves to the other server: ['spare', 'spare', …]
   PASS the maintenance slot serves nothing: {'served': 1, 'before': 1}
   PASS status reports the window: {'state': 'maintenance', 'active': 0, 'drained': True, …}
   PASS metrics count one maintenance slot: 1
   PASS metrics count no drain completion: 0
   ```

   The last two are the published contract: the window has its own gauge and
   **no** `drains_completed_total`, so the existing drain metric keeps one
   meaning.

4. **An in-flight exchange is never cut.** With a held response mid-exchange:

   ```
   PASS the window opens with the exchange still running: (200, {'state': 'maintenance', 'active': 1, 'drained': False, …})
   PASS the client still got its answer: {'expected': 'spare', 'answers': {'spare': 200}}
   PASS the window opens when the last exchange ends: {'state': 'maintenance', 'active': 0, 'drained': True, …}
   PASS the finished exchange is not parked on the maintenance slot: {'open': 0}
   PASS the log names the window opening: [… 'INFO server ready for maintenance: backend=api target=127.0.0.1:49176 active=0']
   PASS no drain completion was invented: []
   ```

   The log line is written where the last guard drops, not by a timer
   (ADR-0024's pattern reused for the window).

5. **`ready` restores rotation** and the gauge falls back:

   ```
   PASS ready is accepted on primary: (200, {'state': 'ready', …})
   PASS ready is accepted on spare: (200, {'state': 'ready', …})
   PASS the gauge goes back to zero: 0
   PASS the recovered slot serves again: {'label': 'spare', 'served': 13}
   ```

## Tests that cover what the journey does not

- **Backend HTTP/2 sessions**: two E2E cases with a real h2 origin —
  an idle session ends **at once** ([e2e_backend_h2.rs:1140](eqproxy-net/tests/e2e_backend_h2.rs#L1140))
  and an in-flight stream is cut loose only when it ends
  ([:1215](eqproxy-net/tests/e2e_backend_h2.rs#L1215)).
- **The wire route** (role, refusal of a browser origin, declared media type,
  body bound, idempotence, status publication) is covered over a real admin
  socket at [e2e_admin.rs:433](eqproxy-net/tests/e2e_admin.rs#L433) with the
  debug profile; this page is the release-binary run of the same route.
- **State round trip and gauge** are unit-tested in
  [admin.rs:2454](eqproxy-net/src/admin.rs#L2454) and
  [balancer.rs:1463](eqproxy-net/src/balancer.rs#L1463) (completion is **not** a
  drain completion).

## Not executed in this run

- **h2/h3/TCP/gRPC maintenance cases against the release binary**:
  **NOT EXECUTED**. The h2 session close has its own E2E on the debug profile;
  h3/gRPC/TCP ride the same per-slot state (`ServerModes`) and were not driven
  through the release journey. No claim of protocol-level coverage is made from
  this page beyond the h2 E2E named above.
- **Docker image / Docker Scout**: **NOT EXECUTED** — nothing is published
  here.
- **The deeper audit legs** (`cargo --deep`, `--supply-chain`, `--miri`,
  `scan --online`): covered by the increment's audit table, not by this page.

## Limitations

- The journey observes the **h1 pool** socket and the slot state. The h2
  session close is proven by the E2E above, not by this script.
- The idle-connection observation depends on the proxy having parked a
  connection; the journey asserts that precondition (`open: 1`) before it
  asserts the closure, so a run where nothing was parked fails instead of
  passing vacuously.
- The first run of this harness (`raw/run-20261026T225819Z/`) failed on two
  **harness** bugs (an answer map keyed by origin label rather than target, and
  a gauge read while the second server was still in maintenance). Both were
  fixed in the harness and the run was repeated; no product code changed
  between the two runs. The failing run is left on disk. `run-20261026T225841Z/`
  is green against an intermediate binary; the run cited above is the final
  one.
- A maintenance mark is runtime-only, like every per-server state: it survives
  `SIGHUP` (ADR-0018) but not a restart, and the file is the baseline.
