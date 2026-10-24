# v0.7 slice 4 — backend HTTP/2 session lifecycle inside the image

Language: **English**. Evidence for the container gate of the fourth v0.7
increment, collected on 2026-10-22 (macOS 26 arm64 host, Docker 29.8.2,
buildx 0.37.2, Docker Scout CLI 1.25.0, Python 3.14 + hyper-h2 4.2.0,
curl 8.7.1). Unreleased: the images below are local builds of `b93883e`,
nothing was pushed or tagged.

## 1. Objective

The source-level evidence ([v07-http2-session-lifecycle](v07-http2-session-lifecycle.md))
showed the idle close, the GOAWAY drain and the refusal replay against the
built binary on the host. This run answers the container question the project's
gate asks: **does the artifact we ship behave the same way inside the image,
on linux/amd64 and linux/arm64, and does it pass the Docker Scout gate?**

Journeys: `--version`, `config validate`, `config apply` (state directory),
live proxied traffic through a real TLS+h2 backend, idle close, GOAWAY drain
with a replayed request, and the `RST_STREAM(REFUSED_STREAM)` replay.

## 2. Artifact under test

| Item | Value |
|---|---|
| Commit | `b93883e` (`docs: record the backend HTTP/2 session lifecycle slice`; code in `34a5925`) |
| Build | `docker buildx build --file docker/Dockerfile --platform linux/<arch> --load -t eqproxy-local:v07-<arch> .` |
| `linux/arm64` | image `sha256:14c026e2ec52cac6a64af8a3ff196bc5f1ba9902f99bbad79d11303954e0378b`, 17 925 201 B |
| `linux/amd64` | image `sha256:cbe6716f82078792194da531390cb61dd59a5704ff4a6dfd90437c4b556a64d0`, 19 805 651 B |
| Version inside | `eqproxy 0.6.3` (the v0.7 slices are unreleased, so the version is still 0.6.3) |
| Host | macOS 26 arm64; amd64 runs under QEMU emulation, not native |

Both builds exit 0. The amd64 build took ~25 min under emulation; the arm64
build 5 min 34 s. Neither is a timing claim about the product.

## 3. Harness

Files in this directory are the harness that was run:

- `origin.py` — the independent **hyper-h2 4.2.0** server over real TLS with
  ALPN `h2` (not the Rust `h2` crate, not a mock). It records every accepted
  session, every requested stream and every answered stream to JSONL. The
  one-shot refusal (`x-refuse: 1`) is the RFC 9113 §8.1.4 case: reset the
  stream with `REFUSED_STREAM`, answer nothing.
- `journey.sh` — starts the origin on the host, runs the proxy **in the
  image** on a user-defined bridge, and drives it with `curl`. The container
  gets `--add-host=host.docker.internal:host-gateway` because this engine has
  no `host.docker.internal` entry by default (the first attempt returned
  `503` with `dns[failures=1]`, which is how the need was found); the backend
  address in the config is `host.docker.internal:<port>`.
- `probe-refused.sh` — the diagnostic in §5.2 (replay latency, repeated).

The proxy is stopped with `docker kill --signal=INT` (SIGINT, the signal the
binary drains on), so the container's final `METRICS` line and
`shutdown complete` are in the captured log. `config apply` runs with the
image's default `EQPROXY_STATE_DIR=/var/lib/eqproxy`.

Two configuration points matter for the journeys: `idle_timeout = "1s"` for
the idle close and `"5s"` for the GOAWAY/refusal journeys (the in-flight
stream holds 1.5 s and must not hit the per-operation inactivity bound).

One harness limitation was found and fixed **in the harness, not the
product**: hyper-h2's server-side `close_connection()` moves its state
machine to `CLOSED` and aborts the streams it had already accepted, so an
origin built on it cannot demonstrate a graceful drain. `origin.py` now puts
the GOAWAY frame on the wire directly (RFC 9113 §6.8, 8-byte payload) and
keeps answering the accepted stream, which is what a real server does. The
first run with `close_connection()` produced the correct
`h2[goaway=1 refused_retried=1]` and replay, but the drained stream timed out
(`502` at 5.009 s); that run is not cited as a pass.

## 4. Journeys and results

Both architectures ran the same harness; `results-<arch>.txt` is the raw
output and `<arch>/` holds the container logs and the origin's JSONL. Each
run ends `=== <arch> failures: 0 ===` with harness exit 0. The logs quoted
below are the arm64 ones; the amd64 records are in `amd64/` and show the same
shape (the deltas are called out where they differ).

| Journey | linux/arm64 | linux/amd64 |
|---|---|---|
| `--version` | `eqproxy 0.6.3`, exit 0 | `eqproxy 0.6.3`, exit 0 |
| `config validate` | `config OK: 1 listener(s), 1 backend(s)` | same |
| `config apply` | `applied: /c.toml -> /var/lib/eqproxy/current.toml`, exit 0 | same |
| J1 idle close | PASS (all 8 checks) | PASS (all 8 checks) |
| J2 GOAWAY drain + replay | PASS (all 13 checks) | PASS (all 13 checks) |
| J3 REFUSED_STREAM replay | PASS (all 8 checks) | PASS (all 8 checks) |

### 4.1 J1 — idle close (`idle_timeout = "1s"`)

Two requests 2.2 s apart, through the container:

```
first:      200 ok:first
after-idle: 200 ok:after-idle

proxy (container log):
INFO listener web listening on 0.0.0.0:28081
INFO [web] closed an idle HTTP/2 session to 192.168.65.254:28471 after 1s
METRICS … backend[connect_failures=0 tls_failures=0 discarded=0 reused=0 opened=2 proxied=2]
        … h2[sessions_idle_closed=1 goaway=0 refused_retried=0] (final)

origin (JSONL, order preserved; `t`, `method` and `path` elided):
{"session_opened": 1}
{"connection": 1, "stream": 1, "x_req": "first", "phase": "answered"}
{"session_closed": 1}
{"session_opened": 2}
{"connection": 2, "stream": 1, "x_req": "after-idle", "phase": "answered"}
{"session_closed": 2}
```

The origin sees the first session closed **before** the second is dialed, the
second request lands on connection 2, and the proxy counts exactly one idle
close. Identical records on amd64.

### 4.2 J2 — GOAWAY drain and replay (`idle_timeout = "5s"`)

Warm request, a 1.5 s in-flight request, `/goaway`, then a request sent
200 ms later while the drained session still has the in-flight stream:

```
warm:            200 ok:warm
inflight:        200 ok:inflight time=1.508992s   (the hold is 1.5 s)
goaway:          200 ok:g1
after-goaway:    200 ok:after-goaway time=0.013092s

origin:
{"session_opened": 1}
{"connection": 1, "stream": 1, "x_req": "warm", "phase": "answered"}
{"connection": 1, "stream": 3, "x_req": "inflight", "phase": "start"}
{"connection": 1, "stream": 5, "x_req": "g1"}
{"connection": 1, "goaway_sent": 5}
{"session_opened": 2}
{"connection": 2, "stream": 1, "x_req": "after-goaway", "phase": "answered"}
{"connection": 1, "stream": 3, "x_req": "inflight", "phase": "end", "held_ms": 1500}
{"connection": 1, "stream": 3, "x_req": "inflight", "phase": "answered"}
{"session_closed": 1}

proxy:
WARN [web] backend 192.168.65.254:28471 is closing its HTTP/2 session (GOAWAY):
     in-flight streams drain, new exchanges dial a fresh session
METRICS … backend[connect_failures=0 … reused=3 opened=2 proxied=4]
        h2[sessions_idle_closed=0 goaway=1 refused_retried=1] (final)
```

Three properties are checked from the records, not from the exit code:

1. the in-flight stream is **answered after** the GOAWAY was sent (`end` and
   `answered` lines follow `goaway_sent`), and session 1 closes only after
   that — the drain does not cut admitted work;
2. `after-goaway` has **exactly one** answered record and it is on
   **connection 2**, so the request the drained session refused was replayed
   once, on a fresh session, and not run twice on connection 1;
3. `h2[goaway=1 refused_retried=1]` and `opened=2`.

amd64: identical shape, `inflight` 200 in 1.551 s, `after-goaway` 200 in
0.077 s, same counters and the same record order.

### 4.3 J3 — `RST_STREAM(REFUSED_STREAM)` replay

The origin refuses the first stream of the first session without reading or
answering it, then serves normally:

```
curl -H 'x-req: replay-me' -H 'x-refuse: 1' …/echo
200 ok:replay-me time=0.074590s      (arm64)
200 ok:replay-me time=4.918627s      (amd64, see §5.2)

origin:
{"session_opened": 1}
{"connection": 1, "stream": 1, "x_req": "replay-me"}
{"connection": 1, "stream": 1, "x_req": "replay-me", "refused": true}
{"session_opened": 2} … {"session_closed": 1}
{"connection": 2, "stream": 1, "x_req": "replay-me", "phase": "answered"}

proxy:
METRICS … backend[… opened=2 proxied=1] h2[sessions_idle_closed=0 goaway=0 refused_retried=1] (final)
```

Exactly one refusal, exactly one answered copy, on the second session: the
client got `200` and the origin saw the work once. `proxied=1` with
`opened=2` is the extra handshake the replay costs.

## 5. Timing notes (not performance evidence)

### 5.1 Emulated amd64

The amd64 image runs under QEMU. No latency or throughput claim is made for
it; the journeys assert behavior, not speed.

### 5.2 Why one amd64 request took ~5 s

In the full run, J3's `curl` reported 4.918 s while the origin answered
230 ms after the refused request. `probe-refused.sh` repeated the journey
three times with fresh origin and proxy per attempt and split the time:

| Attempt | curl total | curl → origin request | request → answered (replay incl. 2nd handshake) |
|---|---|---|---|
| 1 | 1.273 s | 1.213 s | 0.060 s |
| 2 | 2.043 s | 1.980 s | 0.051 s |
| 3 | 1.194 s | 1.136 s | 0.053 s |

The replay itself is 51–60 ms; the variable seconds sit **before** the first
request reaches the origin (the container resolving `host.docker.internal`
and dialing its first TLS session under emulation — the proxy counts
`dns[updates=1]` once per process). The full journey's 4.918 s is the same
shape: the origin answered 230 ms after the refused request. Raw output:
`replay-latency-amd64.txt` (three fresh origin/proxy pairs, one attempt each).

## 6. Docker Scout gate (critical/high = 0)

```
$ docker scout cves --only-severity critical,high --exit-code \
    --platform linux/arm64 eqproxy-local:v07-arm64 ; echo $?
0
$ docker scout cves --only-severity critical,high --exit-code \
    --platform linux/amd64 eqproxy-local:v07-amd64 ; echo $?
0
```

| Platform | Image | Packages | C / H / M / L | Base |
|---|---|---|---|---|
| `linux/arm64` | `sha256:14c026e2…` | 0 | 0 / 0 / 0 / 0 | `rust:1.97-alpine` |
| `linux/amd64` | `sha256:cbe6716f…` | 0 | 0 / 0 / 0 / 0 | `rust:1.97-alpine` |

Full reports: [SCOUT-v07-linux-arm64.md](v07-lifecycle-container/SCOUT-v07-linux-arm64.md)
and [SCOUT-v07-linux-amd64.md](v07-lifecycle-container/SCOUT-v07-linux-amd64.md).
The runtime is `scratch` (0 packages), so the zero means "no OS package was
added to the image", not "the Rust binary has no vulnerability" — the same
caveat as the v0.6.1 and v0.6.3 reports. Scout scanned the **local** images:
there is no pushed index and no registry reference for this unreleased slice.

## 7. Reproduction

```bash
docker buildx build --file docker/Dockerfile --platform linux/arm64 \
  --load -t eqproxy-local:v07-arm64 .
docker buildx build --file docker/Dockerfile --platform linux/amd64 \
  --load -t eqproxy-local:v07-amd64 .          # ~25 min under QEMU on this host

docs/evidence/v07-lifecycle-container/journey.sh \
  eqproxy-local:v07-arm64 arm64 28471 28081 /tmp/lifecycle-arm64
docs/evidence/v07-lifecycle-container/journey.sh \
  eqproxy-local:v07-amd64 amd64 28472 28082 /tmp/lifecycle-amd64
bash docs/evidence/v07-lifecycle-container/probe-refused.sh
```

Each harness run needs the origin's ports (`28471`/`28472`) free and the
proxy port (`28081`/`28082`) unbound; it tears down its container and origin
on the way out.

## 8. Limits of this evidence

- The images are **local builds of `b93883e`**, never pushed. Docker Scout
  scanned the local manifest, not a registry index; promotion and the
  digest-pinned scan belong to the release workflow.
- `linux/amd64` ran under QEMU. Behavior is verified; timing is not.
- The origin is the Python `hyper-h2` implementation. It is independent of the
  Rust `h2` crate and speaks the real protocol over TLS, but it is one
  implementation; interop with nginx/Envoy/Cloudflare is not claimed.
- The GOAWAY frame in the origin is written directly on the socket (see §3);
  the client under test still receives a real GOAWAY on the wire.
- No soak, no repeated-run statistical sample beyond the probe’s three
  attempts, and no throughput/latency figure.
