# v0.7.0 — Wolfi runtime image, Scout gate and container journeys

## 1. What was asked

The v0.7.0 image must run on **Wolfi** (`cgr.dev/chainguard/wolfi-base`),
pass **Docker Scout with 0 critical / 0 high** on both architectures before
anything is uploaded, and the binary inside must work: version, configuration
gate, state commands and live proxied traffic. Design decision and trade-off:
[ADR-0016](../adr/0016-wolfi-runtime-base.md) (it supersedes the `scratch`
base of [ADR-0005](../adr/0005-container-image-runtime.md)).

## 2. Artifact under test

| | |
|---|---|
| Source tree | this commit, workspace version `0.7.0` |
| Dockerfile | `docker/Dockerfile`, runtime stage `cgr.dev/chainguard/wolfi-base@sha256:360896efb0753a5701c48f860e17130c205eae5a264797aa3e7ea126ee2923a7` |
| Builder stage | `rust:1.97-alpine` (musl), release profile, the Dockerfile's `file` gate requires a static binary |
| arm64 image | `sha256:b0d73bb3739aceaa1fa2cfa25c5dadb1b13b4d39c59c9cfa25255df514743c57` |
| amd64 image | `sha256:aca67ff8b0b1f4de9c0fb2922c436544a52614697eab8fab1d0ea49b664992e8` |
| Host | macOS aarch64 (Apple M2 Max), Docker 29.8.2, buildx 0.37.2, Docker Scout CLI |

Both images were built locally with `--load`; **nothing was pushed** in this
step. `linux/amd64` was built under emulation on the arm64 host.

```bash
# arm64 (native)
docker buildx build --platform linux/arm64 --load \
  -t eqproxy:0.7.0-wolfi-arm64 --file docker/Dockerfile .
# amd64 (emulated; ~25 min for the release build)
docker buildx build --platform linux/amd64 --load \
  -t eqproxy:0.7.0-wolfi-amd64 --file docker/Dockerfile .
```

## 3. Docker Scout — critical/high gate

```bash
docker scout cves --only-severity critical,high --exit-code eqproxy:0.7.0-wolfi-arm64
docker scout cves --only-severity critical,high --exit-code eqproxy:0.7.0-wolfi-amd64
```

| Architecture | Exit | critical | high | medium | low | Packages | Size (Scout) |
|---|---|---|---|---|---|---|---|
| linux/arm64 | **0** | **0** | **0** | **0** | **0** | 36 | 13 MB |
| linux/amd64 | **0** | **0** | **0** | **0** | **0** | 36 | 15 MB |

Both reports state `No vulnerable packages detected`. For reference, the
`scratch` image this replaces reported 0 packages and 0C/0H/0M/0L; the Wolfi
base adds 36 packages (glibc, busybox, `apk-tools`, CA bundle…) and keeps the
same zero. The two reports are kept verbatim in
[`v07-wolfi-image/scout-arm64.txt`](v07-wolfi-image/scout-arm64.txt) and
[`v07-wolfi-image/scout-amd64.txt`](v07-wolfi-image/scout-amd64.txt); both
were re-run after the last build and exited 0.

## 4. Container journeys (both architectures)

Each row was executed twice, once per architecture: `--platform linux/<arch>`
with the image above, the origin a real `nginx:alpine` container on a private
bridge network, and the proxy reached through a published loopback port.

| Journey | arm64 | amd64 |
|---|---|---|
| `eqproxy --version` | `eqproxy 0.7.0` | `eqproxy 0.7.0` |
| Runs as uid 65532 (`nonroot`) | yes | yes |
| `config validate` accepts a good config (stdin) | `config OK: 1 listener(s), 1 backend(s)` | same |
| `config validate` accepts `alpn = ["h2"]` on an http listener (v0.7 change) | accepted with a real self-signed cert | same |
| `config validate` rejects `alpn = ["h3"]` on the TCP table | exit 1, `belongs to the QUIC endpoint` | same |
| `config apply` writes the state directory (was `Permission denied` pre-v0.6.3) | `applied:` | same |
| Live proxied traffic: `curl http://127.0.0.1:<port>/` | **HTTP 200** | **HTTP 200** |
| h2c: `curl --http2-prior-knowledge` | HTTP/2 (`http_version 2`) | HTTP/2 |
| Startup log inside the image | listener banner + METRICS line | same |

The last re-run of the whole table, against the image digests above, exited
**0 on arm64 and 0 on amd64**; the transcripts are
[`e2e-arm64.txt`](v07-wolfi-image/e2e-arm64.txt) and
[`e2e-amd64.txt`](v07-wolfi-image/e2e-amd64.txt).

Commands (the script uses no product code, only the public CLI and HTTP):

```bash
docker run --rm --platform linux/arm64 eqproxy:0.7.0-wolfi-arm64 --version
printf '%s' "$CONFIG" | docker run --rm -i eqproxy:0.7.0-wolfi-arm64 config validate --config /dev/stdin
docker network create --subnet 172.31.7.0/24 wolfi-e2e-arm64
docker run -d --network wolfi-e2e-arm64 --ip 172.31.7.10 --name wolfi-back-arm64 nginx:alpine
docker run -d --network wolfi-e2e-arm64 --ip 172.31.7.20 --name wolfi-prox-arm64 \
  -p 127.0.0.1::18080 -v /tmp/e2e-proxy.toml:/c.toml:ro \
  eqproxy:0.7.0-wolfi-arm64 run --config /c.toml
curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/"            # 200
curl -s -o /dev/null -w '%{http_version}' --http2-prior-knowledge "http://127.0.0.1:$PORT/"  # 2
```

## 5. Release-workflow blocker found and fixed

The release workflow still asserted the **v0.6.3** behaviour in two steps
(`Verify image artifact…` and `Re-pull the published image…`): that
`config validate` **rejects** `alpn = ["h2"]` on an `http` listener with
`ALPN protocol "h2" cannot be served`. v0.7.0 serves h2 there, so validation
now reaches the certificate files and the assertion would have failed the
first tagged release — a real blocker for publishing, not a test to relax.

The steps now:

1. generate a self-signed certificate with `openssl` and assert the gate
   **accepts** `alpn = ["h2"]` on an `http` listener (`config OK`), and
2. keep a negative test with the coding that is still reserved: `alpn = ["h3"]`
   on the TCP table must exit 1 and say `belongs to the QUIC endpoint`.

Both were reproduced locally against both images before editing the workflow,
and the edited workflow was re-read as YAML (see §6).

## 6. Checks executed

```bash
veyra audit . --profile standard                          # ACCEPTED, exit 0, .veyra/evidence/20261024T033509Z/
cargo test --workspace                                    # 424 passed, 0 failed, 2 ignored, 28 suites
cargo run -q -p eqproxy-cli -- --version                  # eqproxy 0.7.0
docker buildx build --platform linux/arm64 --load …       # exit 0
docker buildx build --platform linux/amd64 --load …       # exit 0
docker scout cves --only-severity critical,high --exit-code (both)  # exit 0, 0C/0H
yaml.safe_load(.github/workflows/release.yml)             # 5 jobs: guard, darwin, linux, release, image
docs/evidence/v07-wolfi-image/…                           # scout + e2e transcripts of the re-run
```

The 424-test figure is the `cargo test`/`nextest` result of that Veyra run
(28 suites, 2 ignored: the two Docker-gated harnesses).
```

## 7. Limits and NOT EXECUTED

- The images were **built and tested locally**; the publish, promote and
  re-pull journeys are the release workflow's job and were **not executed**
  here (no tag, no push in this step).
- The two digests in §2 were built **before** the GOAWAY-race fix documented
  in [`v07-http2-session-lifecycle.md`](v07-http2-session-lifecycle.md) §5.1.
  They prove the Wolfi packaging, the Scout gate and the container journeys;
  the release workflow rebuilds both architectures from the final tag and
  re-runs the same journeys, so the published digests differ from these.
- **HTTP/3 inside the container was NOT EXECUTED**: the journeys above cover
  h1 and h2c. h3 is covered by the crate-level E2E suites (`e2e_http3.rs`) and
  the `aioquic`/`quic-go` runs in
  [v07-http3.md](v07-http3.md), not by this image run.
- The amd64 build ran under emulation on an arm64 host; the workflow builds it
  natively. Timings from that build are not representative and are not quoted.
- The image contains Wolfi's glibc even though the binary is static musl and
  does not use it; that is the cost of the requested base
  ([ADR-0016](../adr/0016-wolfi-runtime-base.md)).
- `docker scout cves` results are a point-in-time view of the pinned base
  digest; a newer Wolfi digest can change them, and the workflow re-scans the
  candidate manifest before promoting it.
