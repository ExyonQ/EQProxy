# TLS parity — ECDSA termination, session resumption and HTTP/2 (v0.6.2)

Language: **English**. Date: 2026-10-21. Artifacts under test: a **glibc build
made for this report** and the **published static musl release binary**, both
running inside the *same* `debian:bookworm-slim` image so the only variable is
the libc the binary was linked against.

## 0. Why this report exists, and a correction

The [v0.6.1 parity report](../v0.6.1-parity/README.md) called one column
"glibc", but that column ran the **release asset**, which is a static musl
build (`docker/Dockerfile` builds from `rust:1.97-alpine`). Both columns were
the same binary in different images: the experiment measured the image base
(Debian vs `scratch`) and the user (root vs `65532`), **not** libc. An erratum
now sits at the top of that report; its "no measurable cost" conclusion is
about packaging, and it never was a glibc-vs-musl result.

This report does the libc comparison properly, over the three TLS dimensions
that were still unmeasured:

1. **ECDSA P-256 termination** under load.
2. **Session resumption** (TLS 1.2 and TLS 1.3).
3. **HTTP/2** — which turns out not to be a parity question at all.

## 1. Artifacts

| | glibc build | musl build |
|---|---|---|
| Origin | `cargo build --release --locked -p eqproxy-cli` in `rust:1.97-bookworm`, native on each host | `eqproxy-linux-{arm64,amd64}` from the [v0.6.2 release](https://github.com/ExyonQ/EQProxy/releases/tag/v0.6.2) |
| Linkage | dynamic (`libc.so.6`, `libgcc_s.so.1`, `libm.so.6`) | static (`readelf`: 0 `NEEDED`, 0 `PT_INTERP`) |
| sha256 arm64 | `3efb27856a4a4fb6fef9f5f508018db5c0bcd5cf77d512623fad3885a8d87e8f` | `ec1139be4dd5893b769ccbd812b643c3ef25fde1e588312be102b0b376f822e1` |
| sha256 amd64 | `d0af1d1ba977963e42d5c6daa6383b74f7a7db637e28965a4779fe0764bfd540` | `337c114b5324aa7c5407df614b5b6af5c6adbedde028700f647e1ca0cac83a26` |
| Runtime image | `debian:bookworm-slim` | `debian:bookworm-slim` (same base, so the libc is the variable) |

Note what this implies: the project only **publishes** musl binaries, so the
glibc build benchmarked by CI is not what a user downloads.

## 2. Environments

| | arm64 | amd64 |
|---|---|---|
| Host | macOS aarch64, Docker Desktop VM (10 vCPU / 8 GiB) | `netcup-bench`, Ubuntu 24.04, 8 vCPU / 15 GiB (shared) |
| Load generator | `oha` 1.14.0 on the host, `-z 10s -c 50 --latency-correction --insecure` | same |
| TLS probes | `openssl` 3.0.22 in `debian:bookworm-slim`, `curl` 7.88 | same |
| Certificate | ECDSA P-256, self-signed, `CN=localhost` + `SAN localhost,127.0.0.1`, generated per run | same |
| Listener | `alpn = ["http/1.1"]`, TLS 1.2+ (default), ECDSA leaf | same |

## 3. ECDSA termination under load (A B B A blocks)

Six measured reps per block, four blocks per architecture, order
**glibc → musl → musl → glibc**, all reps of a block in one container start:

| Architecture | glibc | musl | Δ musl | p (permutation) | p50 glibc → musl | p95 glibc → musl |
|---|---|---|---|---|---|---|
| arm64 | 9 756 rps | 9 522 rps | **−2.4 %** | 0.278 | 4.32 → 4.47 ms | 9.11 → 9.40 ms |
| amd64 | 27 423 rps | 21 919 rps | **−20.1 %** | **0.001** | 1.65 → 2.08 ms | 3.39 → 4.14 ms |

Every amd64 block agrees on the direction (glibc 29 127 and 26 811 in the two
A blocks; musl 22 896 and 21 484 in the two B blocks), every response a `200`
with `successRate = 1.0`.

### Is that TLS, or is it the libc in general? (control, no TLS)

The same A B B A design with a **plain HTTP** listener on the same amd64 host:

| amd64, no TLS | glibc | musl | Δ musl | p |
|---|---|---|---|---|
| Throughput | 27 260 rps | 24 290 rps | **−10.9 %** | 0.0001 |
| p50 | 1.65 ms | 1.89 ms | | |

So on this host the musl build is ~11 % behind **without any handshake**, and
~20 % behind with ECDSA TLS at `-c 50`. The gap is not a TLS or crypto cost;
TLS roughly doubles it, which fits allocation-heavy per-connection work on top
of a slower allocator, but that explanation is a hypothesis, not something this
run isolates.

## 4. Session resumption

`openssl s_time` reconnect rate (median of 5 × 5 s), plus the decisive check:
save the session with `-sess_out`, reconnect with `-sess_in`, and read whether
the server resumed it.

| | TLS 1.2 full | TLS 1.2 resumed | ratio | TLS 1.3 full | TLS 1.3 "reuse" | session replay |
|---|---|---|---|---|---|---|
| arm64 glibc | 3 134/s | 8 322/s | 2.7× | 3 578/s | 6 287/s | TLS 1.2 `Reused` · TLS 1.3 **no session saved** |
| arm64 musl | 3 551/s | 9 023/s | 2.5× | 3 310/s | 5 737/s | same |
| amd64 glibc | 2 113/s | 6 880/s | 3.3× | 2 181/s | 4 331/s | same |
| amd64 musl | 1 948/s | 5 875/s | 3.0× | 2 059/s | 3 972/s | same |

**TLS 1.2 resumes; TLS 1.3 does not.** The client cannot save a session after a
TLS 1.3 handshake (`-sess_out` produces no file), which is what a server that
sends no `NewSessionTicket` looks like. That matches the code: `tls.rs` sets no
`ticketer`, and rustls without one issues no TLS 1.3 tickets, while TLS 1.2
resumption works through its default in-memory session cache. The higher
TLS 1.3 "reuse" number is the tool's reconnect loop, **not** resumption — there
is no session to resume, so do not read it as a PSK handshake.

Parity: the direction is not consistent between architectures (arm64: musl
faster on full handshakes; amd64: glibc faster), so handshake-rate differences
between the two builds are within the noise of a single 5 s sample chain. The
capability gap is identical in both builds, which is expected: it comes from
the TLS configuration, not from libc.

## 5. HTTP/2

EQProxy is an HTTP/1.1 proxy (`eqproxy-net/src/http1.rs`); there is no HTTP/2
frame parser. That is a capability gap, not a parity cell, and it has a
configurable foot-gun:

| Probe | Result |
|---|---|
| Listener `alpn = ["http/1.1"]`, client offers only `h2` | TLS alert `no application protocol` (correct RFC 7301 behaviour) |
| Listener `alpn = ["http/1.1"]`, `curl --http2` (offers `h2,http/1.1`) | `http_version=1.1`, `200` — falls back cleanly |
| Listener **`alpn = ["h2"]`**, `openssl s_client -alpn h2` | handshake succeeds, **`ALPN protocol: h2`** |
| …then `curl --http2` to that listener | **fails**: `curl_exit=52`, `http_version=0`, empty reply |
| Proxy counters after those attempts | `client[accepted=0 …]` — the h2 preface is never counted as a client |

So a listener configured with `alpn = ["h2"]` completes a handshake that
promises HTTP/2 and then cannot serve it. The config gate currently accepts
that value. Raw transcript: [`raw/h2-probe.txt`](raw/h2-probe.txt).

## 6. What this changes

- **TLS 1.3 session resumption is missing.** Every TLS 1.3 client — the
  default for curl, browsers, Go, Python 3.10+ — performs a full handshake on
  every connection. Fixing it is a configuration change in `tls.rs`
  (a ticketer), not a protocol feature.
- **`alpn = ["h2"]` should be rejected by the config gate**, or documented as
  unsupported: today it negotiates a protocol the proxy cannot speak.
- **The published binaries are musl**, and on this amd64 host that costs ~11 %
  without TLS and ~20 % with ECDSA TLS against a glibc build of the same
  commit. arm64 shows no distinguishable difference. Either the tier-1
  performance claims apply to an artifact nobody downloads, or the release
  should also ship glibc variants.
- The v0.6.1 report's "glibc" label was wrong; the erratum is in place.

## 7. Limits

- One host per architecture, one concurrency (`-c 50`), one certificate type
  (ECDSA P-256), self-signed, HTTP/1.1 only.
- The glibc builds are native `cargo build --release` of the same commit; they
  are not the artifacts CI would ship (it ships musl), so this is a property of
  the code + libc, not of a published artifact.
- Handshake rates are medians of five 5 s samples per label — enough to show
  the resumption capability, not enough for a precise rps comparison.
- The macOS client `curl`/`openssl` (LibreSSL 3.3.6) cannot complete a TLS 1.3
  handshake here **against nginx either**, so all TLS 1.3 probing was done from
  a Debian OpenSSL 3.0 container. It is a client limitation, not an EQProxy
  finding.

## 8. Reproduce

```bash
# build a glibc binary for the host architecture
docker run --rm -v "$PWD":/src:ro -w /src -e CARGO_TARGET_DIR=/out \
  -v eqglibc:/out rust:1.97-bookworm cargo build --release --locked -p eqproxy-cli

# the harness is maintainer-local; --out is the path you want the JSON in
python3 scripts/evidence/v0.6.2-tls-parity/run.py --binary /path/to/eqproxy \
  --label glibc --arch amd64 --out docs/evidence/v0.6.2-tls-parity/raw/glibc-amd64.json
python3 scripts/evidence/v0.6.2-tls-parity/run.py --binary /path/to/eqproxy-linux-amd64 \
  --label musl --arch amd64 --out docs/evidence/v0.6.2-tls-parity/raw/musl-amd64.json

# interleaved blocks (what the tables above use)
for block in 1 2 3 4; do
  case $block in 1|4) label=glibc ;; 2|3) label=musl ;; esac
  python3 scripts/evidence/v0.6.2-tls-parity/run.py --binary /path/to/$label \
    --label $label --arch amd64 --reps 6 --skip-handshakes \
    --out docs/evidence/v0.6.2-tls-parity/raw/blocks/block${block}-${label}.json
done

# control: same, without TLS
python3 scripts/evidence/v0.6.2-tls-parity/run.py --binary /path/to/$label \
  --label $label --arch amd64 --plain --reps 6 --skip-handshakes \
  --out docs/evidence/v0.6.2-tls-parity/raw/blocks/plain${block}-${label}.json
```

Raw data: `raw/{glibc,musl}-{arm64,amd64}.json` (load + handshakes +
capabilities), `raw/blocks/` (the A B B A runs and the plain-HTTP control),
`raw/h2-probe.txt`.
