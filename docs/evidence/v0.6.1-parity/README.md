# Parity report — glibc release binary vs musl container (v0.6.1)

Language: **English**. Same scenario, same host, same backend, same load
generator; the only variable is the runtime pair (glibc + Debian vs static
musl + `scratch`). Measured over **both architectures and both transports**:
`linux/arm64`/`linux/amd64` × HTTP/TLS, 16 measured reps per artifact per cell.

## Why this exists

ADR-0005 moved the published image to a static musl binary on `scratch` to
remove 17 Debian CVEs (4 critical, 13 high) that were not ours. That makes the
container a *different build* from the released glibc binaries, while ADR-0001
keeps performance claims on glibc x86_64. This report closes the question:
**does the container cost anything measurable, on amd64 and with TLS?**

## Artifacts under test

| | glibc | musl |
|---|---|---|
| What ran | the release asset (`eqproxy-linux-arm64` sha256 `5913e60dc7f8…` / `eqproxy-linux-amd64` sha256 `a9308e2029c7…`, the files listed in `SHA256SUMS.txt`), wrapped in its own image | `ghcr.io/exyonq/eqproxy:0.6.1` (index `sha256:ae15bb0f3651c9a76dd5be7b592ae007839ad46883a7c57756c52c2dcd4c4418`) |
| Base | `debian:bookworm-slim` + the asset copied in at build time | `scratch` |
| User | root (Debian default) | `65532:65532` |

Both sides receive the binary **inside an image layer**. An earlier version of
this report bind-mounted the glibc asset from the host; on macOS that is
virtiofs, and deferred page faults of code pages made the glibc side produce
TLS outliers (down to 1 347 rps) and an inflated RSS. The correction is
documented under “Correction” below; superseded summaries are kept in
[`raw/superseded/`](raw/superseded/).

## Environments

| | arm64 | amd64 |
|---|---|---|
| Host | macOS aarch64, Docker Desktop VM | netcup-bench, bare Linux server |
| CPUs / RAM | 10 vCPU / 8 GiB (virtualised) | 8 vCPU / 15 GiB (shared vCPU) |
| Kernel | Docker 29.8.2 VM | 6.8 (Ubuntu 24.04), Docker 29.6.1 |
| `oha` | 1.14.0, run on the host against the published loopback port | same |

Backend and proxy are containers on one bridge network (`172.20.0.0/24`);
`oha` runs on the host. Nothing else runs on the measured host during a block.

## Scenario and protocol

The published S-H1-04 config, unchanged
([s-h1-04-eqproxy.toml](../v06-bench/configs/s-h1-04-eqproxy.toml)): **11
listeners, 200 backend entries, 20 routing rules, HTTP health checks** every
2 s; the backend is one asyncio process answering `200` with a 1 KiB body
([backend.py](backend.py)).

- `oha -z 10s -c 50 --latency-correction`.
- Per block: start the container, wait for a real `200` through it, settle 7 s
  (health checks), discard one 5 s warm-up, then 8 measured reps.
- Blocks run **A B B A** (glibc, musl, musl, glibc) → **16 measured reps per
  artifact**, so drift hits both equally.
- CPU/RSS sampled every second during the window (`docker stats`), median
  reported.
- TLS variant: `[listener.web.tls]` added to the same config with a per-run
  self-signed RSA-2048 leaf (SAN `IP:127.0.0.1,DNS:localhost`), `oha --insecure`.
  The handshake, key exchange and record layer are real; only certificate
  verification by the generator is skipped.
- Significance: two-sided permutation test on the difference of medians
  (20 000 shuffles), computed from the per-rep values.

Reproduce:

```bash
cd docs/evidence/v0.6.1-parity
python3 run.py --binary /path/to/eqproxy-linux-amd64 \
    --config ../v06-bench/configs/s-h1-04-eqproxy.toml --out raw/amd64-http --reps 8 --secs 10
python3 run.py --binary /path/to/eqproxy-linux-amd64 \
    --config ../v06-bench/configs/s-h1-04-eqproxy.toml --out raw/amd64-tls --reps 8 --secs 10 --tls
```

Raw `oha` JSON per rep and the machine summary live in
[`raw/arm64-http/`](raw/arm64-http/), [`raw/arm64-tls/`](raw/arm64-tls/),
[`raw/amd64-http/`](raw/amd64-http/), [`raw/amd64-tls/`](raw/amd64-tls/).

## Results — medians of 16 reps

| Cell | glibc | musl | musl − glibc | p | p50 | p95 | RSS |
|---|---|---|---|---|---|---|---|
| **arm64 HTTP** | 8 543 rps | 8 681 rps | **+1.6 %** | 0.51 | 4.00 → 4.02 ms | 10.78 → 10.34 ms | 6.6 / 6.5 MiB |
| **arm64 TLS** | 7 272 rps | 7 418 rps | **+2.0 %** | 0.68 | 4.37 → 4.43 ms | 12.81 → 12.21 ms | 7.2 / 7.2 MiB |
| **amd64 HTTP** | 13 003 rps | 13 802 rps | **+6.2 %** | 0.062 | 3.62 → 3.43 ms | 6.15 → 5.57 ms | 5.3 / 5.4 MiB |
| **amd64 TLS** | 13 323 rps | 14 129 rps | **+6.0 %** | 0.027 | 3.53 → 3.40 ms | 5.91 → 5.20 ms | 6.1 / 6.2 MiB |

Every cell: `successRate = 1.0`, **every response a `200`**, 16 reps each.
Proxy CPU medians track load, not runtime: 344 % / 314 % (arm64 HTTP),
363 % / 385 % (arm64 TLS), 288 % / 278 % (amd64 HTTP), 296 % / 297 % (amd64 TLS).
Per-run throughput ranges: arm64 HTTP 7 327–9 615 / 8 072–9 146; arm64 TLS
4 648–8 916 / 5 064–8 353; amd64 HTTP 12 002–14 711 / 12 078–15 614; amd64 TLS
10 449–16 302 / 12 906–15 294.

## Interpretation

- **Parity within measurement noise on three of four cells.** On arm64 (HTTP
  and TLS) the difference is +1.6 % / +2.0 % with p = 0.51 / 0.68: no evidence
  of any difference. TLS costs ~15 % throughput on both artifacts equally, as
  expected from per-connection handshakes.
- **On amd64 musl is ahead by ~6 %** (p = 0.062 in HTTP, 0.027 in TLS): the TLS
  cell is statistically distinguishable, the HTTP cell is not at the 5 % level.
  Even so, this is one campaign on a shared-vCPU host.
- **The sign is not stable across campaigns.** The same amd64 host, measured
  earlier with the glibc asset bind-mounted, gave the opposite direction
  (−3.2 % HTTP, −5.0 % TLS) while its absolute throughput was 10–15 % higher.
  A campaign-to-campaign swing larger than the effect means no directional
  claim is defensible: what these runs support is **“the container is not
  meaningfully slower”**, not “musl is faster”.
- **Memory is at parity** (6.5–6.6, 7.2, 5.3–5.4, 6.1–6.2 MiB). The −40 % RSS
  reported in the first version of this document was an artifact of the
  bind mount and is withdrawn.
- **No errors on either side**: no timeouts, no 5xx, no connection failures at
  `-c 50` in 128 measured reps.

## Correction (methodology, 2026-10-20)

The first version of this report measured only arm64 HTTP and bind-mounted the
glibc asset. Adding amd64 and TLS exposed two artifacts of that method:

1. **TLS outliers on the glibc side only** (4 747 rps in one rep, 1 347 in
   another attempt) while the musl side stayed tight — the signature of code
   pages being faulted through virtiofs on first use, which a bind mount pays
   and an image layer does not.
2. **RSS 10.8 vs 6.5 MiB**, which disappeared (6.6 vs 6.5) once the binary was
   copied into an image.

Both were fixed by wrapping the asset in `FROM debian:bookworm-slim; COPY …`
and re-running every cell. Superseded summaries are kept in
[`raw/superseded/`](raw/superseded/) so the correction can be audited; the
earlier numbers are **not** used in the tables above.

## Limits (declared, not hidden)

- **TLS here is termination only**: no backend TLS, no mTLS, no ALPN/HTTP2;
  the leaf is a per-run self-signed RSA-2048 certificate and `oha --insecure`
  skips verification (the handshake itself is real). ECDSA/1.3-only
  configurations and session resumption rates are not covered.
- **One concurrency point** (`-c 50`, the one the project's S-H1-04 evidence
  uses); no sweep.
- **`oha` 1.14.0** here vs 1.16.0 in the published benchmark campaign: absolute
  rps are **not** comparable with [`docs/evidence/v06-bench/`](../v06-bench/) —
  only the musl/glibc ratio in this report is.
- **arm64 is a Docker Desktop VM**, amd64 is a shared-vCPU server without CPU
  affinity; neither is a dedicated benchmark host. The absolute numbers vary
  between campaigns by more than the measured differences (shown above).
- **S-H1-05** (500 backends) and long-run soak are not repeated here; they
  belong to the version's benchmark plan, not to this parity question.
- The glibc side runs as root, the musl image as `65532`; kernel paths are the
  same and the difference is noted for completeness.
