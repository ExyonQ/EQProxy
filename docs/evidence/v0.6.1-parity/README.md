# Parity report — glibc release binary vs musl container (v0.6.1)

Language: **English**. Measured 2026-10-20 on the same host, same scenario,
same backend and same load generator; the only variable is the runtime pair
(glibc + Debian vs static musl + `scratch`).

## Why this exists

ADR-0005 moved the published image to a static musl binary on `scratch` to
remove 17 Debian CVEs (4 critical, 13 high) that were not ours. The container
is therefore a *different build* from the released glibc binaries, and
ADR-0001 keeps performance claims on glibc x86_64. This report answers the
question that leaves open: **does the container lose anything measurable?**
It compared the exact artifacts users get, not a rebuild.

## Artifacts under test

| | glibc | musl |
|---|---|---|
| What ran | the v0.6.1 release asset `eqproxy-linux-arm64` (sha256 `5913e60dc7f87b86c47c54c29c709b399483bf8dfb38e13c656330b1e21bb9dd`, the file from `SHA256SUMS.txt`), mounted read-only | `ghcr.io/exyonq/eqproxy:0.6.1` (index `sha256:ae15bb0f3651c9a76dd5be7b592ae007839ad46883a7c57756c52c2dcd4c4418`, amd64+arm64) |
| Runtime | `debian:bookworm-slim` (the base the v0.6.0 image shipped) | `scratch`, image digest as pulled |
| User | root (Debian default) | `65532:65532` |

## Environment

macOS aarch64 host, Docker 29.8.2 (Docker Desktop Linux VM: **10 vCPU, 8 GiB**),
`oha 1.14.0`, Rust release binaries built by CI. The load generator runs on the
host against a published loopback port; backend, proxy and network are
containers on the same bridge (`172.20.0.0/24`).

## Scenario

The published S-H1-04 config, unchanged
([s-h1-04-eqproxy.toml](../v06-bench/configs/s-h1-04-eqproxy.toml)):
**11 listeners, 200 backend entries, 20 routing rules, HTTP health checks**
every 2 s. Backend: one asyncio process answering `200` with a 1 KiB body on
the ports the config references ([backend.py](backend.py)). Request path `/`,
`oha -z 10s -c 50 --latency-correction`.

Protocol, identical for both artifacts: start the container, wait for the
listener to answer, settle 7 s (health checks), discard one 5 s warm-up, then
**8 measured reps of 10 s**. Blocks run **A B B A** (glibc, musl, musl, glibc),
16 measured reps per artifact, so drift hits both equally. CPU and RSS are
sampled every second during the measured window (`docker stats`) and the
median is reported.

Reproduce:

```bash
cd docs/evidence/v0.6.1-parity
python3 run.py --binary /path/to/eqproxy-linux-arm64 \
    --config ../v06-bench/configs/s-h1-04-eqproxy.toml --out raw --reps 8 --secs 10
```

Raw `oha` JSON for every rep: [`raw/`](raw/), machine summary:
[`raw/summary.json`](raw/summary.json).

## Results (medians of 16 reps)

| Metric | glibc (asset + bookworm) | musl (published image) | musl / glibc |
|---|---|---|---|
| Throughput | **9 798 rps** | **9 643 rps** | **0.984** |
| p50 latency | 3.67 ms | 3.67 ms | 1.000 |
| p95 latency | 8.76 ms | 9.21 ms | 1.051 |
| p99 latency | 38.5 ms | 35.2 ms | 0.914 |
| Proxy CPU (median) | 293 % | 333 % | 1.137 |
| Proxy RSS (median) | 10.8 MiB | **6.5 MiB** | **0.60** |
| Success rate | 1.000 | 1.000 | — |
| Responses | 16 runs, all `200` | 16 runs, all `200` | — |

Per-run throughput spread: glibc **8 579 – 10 769 rps**, musl
**8 579 – 10 437 rps** (≈ ±12 % around the median on both sides).

## Interpretation

- **Parity holds for throughput and median latency.** The medians differ by
  −1.6 % (rps), 0.0 % (p50) and +5 % (p95), all well inside the ±12 % per-run
  spread of this shared Docker Desktop VM. No regression is measured in either
  direction: the 2 % difference is smaller than the noise the host produces
  between consecutive runs of the *same* artifact.
- **Memory improves**, as expected from a static binary with no shared
  libraries: 6.5 MiB vs 10.8 MiB median RSS (−40 %).
- **CPU is inconclusive here**: the median 293 % vs 333 % has no stable
  ordering across blocks (the same artifact varies 199–421 % between reps), and
  the load generator on the host competes for the same cores.
- **Every response was a real `200`** in all 32 measured runs. Each run also
  reports ~50 `aborted due to deadline` — one in-flight request per keep-alive
  connection when the fixed 10 s window closes; `oha` counts them separately
  from errors (`successRate = 1.0`). They are a property of `-z`, not of the
  proxy, and they are identical on both sides.

## Limits (declared, not hidden)

- **One host, one architecture (arm64).** The published benchmark matrix and
  its glibc claims stay on x86_64; this report does not extend them, it only
  shows that the container build does not regress relative to the glibc asset
  on the same machine.
- **Docker Desktop VM** (virtualised network and CPU scheduling), not a bare
  metal host: absolute numbers are lower than the netcup-bench runs and the
  variance is higher. Comparisons between the two artifacts are still valid
  because they share everything.
- **One concurrency point** (`-c 50`), chosen because it is the point the
  project's own S-H1-04 evidence records; a sweep was out of scope.
- **Different `oha`** (1.14.0 here vs 1.16.0 in the published bench), so these
  absolute numbers must not be compared with that evidence.
- The glibc side runs the asset inside `debian:bookworm-slim` **as root**; the
  musl image runs as `65532`. Kernel-side work is the same; the difference is
  noted for completeness.
- **Not measured**: amd64 (this host is arm64; CI builds and verifies the
  amd64 image functionally, not performance), TLS termination, and the S-H1-05
  500-backend scenario.
