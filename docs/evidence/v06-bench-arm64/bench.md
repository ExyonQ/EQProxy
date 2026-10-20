# v0.6 benchmarks S-H1-04/05 — repetición arm64 (segunda arquitectura)

Campaign repeated verbatim on the second supported architecture to validate
the gaps measured on amd64. Methodology identical to the canonical amd64
runs ([../v06-bench/report.json](../v06-bench/report.json)): same harness
(`scripts/bench_v06.py` + `bench_v06_backends.py`, maintainer-local), same
source tree, same oha version and flags, 5 reps × 10 s measured + one
discarded warm-up per run, alternating order per rep, CPU/RSS sampled per
run.

## Disclosure (from `report.json` §disclosure)

| Field | Value |
|---|---|
| Date (UTC) | 2026-10-19T12:17:33Z |
| Host | oracle-quasar · aarch64 · 4 vCPU · 23 GiB · Linux 6.17.0-1018-oracle-aarch64 · Docker 29.1.3 |
| CPU | aarch64 (Oracle Ampere; `/proc/cpuinfo` exposes no `model name`) |
| Source tree | `3e21f28+uncommitted-session-tree` (same label as the amd64 campaign) |
| EQProxy image | `eqproxy-bench:v06`, id `2cd6eb3aca8b` (built in-situ by the harness from `docker/Dockerfile`) |
| HAProxy image | `haproxy:3.4.6`, id `e273915691a8` (same image id as amd64) |
| Generator | `oha 1.16.0 -z 10s -c 50 --no-tui --output-format json --latency-correction` |
| Runs | 20/20, 100 % HTTP 200, no exclusions, no failed runs |

## Results (medians of 5, arm64)

| Scenario | Product | req/s | p50 ms | p95 ms | p99 ms | CPU %1core | RSS |
|---|---|---|---|---|---|---|---|
| S-H1-04 | EQProxy | 12 761.6 | 3.683 | 5.794 | 7.811 | 104.1 | 11.0 MiB |
| S-H1-04 | HAProxy | 11 094.9 | 4.053 | 8.002 | 12.670 | 97.5 | 48.9 MiB |
| S-H1-05 | EQProxy | 13 025.4 | 3.561 | 5.627 | 7.554 | 103.5 | 20.1 MiB |
| S-H1-05 | HAProxy | 10 014.5 | 4.496 | 8.524 | 14.365 | 101.3 | 51.8 MiB |

Gaps (arm64, medians): S-H1-04 `rps_eq/hap` **1.150**, e2e p50/p95/p99
**1.10× / 1.38× / 1.62×**; S-H1-05 `rps_eq/hap` **1.301**, e2e
**1.26× / 1.52× / 1.90×**. Ratios > 1 favour EQProxy (lower latency /
higher throughput).

## Cross-architecture comparison (median of 5 per cell)

| Metric | S-H1-04 amd64 | S-H1-04 arm64 | S-H1-05 amd64 | S-H1-05 arm64 |
|---|---|---|---|---|
| `rps_eq_over_ha` | 1.141 | 1.150 | 4.507 | 1.301 |
| e2e p50 `ha/eq` | 1.071 | 1.100 | 3.272 | 1.263 |
| e2e p95 `ha/eq` | 1.330 | 1.381 | 6.085 | 1.515 |
| e2e p99 `ha/eq` | 1.280 | 1.622 | 12.542 | 1.902 |
| EQProxy req/s | 18 207.3 | 12 761.6 | 15 624.5 | 13 025.4 |
| HAProxy req/s | 15 957.3 | 11 094.9 | 3 466.5 | 10 014.5 |

### Conclusions

1. **S-H1-04 gap validated on both architectures.** rps ratio 1.141 →
   1.150 and e2e p95 gap 1.33× → 1.38× replicate within noise across an
   x86-64 EPYC (8 vCPU) and an Ampere aarch64 (4 vCPU).
2. **S-H1-05 direction holds; magnitude is host-dependent.** EQProxy leads
   on both, but the amd64 4.51× rps factor is **not universal**: it is
   driven by HAProxy's weak S-H1-05 on that host (3 466 req/s at 88.6 % of
   one core — not CPU-bound) versus 10 014 req/s at 101 % on arm64.
   EQProxy is comparatively stable across hosts (15 625 → 13 025 req/s,
   consistent with the 8→4 vCPU change). Cross-arch claims for S-H1-05
   must therefore quote per-host factors, not a single global ratio.
3. Both products are ~one-core bound at `-c 50` on arm64 (CPU %1core
   ≈ 100): the ratio at higher concurrency or wider hosts is unmeasured.

## Integrity

- Medians recomputed from the 20 raw oha JSONs and squared with
  `report.json` summaries (all metrics match exactly).
- Every measured run reports `statusCodeDistribution == {"200": 1…}`;
  no run excluded, no retries, no failed runs.
- Raw oha JSON per repetition in [`raw/`](raw/), generated configs in
  [`configs/`](configs/), full campaign log in [`run.log`](run.log),
  complete disclosure + summaries + gaps in [`report.json`](report.json).

## Reproduce

```bash
# on oracle-quasar (alias from SERVIDORES.md), from the synced tree
OHA_BIN=$HOME/bin/oha REPS=5 OHA_SECS=10 \
  python3 scripts/bench_v06.py --commit "<tree label>" --out ~/bench-v06-arm64
# oha 1.16.0 arm64 binary: github.com/hatoo/oha/releases/download/v1.16.0/oha-linux-arm64
```
