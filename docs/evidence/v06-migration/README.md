# Migration gate evidence — `migration_matrix_same_routing_as_the_originals`

Reproduction of the v0.6 gate criterion «migración demostrada»: the four real
source configs of [`docs/migration/`](../../migration/README.md) and their EQProxy
translation route the matrix identically.

## Command

```bash
cargo test -p eqproxy-cli --test migration -- --ignored --nocapture
```

- Date (UTC): 2026-10-20T13:14Z (report epoch 1792502050), repeated after
  `cargo fmt` and the `0.6.0` version pin, i.e. on the exact tree that ships.
- Environment: Darwin 25.5.0 (macOS 26.5.1), arm64, Docker 29.8.2,
  rustc 1.97.1 (8bab26f4f 2026-07-14), cargo 1.97.1, working tree of `main`
  with the v0.6.0 release slice.
- Binary under test: `target/debug/eqproxy`,
  sha256 `31ef7e1004810056745a481aa41de7552feeab846c3bfc332ced37e98f2b0ed3`
  (an earlier identical-verdict run on the pre-pin binary is
  `8fdefe8d…f753c`).
- Originals (container digests in the report): `haproxy:3.4.6`,
  `nginx:alpine`, `registry.k8s.io/ingress-nginx/controller:v1.13.0`,
  `envoyproxy/envoy:v1.34.2`; backends `nginx:alpine`.

## Result

```
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 24.77s
verdict: 13/13 cases route identically across the five implementations (65 checks).
```

The raw harness output is [report.md](report.md) (written unedited by the test;
absolute paths point at the runner's checkout and build tree).

## What this proves, and what it does not

- Proves: for the 13 matrix cases, HAProxy, operator nginx, the ingress-nginx
  data plane (controller-shaped generated config) and Envoy answer exactly what
  EQProxy answers with [eqproxy.toml](../../migration/eqproxy.toml) — asserted
  on status, `Location` (reduced to path + query) and body (which echoes the
  pool and the received path, so pool choice and rewrites are both checked).
- Declared substitutions: the EQProxy translation runs with a free local listen
  address and reaches the five pools through their published host ports; the
  containers use the fixed demo addresses. Nothing else differs.
- Does not prove: the ingress-nginx **controller** object → config translation
  (the generated shapes are what runs), TLS/SNI, WebSocket upgrades, HTTP/2, and
  multi-server balancing per pool. Those keep their own slices (see the
  limitations in [docs/migration/README.md](../../migration/README.md)).
