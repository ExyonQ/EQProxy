# Release v0.6.2 — publication audit

Date: 2026-10-20. Tag `v0.6.2` (commit `2e87aa4`), workflow run
**39494833437** on `push` of the tag. Every check below was run **after**
publication, against the published artifacts, not against the build output.

## 1. Pipeline

The run is the first one produced by the reworked image job. All five jobs
green:

| Job | Result |
|---|---|
| Tag matches the workspace version | success |
| Binaries darwin (build + E2E verify) | success |
| Binaries linux (build + E2E verify) + SBOM | success |
| Multi-arch image (build + Scout both archs + E2E + promote) | success |
| GitHub release (binaries + SHA256SUMS + SBOM + Scout) | success |

Inside the image job, in this order: build and push the candidate index →
record its digest → Docker Scout on `linux/amd64` **and** `linux/arm64` →
container E2E (`--version`, `config validate`, live proxied traffic) on both
architectures → upload the two reports → promote the recorded digest →
mirror to Docker Hub → re-read every published tag and compare its digest.
The release job ran only after that job succeeded.

## 2. Release assets (11)

`eqproxy-darwin-amd64`, `eqproxy-darwin-arm64`, `eqproxy-linux-amd64`,
`eqproxy-linux-arm64`, `SHA256SUMS.txt`, four CycloneDX SBOMs,
`SCOUT-0.6.2-linux-amd64.md`, `SCOUT-0.6.2-linux-arm64.md`.

The Linux binaries are static musl; verified on the downloaded files:

```
shasum -a 256 -c <(grep linux SHA256SUMS.txt)   -> both OK
file eqproxy-linux-amd64 -> static-pie linked, x86-64
file eqproxy-linux-arm64 -> statically linked, ARM aarch64
FROM scratch + --version -> "eqproxy 0.6.2" on both architectures
```

The `scratch` run is the functional proof: a dynamically linked binary cannot
start without a loader. The arm64 run is under QEMU on this host.

## 3. Image

Index `sha256:aa1a4ec5617b2740aa07b910630550833c52cee9c47742bef7ebe434f8285955`,
with `linux/amd64` + `linux/arm64` + **2 attestation manifests**.

| Reference | Digest |
|---|---|
| `ghcr.io/exyonq/eqproxy:0.6.2` | `aa1a4ec5…` |
| `ghcr.io/exyonq/eqproxy:latest` | `aa1a4ec5…` |
| `ghcr.io/exyonq/eqproxy:0.6.2-candidate` | `aa1a4ec5…` (the scanned one) |
| `exyonq/eqproxy:0.6.2` | `aa1a4ec5…` |
| `exyonq/eqproxy:latest` | `aa1a4ec5…` |

The candidate tag that Scout scanned and the tags users pull are the **same
digest**, which is the property the promotion step exists for.

Docker Scout, re-run independently after publication:

| Platform | Manifest | Packages | C/H/M/L | Exit |
|---|---|---|---|---|
| `linux/amd64` | `cafb831c…` | 0 | 0 / 0 / 0 / 0 | 0 |
| `linux/arm64` | `b402e4bd…` | 0 | 0 / 0 / 0 / 0 | 0 |

As in v0.6.1, the zero is about OS packages: the runtime is `scratch`, so Scout
indexes 0 packages. It proves nothing was added to the image; it is not a
verdict on the Rust binary, which Scout does not scan.

Live traffic through the Docker Hub image (`exyonq/eqproxy:0.6.2`, native
arm64 here) with a real nginx backend:

```
HTTP 200, <title>Welcome to nginx!</title>
WARN listener "web" listens on 0.0.0.0:18182 without TLS ...
INFO listener web listening on 0.0.0.0:18182
METRICS client[accepted=0 ...] proxy[no_server=0 ...] ...
```

## 4. Security fix contained in this release

`webpki-roots` 1.0.10 and `rustls-webpki` 0.103.16 (RUSTSEC-2026-0381,
RUSTSEC-2026-0382). The v0.6.1 artifacts predate those advisories and keep the
old roots; these do not. `veyra audit . --profile standard` on the released
tree: **ACCEPTED**, exit 0, evidence `.veyra/evidence/20261020T203924Z/`
(the earlier run, `.veyra/evidence/20261020T203004Z/`, is the REJECTED one that
motivated the bump). `cargo fmt --check`, `clippy --workspace --all-targets --
-D warnings` and `cargo test --workspace`: **327 passed, 0 failed**.

## 5. Known limitations

- arm64 containers run under QEMU in CI (and on this host); correct, not fast.
- The Scout gate covers `cves --only-severity critical,high --exit-code` on a
  0-package image: a tripwire for a future base change, not a security verdict.
- Scout's advisory coverage has gaps (EOL tags such as `debian:9` or
  `ubuntu:18.04` report zero), so a pass is never proof of absence.
- `cargo-geiger` is INCONCLUSIVE (coverage warnings in 4 runs); dylint and
  semver-checks are skipped (no configuration / no registry baseline). Reported
  as such, never as passes.
- The `-candidate` tag stays in the registry as the record of what was scanned;
  it is not documented and `:latest` does not point at it by name.
