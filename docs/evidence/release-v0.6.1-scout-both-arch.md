# v0.6.1 — static musl binaries and Docker Scout on both architectures

Date: 2026-10-20. Host: macOS 26.1 (aarch64), Docker 29.8.2, buildx 0.37.2,
Docker Scout CLI 1.25.0. Artifacts under test: the **published** v0.6.1 release
assets and image, not a local rebuild.

## 1. Are the arm64 and amd64 Linux binaries static musl?

Yes — they always were for 0.6.x, and nothing in the docs said so. The four
release assets and their checksums:

| Asset | Size | sha256 |
|---|---|---|
| `eqproxy-linux-amd64` | 12 844 912 B | `a9308e2029c7184461de72da20936dd5a30b4c2a1cade0c4ab221104d77e0834` |
| `eqproxy-linux-arm64` | 11 243 640 B | `5913e60dc7f87b86c47c54c29c709b399483bf8dfb38e13c656330b1e21bb9dd` |
| `eqproxy-darwin-amd64` | 11 666 120 B | `afea82d6c180e7d01074da6d36024bdd1adf40346d3340254b260aae9ea8f320` |
| `eqproxy-darwin-arm64` | 10 404 352 B | `36f2cfa34d9388218ab6a8566462741531c9f10506a5a9171a7c136de2ee4641` |

Evidence, run on the downloaded files:

```
shasum -a 256 -c <(grep linux SHA256SUMS.txt)      -> both OK
file eqproxy-linux-amd64  -> ELF 64-bit LSB pie executable, x86-64, static-pie linked
file eqproxy-linux-arm64  -> ELF 64-bit LSB executable, ARM aarch64, statically linked
```

The consequence that matters is not the `file` wording but that they run with
**no libc and no filesystem at all**. Each asset was copied into a
`FROM scratch` image and executed:

```
$ docker build --platform linux/amd64 -f Dockerfile.amd64 -t eqp-static-amd64 .
$ docker run --rm --platform linux/amd64 eqp-static-amd64 --version
eqproxy 0.6.1
$ docker build --platform linux/arm64 -f Dockerfile.arm64 -t eqp-static-arm64 .
$ docker run --rm --platform linux/arm64 eqp-static-arm64 --version
eqproxy 0.6.1
```

In `alpine:3.20` (musl, no glibc) both assets also served `--version` and
`config validate` through stdin (`config OK: 1 listener(s), 1 backend(s)`). In
`scratch` only `--version` is run because `/dev/stdin` does not exist there.
A dynamically linked binary cannot start in `scratch` at all (the loader would
be missing), so the `scratch` run is a functional proof of static linkage, not
an inference from the ELF header. The arm64 run executes under QEMU on this
host; the result is real, the timing is not.

## 2. Is the image scanned on both architectures?

The published index is `sha256:ae15bb0f3651c9a76dd5be7b592ae007839ad46883a7c57756c52c2dcd4c4418`,
with `linux/amd64` `sha256:f1b1ff07117706e59352c60bd5eebfd8f73bc11fc03bdafa25eaeb758ff27ce1`
and `linux/arm64` `sha256:517945df383f2ebdbb09a2fd8ab22a7672fb99ac58320b217ad0518fe021818b`
(`docker buildx imagetools inspect`).

```
$ docker scout cves --only-severity critical,high --exit-code \
    --platform linux/amd64 ghcr.io/exyonq/eqproxy:0.6.1; echo $?
0
$ docker scout cves --only-severity critical,high --exit-code \
    --platform linux/arm64 ghcr.io/exyonq/eqproxy:0.6.1; echo $?
0
```

| Platform | Digest | Packages | C/H/M/L | Size |
|---|---|---|---|---|
| `linux/amd64` | `f1b1ff07…` | 0 | 0 / 0 / 0 / 0 | 4.6 MB |
| `linux/arm64` | `517945df…` | 0 | 0 / 0 / 0 / 0 | 4.3 MB |

The full reports are committed as `v0.6.1-scout-both-arch/SCOUT-0.6.1-linux-amd64.md`
and `…-arm64.md` in this directory, and attached to the GitHub release under the
same names.

**How much that zero is worth:** the runtime is `scratch`, so Scout indexes **0
packages** — there is nothing for it to find, and it does not scan the Rust
binary itself. The report proves "no OS package was added to the image we
ship", not "no vulnerability exists in EQProxy". It is a regression tripwire,
not a security verdict.

**Does the gate have teeth?** On `python:3.8-slim`, the same command returns
exit **2** with `8C 67H`:

```
$ docker scout cves --only-severity critical,high --exit-code \
    --platform linux/amd64 python:3.8-slim > /tmp/neg.txt 2>&1; echo $?
2
8C    67H     0M     0L
```

A second caveat found while testing the control: `debian:9`, `ubuntu:18.04` and
`ubuntu:20.04` return `0C 0H` here even though they are EOL — Scout's advisory
coverage for those tags is incomplete, and a zero can mean "no data". That is
why the gate is described as a tripwire over what we ship, never as proof of
absence of vulnerabilities.

## 3. The pipeline now enforces both checks

Until this change the image job built and scanned **only `linux/amd64`**;
`linux/arm64` was pushed without a scan (ADR-0005 said so explicitly). The
release job also did not depend on the image job, so a release could exist next
to an unscanned image. `.github/workflows/release.yml` now:

1. builds the multi-arch index once and pushes it under a throwaway
   `<version>-candidate` tag (`--provenance=mode=max --sbom=true`);
2. records the index digest from the registry
   (`imagetools inspect --raw | sha256sum`);
3. runs `docker scout cves --only-severity critical,high --exit-code` on
   `linux/amd64` **and** `linux/arm64` of that digest, writing
   `SCOUT-<version>-linux-<arch>.md`;
4. runs the container E2E journeys (`--version`, `config validate`, live
   proxied traffic through nginx) on both architectures;
5. promotes **that digest** to `<version>` / `:latest` and mirrors it to Docker
   Hub — no rebuild, so the scanned bytes are the published bytes;
6. re-reads every published tag and fails if its digest is not the scanned one;
7. the `release` job now `needs` the image job and uploads the two Scout
   reports as release assets.

## 4. What is NOT verified here

- **The modified workflow has not run on GitHub Actions yet** — that happens on
  the next tag push. The new steps were validated as YAML (all five jobs parse,
  dependency graph `guard → darwin/linux → image → release`, no cycle) and each
  command was exercised locally against the published digest (raw-digest
  computation matched `ae15bb0f…`, both Scout invocations, both scratch runs).
  The promotion step cannot be exercised without pushing a tag: **NOT
  EXECUTED**.
- arm64 containers run under QEMU in CI; the journeys prove the artifact, not
  native arm64 performance.
- Scout policies, the Docker Hub health score and `docker scout compare` are
  not part of the gate.
