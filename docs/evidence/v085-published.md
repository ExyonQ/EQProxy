# v0.8.5 — published: the artifact gate

Language: **English**.

**What this page answers:** whether the `v0.8.5` artifacts that are public are
**exactly** the ones the gates verified — the tag commit, the digest Docker
Scout scanned before promotion, the checksums of the release assets, and a
journey replayed against the pulled image rather than against a local build.
It is the §5 gate of [docs/release-0.8.5.md](../release-0.8.5.md), executed.

| Piece | Value |
|---|---|
| Tag | `v0.8.5` (annotated, remote object `f2e2bfd0…9f53`) → commit `6e938ae98f20e7e59beff2f8c78083d22e080c16` |
| Version | `Cargo.toml` `[workspace.package] version = "0.8.5"`, so `v$VER == $GITHUB_REF_NAME` |
| Run | [41165822327](https://github.com/ExyonQ/EQProxy/actions/runs/41165822327) — `completed success`, six jobs |
| Scanned index digest | `sha256:bf1a06cd82338754e2cfae17fd297c6f2699fc83b889ba71549aec7ad0cae625` |
| Release | [v0.8.5](https://github.com/ExyonQ/EQProxy/releases/tag/v0.8.5), published `2026-10-31T06:44:43Z`, 12 assets |
| Raw transcripts | [`v085-published/raw/20261031T064643Z/`](v085-published/raw/20261031T064643Z/) |

Toolchain, unchanged from the cut: `rust-toolchain.toml` `channel = "1.99.1"`
and `docker/Dockerfile` `ARG RUST_VERSION=1.99.1`; the builder named in the
build log is `rust:1.99.1-alpine` and the runtime base stayed
`cgr.dev/chainguard/wolfi-base@sha256:360896ef…ee2923a7`.

## 1. The tag run: six jobs, all green

Pushed `main` (`ad0050a..6e938ae`) and then the tag; a `v*` tag is what runs
this pipeline. Created `03:46:48Z`, last update `06:45:05Z` — **2 h 58 min 17 s**
of wall time.

| Job | Start (UTC) | End (UTC) | Verdict |
|---|---|---|---|
| `guard` — line gates before any build | 03:46:51 | 03:54:20 | success |
| `darwin` — binaries + E2E | 03:54:23 | 04:01:52 | success |
| `linux` — binaries + E2E + SBOM | 03:54:23 | 05:35:29 | success |
| `image` — build + Scout both archs + E2E + promote | 05:35:32 | 06:44:30 | success |
| `release` — assets, tarball, checksums, GitHub release | 06:44:33 | 06:44:46 | success |
| `docker hub page` — rendered, published, read back | 06:44:48 | 06:45:04 | success |

`guard` ran on the tag commit, not on an earlier push: both suite tiers
(`--nocapture`, unprivileged and `root`) with their `uid-skips` transcripts, the
three detector self-tests and verdicts, and the version pin.

The long durations are structural, not stalls: `linux` and `image` each build
the image twice (amd64 native, **arm64 under QEMU**), from a container with no
cargo cache. The same two builds took 31 and 27 minutes on the maintainer's
machine.

## 2. The digest: scanned first, promoted second

The `image` job built and pushed **only** `:0.8.5-candidate`, recorded the
index digest of those bytes, scanned it, and promoted the digest — never a
rebuild:

```console
candidate index: ghcr.io/exyonq/eqproxy:0.8.5-candidate@sha256:bf1a06cd…0cae625
```

After promotion the job compared every published tag against that digest, and
the pull of `:0.8.5` resolved to the same bytes:

```console
ghcr.io/exyonq/eqproxy:0.8.5           -> sha256:bf1a06cd…0cae625 (scanned)
ghcr.io/exyonq/eqproxy:latest          -> sha256:bf1a06cd…0cae625 (scanned)
ghcr.io/exyonq/eqproxy:0.8.5-candidate -> sha256:bf1a06cd…0cae625 (scanned)
exyonq/eqproxy:0.8.5                   -> sha256:bf1a06cd…0cae625 (scanned)
exyonq/eqproxy:latest                  -> sha256:bf1a06cd…0cae625 (scanned)
```

Re-checked by hand after the run, including the Docker Hub mirror:

```console
$ docker buildx imagetools inspect ghcr.io/exyonq/eqproxy:0.8.5 --format '{{.Manifest.Digest}}'
sha256:bf1a06cd82338754e2cfae17fd297c6f2699fc83b889ba71549aec7ad0cae625
$ docker buildx imagetools inspect ghcr.io/exyonq/eqproxy:latest --format '{{.Manifest.Digest}}'
sha256:bf1a06cd82338754e2cfae17fd297c6f2699fc83b889ba71549aec7ad0cae625
$ docker buildx imagetools inspect docker.io/exyonq/eqproxy:0.8.5 --format '{{.Manifest.Digest}}'
sha256:bf1a06cd82338754e2cfae17fd297c6f2699fc83b889ba71549aec7ad0cae625
$ docker pull ghcr.io/exyonq/eqproxy:0.8.5 2>&1 | tail -1
Digest: sha256:bf1a06cd82338754e2cfae17fd297c6f2699fc83b889ba71549aec7ad0cae625
```

Both architectures are in the index, with the child digests the build exported:

```console
linux/amd64 sha256:9c1741e8412eb6a5c51385d525814dfb454731c197dcc48ba114f774f787a224
linux/arm64 sha256:8ec5cdb35c83878e06d98a9dcc9e7d90c2b08677ed54be476d2bd10bffaec2ae
```

## 3. Scout: 0 critical, 0 high on both architectures

Two independent readings, both on the **published** artifact:

In the run, on the candidate the promotion copies (`--exit-code`,
`--only-severity critical,high`, `pipefail`):

```console
scout: no critical or high vulnerability on linux/amd64
   vulnerabilities │    0C     0H     0M     0L
scout: no critical or high vulnerability on linux/arm64
   vulnerabilities │    0C     0H     0M     0L
```

By hand, on the tag as it is served today, with the SBOM taken from the
attestation rather than from a local load:

```console
$ docker scout cves --only-severity critical,high --exit-code --platform linux/amd64 ghcr.io/exyonq/eqproxy:0.8.5
    ✓ SBOM obtained from attestation, 69 packages found
    ✓ No vulnerable package detected
   vulnerabilities │    0C     0H     0M     0L
# exit 0
$ docker scout cves --only-severity critical,high --exit-code --platform linux/arm64 ghcr.io/exyonq/eqproxy:0.8.5
    ✓ SBOM obtained from attestation, 69 packages found
   vulnerabilities │    0C     0H     0M     0L
# exit 0
```

The two reports shipped as release assets name the scanned index
(`sha256:bf1a06cd…`) and the per-architecture child digest, with
`critical: 0 high: 0 medium: 0 low: 0` and 69 packages
(`raw/…/scout/published-linux-{amd64,arm64}.txt`, and the assets
`SCOUT-0.8.5-linux-{amd64,arm64}.md`).

## 4. Release assets and checksums

`gh release view v0.8.5`: 12 assets, not a draft, not a prerelease, published
`2026-10-31T06:44:43Z`.

| Asset | Bytes |
|---|---|
| `eqproxy-linux-amd64` | 36 709 384 |
| `eqproxy-linux-arm64` | 31 181 160 |
| `eqproxy-darwin-amd64` | 33 554 960 |
| `eqproxy-darwin-arm64` | 28 848 432 |
| `eqproxy-0.8.5-src.tar.gz` | 3 237 944 |
| `SHA256SUMS.txt` | 437 |
| `eqproxy-{core,config,net,cli}.cdx.json` | 4 SBOMs |
| `SCOUT-0.8.5-linux-{amd64,arm64}.md` | 2 Scout reports |

Downloaded again and checked against the published sums — all five lines:

```console
$ gh release download v0.8.5 --dir /tmp/rel085
$ shasum -a 256 -c SHA256SUMS.txt
eqproxy-darwin-amd64: OK
eqproxy-darwin-arm64: OK
eqproxy-linux-amd64: OK
eqproxy-linux-arm64: OK
eqproxy-0.8.5-src.tar.gz: OK
# exit 0
```

The source tarball is the tagged tree and nothing else: root `eqproxy-0.8.5/`,
`Cargo.toml` at `0.8.5` (the fuzz workspace keeps its own `0.0.0`), 1 492
`docs/` entries, and **zero** entries under `scripts/`, `report/`,
`ROADMAP EQPROXY/` or `AGENTS.md` — the maintainer-local material did not
travel into the published sources.

## 5. Re-pull and journeys on the public artifact

The pipeline re-pulled every published reference and replayed a journey on
each, after the promotion:

```console
==> published ghcr.io/exyonq/eqproxy:0.8.5 linux/amd64: version, digest, h2 gate, config apply and live traffic OK
==> published ghcr.io/exyonq/eqproxy:0.8.5 linux/arm64: version, digest, h2 gate, config apply and live traffic OK
==> published exyonq/eqproxy:0.8.5 linux/amd64: version, digest, h2 gate, config apply and live traffic OK
==> published exyonq/eqproxy:0.8.5 linux/arm64: version, digest, h2 gate, config apply and live traffic OK
```

Repeated by hand on this machine, so the evidence does not rest on the same
job that produced the artifact:

```console
$ docker run --rm --platform linux/amd64 ghcr.io/exyonq/eqproxy:0.8.5 --version
eqproxy 0.8.5
$ docker run --rm --platform linux/arm64 ghcr.io/exyonq/eqproxy:0.8.5 --version
eqproxy 0.8.5
```

The published darwin binary, executed on the host architecture (credential-free
CLI paths):

```console
$ ./eqproxy-darwin-arm64 --version
eqproxy 0.8.5
$ printf 'schema_version = 1\n[listener.web]\nlisten = "127.0.0.1:0"\nbackend = "api"\n[backend.api]\nserver = "127.0.0.1:9"\n' \
  | ./eqproxy-darwin-arm64 config validate --config /dev/stdin
config OK: 1 listener(s), 1 backend(s) in /dev/stdin
# exit 0
```

Live proxied traffic through the published image (nginx in a Docker network on
a static IP, because dynamic backend DNS is not part of this version):

```console
$ curl -s -o /tmp/eqpub.body -w '%{http_code}' http://127.0.0.1:18083/
200
$ head -c 60 /tmp/eqpub.body
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</titl
$ grep -iE '^(HTTP/|server|content-type)' /tmp/eqpub.hdr
HTTP/1.1 200 OK
Server: nginx/1.31.8
Content-Type: text/html
$ docker logs eqpub-prox | grep 'listener web listening'
INFO listener web listening on 0.0.0.0:18083
```

## 6. What this does not prove

- **Nothing about behaviour under production load.** The journeys are the
  functional ones; the performance evidence for this line stays the v0.6/v0.7
  campaigns and S-PLG-01, with their own caveats.
- **No re-scan over time.** Scout reads the registry today; a CVE published
  later changes the answer without changing this page. The gate is a point in
  time, recorded with its date.
- **amd64 was never executed natively here.** Both the run's build and this
  machine's re-pull of `linux/amd64` go through emulation, so the timings in
  this page say nothing about native amd64 speed, and a platform-specific
  behaviour that only shows on real amd64 hardware is not covered by it.
- **The Docker Hub page** is verified by its own job (rendered, published and
  read back); its content is not re-read here.
- **v0.8.5 is not "production ready".** This page closes the artifact gate of
  the 0.8.5 roadmap; the production verdict is the Phase 9 gate of the 1.0
  line and remains open.
