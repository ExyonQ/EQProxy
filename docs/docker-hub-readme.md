# EQProxy

EQProxy is a reverse proxy and load balancer written in Rust. It speaks
HTTP/1.1 with strict framing (including interim 1xx and `Expect:
100-continue`), TLS termination and backend TLS (verification on by
default), mTLS with client CAs, weighted round-robin with active TCP/HTTP
health checks and passive failure detection, safe connect-phase retries,
bounded backend queues, incoming PROXY protocol v1 with origin allowlists,
forwarded headers, and hot config + certificate reload under traffic.

The image is tiny and has no OS: a statically linked (musl) binary at
`/opt/eqproxy`, a CA bundle for operators that use the system trust store,
and nothing else — `scratch` as the base, so no shell, no package manager
and no distribution packages at all (15.8 MB, 0 packages reported by Docker
Scout, `0C 0H 0M 0L`). It runs as the unprivileged user `65532:65532`. It
listens wherever the configuration says (the convention in the examples is
port 8080).

`linux/amd64` and `linux/arm64` are built from the same Dockerfile and are
both scanned with Docker Scout before the release tag exists: the workflow
scans each architecture, runs the container journeys on each, and only then
promotes the scanned digest to `:<version>` and `:latest`. The two reports
(`SCOUT-<version>-linux-amd64.md`, `…-arm64.md`) are attached to every GitHub
release. The scan indexes the image, which contains 0 packages, so a clean
report means "no OS package was added", not a vulnerability verdict on the
proxy itself.

Standalone binaries for both architectures — `eqproxy-linux-amd64` and
`eqproxy-linux-arm64`, static musl, no libc required — are on the release page
together with `SHA256SUMS.txt`.

The musl binary was measured against **genuinely built glibc binaries** on
arm64 and amd64, same scenario and same hosts, every response a real `200`
([TLS parity report](https://github.com/ExyonQ/EQProxy/blob/v0.6.3/docs/evidence/v0.6.2-tls-parity/README.md)):
arm64 is at parity (−2.4 %, p 0.28); on amd64 musl is 20 % behind under TLS
(p 0.001) and 11 % behind with no TLS at all (p 0.0001), so the gap is
libc-general rather than handshake cost. An earlier version of this page
reported +1.6 %–6.2 % because the "glibc" column also ran the musl release
asset inside a Debian image; that comparison is withdrawn.

## Quick reference

- **Maintained by:** [ExyonQ](https://github.com/ExyonQ/EQProxy)
- **Where to get help:** [GitHub issues](https://github.com/ExyonQ/EQProxy/issues) or contact@exyonq.org
- **Security:** security@exyonq.org
- **Supported architectures:** `linux/amd64`, `linux/arm64`
- **Source of this image:** https://github.com/ExyonQ/EQProxy/blob/v0.6.3/docker/Dockerfile
- **Release:** https://github.com/ExyonQ/EQProxy/releases/tag/v0.6.3

## Supported tags

- `0.6.3` — the released version (pinned).
- `latest` — the same image as the newest release.

```bash
docker pull exyonq/eqproxy:0.6.3
```

The same images are published on GitHub Container Registry as
`ghcr.io/exyonq/eqproxy` with identical digests.

## How to use this image

The entrypoint is `/opt/eqproxy`; arguments after the image name go to the
CLI. Without arguments it prints `--help`.

### Validate a configuration (no network, no ports)

```bash
docker run --rm -v /path/to/eqproxy.toml:/etc/eqproxy/eqproxy.toml:ro \
  exyonq/eqproxy:0.6.3 config validate --config /etc/eqproxy/eqproxy.toml
```

### Run the proxy

`eqproxy.toml`:

```toml
schema_version = 1

[listener.web]
listen = "0.0.0.0:8080"
mode = "http"
backend = "api"

[backend.api]
server = "api:9000"
```

```bash
docker run --name eqproxy -d -p 8080:8080 \
  -v /path/to/eqproxy.toml:/etc/eqproxy/eqproxy.toml:ro \
  exyonq/eqproxy:0.6.3 run --config /etc/eqproxy/eqproxy.toml
```

Traffic to `localhost:8080` is proxied to `api:9000` — put the backend in
the same Docker network (or use `host.docker.internal` for a host service).
The mounted file must be readable by uid **65532** (the image runs as
`65532:65532`; `chmod 644` is enough). Ports below 1024 need a host-side
mapping or `--user 0`: a non-root process cannot bind them.

### Inspect and operate

```bash
# What each timeout does when it fires, per phase:
docker run --rm -v /path/to/eqproxy.toml:/etc/eqproxy/eqproxy.toml:ro \
  exyonq/eqproxy:0.6.3 config explain --config /etc/eqproxy/eqproxy.toml

# Pre-flight checks (bind probe, config gate):
docker run --rm -v /path/to/eqproxy.toml:/etc/eqproxy/eqproxy.toml:ro \
  exyonq/eqproxy:0.6.3 doctor --config /etc/eqproxy/eqproxy.toml

# Stage a validated config and keep history for rollback. The image sets
# EQPROXY_STATE_DIR=/var/lib/eqproxy; mount a volume there to keep it across
# container replacements.
docker run --rm -e EQPROXY_STATE_DIR=/var/lib/eqproxy \
  -v eqproxy-state:/var/lib/eqproxy \
  -v /path/to/eqproxy.toml:/etc/eqproxy/eqproxy.toml:ro \
  exyonq/eqproxy:0.6.3 config apply --config /etc/eqproxy/eqproxy.toml

# Hot reload under traffic (the container forwards signals). The running
# process re-reads the mounted file, so edit it in place and signal it:
docker kill --signal=HUP eqproxy
```

## What is in the image

- `/opt/eqproxy` — the binary (CLI `eqproxy run|config|doctor`), statically
  linked against musl
- CA certificates at `/etc/ssl/certs/ca-certificates.crt`
- `/var/lib/eqproxy` — writable state directory for `config apply`/
  `config rollback` (owned by 65532, `EQPROXY_STATE_DIR` points at it)
- Nothing else: no shell, no package manager, no distribution packages. No
  configuration is baked in — mount yours (see above).

## Documentation

- [README](https://github.com/ExyonQ/EQProxy#readme) — status, install, quick start
- [SPEC.md](https://github.com/ExyonQ/EQProxy/blob/v0.6.3/SPEC.md) — specified behaviour
- [eqproxy.toml.example](https://github.com/ExyonQ/EQProxy/blob/v0.6.3/eqproxy.toml.example) — every option documented
- [THREAT_MODEL.md](https://github.com/ExyonQ/EQProxy/blob/v0.6.1/THREAT_MODEL.md) — threat model and non-protections

## License

Dual: MIT OR Apache-2.0, at the recipient's choice.

https://github.com/ExyonQ/EQProxy/blob/v0.6.1/LICENSE-MIT
