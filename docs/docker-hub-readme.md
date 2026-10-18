# EQProxy

EQProxy is a reverse proxy and load balancer written in Rust. It speaks
HTTP/1.1 with strict framing (including interim 1xx and `Expect:
100-continue`), TLS termination and backend TLS (verification on by
default), mTLS with client CAs, weighted round-robin with active TCP/HTTP
health checks and passive failure detection, safe connect-phase retries,
bounded backend queues, incoming PROXY protocol v1 with origin allowlists,
forwarded headers, and hot config + certificate reload under traffic.

The image is small: `debian:bookworm-slim` with CA certificates and one
static-ish binary at `/opt/eqproxy`. It runs as the unprivileged `nobody`
user. It listens wherever the configuration says (the convention in the
examples is port 8080).

## Quick reference

- **Maintained by:** [ExyonQ](https://github.com/ExyonQ/EQProxy)
- **Where to get help:** [GitHub issues](https://github.com/ExyonQ/EQProxy/issues) or contact@exyonq.org
- **Security:** security@exyonq.org
- **Supported architectures:** `linux/amd64`, `linux/arm64`
- **Source of this image:** https://github.com/ExyonQ/EQProxy/blob/v0.5.0/docker/Dockerfile
- **Release:** https://github.com/ExyonQ/EQProxy/releases/tag/v0.5.0

## Supported tags

- `0.5.0` — the released version (pinned).
- `latest` — the same image as the newest release.

```bash
docker pull exyonq/eqproxy:0.5.0
```

The same images are published on GitHub Container Registry as
`ghcr.io/exyonq/eqproxy` with identical digests.

## How to use this image

The entrypoint is `/opt/eqproxy`; arguments after the image name go to the
CLI. Without arguments it prints `--help`.

### Validate a configuration (no network, no ports)

```bash
docker run --rm -v /path/to/eqproxy.toml:/etc/eqproxy/eqproxy.toml:ro \
  exyonq/eqproxy:0.5.0 config validate --config /etc/eqproxy/eqproxy.toml
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
  exyonq/eqproxy:0.5.0 run --config /etc/eqproxy/eqproxy.toml
```

Traffic to `localhost:8080` is proxied to `api:9000` — put the backend in
the same Docker network (or use `host.docker.internal` for a host service).
The mounted file must be readable by uid `nobody` (65534).

### Inspect and operate

```bash
# What each timeout does when it fires, per phase:
docker run --rm -v /path/to/eqproxy.toml:/etc/eqproxy/eqproxy.toml:ro \
  exyonq/eqproxy:0.5.0 config explain --config /etc/eqproxy/eqproxy.toml

# Pre-flight checks (bind probe, config gate):
docker run --rm -v /path/to/eqproxy.toml:/etc/eqproxy/eqproxy.toml:ro \
  exyonq/eqproxy:0.5.0 doctor --config /etc/eqproxy/eqproxy.toml

# Hot reload under traffic (the container forwards signals):
docker kill --signal=HUP eqproxy
```

## What is in the image

- `/opt/eqproxy` — the binary (CLI `eqproxy run|config|doctor`)
- CA certificates at `/etc/ssl/certs/ca-certificates.crt`
- No shell tooling beyond `debian:bookworm-slim`; no configuration is
  baked in — mount yours (see above).

## Documentation

- [README](https://github.com/ExyonQ/EQProxy#readme) — status, install, quick start
- [SPEC.md](https://github.com/ExyonQ/EQProxy/blob/v0.5.0/SPEC.md) — specified behaviour
- [eqproxy.toml.example](https://github.com/ExyonQ/EQProxy/blob/v0.5.0/eqproxy.toml.example) — every option documented
- [THREAT_MODEL.md](https://github.com/ExyonQ/EQProxy/blob/v0.5.0/THREAT_MODEL.md) — threat model and non-protections

## License

Dual: MIT OR Apache-2.0, at the recipient's choice.

https://github.com/ExyonQ/EQProxy/blob/v0.5.0/LICENSE-MIT
