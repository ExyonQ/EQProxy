# Official EQProxy image (multi-arch: linux/amd64 + linux/arm64).
#
# Usage:
#   docker buildx build --file docker/Dockerfile --platform linux/amd64,linux/arm64 \
#     --tag ghcr.io/exyonq/eqproxy:0.6.3 --tag ghcr.io/exyonq/eqproxy:latest \
#     --provenance=mode=max --sbom=true --push .
#
# The binary runs with `docker run ghcr.io/exyonq/eqproxy --help`.
# The `export` stage isolates the binary to extract it as a release artifact:
#   docker buildx build --file docker/Dockerfile --target export \
#     --platform linux/amd64 --output type=local,dest=docker-out-amd64 .
#
# Runtime base is `scratch` (v0.6.3): the release binary is linked against
# musl and is fully static, so the published image carries **no** OS
# packages — no shell, no package manager, no perl/openssl/util-linux from a
# Debian base. Docker Scout scanned the previous Debian-bookworm-slim image
# with 4 critical + 13 high findings, all inherited from that base and none
# in EQProxy; this removes the source instead of hiding the count. The only
# files in the image are the binary, a CA bundle for operators that point
# `ca_file` at the system trust store (default verification uses the
# compiled-in Mozilla roots) and the writable state directory below.
ARG RUST_VERSION=1.97

FROM rust:${RUST_VERSION}-alpine AS builder
WORKDIR /src

# musl-dev/cmake/perl build aws-lc-rs (the rustls crypto provider);
# ca-certificates provides the bundle copied into the runtime image.
RUN apk add --no-cache musl-dev cmake make gcc g++ perl linux-headers \
    ca-certificates file

# Dependencies first: the registry cache layer survives code changes.
COPY Cargo.toml Cargo.lock ./
# Compiled in by `eqproxy-config` (`include_str!`): the public JSON Schema
# ships inside the binary, so it must exist before the crate is compiled.
COPY eqproxy.schema.json ./
COPY eqproxy-core/Cargo.toml eqproxy-core/Cargo.toml
COPY eqproxy-config/Cargo.toml eqproxy-config/Cargo.toml
COPY eqproxy-net/Cargo.toml eqproxy-net/Cargo.toml
COPY eqproxy-cli/Cargo.toml eqproxy-cli/Cargo.toml
# Minimal stubs: cargo requires targets when parsing the manifests.
RUN mkdir -p eqproxy-core/src eqproxy-config/src eqproxy-net/src eqproxy-cli/src \
    && echo "" > eqproxy-core/src/lib.rs \
    && echo "" > eqproxy-config/src/lib.rs \
    && echo "" > eqproxy-net/src/lib.rs \
    && echo "fn main() {}" > eqproxy-cli/src/main.rs \
    && cargo fetch --locked

COPY eqproxy-core eqproxy-core
COPY eqproxy-config eqproxy-config
COPY eqproxy-net eqproxy-net
COPY eqproxy-cli eqproxy-cli
# On the musl target (the default of rust:alpine) this produces a static
# executable; the `file` gate fails the build if that ever stops being true,
# because a dynamic binary would not run on `scratch`.
RUN cargo build --release --locked -p eqproxy-cli \
    && cp target/release/eqproxy /opt/eqproxy \
    && file /opt/eqproxy | grep -Eq 'statically linked|static-pie linked'

# Only the binary, to extract with --target export --output type=local.
FROM scratch AS export
COPY --from=builder /opt/eqproxy /eqproxy

# State directory for `config apply`/`config rollback` (v0.6.3). The
# default `./.eqproxy` resolves to `/` in this image, which uid 65532 cannot
# write, so the documented offline state commands used to fail with
# "Permission denied" inside the container. It is created here (scratch has
# no RUN) and mounted as a volume by operators that want it to survive a
# container replacement.
FROM builder AS state
RUN mkdir -p /var/lib/eqproxy && chown 65532:65532 /var/lib/eqproxy

# Minimal runtime (default stage): no OS packages at all, unprivileged user.
FROM scratch AS runtime
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=state --chown=65532:65532 /var/lib/eqproxy /var/lib/eqproxy
COPY --from=builder /opt/eqproxy /opt/eqproxy
ENV EQPROXY_STATE_DIR=/var/lib/eqproxy
USER 65532:65532
EXPOSE 8080
EXPOSE 8443
ENTRYPOINT ["/opt/eqproxy"]
CMD ["--help"]
