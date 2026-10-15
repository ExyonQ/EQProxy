# Official EQProxy image (multi-arch: linux/amd64 + linux/arm64).
#
# Usage:
#   docker buildx build --file docker/Dockerfile --platform linux/amd64,linux/arm64 \
#     --tag ghcr.io/exyonq/eqproxy:0.4.1 --tag ghcr.io/exyonq/eqproxy:latest --push .
#
# The binary runs with `docker run ghcr.io/exyonq/eqproxy --help`.
# The `export` stage isolates the binary to extract it as a release artifact:
#   docker buildx build --file docker/Dockerfile --target export \
#     --platform linux/amd64 --output type=local,dest=docker-out-amd64 .
ARG RUST_VERSION=1.97

FROM rust:${RUST_VERSION}-bookworm AS builder
WORKDIR /src

# Dependencies first: the registry cache layer survives code changes.
COPY Cargo.toml Cargo.lock ./
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
RUN cargo build --release --locked -p eqproxy-cli \
    && cp target/release/eqproxy /opt/eqproxy

# Only the binary, to extract with --target export --output type=local.
FROM scratch AS export
COPY --from=builder /opt/eqproxy /eqproxy

# Minimal runtime (default stage): unprivileged user, no toolchain.
# ca-certificates covers operators pointing `ca_file` at the
# system bundle; default verification uses the compiled-in Mozilla roots.
FROM debian:bookworm-slim AS runtime
ENV LANG=C.UTF-8
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /opt/eqproxy /opt/eqproxy
USER nobody
EXPOSE 8080
ENTRYPOINT ["/opt/eqproxy"]
CMD ["--help"]
