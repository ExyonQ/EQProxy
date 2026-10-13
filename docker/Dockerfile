# Imagen oficial de EQProxy (multi-arquitectura: linux/amd64 + linux/arm64).
#
# Uso:
#   docker buildx build --file docker/Dockerfile --platform linux/amd64,linux/arm64 \
#     --tag ghcr.io/ExyonQ/eqproxy:0.1.0 --tag ghcr.io/ExyonQ/eqproxy:latest --push .
#
# El binario se ejecuta con `docker run ghcr.io/ExyonQ/eqproxy --help`.
# El stage `export` deja el binario aislado para extraerlo como artefacto de release:
#   docker buildx build --file docker/Dockerfile --target export \
#     --platform linux/amd64 --output type=local,dest=docker-out-amd64 .
ARG RUST_VERSION=1.97

FROM rust:${RUST_VERSION}-bookworm AS builder
WORKDIR /src

# Dependencias primero: la capa de caché del registry sobrevive a cambios de código.
COPY Cargo.toml Cargo.lock ./
COPY eqproxy-core/Cargo.toml eqproxy-core/Cargo.toml
COPY eqproxy-config/Cargo.toml eqproxy-config/Cargo.toml
COPY eqproxy-net/Cargo.toml eqproxy-net/Cargo.toml
COPY eqproxy-cli/Cargo.toml eqproxy-cli/Cargo.toml
# Stubs mínimos: cargo exige targets al parsear los manifiestos.
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

# Solo el binario, para extraerlo con --target export --output type=local.
FROM scratch AS export
COPY --from=builder /opt/eqproxy /eqproxy

# Runtime mínimo (stage por defecto): nadie con privilegios, sin toolchain,
# sin shell.
FROM debian:bookworm-slim AS runtime
ENV LANG=C.UTF-8
COPY --from=builder /opt/eqproxy /opt/eqproxy
USER nobody
EXPOSE 8080
ENTRYPOINT ["/opt/eqproxy"]
CMD ["--help"]
