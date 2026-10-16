#!/bin/bash
# Release pipeline for EQProxy (v0.4.2+).
#
# Builds four release binaries, regenerates the SBOM, and E2E-verifies
# EVERY artifact (real binary, real sockets, observable results) BEFORE
# any checksum is recorded. Nothing here is a smoke test: each binary
# must validate, explain, diff and proxy live traffic.
#
# Outputs (gitignored): dist/eqproxy-{darwin,linux}-{amd64,arm64},
# dist/SHA256SUMS.txt, sbom/*.cdx.json.
#
# A local run never pushes to the registry nor creates the GitHub
# release (operator credentials); on success it prints the exact
# commands. Pushing a `v*` tag runs the same stages in CI
# (.github/workflows/release.yml), which publishes both with GITHUB_TOKEN.
#
# Usage: ./scripts/release.sh [all|darwin|linux|sbom|sums|verify-image <ref>]
#   all (default): darwin + linux + sbom + sums, the full local release.
#   darwin/linux:  build + E2E-verify that platform's binaries into dist/.
#   sbom:          regenerate sbom/*.cdx.json from the workspace.
#   sums:          write dist/SHA256SUMS.txt (requires all four binaries).
#   verify-image:  E2E-verify a built container image (version, config
#                  gate and live proxied traffic through the container).
# Env:   RUST_IMAGE (default rust:1.97-bookworm) for the Linux builds.
set -euo pipefail

VER="0.5.0"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
RUST_IMAGE="${RUST_IMAGE:-rust:1.97-bookworm}"

log() { printf '==> %s\n' "$*"; }
fail() { printf 'release FAILED: %s\n' "$*" >&2; exit 1; }

GOOD_CONFIG='schema_version = 1
[listener.web]
listen = "127.0.0.1:0"
backend = "api"
[backend.api]
server = "127.0.0.1:9"
'

# --- per-binary E2E verification (real behavior, observable results) ---
# $1 = "native", $2 = host path of the binary. Linux binaries are
# verified by the container blocks further below, never by fakes.
verify_cli() {
    local mode="$1" bin="$2"
    [ "$mode" = "native" ] || fail "verify_cli supports native only"
    local run
    run() { "$bin" "$@"; }
    log "E2E $bin: --version"
    run --version | grep -q "eqproxy $VER" || fail "$bin reports wrong version"
    log "E2E $bin: validate accepts good config"
    printf '%s' "$GOOD_CONFIG" | run config validate --config /dev/stdin \
        | grep -q "config OK: 1 listener(s), 1 backend(s)" \
        || fail "$bin validate happy path"
    log "E2E $bin: validate rejects missing file with exit 1"
    if run config validate --config /nonexistent-e2e.toml 2>/tmp/e2e-err.txt; then
        fail "$bin accepted a missing file"
    fi
    grep -q "could not read the file" /tmp/e2e-err.txt \
        || fail "$bin missing-file error not actionable"
    log "E2E $bin: explain simulates without side effects"
    printf '%s' "$GOOD_CONFIG" | run config explain --config /dev/stdin \
        | grep -q "simulation: true (no requests issued, no state changed)" \
        || fail "$bin explain report"
    log "E2E $bin: diff finds no differences on identical input"
    printf '%s' "$GOOD_CONFIG" > /tmp/e2e-left.toml
    cp /tmp/e2e-left.toml /tmp/e2e-right.toml
    run config diff /tmp/e2e-left.toml /tmp/e2e-right.toml 2>/dev/null \
        | grep -q "no differences" || fail "$bin diff identical"
    log "E2E $bin: apply stores offline and rollback walks back"
    export EQPROXY_STATE_DIR
    EQPROXY_STATE_DIR="$(mktemp -d /tmp/e2e-state-XXXXXX)"
    printf '%s' "$GOOD_CONFIG" > /tmp/e2e-cand.toml
    run config apply --config /tmp/e2e-cand.toml > /tmp/e2e-apply.txt \
        || fail "$bin apply first failed"
    grep -q "no previous configuration" /tmp/e2e-apply.txt \
        || fail "$bin apply first"
    run config apply --config /tmp/e2e-cand.toml > /tmp/e2e-apply.txt \
        || fail "$bin apply idempotent failed"
    grep -q "already applied" /tmp/e2e-apply.txt \
        || fail "$bin apply idempotent"
    log "E2E $bin: doctor passes pre-flight on a free port"
    run doctor --config /tmp/e2e-cand.toml > /tmp/e2e-doctor.txt \
        || fail "$bin doctor failed"
    grep -q "doctor: PASS" /tmp/e2e-doctor.txt \
        || fail "$bin doctor verdict"
    grep -q "ok: bind" /tmp/e2e-doctor.txt \
        || fail "$bin doctor bind probe"
    if run config rollback 2>/tmp/e2e-err.txt; then
        fail "$bin rollback with empty history succeeded"
    fi
    grep -q "no previous configuration" /tmp/e2e-err.txt \
        || fail "$bin rollback empty not explicit"
    rm -rf "$EQPROXY_STATE_DIR"
    unset EQPROXY_STATE_DIR
}

# Waits until 127.0.0.1:$1 accepts TCP (bounded); fails with logs on timeout.
wait_for_port() {
    local port="$1" label="$2" i
    for i in $(seq 1 50); do
        if python3 -c "import socket,sys; socket.create_connection(('127.0.0.1',$port),timeout=1).close()" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
    done
    # Logs on timeout, as promised: a silent 60s wait in CI is undiagnosable.
    {
        echo "--- diagnostics: $label on 127.0.0.1:$port ---"
        python3 --version 2>&1
        echo "connect_ex (0 ok / 61 refused / 60 timeout): $(python3 -c "import socket; s=socket.socket(); s.settimeout(2); print(s.connect_ex(('127.0.0.1',$port)))" 2>&1)"
        lsof -nP -iTCP:$port 2>&1 || true
        echo "--- /tmp/e2e-backend.log ---"
        cat /tmp/e2e-backend.log 2>&1 || true
    } >&2
    fail "$label never listened on 127.0.0.1:$port"
}

# Live traffic through a natively-executed binary (python backend). Ports
# are probed free at runtime: fixed ports risk stale holders (e.g. a
# lingering userland proxy), which must fail loudly, never be assumed.
verify_live_native() {
    local bin="$1"
    local port backend_port
    read -r port backend_port <<< "$(python3 -c "import socket
a=socket.socket(); a.bind(('127.0.0.1',0)); p1=a.getsockname()[1]; a.close()
b=socket.socket(); b.bind(('127.0.0.1',0)); p2=b.getsockname()[1]; b.close()
print(p1,p2)")"
    log "E2E $bin: live proxied traffic on 127.0.0.1:$port"
    # Raw-socket test backend. NOT python3 -m http.server: since CPython 3.13
    # (DualStackServer removed) the CLI resolves socket.getfqdn() between
    # bind() and listen(), and that reverse DNS blocks for minutes on runners
    # with a slow PTR resolver (CI darwin job 2026-10-16: socket bound,
    # listen() never reached, banner never printed). No name resolution here.
    python3 -c "
import socket
body = b'hello-release-e2e\n'
resp = (b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode()
        + b'\r\nConnection: close\r\n\r\n' + body)
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $backend_port))
s.listen(16)
print('listening', flush=True)
while True:
    c, _ = s.accept()
    try:
        c.recv(65536)
        c.sendall(resp)
    finally:
        c.close()
" >/tmp/e2e-backend.log 2>&1 &
    local backend_pid=$!
    wait_for_port "$backend_port" "backend"
    cat > /tmp/e2e-proxy.toml <<EOF
schema_version = 1
[listener.web]
listen = "127.0.0.1:$port"
mode = "http"
backend = "api"
[backend.api]
server = "127.0.0.1:$backend_port"
EOF
    "$bin" run --config /tmp/e2e-proxy.toml >/tmp/e2e-proxy.log 2>&1 &
    local proxy_pid=$!
    wait_for_port "$port" "proxy $bin"
    local body
    body="$(curl -s "http://127.0.0.1:$port/")" \
        || fail "$bin live traffic: curl failed"
    kill "$proxy_pid" "$backend_pid" 2>/dev/null || true
    [ "$body" = "hello-release-e2e" ] \
        || fail "$bin live traffic mismatch: $body"
    log "E2E $bin: live traffic OK"
}

# Live proxied traffic through a container on a static-IP docker network
# (backend nginx: dynamic DNS is Phase 4, B16, so hostnames stay rejected).
# $1 = verdict label, $2 = proxy image, remaining args go to `docker run`
# before the image (mounted binary + entrypoint, or nothing for the real
# release image).
verify_live_container() {
    local verdict="$1" proxy_image="$2"; shift 2
    local net="eqrel-net"
    log "E2E $proxy_image: live proxied traffic ($verdict)"
    docker network create --subnet 172.22.0.0/24 "$net" >/dev/null
    docker run -d --network "$net" --ip 172.22.0.10 --name eqrel-back \
        nginx:alpine >/dev/null
    sleep 2
    cat > /tmp/e2e-proxy.toml <<'EOF'
schema_version = 1
[listener.web]
listen = "0.0.0.0:18082"
mode = "http"
backend = "api"
[backend.api]
server = "172.22.0.10:80"
EOF
    docker run -d --network "$net" --ip 172.22.0.20 --name eqrel-prox \
        -p 18082:18082 "$@" \
        -v /tmp/e2e-proxy.toml:/c.toml:ro \
        "$proxy_image" run --config /c.toml >/dev/null
    sleep 4
    local code
    code="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18082/)"
    docker rm -f eqrel-prox eqrel-back >/dev/null
    docker network rm "$net" >/dev/null
    [ "$code" = "200" ] || fail "$proxy_image live traffic HTTP $code ($verdict)"
    log "E2E $proxy_image: live traffic OK ($verdict)"
}

# Live traffic for a Linux dist binary inside containers.
verify_live_linux() {
    local platform="$1" bin_host="$2" verdict="$3"
    verify_live_container "$platform, $bin_host" debian:bookworm-slim \
        --platform "$platform" -v "$bin_host:/eqproxy:ro" --entrypoint /eqproxy
}

# Image artifact verification: the release image must report the pinned
# version, accept the good config and proxy live traffic as a container.
verify_image() {
    local image="$1"
    log "E2E $image: --version"
    docker run --rm "$image" --version | grep -q "eqproxy $VER" \
        || fail "$image reports wrong version"
    log "E2E $image: validate accepts good config"
    printf '%s' "$GOOD_CONFIG" | docker run --rm -i "$image" \
        config validate --config /dev/stdin \
        | grep -q "config OK: 1 listener(s), 1 backend(s)" \
        || fail "$image validate happy path"
    verify_live_container "image artifact" "$image"
}

# --- stages: one source of truth for local runs and the Release workflow ---

stage_darwin() {
    log "building darwin binaries (native toolchain)"
    local target
    for target in aarch64-apple-darwin x86_64-apple-darwin; do
        (cd "$ROOT" && cargo build --release --locked -p eqproxy-cli \
            --target "$target") || fail "build $target"
    done
    cp "$ROOT/target/aarch64-apple-darwin/release/eqproxy" "$DIST/eqproxy-darwin-arm64"
    cp "$ROOT/target/x86_64-apple-darwin/release/eqproxy" "$DIST/eqproxy-darwin-amd64"

    log "verifying darwin-arm64 (native)"
    verify_cli native "$DIST/eqproxy-darwin-arm64"
    verify_live_native "$DIST/eqproxy-darwin-arm64"

    log "verifying darwin-amd64 (Rosetta)"
    if arch -x86_64 true 2>/dev/null; then
        verify_cli native "$DIST/eqproxy-darwin-amd64"
        verify_live_native "$DIST/eqproxy-darwin-amd64"
    else
        fail "Rosetta missing: darwin-amd64 NOT EXECUTED is not acceptable for release"
    fi
}

stage_linux() {
    local arch bin
    log "building linux binaries (locked, in $RUST_IMAGE per arch)"
    for arch in amd64 arm64; do
        docker buildx build --platform "linux/$arch" --file "$ROOT/docker/Dockerfile" \
            --target export --output "type=local,dest=$DIST/linux-$arch-tmp" "$ROOT" \
            || fail "linux/$arch image build"
        mv "$DIST/linux-$arch-tmp/eqproxy" "$DIST/eqproxy-linux-$arch"
        rm -rf "$DIST/linux-$arch-tmp"
    done

    for arch in arm64 amd64; do
        bin="$DIST/eqproxy-linux-$arch"
        log "verifying linux-$arch (container)"
        docker run --rm --platform "linux/$arch" \
            -v "$DIST:/d:ro" -v /tmp:/tmp \
            --entrypoint /bin/bash debian:bookworm-slim -c "
                set -e
                /d/eqproxy-linux-$arch --version | grep -q 'eqproxy $VER'
                printf '%s' '$GOOD_CONFIG' | /d/eqproxy-linux-$arch config validate --config /dev/stdin | grep -q 'config OK'
            " || fail "$bin container CLI verification"
        verify_live_linux "linux/$arch" "$bin" "HTTP 200"
    done
}

stage_sbom() {
    log "regenerating SBOM (JSON, one file per crate into sbom/)"
    (cd "$ROOT" && cargo cyclonedx --all --format json) || fail "SBOM regeneration"
    local crate
    for crate in eqproxy-core eqproxy-config eqproxy-net eqproxy-cli; do
        mv "$ROOT/$crate/$crate.cdx.json" "$ROOT/sbom/$crate.cdx.json"
    done
    # Machine layout must never ship: strip the absolute build path from the
    # `path+file://` bom-refs (audit 2026-10-16: /Volumes/... in published
    # SBOMs). Portable sed (-i.bak works on BSD and GNU), then drop the backups.
    sed -i.bak -E 's|path[+]file://[^"#]*/(eqproxy-[^"/#]+)|path+file://\1|g' \
        "$ROOT"/sbom/*.cdx.json || fail "SBOM path sanitization"
    rm -f "$ROOT"/sbom/*.cdx.json.bak
    if grep -q -F 'path+file:///' "$ROOT"/sbom/*.cdx.json; then
        fail "SBOM still contains absolute paths after sanitization"
    fi
}

write_sums() {
    local bin
    for bin in eqproxy-darwin-amd64 eqproxy-darwin-arm64 \
               eqproxy-linux-amd64 eqproxy-linux-arm64; do
        [ -f "$DIST/$bin" ] || fail "missing $bin in $DIST (run the build stages first)"
    done
    log "writing SHA256SUMS (only after every artifact passed)"
    (cd "$DIST" && if command -v sha256sum >/dev/null 2>&1; then
        sha256sum eqproxy-darwin-amd64 eqproxy-darwin-arm64 \
            eqproxy-linux-amd64 eqproxy-linux-arm64 > SHA256SUMS.txt
    else
        shasum -a 256 eqproxy-darwin-amd64 eqproxy-darwin-arm64 \
            eqproxy-linux-amd64 eqproxy-linux-arm64 > SHA256SUMS.txt
    fi)
    cat "$DIST/SHA256SUMS.txt"
}

print_next_steps() {
    printf '%s\n' \
        "" \
        "Next (operator, needs credentials — NOT run by this script):" \
        "  docker buildx build --file docker/Dockerfile \\" \
        "    --platform linux/amd64,linux/arm64 \\" \
        "    --tag ghcr.io/exyonq/eqproxy:$VER --tag ghcr.io/exyonq/eqproxy:latest --push ." \
        "  git tag v$VER && git push origin v$VER" \
        "  gh release create v$VER dist/* sbom/*.cdx.json --title v$VER --notes-file CHANGELOG.md" \
        "(pushing the v$VER tag runs the same stages in CI and publishes both)"
}

mkdir -p "$DIST"

log "checking version pins"
grep -q "version = \"$VER\"" "$ROOT/Cargo.toml" \
    || fail "workspace version is not $VER"

case "${1:-all}" in
    darwin)
        stage_darwin
        ;;
    linux)
        stage_linux
        ;;
    sbom)
        stage_sbom
        ;;
    sums)
        write_sums
        ;;
    verify-image)
        [ -n "${2:-}" ] || fail "usage: release.sh verify-image <image-ref>"
        verify_image "$2"
        ;;
    all)
        stage_darwin
        stage_linux
        stage_sbom
        write_sums
        log "release artifacts ready in $DIST"
        print_next_steps
        ;;
    *)
        fail "unknown stage '$1' (darwin|linux|sbom|sums|verify-image <ref>|all)"
        ;;
esac
