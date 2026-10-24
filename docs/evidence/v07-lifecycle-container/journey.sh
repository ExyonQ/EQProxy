#!/usr/bin/env bash
# Container journeys for the backend HTTP/2 session lifecycle (v0.7 slice 4).
#
# usage: journey.sh <image> <arch-label> <origin-port> <proxy-port> <workdir>
#
# The origin is the independent Python hyper-h2 server (/tmp/dockerlife/origin.py)
# listening on the host loopback; the proxy container reaches it through
# host.docker.internal, so the container really dials TLS+h2 to a process outside
# itself. curl runs on the host against the published listener port.
set -uo pipefail

IMAGE="$1"
ARCH="$2"
ORIGIN_PORT="$3"
PROXY_PORT="$4"
OUT="$5"

REPO=/Volumes/Lexar/Cursor/EQProxy
CERT="$REPO/eqproxy-net/tests/fixtures/cert.pem"
KEY="$REPO/eqproxy-net/tests/fixtures/key.pem"
NAME="eqplife-$ARCH"
ORIGIN_PID=""
FAILED=0

mkdir -p "$OUT"
pass() { printf 'PASS %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; FAILED=1; }

check_contains() { # file needle label
  if grep -qF -- "$2" "$1"; then pass "$3"; else fail "$3 (missing: $2 in $1)"; fi
}
check_absent() { # file needle label
  if grep -qF -- "$2" "$1"; then fail "$3 (unexpected: $2)"; else pass "$3"; fi
}

check_counter() { # file counter value label
  if grep -qE "h2\\[[^]]*$2=$3([^0-9]|$)" "$1"; then pass "$4"; else fail "$4 (h2 group: $(grep -o 'h2\[[^]]*\]' "$1" | tail -1))"; fi
}

start_origin() { # record label
  python3 /tmp/dockerlife/origin.py "$CERT" "$KEY" "$ORIGIN_PORT" "$1" \
    > "$OUT/origin-$2.log" 2>&1 &
  ORIGIN_PID=$!
  for _ in $(seq 60); do
    grep -q 'origin listening' "$OUT/origin-$2.log" 2>/dev/null && return 0
    sleep 0.1
  done
  fail "origin did not start on $ORIGIN_PORT"
  return 1
}

stop_origin() {
  if [ -n "$ORIGIN_PID" ]; then kill "$ORIGIN_PID" 2>/dev/null; wait "$ORIGIN_PID" 2>/dev/null; fi
  ORIGIN_PID=""
}

write_config() { # idle_timeout path
  cat > "$2" <<EOF
schema_version = 1

[listener.web]
listen = "0.0.0.0:$PROXY_PORT"
mode = "http"
backend = "api"
idle_timeout = "$1"

[backend.api]
server = "host.docker.internal:$ORIGIN_PORT"
tls = { ca_file = "/certs/cert.pem", server_name = "localhost", alpn = ["h2"] }
EOF
}

start_proxy() { # config
  docker rm -f "$NAME" >/dev/null 2>&1
  # This engine has no host.docker.internal DNS entry; map it to the gateway
  # explicitly (the same flag works on Docker Desktop and on Linux).
  docker run -d --name "$NAME" --platform "linux/$ARCH" \
    --add-host=host.docker.internal:host-gateway \
    -p "$PROXY_PORT:$PROXY_PORT" \
    -v "$1:/c.toml:ro" -v "$REPO/eqproxy-net/tests/fixtures:/certs:ro" \
    "$IMAGE" run --config /c.toml > "$OUT/container-id.txt" 2>&1
}

wait_ready() { # label
  # The listener line is printed once the socket is bound; probing with a real
  # request would add a stream to the origin's record and blur the journey.
  for _ in $(seq 100); do
    if docker logs "$NAME" 2>&1 | grep -q "listener web listening on 0.0.0.0:$PROXY_PORT"; then
      sleep 0.2
      return 0
    fi
    sleep 0.1
  done
  fail "proxy did not listen on $PROXY_PORT ($1)"
  docker logs "$NAME" >&2 2>&1
  return 1
}

stop_proxy() { # logfile
  docker kill --signal=INT "$NAME" >/dev/null 2>&1
  local status
  status="$(docker wait "$NAME" 2>/dev/null)"
  docker logs "$NAME" > "$1" 2>&1
  docker rm -f "$NAME" >/dev/null 2>&1
  [ "$status" = "0" ] || fail "proxy exited $status on SIGINT"
}

echo "=== $ARCH · $IMAGE ==="
docker image inspect --format '{{.Id}} {{.Architecture}} {{.Os}}' "$IMAGE" > "$OUT/image.txt"
cat "$OUT/image.txt"

# --- J0: CLI -----------------------------------------------------------------
docker run --rm --platform "linux/$ARCH" "$IMAGE" --version > "$OUT/version.txt" 2>&1
grep -q 'eqproxy 0.6.3' "$OUT/version.txt" && pass "--version ($(cat "$OUT/version.txt"))" || fail "--version: $(cat "$OUT/version.txt")"

write_config "5s" "$OUT/c.toml"
docker run --rm --platform "linux/$ARCH" -v "$OUT/c.toml:/c.toml:ro" \
  -v "$REPO/eqproxy-net/tests/fixtures:/certs:ro" "$IMAGE" \
  config validate --config /c.toml > "$OUT/validate.txt" 2>&1
grep -q 'config OK: 1 listener(s), 1 backend(s)' "$OUT/validate.txt" \
  && pass "config validate" || fail "config validate: $(cat "$OUT/validate.txt")"

# --- J1: idle close ----------------------------------------------------------
echo "--- J1 idle close (idle_timeout = 1s)"
write_config "1s" "$OUT/c-idle.toml"
start_origin "$OUT/seen-idle.jsonl" idle || exit 1
start_proxy "$OUT/c-idle.toml"
wait_ready idle || true
curl -sS --max-time 5 -H 'x-req: first' "http://127.0.0.1:$PROXY_PORT/echo" > "$OUT/idle-first.txt"
sleep 2.2
curl -sS --max-time 5 -H 'x-req: after-idle' "http://127.0.0.1:$PROXY_PORT/echo" > "$OUT/idle-second.txt"
sleep 0.5
stop_proxy "$OUT/proxy-idle.log"
stop_origin
[ "$(cat "$OUT/idle-first.txt")" = "ok:first" ] && pass "J1 first request" || fail "J1 first: $(cat "$OUT/idle-first.txt")"
[ "$(cat "$OUT/idle-second.txt")" = "ok:after-idle" ] && pass "J1 request after the window" || fail "J1 second: $(cat "$OUT/idle-second.txt")"
check_contains "$OUT/seen-idle.jsonl" '{"session_opened": 1}' 'J1 session 1 opened'
check_contains "$OUT/seen-idle.jsonl" '{"session_closed": 1}' 'J1 session 1 closed by the idle close'
check_contains "$OUT/seen-idle.jsonl" '{"session_opened": 2}' 'J1 second session dialed'
check_contains "$OUT/proxy-idle.log" 'closed an idle HTTP/2 session' 'J1 proxy logged the idle close'
check_contains "$OUT/proxy-idle.log" 'h2[sessions_idle_closed=1 goaway=0 refused_retried=0]' 'J1 counters'
# Order: the first session closed before the second opened.
closed_line=$(grep -n '{"session_closed": 1}' "$OUT/seen-idle.jsonl" | head -1 | cut -d: -f1)
opened2_line=$(grep -n '{"session_opened": 2}' "$OUT/seen-idle.jsonl" | head -1 | cut -d: -f1)
if [ -n "$closed_line" ] && [ -n "$opened2_line" ] && [ "$closed_line" -lt "$opened2_line" ]; then
  pass "J1 closed before redial (line $closed_line < $opened2_line)"
else
  fail "J1 order: closed=$closed_line opened2=$opened2_line"
fi

# --- J2: GOAWAY drain + safe replay -----------------------------------------
echo "--- J2 GOAWAY drain + replay (idle_timeout = 5s)"
start_origin "$OUT/seen-goaway.jsonl" goaway || exit 1
start_proxy "$OUT/c.toml"
wait_ready goaway || true
sleep 0.3
curl -sS --max-time 5 -H 'x-req: warm' "http://127.0.0.1:$PROXY_PORT/echo" > "$OUT/g-warm.txt"
( curl -sS --max-time 8 -o "$OUT/g-inflight.txt" -w '%{http_code} %{time_total}\n' \
    -H 'x-req: inflight' "http://127.0.0.1:$PROXY_PORT/hold?ms=1500" \
    > "$OUT/g-inflight.timing" ) &
HOLD=$!
sleep 0.15
curl -sS --max-time 5 -o "$OUT/g-goaway.txt" -w '%{http_code} %{time_total}\n' \
  -H 'x-req: g1' "http://127.0.0.1:$PROXY_PORT/goaway" > "$OUT/g-goaway.timing"
sleep 0.2
curl -sS --max-time 5 -o "$OUT/g-after.txt" -w '%{http_code} %{time_total}\n' \
  -H 'x-req: after-goaway' "http://127.0.0.1:$PROXY_PORT/echo" > "$OUT/g-after.timing"
wait "$HOLD"
sleep 0.5
stop_proxy "$OUT/proxy-goaway.log"
stop_origin
[ "$(cat "$OUT/g-warm.txt")" = "ok:warm" ] && pass "J2 warm request" || fail "J2 warm: $(cat "$OUT/g-warm.txt")"
[ "$(cat "$OUT/g-goaway.txt")" = "ok:g1" ] && pass "J2 GOAWAY announced" || fail "J2 goaway: $(cat "$OUT/g-goaway.txt")"
[ "$(cat "$OUT/g-after.txt")" = "ok:after-goaway" ] && pass "J2 request racing GOAWAY served once" || fail "J2 after: $(cat "$OUT/g-after.txt")"
[ "$(cat "$OUT/g-inflight.txt")" = "ok:inflight" ] && pass "J2 in-flight stream drained" || fail "J2 in-flight: $(cat "$OUT/g-inflight.txt") $(cat "$OUT/g-inflight.timing")"
check_contains "$OUT/seen-goaway.jsonl" '"goaway_sent": 5' 'J2 origin announced GOAWAY'
check_contains "$OUT/proxy-goaway.log" 'is closing its HTTP/2 session (GOAWAY)' 'J2 proxy logged the drain'
check_counter "$OUT/proxy-goaway.log" goaway 1 'J2 GOAWAY counted'
check_counter "$OUT/proxy-goaway.log" refused_retried 1 'J2 replay counted'
check_contains "$OUT/proxy-goaway.log" 'backend[connect_failures=0' 'J2 backend counters'
# The replayed request reached the origin exactly once, on the second session.
after_records=$(grep '"x_req": "after-goaway"' "$OUT/seen-goaway.jsonl" | grep -c '"phase": "answered"')
after_conns=$(grep '"x_req": "after-goaway"' "$OUT/seen-goaway.jsonl" | grep '"phase": "answered"' | grep -c '"connection": 2')
[ "$after_records" = "1" ] && pass "J2 exactly one copy at the origin" || fail "J2 copies=$after_records"
[ "$after_conns" = "1" ] && pass "J2 replayed on the fresh session" || fail "J2 replayed on conn 2? conns=$after_conns"
# The drain: the in-flight stream's answer came after the GOAWAY was sent.
end_line=$(grep -n '"x_req": "inflight".*"phase": "end"' "$OUT/seen-goaway.jsonl" | cut -d: -f1 | head -1)
goaway_line=$(grep -n '"goaway_sent"' "$OUT/seen-goaway.jsonl" | cut -d: -f1 | head -1)
if [ -n "$end_line" ] && [ -n "$goaway_line" ] && [ "$goaway_line" -lt "$end_line" ]; then
  pass "J2 in-flight answer after the GOAWAY (line $goaway_line < $end_line)"
else
  fail "J2 drain order: goaway=$goaway_line end=$end_line"
fi
closed1_line=$(grep -n '{"session_closed": 1}' "$OUT/seen-goaway.jsonl" | cut -d: -f1 | head -1)
if [ -n "$closed1_line" ] && [ -n "$end_line" ] && [ "$end_line" -lt "$closed1_line" ]; then
  pass "J2 first session closed only after the drained stream"
else
  fail "J2 session 1 close order: end=$end_line closed=$closed1_line"
fi

# --- J3: REFUSED_STREAM replay, exactly once ---------------------------------
echo "--- J3 REFUSED_STREAM replay (idle_timeout = 5s)"
start_origin "$OUT/seen-refuse.jsonl" refuse || exit 1
start_proxy "$OUT/c.toml"
wait_ready refuse || true
curl -sS --max-time 8 -o "$OUT/r-body.txt" -w '%{http_code} %{time_total}\n' \
  -H 'x-req: replay-me' -H 'x-refuse: 1' "http://127.0.0.1:$PROXY_PORT/echo" > "$OUT/r-timing.txt"
sleep 0.3
stop_proxy "$OUT/proxy-refuse.log"
stop_origin
[ "$(cat "$OUT/r-body.txt")" = "ok:replay-me" ] && pass "J3 replayed request served 200" || fail "J3 body: $(cat "$OUT/r-body.txt")"
check_contains "$OUT/seen-refuse.jsonl" '"refused": true' 'J3 origin refused the first stream'
check_counter "$OUT/proxy-refuse.log" goaway 0 'J3 no GOAWAY'
check_counter "$OUT/proxy-refuse.log" refused_retried 1 'J3 replay counted'
served=$(grep -c '"phase": "answered"' "$OUT/seen-refuse.jsonl")
refused=$(grep -c '"refused": true' "$OUT/seen-refuse.jsonl")
[ "$served" = "1" ] && pass "J3 exactly one answered copy" || fail "J3 answered copies=$served"
[ "$refused" = "1" ] && pass "J3 exactly one refusal" || fail "J3 refusals=$refused"
replayed_conn=$(grep '"phase": "answered"' "$OUT/seen-refuse.jsonl" | grep -c '"connection": 2')
[ "$replayed_conn" = "1" ] && pass "J3 replay on a fresh session" || fail "J3 replay conn: $replayed_conn"
check_contains "$OUT/proxy-refuse.log" 'backend[connect_failures=0' 'J3 backend counters'

echo "=== $ARCH failures: $FAILED ==="
cat "$OUT"/*.timing 2>/dev/null
exit "$FAILED"
