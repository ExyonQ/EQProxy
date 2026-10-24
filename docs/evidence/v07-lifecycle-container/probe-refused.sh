#!/usr/bin/env bash
# Measure one REFUSED_STREAM replay per fresh origin/proxy pair on amd64.
set -uo pipefail
REPO=/Volumes/Lexar/Cursor/EQProxy
E="$REPO/docs/evidence/v07-lifecycle-container"
ARCH=amd64
ORIGIN=28473
PROXY=28083
OUT=/tmp/dockerlife/probe-amd64
rm -rf "$OUT"; mkdir -p "$OUT"

for attempt in 1 2 3; do
  rec="$OUT/seen-$attempt.jsonl"
  python3 "$E/origin.py" "$REPO/eqproxy-net/tests/fixtures/cert.pem" \
    "$REPO/eqproxy-net/tests/fixtures/key.pem" "$ORIGIN" "$rec" \
    > "$OUT/origin-$attempt.log" 2>&1 &
  OPID=$!
  for _ in $(seq 60); do grep -q 'origin listening' "$OUT/origin-$attempt.log" && break; sleep 0.1; done

  cat > "$OUT/c.toml" <<CFG
schema_version = 1
[listener.web]
listen = "0.0.0.0:$PROXY"
mode = "http"
backend = "api"
idle_timeout = "5s"
[backend.api]
server = "host.docker.internal:$ORIGIN"
tls = { ca_file = "/certs/cert.pem", server_name = "localhost", alpn = ["h2"] }
CFG
  docker rm -f eqplife-probe >/dev/null 2>&1
  docker run -d --name eqplife-probe --platform "linux/$ARCH" \
    --add-host=host.docker.internal:host-gateway \
    -p "$PROXY:$PROXY" -v "$OUT/c.toml:/c.toml:ro" \
    -v "$REPO/eqproxy-net/tests/fixtures:/certs:ro" \
    eqproxy-local:v07-$ARCH run --config /c.toml >/dev/null
  for _ in $(seq 100); do
    docker logs eqplife-probe 2>&1 | grep -q "listening on 0.0.0.0:$PROXY" && break
    sleep 0.1
  done
  sleep 0.2

  t1=$(python3 -c 'import time; print(time.time())')
  curl -sS -o "$OUT/body-$attempt.txt" \
    -w '%{http_code} total=%{time_total} connect=%{time_connect} ttfb=%{time_starttransfer}\n' \
    -H "x-req: replay-$attempt" -H 'x-refuse: 1' \
    --max-time 10 "http://127.0.0.1:$PROXY/echo" > "$OUT/timing-$attempt.txt"
  t2=$(python3 -c 'import time; print(time.time())')

  docker kill --signal=INT eqplife-probe >/dev/null 2>&1
  docker wait eqplife-probe >/dev/null
  docker logs eqplife-probe > "$OUT/proxy-$attempt.log" 2>&1
  docker rm -f eqplife-probe >/dev/null 2>&1
  kill "$OPID" 2>/dev/null; wait "$OPID" 2>/dev/null

  printf 'attempt %s: body=%s %s\n' "$attempt" "$(cat "$OUT/body-$attempt.txt")" "$(cat "$OUT/timing-$attempt.txt")"
  python3 - "$rec" "$t1" "$t2" <<'PY'
import json, sys
rec, t1, t2 = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
rows = [json.loads(line) for line in open(rec)]
first = next(r for r in rows if r.get("phase") is None and "path" in r)
answered = next(r for r in rows if r.get("phase") == "answered")
print(f"  curl_start->origin_request: {first['t'] - t1:.3f}s")
print(f"  origin_request->answered:   {answered['t'] - first['t']:.3f}s")
print(f"  curl_start->curl_end:       {t2 - t1:.3f}s")
print(f"  refusals={sum(1 for r in rows if r.get('refused'))} answered={sum(1 for r in rows if r.get('phase') == 'answered')}")
PY
  grep -o 'h2\[[^]]*\]' "$OUT/proxy-$attempt.log" | tail -1 | sed 's/^/  /'
done
