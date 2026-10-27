#!/usr/bin/env bash
# v0.8 / B-H14 (ADR-0023): POSIX ACL named users on the admin Unix socket.
#
# Published at `.github/scripts/` because the release pipeline needs it and
# `scripts/` never ships. Two callers, one file:
#   * `.github/workflows/release.yml`, step "Admin socket ACL E2E on both
#     architectures", which runs it on linux/amd64 and linux/arm64 against the
#     binary of the candidate image and blocks the digest promotion if it
#     fails;
#   * `scripts/evidence/v08-admin-unix-acl/{e2e-multiarch,run}.sh`, the local
#     evidence harness, which mounts it into a container of the platform under
#     test.
#
# Runs as root on Linux: it starts the real eqproxy as uid 1000 / gid 2000,
# then makes four clients with `setpriv` — the owner, a user admitted **only**
# by the ACL, a member of the socket's group without an ACL entry, and an
# outsider. Every answer is real: the kernel decides at connect(2), `getfacl`
# reads the attribute back, and a SIGHUP removes the named user without
# touching the mode.
#
# The binary under test is `$EQPROXY_BIN` when set (the native CI job runs the
# binary it just compiled for its own architecture), `/opt/eqproxy` otherwise
# (the release gate mounts the bytes extracted from the scanned image).
#
# It is an E2E journey, not a smoke test: every observable result below is
# compared against its expectation and the script exits 1 if any differs.
set -euo pipefail

say() { printf '%s\n' "$*"; }
step() { printf '\n$ %s\n' "$*"; }

failures=0
expect() { # label expected actual
    if [[ "$3" == "$2" ]]; then
        say "PASS $1: $3"
    else
        say "FAIL $1: expected [$2], got [$3]"
        failures=$((failures + 1))
    fi
}

apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends curl acl >/dev/null

# The uid the ACL admits. Defaults to the ACL-only client; `ACL_UID=2002` is the
# negative control that makes the assertions below fail on purpose, which is
# how this script proves it is not vacuously green.
acl_uid=${ACL_UID:-2001}

token="9c2f5a7e1b4d8c6f0a3e5b7d9f1c4a6e"
bin=${EQPROXY_BIN:-/opt/eqproxy}
sock=/srv/eqproxy/admin.sock
config=/etc/eqproxy/eqproxy.toml
log=/var/log/eqproxy.log

# The socket lives on the container's overlayfs: Docker's tmpfs mounts on this
# kernel are created without ACL support (setfacl: Operation not supported),
# while overlayfs carries system.posix_acl_access.
mkdir -p /srv/eqproxy /etc/eqproxy
rm -f /srv/eqproxy/*
rm -f /etc/eqproxy/*
chown 1000:2000 /srv/eqproxy
chmod 0755 /srv/eqproxy /etc/eqproxy

write_config() { # acl list
    cat >"$config" <<EOF
schema_version = 1
shutdown_grace = "1s"
[listener.web]
listen = "127.0.0.1:38080"
mode = "http"
backend = "api"
[backend.api]
server = "127.0.0.1:38081"
[admin]
unix_socket = "/srv/eqproxy/admin.sock"
token = "$token"
unix_socket_mode = "0660"
unix_socket_gid = 2000
unix_socket_acl_uids = [$1]
EOF
    chmod 0644 "$config"
}

# Runs `curl` (or any command) as a concrete uid/gid with no supplementary
# groups, so the group path is exactly the one the socket names.
as_uid() { # uid gid command...
    local uid=$1 gid=$2
    shift 2
    setpriv --reuid="$uid" --regid="$gid" --clear-groups -- "$@"
}

status_as() { # uid gid -> "<curl exit> <http code>"
    local code status
    code=$(as_uid "$1" "$2" curl -s -o /dev/null -w '%{http_code}' \
        --unix-socket "$sock" -H "Authorization: Bearer $token" \
        http://localhost/api/v1/status 2>/dev/null) || status=$?
    printf '%s %s' "${status:-0}" "${code:-000}"
}

wait_log() { # needle
    local deadline=$((SECONDS + 60))
    while ((SECONDS < deadline)); do
        grep -qF -- "$1" "$log" && return 0
        sleep 0.1
    done
    say "TIMEOUT waiting for: $1"
    tail -5 "$log"
    return 1
}

say "kernel: $(uname -sr), machine: $(uname -m)"
say "server binary: $bin"
say "eqproxy version: $("$bin" --version 2>/dev/null || true)"
say "uid/gid plan: owner 1000:2000, ACL-only 2001:3001, group-only 2003:2000, outsider 2002:3002"
say "ACL admits uid: $acl_uid"

write_config "$acl_uid"
step "eqproxy run --config $config  (as 1000:2000)"
setpriv --reuid=1000 --regid=2000 --clear-groups -- "$bin" run --config "$config" \
    --metrics-interval 1h >>"$log" 2>&1 &
server=$!
for _ in $(seq 600); do [[ -S "$sock" ]] && break; sleep 0.05; done
[[ -S "$sock" ]] || { say "socket never appeared"; tail -20 "$log"; exit 1; }
wait_log "admin listening on unix:" || exit 1
grep -F "admin listening" "$log"

step "stat -c '%a %u %g %F' $sock"
stat_out=$(stat -c '%a %u %g %F' "$sock")
say "$stat_out"
expect "socket owner/mode/type" "660 1000 2000 socket" "$stat_out"

step "getfacl -p $sock"
facl=$(getfacl -p "$sock")
say "$facl"
if grep -qx "user:$acl_uid:rw-" <<<"$facl"; then say "PASS named user in ACL: user:$acl_uid:rw-"; else say "FAIL named user user:$acl_uid:rw- missing from ACL"; failures=$((failures + 1)); fi
if grep -qx 'mask::rw-' <<<"$facl"; then say "PASS group-class mask: mask::rw-"; else say "FAIL group-class mask not rw-"; failures=$((failures + 1)); fi
if grep -qx 'other::---' <<<"$facl"; then say "PASS others have no access: other::---"; else say "FAIL others are not excluded"; failures=$((failures + 1)); fi

step "id 2001 (not in group 2000) / id 2003 (in group 2000)"
say "$(as_uid 2001 3001 id)"
say "$(as_uid 2003 2000 id)"

step "status as owner 1000:2000"
r=$(status_as 1000 2000); say "exit/http = $r"; expect "owner reaches the plane" "0 200" "$r"
step "status as ACL-only 2001:3001"
r=$(status_as 2001 3001); say "exit/http = $r"; expect "ACL user reaches the plane" "0 200" "$r"
step "status as group-only 2003:2000"
r=$(status_as 2003 2000); say "exit/http = $r"; expect "group member reaches the plane" "0 200" "$r"
step "status as outsider 2002:3002 (not owner, not group, no ACL)"
r=$(status_as 2002 3002); say "exit/http = $r"; expect "outsider is refused by the kernel" "7 000" "$r"

# --- hot reload: remove the named user, keep the mode and the group --------
write_config ""
step "sed -n '/\\[admin\\]/,\$p' $config; kill -HUP $server"
sed -n '/\[admin\]/,$p' "$config"
kill -HUP "$server"
wait_log "INFO admin socket policy applied" || exit 1
grep -F "INFO admin socket policy applied" "$log"

step "getfacl -p $sock  (named user gone, mode and group intact)"
facl=$(getfacl -p "$sock")
say "$facl"
if grep -q "^user:$acl_uid:" <<<"$facl"; then say "FAIL named user user:$acl_uid survived the reload"; failures=$((failures + 1)); else say "PASS named user removed from the ACL"; fi
stat_out=$(stat -c '%a %u %g' "$sock")
say "$stat_out"
expect "mode/owner kept across the reload" "660 1000 2000" "$stat_out"

step "status as ACL-only 2001:3001 after the reload"
r=$(status_as 2001 3001); say "exit/http = $r"; expect "removed user is refused after the reload" "7 000" "$r"
step "status as group-only 2003:2000 after the reload"
r=$(status_as 2003 2000); say "exit/http = $r"; expect "group member still reaches the plane" "0 200" "$r"
step "status as owner 1000:2000 after the reload"
r=$(status_as 1000 2000); say "exit/http = $r"; expect "owner still reaches the plane" "0 200" "$r"

# --- clean shutdown --------------------------------------------------------
step "kill -INT $server; wait"
kill -INT "$server"
exit_code=0
wait "$server" || exit_code=$?
say "exit=$exit_code"
expect "clean shutdown exit code" "0" "$exit_code"
if [[ -e "$sock" ]]; then say "FAIL socket left behind"; failures=$((failures + 1)); else say "PASS socket removed on shutdown"; fi
if grep -qE '^(ERROR|WARN)' "$log"; then
    say "FAIL server logged an error or warning:"
    grep -E '^(ERROR|WARN)' "$log"
    failures=$((failures + 1))
else
    say "PASS no ERROR/WARN line in the server log"
fi

say ""
if ((failures > 0)); then
    say "RESULT: $failures assertion(s) failed"
    exit 1
fi
say "RESULT: all assertions passed"
