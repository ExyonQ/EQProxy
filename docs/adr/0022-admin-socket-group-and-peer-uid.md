# ADR-0022: Group-shared admin socket and peer-uid allowlist

Language: **English**.

- State: **Accepted** (2026-10-25, roadmap v0.8 B-H14)
- Date: 2026-10-25
- Related: [ADR-0021](0021-admin-unix-socket.md) (Unix socket endpoint),
  [ADR-0017](0017-read-only-admin-plane.md),
  [ADR-0018](0018-first-write-path-server-state.md),
  [SPEC §9](../SPEC.md), [THREAT_MODEL.md](../../THREAT_MODEL.md)

## Context

ADR-0021 gave the administration plane a Unix socket with mode `0600`. That
is correct for a single operator uid, but it makes the plane unusable for the
common deployment where a monitoring or operations group must read it: every
member would need the owner's uid, and containers frequently run the proxy
under a different uid from the scrapers.

Loosening the mode alone is not enough. `0660` admits **every** process whose
gid matches, including a compromised sidecar in that group. The kernel
already reports the connecting peer's uid (`SO_PEERCRED` on Linux,
`getpeereid` on macOS); using it as a second, explicit allowlist keeps the
failure mode narrow.

## Decision

`[admin]` accepts, only together with `unix_socket`:

```toml
unix_socket = "/run/eqproxy/admin.sock"
unix_socket_mode = "0660"          # "0600" (default) or "0660", nothing else
unix_socket_gid = 20               # numeric gid, required with 0660
unix_socket_allow_uids = [501, 502] # optional; empty = any uid the mode allows
```

### Semantics

- **Mode and group form a pair.** `0600` means owner only and refuses a gid;
  `0660` requires the numeric gid. Any other mode string is a configuration
  error. The order is `bind` → optional `chown(gid)` → `chmod(mode)`, because
  `chown` may clear mode bits; a failing `chown` aborts startup and removes
  the socket it just created.
- **Numeric gid only.** Group *names* need NSS (`getgrnam_r`), which is not
  reachable from this crate: the workspace forbids `unsafe`, and shelling out
  to `id`/`getent` would make startup depend on another binary. The operator
  supplies the number their platform already uses.
- **The allowlist is checked before HTTP.** Immediately after `accept`, the
  peer credential is compared with the list; a non-member (or a peer whose
  uid the kernel did not report) is closed with a `WARN` line, without
  reading a request line, headers or body. An empty list keeps the
  filesystem as the only boundary.
- **The bearer token still applies.** The uid check precedes the HTTP parser;
  after it, the read/write tokens gate the routes exactly as before. The
  filesystem, the uid list and the token are three independent layers.
- **Audit identity.** The existing `AUDIT` lines keep the peer as
  `unix-socket:uid=<uid>`, so a write can be traced to the uid the kernel
  reported. The uid is recorded, not trusted beyond the allowlist decision.

### Hot reload (SIGHUP)

Mode, group and allowlist are **not** startup-only. `AdminHandle` exposes a
[`UnixSocketPolicy`](../../eqproxy-net/src/admin.rs) whose `apply` writes the
file policy and swaps the list the accept loop reads. On SIGHUP the
configuration task:

1. validates the candidate (the usual whole-document check);
2. applies the new policy **before** the dataplane swap — `chown` then
   `chmod`, because a `chown` may clear mode bits, restoring the previous
   ownership and mode if either call fails;
3. asks the dataplane to swap, and puts the previous policy back if the swap
   is refused.

The peer-uid list is read once per accepted connection from a shared cell
(an `Arc` clone, no lock across an `await`), so the next peer is judged by
the new list even though the listener, the accept loop and every open
connection are untouched. A failed policy application is a rejected
generation: nothing is swapped, the file keeps the old bits, the old list
stays in force, and the rejection is logged with the failing syscall. The
endpoint and the tokens remain fixed at startup (they are a bound socket and
loaded secrets); a reload that changes them logs a `WARN` and keeps serving
the old ones.

### Rejected alternatives

- **A single `chmod` knob up to `0666`.** A world-writable admin socket is
  never a supported configuration.
- **Resolving group names in-process.** Would add a C/NSS dependency and
  `unsafe`, against the workspace lint.
- **Using the group alone as authorization.** A compromised process in the
  group would gain the whole plane; the uid list narrows that.

## Consequences

- **Deployment needs a gid.** `unix_socket_gid` must match a group that
  already exists and that the proxy may assign; an unprivileged process can
  only `chown` to a group it belongs to, otherwise startup fails with the OS
  error. This is deliberate: no silent fallback to `0600` or `0660`.
- **Filesystem + kernel assumptions.** The mode is POSIX; `SO_PEERCRED` is
  Linux and `getpeereid` is macOS/BSD, both behind Tokio's `peer_cred()`. On a
  platform where the credential is unavailable, a non-empty allowlist denies
  every connection (fail closed); an empty list is unaffected.
- **No pid check.** Only uid is compared; a uid allowlist authorizes every
  process of that user, not one process.
- **Root can still bypass the filesystem.** This is a boundary against
  unprivileged peers, not against the platform administrator.
- **Hot policy, fixed endpoint.** Changing the path or the tokens still
  needs a restart; changing mode, group or allowlist does not.
- **Still pending for v0.9.1:** ACLs, abstract sockets and systemd socket
  activation.
