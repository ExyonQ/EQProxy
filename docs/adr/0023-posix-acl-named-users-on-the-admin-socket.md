# ADR-0023: Named users in the admin socket's POSIX ACL

Language: **English**.

- State: **Accepted** (2026-10-25, roadmap v0.8 B-H14 / v0.9.1 item)
- Date: 2026-10-25
- Related: [ADR-0021](0021-admin-unix-socket.md) (Unix endpoint),
  [ADR-0022](0022-admin-socket-group-and-peer-uid.md) (group mode and peer-uid
  allowlist), [ADR-0016](0016-wolfi-runtime-base.md) (static musl image),
  [SPEC §9](../SPEC.md), [THREAT_MODEL.md](../../THREAT_MODEL.md)

## Context

ADR-0022 left two layers on the admin Unix socket: the **file** (`0660` plus a
group) and a **peer-uid allowlist** checked after `accept`. They are not
interchangeable:

- the group is all-or-nothing — every member of the gid may `connect`;
- the allowlist is a *filter*, not a grant. A user outside the group cannot
  open the socket at all, so adding that uid to `unix_socket_allow_uids`
  changes nothing: the kernel refuses the connection first.

An operator who wants "the monitoring user and nobody else in that group"
therefore has no option today except widening the group. That is exactly what
POSIX ACLs solve: named users on the file, enforced by the kernel at
`connect`, without touching the group.

## Decision

`[admin]` accepts, only together with a Unix socket in group mode:

```toml
unix_socket = "/run/eqproxy/admin.sock"
unix_socket_mode = "0660"
unix_socket_gid = 20
unix_socket_acl_uids = [501, 502]   # named users with rw, in addition to gid 20
```

### Semantics

- **Requires `0660` + a gid.** An access ACL with named users needs a mask,
  and the file mode's group class *is* that mask. Asking for `0600` and a
  named user would silently make the file group-readable, so validation
  refuses the combination instead of picking one interpretation.
- **Adds, never replaces.** The named users join the group in the `rw` class;
  the group keeps its access, and the owner keeps theirs. `other` stays
  `---`.
- **Enforced by the kernel at `connect`.** A named user outside the group can
  now open the socket; a user in neither the group nor the ACL still gets
  `EACCES` from `connect` and never reaches this process.
- **Independent of the allowlist.** `unix_socket_allow_uids` still filters
  the peer credential after `accept`; the ACL is the filesystem grant. Both
  apply (AND). A named user who is also in the allowlist passes both.
- **Hot like the rest of the policy.** `SIGHUP` replaces the named entries,
  and an emptied list **removes** the attribute so no stale user survives the
  reload. The mode, the group and the allowlist move in the same step
  (ADR-0022).
- **Bounded.** At most 64 named users; the encoded attribute is
  `4 + 8 * (4 + n)` bytes, 548 at the limit.

### How it is written

Not with `acl_set_file`: that is a C library (`libacl`), and this workspace
forbids `unsafe`, while the image is a static musl binary on Wolfi
(ADR-0016) where linking another C library would be a new runtime
dependency. Linux stores the access ACL in the extended attribute
`system.posix_acl_access`, whose layout is kernel UAPI
(`include/uapi/linux/posix_acl_xattr.h`); `acl_set_file` ends up writing
exactly that blob. The encoder in `eqproxy-net/src/unix_acl.rs` builds the
canonical shape (owner `rw`, each named uid `rw`, group `rw`, mask `rw`,
other none) with the fixed tag order the kernel validates, and `chmod` runs
*before* the attribute so the mode cannot rewrite the mask afterwards.

An unsupported filesystem (`EOPNOTSUPP`), a rejected blob (`EINVAL`) or a
missing permission is an error: startup aborts, a reload is refused and the
previous ACL stays. There is no fallback to "the group still works", because
that would hand access to people the operator excluded.

## Rejected alternatives

- **Link `libacl`.** Adds a C dependency, a build-time header and a runtime
  library the static image does not ship; the project already chose pure-Rust
  backends over C ones (compression, ADR-0010).
- **Shell out to `setfacl`.** A hidden runtime dependency on another binary
  and on its version; ADR-0022 rejected the same shape for `getent` when
  resolving group names.
- **A filesystem group per user.** Operationally unbounded and leaks into
  every other file the proxy owns.
- **NFSv4 ACLs.** macOS has those, not POSIX.1e; the plane's ACL feature is
  Linux-only by nature, and pretending otherwise would be a different
  feature with different semantics.
- **Treat `unix_socket_allow_uids` as a grant.** Impossible at this layer:
  the kernel refuses the connection before the process sees the peer.

## Consequences

- **Linux only.** On any other platform `unix_socket_acl_uids` is a
  configuration error, not a silent no-op; the rest of the plane is
  unchanged.
- **Filesystem support matters.** ext4/xfs/tmpfs with ACLs work; a filesystem
  mounted `noacl` fails the bind (or the reload) with the OS error.
- **ACLs are not a token.** A named user still needs the bearer token to read
  a route; the ACL only lets them reach the socket.
- **Root still bypasses the filesystem.** As with the mode and the group,
  this is a boundary against unprivileged peers.
- **Group membership still grants access.** The ACL does not narrow the
  group; an operator who wants only named users must give the socket a group
  nobody else is in.
