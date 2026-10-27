# ADR-0021: The admin plane may listen on a Unix domain socket

Language: **English**.

- State: **Accepted** (2026-10-25, roadmap v0.8 B-H14 first step)
- Date: 2026-10-25
- Related: [ADR-0017](0017-read-only-admin-plane.md) (read-only plane),
  [ADR-0018](0018-first-write-path-server-state.md) (first write),
  [ADR-0019](0019-hot-config-writes-via-admin-api.md) (hot configuration),
  [ADR-0022](0022-admin-socket-group-and-peer-uid.md) (group mode and uid
  allowlist), [SPEC §9](../SPEC.md),
  [THREAT_MODEL.md](../../THREAT_MODEL.md)

## Context

The administration plane has always listened on `IP:PORT` (ADR-0017). A
loopback bind keeps the plane off the network, but it is still a TCP port:
every local user and every process in the same network namespace can connect
to it, and the only thing between them and the plane is the bearer token.
On a container host the loopback of one container is not the loopback of
another, but tools that share a network namespace (sidecars, debug pods,
`--network host`) do. Operators coming from HAProxy's `stats socket` and
Envoy's Unix-socket admin expect the stronger boundary: a filesystem object
whose mode decides who may even open the connection.

B-H14 asks for Unix sockets as the first step of local administration; the
complete B-H14 (socket activation, richer local admin) remains for v0.9.1.

## Decision

`[admin]` takes **exactly one** endpoint:

```toml
[admin]
unix_socket = "/run/eqproxy/admin.sock"   # relative to the config file
token_file = "/etc/eqproxy/admin.token"
# listen = "127.0.0.1:9001"               # TCP alternative, never both
```

### Properties

- **Owner-only socket by default.** Immediately after `bind`, the socket
  file is set to mode `0600`, before the accept loop is spawned (ADR-0022
  adds the opt-in `0660` group mode). The creation itself
  still uses the process umask, so there is a microsecond bind→chmod window
  in which a local user could enqueue a connection; the bearer token still
  gates every request. The parent directory is not created: a missing or
  unwritable directory is a startup error, never a silent fallback.
- **The token remains required.** The filesystem decides who can connect;
  the bearer token (and the separate write token) still decides what the
  caller may do. A Unix socket does not turn the plane into an unauthenticated
  one, and the same routes, limits and audit lines apply unchanged.
- **Live sockets are never stolen.** If the path already exists and a
  connection succeeds, binding fails with `AddrInUse`. A crash leaves a
  socket file with no listener; that one is detected by a refused connection,
  removed, and replaced, so a restart works without manual cleanup.
- **Nothing else is deleted.** A path that exists and is not a socket is
  refused (`InvalidInput`) and left untouched. Symlinks are inspected with
  `symlink_metadata`, so a link is not mistaken for the socket it names.
- **Clean shutdown unlinks only our file.** The handle remembers device and
  inode at bind time; cleanup unlinks the path only while it is still that
  inode. A file another process created meanwhile is preserved.
- **Audit identity.** A Unix peer has no `IP:PORT`; the audit line reports
  `unix-socket:uid=<uid>` (or `unix-socket` when the kernel does not expose
  the peer credentials). The uid is recorded, not used for authorization.
- **Fixed at startup.** Like the tokens and the TCP address, the endpoint is
  not hot-applied; a `SIGHUP` keeps the running socket.

`allow_remote` only describes a TCP bind; combining it with `unix_socket` is
rejected instead of being ignored. `listen` and `unix_socket` together, or
neither, are configuration errors.

## Consequences

- **Platform.** The socket path is a Unix feature. The configuration key is
  accepted everywhere, but binding on a non-Unix platform returns
  `Unsupported`; EQProxy's supported deployment targets are Linux and macOS.
- **Path limit.** `bind` fails with the OS error when the path exceeds
  `sun_path` (104 bytes on macOS, 108 on Linux); validation does not guess the
  platform limit.
- **No TCP fallback.** If the socket cannot be opened, startup fails. A
  configured plane that silently moves to another transport would be a
  downgrade.
- **No filesystem group sharing yet.** `0600` means one uid. A shared group
  (`0660` plus `chown`) or a `uid` allowlist checked with `SO_PEERCRED` would
  be a later increment, as would Linux abstract sockets and systemd socket
  activation.
- **Not verified here:** proxy-protocol-style peer identity over Unix
  sockets, filesystem ACLs (`setfacl`) and SELinux/AppArmor policy around the
  path. The mode and inode behaviour are covered by tests.
