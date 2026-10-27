# ADR-0025: Certificate renewal without a restart

Language: **English**.

- State: **Accepted** (2026-10-25, roadmap v0.8 / PARITY D7)
- Date: 2026-10-25
- Related: [ADR-0011](0011-tls-and-certificates.md) (TLS stack),
  [ADR-0013](0013-http3-quic.md) (the QUIC endpoint),
  [ADR-0018](0018-first-write-path-server-state.md) (the write model),
  [ADR-0019](0019-hot-config-writes-via-admin-api.md) (single writer),
  [SPEC §9](../SPEC.md), [THREAT_MODEL.md](../../THREAT_MODEL.md) (T10)

## Context

`SIGHUP` has re-read the certificate files and swapped the listener config
since v0.4.x: on TCP the socket is kept and only the material new connections
see changes. Two gaps kept D7 from being honest:

1. **No way to ask for it.** A renewal required knowing to send `SIGHUP`, and
   the process answered nothing: an operator could not tell whether the new
   certificate had been loaded, or which one was live.
2. **HTTP/3 could not do it.** A quinn endpoint freezes its TLS at creation, so
   a certificate change on a `quic = true` listener was refused
   (`ProxyError::QuicTlsReload`) and needed a restart — the opposite of what
   "renewal in place" means for a listener that serves both protocols.

## Decision

### The certificate lives behind a resolver, not inside the acceptor

`ServerTls` keeps its certificate material in a `HotCerts` resolver: an
`RwLock<Arc<SniResolver>>` consulted on **every handshake**. The TCP acceptor
and the QUIC endpoint built from the same `ServerTls` share that resolver, so
a rotation is one `RwLock` write. A handshake sees the previous set or the new
one, never a mix, and nothing is rebuilt:

- established connections are untouched (TLS was already negotiated),
- new TCP handshakes and new QUIC handshakes read the new material at once,
- no socket is closed, no port released, no retransmission window.

What a live QUIC endpoint genuinely cannot change — ALPN, the client-CA
verifier (mTLS) and the minimum TLS version — is not pretended: the dataplane
compares a digest of exactly those three (`fixed_material_fingerprint`) and
still refuses the swap (`QuicTlsReload`, now with a message that names them)
when one of them differs. Certificates, keys and SNI names are the case that
matters for renewal, and they are the case that is hot.

### The action: `POST /api/v1/certificates/reload`

```
POST /api/v1/certificates/reload
Authorization: Bearer <write token>
Content-Length: 0
```

The operator writes the new files where the configuration already points and
calls the route. It re-reads the configuration **and** its certificate files
through the same single writer as `SIGHUP` and `PUT` (ADR-0019), so:

- every check the file gets at startup applies (a PEM that does not parse, a
  key that does not match, a certificate for another SNI name);
- a rejected candidate leaves the previous generation serving — the live
  handshakes keep using the certificate that was already there (fail closed);
- the answer is only `200` after the dataplane committed the swap.

The answer reports, per TLS listener, what is actually on the wire **after**
the commit: `listener`, `listen`, `fingerprint` (`sha256:<hex>` of the leaf
DER), `changed` (differs from the previous generation) and `quic`. The
fingerprint is computed with AWS-LC — the crypto provider rustls already
links — so identifying a certificate adds no crate and no second
implementation. `GET /api/v1/status` reports the same fingerprint per listener
(`tls_fingerprint`), which is what an alert compares against the file a
renewal wrote.

### Permission model: an action, not a document

The route needs the write role, no browser `Origin`, and **no body** (`400
body_not_allowed` when one is sent): it declares no state and carries no
document, so `If-Match` would be theatre — there is no lost update to protect.
This is the distinction ADR-0018 already drew for the drain route; the
document writes (`PUT /api/v1/{backends|listeners}/{name}`) keep their
revision precondition. Every attempt — accepted, forbidden, refused — writes
one `AUDIT` line whose `method` is `POST`, so the log distinguishes a renewal
from a configuration edit.

A rejected reload is loud in the process log as well: the counter
`config_reload_failures` moves and the line `ERROR config reload rejected:
…` names the reason. Before this slice a rejection after validation (a
certificate that does not parse, an impossible socket policy) only reached the
API caller, which left a `SIGHUP` — nobody to answer — silent.

### What is *not* hot

- The configuration file path, the listener set and the admin endpoint
  (ADR-0018/0021).
- ALPN, mTLS client CA and minimum TLS version on a listener that serves
  HTTP/3: a restart, as above. On a TCP-only listener those still hot-swap
  because the acceptor itself is replaced.
- Certificate *validity* is not checked (an expired certificate loads): the
  job of this route is to load what the operator wrote, not to judge it. A
  `not_after` field needs an X.509 parser, which is a dependency this slice
  does not add.

## Consequences

- A renewal is one authenticated request with an answer that names the live
  fingerprint, on h1, h2 and h3 listeners alike, with no dropped connection.
- The failure mode is unchanged and explicit: a bad PEM answers `400` with the
  parse error and the previous certificate keeps serving — verified against
  the real binary, not assumed.
- `/metrics` does not gain a new series: the fingerprint is high-cardinality
  data whose budget is the configured topology, and `status` is where that
  budget lives (CE4).
- `Skip the resolver lock` is a non-issue on the hot path: handshakes already
  did a virtual call into the resolver; the added cost is one uncontended
  `RwLock` read per handshake.

## Pending (not decided here)

- Certificate validity/expiry reporting (needs X.509 parsing) and an alert on
  a certificate close to expiry.
- Automatic reload on file change (inotify/kqueue): SIGHUP and the route
  already cover the operational need, and a watcher needs debounce semantics
  this slice does not define.
- Client CA and ALPN rotation on a live QUIC endpoint: a second endpoint on
  the same socket needs a datagram-ownership story that is not free.
- Certificate storage in the panel, ACME and per-SNI renewal from the UI.
