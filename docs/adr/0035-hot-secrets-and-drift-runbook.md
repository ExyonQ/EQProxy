# ADR-0035: Hot secrets scope and the multi-instance drift runbook

Language: **English**.

- State: **Accepted** (2026-10-30, roadmap v0.8.5)
- Date: 2026-10-30
- Related: [ADR-0011](0011-tls-and-certificates.md) (TLS stack),
  [ADR-0019](0019-hot-config-writes-via-admin-api.md) (single writer),
  [ADR-0025](0025-certificate-renewal-without-restart.md) (renewal in place),
  [ADR-0027](0027-xds-bridge-decision.md) (no xDS client),
  [SPEC §9](../SPEC.md), [THREAT_MODEL.md](../../THREAT_MODEL.md) (T10)

## Context

The 0.8.5 box `B-E9 · B-H10 (fin) · B-N16 (p) · B-I16 (p)` asks for
"TLS secrets in hot (SDS equivalent) and multi-instance with drift (D10)".
Three of the four TLS-advanced requirements are already implemented and
E2E-proven: mTLS (`client_ca`, A15), multi-certificate per SNI (B-I2/B-H10/B-E9)
and in-place renewal of listener certificates on h1/h2/h3 (ADR-0025). What
remained open was the upstream direction (backend trust), the two leftover
TLS knobs (cipher suites, OCSP stapling) and what "drift" means without a
control plane.

## Decision

### 1. SDS-equivalent = files + the existing reload action, both directions

There is no SDS client (ADR-0027 already decided: no xDS). The equivalent is:

- listener certificates, keys and SNI entries: re-read on `SIGHUP` and on
  `POST /api/v1/certificates/reload`, swapped atomically behind the
  per-handshake resolver (ADR-0025);
- backend trust (`[backend.*.tls] ca_file`, `verify`, `server_name`): re-read
  by the same single writer on the same reload path and applied by the same
  dataplane swap — no restart, no new socket.

Proven by
`eqproxy-net/tests/e2e_resilience.rs::backend_tls_trust_rotation_applies_on_reload_without_restart`:
trust CA → traffic flows; reload trusting the Mozilla roots only → the tunnel
dies closed (EOF/RST, never proxied bytes, `tls_handshake_failures` +1);
reload the CA back → traffic flows again on the same socket. Retries are off
in the test so one exchange is exactly one counted failure.

### 2. Cipher suites and OCSP stapling are out (B-H10 fin)

- Cipher suites: rustls with AWS-LC already negotiates only modern suites;
  exposing operator-chosen ciphers would re-admit the legacy negotiation the
  project bans elsewhere (TLS 1.0/1.1 never). No knob, same policy as
  `min_version`.
- OCSP stapling: needs an unauthenticated background fetch + cache per
  certificate with its own failure semantics; the fingerprint in
  `GET /api/v1/status` (`tls_fingerprint`) is the monitoring hook instead —
  an alert compares it against the file a renewal wrote.

With mTLS, multi-cert/SNI, hot renewal both directions and this scoping,
B-H10 is finished. B-N16/B-I16 stay partial exactly here: nothing nginx or
ingress-nginx asks for beyond this list is implemented.

### 3. Drift: compare topology, not revisions; repair with SIGHUP

The revision is a per-process generation tag (restarts at `v1`): it orders
writes on one instance, it never identifies content across instances. Drift
detection compares `GET /api/v1/status` across instances field by field —
backend servers, `tls_fingerprint` per listener — and the repair is
re-applying the shared file (`SIGHUP` drops runtime edits back to the file
baseline, SPEC §9). There is no central store, no desired-state persistence
and no atomic multi-instance update: SPEC §9 already promises nothing atomic
here, and ADR-0027 keeps the file as the baseline.

Proven by `scripts/evidence/v085-hot-secrets-drift/journey.py` against the
release binary (two instances, one file): same file → `v1`/`v1` and equal
topologies; divergent `PUT` on A → live on A only, `v2` vs `v1`, two servers
vs one; `SIGHUP` on A → topologies equal again while revisions stay apart
(`v3` vs `v1`), which is the documented comparison rule, not a bug.

## Consequences

- Hot rotation covers both TLS directions with fail-closed semantics on both
  (unparseable candidate: `400`, previous material keeps serving).
- Operators get a runbook instead of a control plane: scrape status from
  every instance, alert when topologies or fingerprints differ, repair by
  converging the files and reloading.
- Still pending (not decided here): persistence of runtime edits,
  per-user identities, a durable audit sink — the rest of the SPEC §9 list.

## Pending (not decided here)

- Certificate expiry alerting (needs X.509 parsing; ADR-0025).
- Automatic reload on file change (inotify/kqueue): SIGHUP and the action
  route already cover the operational need.
- Client-CA/ALPN rotation on a live QUIC endpoint: still a restart
  (ADR-0025).
