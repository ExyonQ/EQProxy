# Security policy

Language: **English**. This file is the reporting and scope policy for
EQProxy; the design analysis behind it lives in
[THREAT_MODEL.md](THREAT_MODEL.md) (assets, trust boundaries F1–F7, threat
table, residual risk).

## Supported versions

| Version | Security fixes |
|---|---|
| `0.8.x` — latest patch of the current minor | Yes |
| `0.7.x` and earlier | No (upgrade to `0.8.x`) |

EQProxy is pre-1.0: fixes land in the current minor line and are released as a
new patch, never back-ported. The list of fixes of each release is in
[CHANGELOG.md](CHANGELOG.md); `eqproxy --version` prints the exact build you
are running.

## Reporting a vulnerability

**Do not open a public issue for a suspected vulnerability.** Write to
**<security@exyonq.org>** — the same private maintainer address published in
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — with the subject
`EQProxy security report`. Keep the first message free of secrets (no private
keys, tokens or customer data) and ask for an encrypted channel if the report
needs one.

Please include:

- the exact version (`eqproxy --version`) and how it was built (release
  artifact, container image digest, or the commit for a source build);
- platform and architecture, and the relevant configuration with all
  certificates, keys and tokens **redacted** (never send a real private key or
  admin token);
- the protocol path involved (listener mode, TLS, HTTP/2 or HTTP/3, plugin,
  admin plane, cache) and a reproducer or proof of concept;
- the impact you believe it has, and whether you intend to publish.

### What to expect

These are the commitments already recorded in
[THREAT_MODEL.md §6](THREAT_MODEL.md#6-vulnerability-reporting-procedure):

1. Acknowledgement within **5 working days**.
2. Assessment and fix plan within **30 days**.
3. Coordinated disclosure: the fix ships before details are published, and an
   advisory is published with a CVE when one applies.
4. Affected versions and the fix are documented in `CHANGELOG.md`.

## In scope

Anything an unauthenticated or least-privilege party can do to break the
guarantees the product claims:

- request framing and smuggling (CL/TE conflicts, obs-fold, header-name
  normalization, h2 pseudo-headers);
- TLS handling: SNI routing, client-facing and backend verification, hot
  certificate reload;
- the admin plane: authentication, authorization, the Unix-socket ACL, write
  endpoints;
- configuration parsing and validation: a validated file that still produces
  unsafe behaviour, path traversal in `cert`/`ca_file`/map/plugin paths;
- the WASM plugin host: escaping the denied-by-default capability set,
  reaching the network or the filesystem, exhausting the declared limits;
- the response cache: storing or serving one user's response to another
  (session material), revalidation bypass;
- per-request rule evaluation: a rule that does not match what it says;
- supply chain: a dependency or release artifact that is not what the lockfile
  and checksums say.

## Out of scope

Stated explicitly in [THREAT_MODEL.md §7](THREAT_MODEL.md#7-non-protections-explicit)
and worth repeating here:

- **EQProxy is not a WAF**: payload exploits (SQLi, XSS) aimed at the backend
  are not its layer.
- **Rate limiting is not volumetric DDoS protection**, and no resistance is
  promised to link exhaustion or L2/L3 attacks.
- Deployment mistakes: a listener published to the internet without TLS, an
  admin socket world-writable, or a backend on an untrusted network. The
  product warns about the first at validation time; the rest are the
  operator's responsibility.
- Findings that need a compromised host, root on the machine, or a malicious
  operator with write access to the configuration and certificates.
- Bugs in upstream dependencies: report them upstream; we track and update,
  and a report is still welcome if EQProxy's usage makes the impact worse.
- Missing features (a directive EQProxy does not implement) — that is a
  compatibility gap, tracked in `PARITY_MATRIX.md`, not a vulnerability.

## Security properties you can check

These are enforced in code or configuration, so a report can name them:

- **100 % safe Rust**: `#![forbid(unsafe_code)]` in all four crates
  ([eqproxy-core/src/lib.rs](eqproxy-core/src/lib.rs),
  [eqproxy-config/src/lib.rs](eqproxy-config/src/lib.rs),
  [eqproxy-net/src/lib.rs](eqproxy-net/src/lib.rs),
  [eqproxy-cli/src/main.rs](eqproxy-cli/src/main.rs)). `unsafe` exists only
  inside dependencies, which [THREAT_MODEL.md §8](THREAT_MODEL.md#8-known-residual-risk)
  treats as residual risk.
- **Ambiguous messages are rejected, not interpreted**: one framing
  normalization for every route (principle 1 and 2 of the threat model).
- **Admin plane**: bearer tokens shorter than 16 bytes are rejected at
  validation, the Unix socket can carry a named-user ACL, and the read/write
  split is documented in ADR-0017, ADR-0022 and ADR-0023.
- **Plugins**: a module that imports anything outside the ABI v1 surface —
  WASI, `env.*`, a network shim — fails to load, by construction
  ([ADR-0031](docs/adr/0031-wasm-plugin-host.md)).
- **Cache**: only `GET` without `Set-Cookie` is stored and the key never
  includes `Cookie` or `Authorization` (see `CacheConfig` in
  [eqproxy-config/src/schema.rs](eqproxy-config/src/schema.rs)).
- **Blast-radius limits**: per-listener `maxconn` and, since v0.8.5, per-server
  `maxconn` (`{ addr = "…", maxconn = 50 }`) stop a saturated backend from
  being oversubscribed; the excess fails explicitly with 503, or waits in the
  backend's bounded queue when one is configured (`maxqueue > 0`).
- **Configuration import is static**: `eqproxy config import` parses nginx,
  HAProxy, ingress-nginx and Envoy files and never executes them; the output
  is parsed and validated with the product's own parser before it is written.

## Hardening

Operational guidance (TLS defaults, admin exposure, Unix sockets, container
runtime) is in the [README](README.md) and the ADRs under
[docs/adr](docs/adr); a configuration that validates is not automatically a
safe deployment, and `eqproxy config validate` warns — it does not guarantee.
