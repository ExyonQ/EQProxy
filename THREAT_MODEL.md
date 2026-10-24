# THREAT_MODEL.md — EQProxy threat model

Language: **English**.

- Document version: 0.1 (Phase 0)
- Date: 2026-10-12
- Scope: dataplane, control plane, panel, extensions and supply chain.

## 1. Assets and trust boundaries

**Assets:** client traffic (data in transit), secrets (TLS keys, admin tokens,
backend credentials), configuration, session state (stick-tables, cookies),
metrics/logs (sensitive metadata), service availability.

**Trust boundaries:**

| Boundary | Untrusted side | Rule |
|---|---|---|
| F1 | Clients (Internet) | Every message is hostile until validated: framing, size, rate |
| F2 | Backends | They may fail, return garbage or attack (malformed responses) |
| F3 | Network between proxy and backends/DNS | MITM, DNS cache poisoning, partitions |
| F4 | Admin panel/API | Authenticated operators only; RBAC; audited writes |
| F5 | Plugins (Lua/WASM) | **Untrusted code**; capability denied by default |
| F6 | Config and files (certs, maps) | Validated origin; no path traversal; no plaintext secrets in diffs |
| F7 | Supply chain (crates, toolchain) | Audit and pin versions; no unnecessary own `unsafe` |

**Actors:** remote attacker without credentials; malicious authenticated
client; least-privilege operator; malicious or buggy plugin; compromised
dependency provider.

## 2. Design principles (cross-cutting)

1. **Safe rejection of ambiguous messages:** given two possible
   interpretations of an HTTP message (framing, duplicated lengths, obs-fold,
   spaces in header names), the request is **rejected** (4xx) and counted.
   Never "pick one interpretation".
2. **Consistent normalization:** a single header/URI normalization, applied
   before evaluating rules and before forwarding, identical on all routes
   (avoids parsing desynchronization = smuggling).
3. **Limits everywhere:** per phase and protocol (request line size, header
   size, header count, body size, handshake duration, timeouts, concurrency,
   queues). No unlimited queues (SPEC §7.3).
4. **Least privilege:** plugins without network/files by default; panel with
   RBAC; the dataplane does not read admin storage.
5. **Secrets never in:** logs, diffs, metrics, error responses, panels,
   repository. By reference only (ADR-0002 §C8).
6. **Explicit fail:** everything not implemented fails or is switched off;
   never a stub that returns success.

## 3. Threat table

State: *Designed* (mitigation specified) / *Designed (scope)* (mitigation
defined at high level; detail in its phase) / *Pending* (no mitigation yet).

| # | Threat | Vector | Impact | Mitigation | Phase | State |
|---|---|---|---|---|---|---|
| T01 | Request smuggling (CL/TE, duplicates, malformed chunked) | F1 | Rule bypass, connection poisoning | Rejection of ambiguous messages (§2.1); a single parser shared between analysis and forwarding; differential tests + framing parser fuzzing | 2 | **Tested** (2026-10-12, Phase 2a: smuggling corpus rejected before the backend, `http1::tests::smuggling_corpus_is_rejected` + `e2e_http1.rs::http1_smuggling_corpus_is_rejected_before_backend` ✓; **parser fuzzing pending**, Phase 2c) |
| T02 | HTTP framing ambiguities (obs-fold, spaces in names, duplicated hop headers) | F1 | Same as T01 | Strict normalization + rejection; published and tested normalization rule list | 2 | **Tested** (2026-10-12, Phase 2a: rejection of obs-fold, spaces in names, loose CR/LF and absolute-form; rules published in `eqproxy-net/src/http1.rs` ✓) |
| T03 | Malformed / extreme headers (thousands of headers, giant lines) | F1 | CPU, memory | Per-message limits (header count, total size) with 431/400 and a metric | 2 | **Tested** (2026-10-12, Phase 2a: `MAX_HEADERS`=100, `MAX_HEAD_BYTES`=16 KiB, `MAX_LINE_BYTES`=8 KiB → 431 + `http_requests_rejected`; `http1::tests::too_many_headers_is_431` ✓) |
| T04 | Slowloris / slow clients | F1 | Connection exhaustion | Per-phase (accept→headers→body) and idle timeouts; `maxconn` limit; slow-client tests | 1–2 | Designed (scope) |
| T05 | Memory exhaustion | F1/F2 | Crash | Per-connection budgets (SPEC §7.3); streaming bodies by default; buffer limits; explicit rejection on exhaustion | 1–2 | Designed (scope) |
| T06 | CPU exhaustion (complex headers, regex, compression) | F1 | Degradation | Rule evaluation time limits; regex only with a bounded engine (no catastrophic backtracking); compression with ratio limit | 4–5 | Designed (scope) |
| T07 | Connection exhaustion (run out of FDs) | F1 | Denial | Connection caps; FD reservation for admin and draining; `eqproxy doctor` warns on `ulimit` | 1 | Designed |
| T08 | Unlimited queues (memory bloat from waiting requests) | F1 | Crash | Bounded queues per backend (`maxqueue`) with timeout and explicit 503 | 3 | Designed (scope) |
| T09 | Abusive decompression (zip bombs) | F2 (if decompression is supported) | CPU/memory | If implemented: ratio and decompressed-size limits; **if unsupported, stated explicitly**. Compression is **response-only**: a request's `Content-Encoding` and body reach the backend untouched and are never decoded, so there is no decompression surface (stated in SPEC §13 item 12 and README) | 5–8 | **Closed** (2026-10-24, not applicable by design) |
| T10 | Invalid TLS/certificates (to client or backend) | F1/F3 | MITM, interruption | Strict chain and hostname validation when loading certs (fail to start with an invalid cert); backend verification on by default; atomic rotation (PARITY D7) | 2–3 | **Tested** (2026-10-13, Phase 2b: invalid cert/key PEM → startup error with field and example; backend TLS verifies certificate **and hostname by default** (Mozilla roots + `ca_file`); untrusted backend cert rejected and counted (`e2e_phase2b.rs::tls_backend_verification_failure_is_counted_and_rejected` + `cli_e2e.rs::validate_reports_missing_cert_file_with_actionable_error` ✓; **rotation/hot-reload pending**, D7) |
| T11 | PROXY protocol misuse (client IP spoofing) | F1 | IP-based rule bypass, rate-limit evasion | PROXY accepted only on declared endpoints (typically internal network); authorised origins by configuration; no ambiguous auto-detection | 2–3 | **Tested** (2026-10-13, send-only: the v1 header is built **from the real socket addresses**, never from client-supplied data — no spoofing surface in send (`e2e_phase2b.rs::proxy_protocol_v1` ✓); **reception pending Phase 3** with the declared-endpoint trust policy) |
| T12 | SSRF via configuration, DNS discovery or plugins | F4/F5/F3 | Access to internal networks, cloud metadata | Destination allowlist for backends by default in safe mode; URL validation in config; plugins without network access (§2.4); DNS with result validation (rebind: minimum TTL + bounded re-resolution) | 4–7 | Designed (scope) |
| T13 | Control plane exposure (panel/API) | F4 | Full proxy control | Listener separation (admin only on a management interface or with TLS+auth); mandatory authentication; RBAC; protected CSRF/sessions; login rate limit; no secrets in responses | 6 | Designed (scope) |
| T14 | Authorization bypass (IDOR, escalation via API) | F4 | Escalation | Per-resource and per-operation authorization; per-endpoint authorization tests; write auditing | 6 | Designed (scope) |
| T15 | Dependency attacks (supply chain) | F7 | Total compromise | `cargo deny`/equivalent (licenses + advisories); pinned `Cargo.lock`; SBOM inventory; `unsafe` review in critical dependencies (FFI); documented periodic updates | 1+ | Designed (scope) |
| T16 | Tenant isolation errors (multi-instance/panel) | F4/F5 | Data leakage between clients | Data model with explicit tenant in the control plane; process isolation for hostile plugins; permission fuzzing review | 6–8 | Designed (scope) |
| T17 | Secret leakage in logs/diffs/errors | F4/F6 | Exposure | Structured redaction of sensitive fields (no ad-hoc regex); `config export` with `***`; log review in tests | 1–3 | Designed (scope) |
| T18 | Attacks on explain/trace diagnostics (data leakage, resource abuse) | F4 | Leakage / degradation | Dedicated permissions; sampling; bounded memory/time; redaction (SPEC §8) | 3–4 | Designed (scope) |
| T19 | HTTP/3-QUIC specific (UDP amplification, state exhaustion, handshake DoS) | F1 | Degradation | QUIC path validation before responding; connection/half-open limits; address validation cookies; tested in Phase 5 with QUIC adversaries | 5 | Designed (scope) |
| T20 | DNS advertisements / rebinding to backends | F3 | SSRF, theft | See T12; DNS cache with bounded TTL; private range blocking in safe mode | 4 | Designed (scope) |

## 4. Secret handling

- By reference (`file://`, `env:`, or the system secret provider), never as
  literals in canonical config if validation detects them (warning or error,
  depending on mode).
- Guaranteed exclusion from: logs, errors, `config diff`, `config export`,
  metrics, panel responses.
- Restart-free rotation (certs and CAs: PARITY D7).
- Log and audit retention policy documented when the panel is implemented.

## 5. Supply chain and inventory

- Component and license inventory generated from `Cargo.lock` (SBOM in a
  standard format, tool to be pinned in Phase 1).
- Allowed licenses: MIT, Apache-2.0, ISC, BSD; anything else requires an ADR.
- Updates: dependencies audited on each release; RustSec advisories monitored;
  documented cadence.
- **Own code 100 % safe Rust:** `#![forbid(unsafe_code)]` in every crate, **no
  exceptions** (user decision, 2026-10-12; tightens the brief). The `unsafe`
  and FFI of dependencies (tokio, hyper, rustls, wasmtime) are inventoried and
  audited (`cargo-geiger` or equivalent) as residual risk (ADR-0004).

## 6. Vulnerability reporting procedure

1. Private channel (to be defined with the project: security email +
   GitHub/GitLab advisories) — **pending setup in Phase 1** (we do not invent a
   channel that does not exist).
2. Acknowledged within ≤ 5 working days; assessment and fix plan within ≤ 30 days.
3. Disclosure coordination with the reporter; advisory publication with CVE
   when applicable.
4. Affected versions and the fix are documented in the changelog.

## 7. Non-protections (explicit)

- **EQProxy is not a WAF.** It does not inspect application payloads for
  exploits (SQLi, XSS, etc.).
- **Rate limiting is not total DDoS protection.** It mitigates rates per key;
  it does not absorb distributed volumetric attacks. Network protection (SYN
  cookies, anycast, scrubbing) lives outside this project.
- No resistance is promised to physical/ICMP-layer attacks nor to link
  bandwidth exhaustion.

## 8. Known residual risk

- The internal `unsafe` of dependencies (including wasmtime, the only plugin
  runtime) does not disappear by writing our own safe code: the audited
  inventory is maintained and, if a plugin's instruction budget is not enough,
  it is isolated in another process (SPEC §10). Lua/mlua is **discarded**
  (C FFI with substantial `unsafe`).
- HTTP/3 adds a new protocol surface (T19); its "experimental" label is kept
  until the Phase 5 adversarial tests are completed.
- Config semantic validation may not detect every dangerous configuration (e.g.
  contradictory rules): it warns, it does not guarantee.
