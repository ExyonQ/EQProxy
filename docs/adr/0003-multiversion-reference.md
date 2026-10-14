# ADR-0003: Multi-version reference and citation policy

Language: **English**.

- State: **Accepted** (Phase 0, project lead's decision)
- Date: 2026-10-12
- Related: parity matrix (internal documentation), [BENCHMARK_PLAN.md](../../BENCHMARK_PLAN.md)

## Context

The brief requires pinning a specific stable version of the reference proxy and
recording version, date, edition, build options, platform and official
documentation. The installed base is heterogeneous: there are deployments on
old LTS branches (2.8, 3.0) alongside the most recent ones (3.2, 3.4). A single
reference would poorly cover legacy-branch users.

## Decision

**Multi-version matrix** (project lead's decision, 2026-10-12):

| Role | Pinned version | Release date | Branch state | Documentation used |
|---|---|---|---|---|
| Primary reference | **3.4.6 OSS** | 2026-09-28 | LTS, EOL expected 2031-Q2 | official 3.4 documentation |
| Legacy reference | **3.0.29 OSS** | 2026-09-28 | LTS, EOL expected 2029-Q2 | official 3.0 documentation |

- **Edition:** Community/OSS, **the only edition in parity scope** (user
  decision, 2026-10-12). The commercial editions of the reference proxy
  (Enterprise, the One platform, ALOHA, Fusion) are **excluded**: the exclusion
  is only documented in the parity matrix (internal documentation), with no
  equivalent goals.
- **Reference build options:** the Community Edition build
  (`TARGET=linux-glibc CPU=generic USE_PCRE2=1 USE_PCRE2_JIT=1 USE_TFO=1
  USE_LINUX_TPROXY=1 USE_LUA=1 USE_GETADDRINFO=1 USE_PROMEX=1 USE_SLZ=1
  USE_OPENSSL_AWSLC=1 USE_PTHREAD_EMULATION=1 USE_QUIC=1`) per the reference's
  official Dockerfile (3.4). For benchmarks the real `-vv` output of the binary
  used is **always** recorded (flags vary by distribution).
- **Reference platform:** Linux x86_64 glibc (matches ADR-0001).
- **Primary semantics source:** the official 3.4 and 3.0 configuration
  documentation (plus the official changelogs and the reference's source
  repository). The concrete URLs live in the project's internal documentation.

## Citation policy (mandatory across the project)

1. Every claim about the reference proxy's capabilities carries an official URL
   and the version it applies to.
2. If a capability differs between 3.0 and 3.4, the matrix records **both**
   semantics and EQProxy declares which one it preserves.
3. Anything not verified against official sources is marked **"unverified"**.
   A gap is never filled with assumptions.
4. Third-party sources (blogs, forums) only count for *user pain points*
   (internal documentation), never to assert product semantics.
5. Reference proxy version policy (verified fact): even-numbered branches are
   LTS with ~5 years of maintenance; odd ones, 12–18 months.

## Alternatives considered

1. **3.4.6 LTS only:** simpler, but it ignores the 3.0 installed base and
   loses the ability to detect semantics that changed between branches.
   Rejected by user decision.
2. **Matrix of all live branches (2.8, 3.0, 3.2, 3.3, 3.4):** disproportionate
   documentation cost. Branches 2.6/2.8 are in "critical fixes only" and 2.4
   is unmaintained; they create no parity commitment.

## Consequences

- The matrix's documentation cost partially doubles; it is mitigated with a
  "Ref. version" column per row and explicit "both" marks when semantics
  match.
- Comparative benchmarks pin 3.4.6 as the main opponent; 3.0.29 is used only
  for declared compatibility/regression scenarios.
- If the reference publishes a new LTS, an ADR is opened to decide whether to
  rotate the primary reference; it is never changed silently.
