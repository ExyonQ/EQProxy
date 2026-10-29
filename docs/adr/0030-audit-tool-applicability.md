# ADR-0030: dylint, semver-checks and geiger — decisions, not perpetual skips

Language: **English**.

- State: **Accepted** (2026-10-28, roadmap v0.8.5 audit debt)
- Date: 2026-10-28
- Related: [roadmap v0.8.5, §3](../../ROADMAP%20EQPROXY/ROADMAP/Roadmap%200.8.5.md)
  (the debt this closes), [v085-audit-tools-decision](../evidence/v085-audit-tools-decision.md)
  (commands and raw output), [v08-health-probe-robust](../evidence/v08-health-probe-robust.md)
  §5/§7 (where the three entries were first recorded),
  [ADR-0004](0004-network-stack-and-crate-layout.md) (workspace layout),
  [veyra.toml](../../veyra.toml) (the audit contract)

## Context

The `veyra audit . --profile standard` leg of the audit stack reports three
tools that do not end in OK:

| Tool | Veyra status | Reason it gives |
|---|---|---|
| `dylint` | SKIPPED | no Dylint configuration or lint libraries found |
| `cargo-semver-checks` | SKIPPED | no baseline for unpublished crates |
| `cargo-geiger` | INCONCLUSIVE | scan completed but reported coverage warnings in 4 runs |

The v0.8.5 roadmap forbids a `SKIPPED` without a decision: either the tool is
configured so it can run for real, or an ADR fixes why it does not apply. A
fourth option — making the tool print OK by relaxing what it checks — is
exactly the theater the audit contract rejects, so it is not on the table.

The three tools answer different questions:

- **dylint** runs *custom* lint libraries, compiled against a pinned toolchain.
- **cargo-semver-checks** compares a crate's public API with a **published**
  baseline (crates.io version, tag, or rustdoc JSON).
- **cargo-geiger** counts `unsafe` in a crate **and its dependencies**.

## Decision

### 1. dylint — not adopted (NOT APPLICABLE)

Dylint is a framework for **authoring and loading lint crates**: its value
starts when a project owns rules that Clippy does not implement, and it pays
for that with a second, pinned toolchain (lint libraries are compiled against a
specific rustc). EQProxy has no lint crate, no `dylint.toml`/`.dylint.toml` and
no rule in mind that Clippy lacks; `cargo-dylint 6.0.4` happens to be installed
on the audit machine, but there is no library for it to load (`dylint-link` is
not on PATH either). Installing a third-party lint set would pin
another toolchain and enable rules nobody chose, which is a new dependency and
a new failure mode, not a safety net.

What covers the ground instead: `cargo clippy --workspace --all-targets` with
`-D warnings` is blocking in CI and in the Veyra `clippy` leg (OK), over
`[workspace.lints]` (`clippy::all` plus `unsafe_code = "forbid"`) inherited by
all four crates.

**If** a rule is ever needed that Clippy cannot express, the first step is a
lint crate with a test that fails on a known-bad fixture; only then does
`dylint` become applicable, and this decision is superseded.

### 2. cargo-semver-checks — not applicable without a published library

`cargo semver-checks check-release` diffs the current API against a registry
version. EQProxy ships a **binary** (GitHub release + container images); the
four workspace crates are internal — `cargo metadata` reports `publish: null`
for all of them and the release pipeline builds a binary, never a crate. The
tool therefore stops at the first crate
(`eqproxy-config not found in registry (crates.io)`), and no configuration can
invent a baseline that means something.

`publish = false` in the four manifests was tried and **reverted**: with it,
`cargo semver-checks check-release` prints `Skipping eqproxy-… (current)` for
the three library crates (`eqproxy-cli` is bin-only) and exits 0, and Veyra
records that as `semver-checks passed` without checking a single API. An honest
SKIP beats a silent pass, so the manifests keep default publishability and the
tool keeps failing loudly at the registry lookup.

A git baseline (`--baseline-rev v0.8.0`) is technically possible, but it would
compare **internal** library APIs that are designed to change together in one
commit. A green result would say nothing about the product's compatibility
surface, and a red one would not be a defect. Running it and calling it a gate
would be the same theater in a different flag.

The real external contracts are:

- the **CLI** (`run`, `config validate|plan|explain|apply|rollback|import`,
  `doctor`), exercised by `eqproxy-cli/tests/cli_e2e.rs` and the
  [veyra.toml](../../veyra.toml) E2E scenarios, including explicit exit-2 for
  the one command not implemented yet;
- the **configuration document**, versioned by `schema_version = 1`: an
  unknown version is rejected with the field and an example, and the JSON
  Schema is drift-gated
  ([eqproxy-config/tests/schema.rs](../../eqproxy-config/tests/schema.rs)).

**If** any crate is ever published, this decision is void: a baseline
(`--baseline-version` for the registry, or a tag for the first release) is
mandatory before publication, and semver-checks becomes a blocking leg.

### 3. cargo-geiger — applicable, informational, never a gate

The question "does EQProxy contain `unsafe`?" is answered structurally, not
statistically: `[workspace.lints.rust] unsafe_code = "forbid"` is inherited via
`[lints] workspace = true` by all four crates, so the compiler refuses unsafe
code. Negative control: appending one `unsafe { 0 }` block to
`eqproxy-core/src/lib.rs` made `cargo check -p eqproxy-core` fail with
`error: usage of an "unsafe" block` (exit 101); the file was restored
byte-for-byte (sha256 `7836a1ac…`, `git diff` empty). The result is therefore
provable without scanning dependencies.

Geiger's INCONCLUSIVE is a property of **its dependency scan**, not of EQProxy:
4,417 "file was never scanned" warning lines across the four per-package runs,
1,130 unique files, 87 registry crates (`libm`, `icu_properties_data`,
`jsonschema`, …), 7 generated files under `target/`, and one non-Rust data file
of ours (`eqproxy.schema.json`, embedded with `include_str!`). **Zero**
workspace `.rs` files are unscanned. The warnings are files that are not
compiled for the host configuration or are not Rust source, so unsafe counts in
those dependencies are a lower bound; the four runs exit 1 with `Found 1082`,
`1087`, `1120` and `1128` warnings, and Veyra classifies that honestly as
INCONCLUSIVE.

Suppressing the exit code or treating a partial scan as a pass would be
false confidence. Dependency risk is handled by the tools that answer it —
`cargo-audit` and `cargo-deny` (both OK in the same audit, advisories and
licenses) — not by counting `unsafe` lines in vendored sources. Geiger remains
in the report as information; a **new** geiger finding would still be read, it
just does not block a release while its coverage is partial.

**If** geiger's file coverage becomes complete (upstream fix) or the dependency
tree drops the crates it cannot scan, the run can become a gate; that is a new
decision, not an automatic promotion.

## Consequences

- The three entries are **decided**, not pending: this ADR is the record, and
  the roadmap box cites it. Veyra keeps printing them — that is the tool being
  honest, not an open debt.
- A **new** tool appearing as `SKIPPED`/`INCONCLUSIVE`/`MISSING` requires its
  own decision; it cannot hide behind this one.
- No audit gate was relaxed: clippy stays blocking, `forbid(unsafe_code)` stays
  compiler-enforced, audit/deny stay OK, and no `veyra.toml` scenario or test
  assertion changed.
- No manifest changed. The `publish = false` experiment was reverted because it
  turned the skip into an empty pass; its transcript stays in the evidence.

## Revisit triggers

1. Any crate gets a publication plan (semver-checks becomes mandatory first).
2. A rule is needed that Clippy cannot express (dylint becomes a candidate,
   with a lint crate and a failing fixture).
3. Geiger reports complete coverage on this dependency tree (can be promoted
   to a gate).
