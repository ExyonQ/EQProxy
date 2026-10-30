# Contributing to EQProxy

EQProxy is a reverse proxy and load balancer in Rust. It is pre-1.0: v0.6.3 is
released and the v0.7 work (HTTP/2 to backends, gRPC, WebSockets over h2,
HTTP/3) lands on `main`. Issues and pull requests are welcome; for a change
that touches behaviour, configuration or the wire protocol, open an issue
first so the scope can be agreed before code is written.

## Development setup

Install a Rust toolchain: the workspace uses edition 2024, so **Rust 1.85 or
newer** is required. The version every leg actually builds with is pinned in
`rust-toolchain.toml` (currently 1.99.1) and `rustup` installs it
automatically when you enter the checkout; CI and the release image use that
same compiler, so bumping the pin is a deliberate change with its own
verification rather than a moving `stable`.

```bash
git clone https://github.com/ExyonQ/EQProxy.git
cd EQProxy
cargo build --workspace
cargo test --workspace
```

Run the proxy against the example configuration, which is also the quickest
smoke test of a change:

```bash
cargo run -p eqproxy-cli -- config validate --config eqproxy.toml.example
cargo run -p eqproxy-cli -- run --config eqproxy.toml.example
```

`config validate` is offline and binds nothing; `run` serves with the example
listeners until `SIGINT`.

## Before opening a PR

Run the three build gates CI runs on every push, with the same flags:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

CI also runs the admin-socket ACL journey on native Linux runners
(`.github/scripts/admin-unix-acl-e2e.sh`, amd64 and arm64). It needs root, `setpriv`
and POSIX ACLs, so it is not part of the loop above; run it on Linux before a
change that touches the admin plane:

```bash
cargo build --release --locked -p eqproxy-cli
sudo env EQPROXY_BIN="$PWD/target/release/eqproxy" \
  bash .github/scripts/admin-unix-acl-e2e.sh
```

Then exercise the behaviour you changed the way a user would: start the
binary with a configuration that reaches your code path and check the
observable result (status, body, headers, log line, metric, clean shutdown).
A green build or a process that starts is not evidence that a feature works.
Request a review before merge; do not assume an automatic review.

## Tests and evidence

- Every fix or feature arrives with the smallest test that demonstrates the
  contract or observable effect. Name the level honestly: unit, contract,
  integration or E2E.
- When a change crosses sockets, TLS, HTTP/2 or QUIC frames, the test uses the
  real dependency (a real origin, a real client) — a mock presented as
  integration is not accepted.
- Cover the error and boundary cases, and state what must happen when a
  dependency fails or invalid input arrives.
- Never weaken an assertion, skip a test or change an expected result to make
  a check pass. If a test has to change, explain why in the PR.
- Report checks that could not run as **not executed**, never as a pass.

## Audits

A change is not finished until it has been audited on four independent legs.
Each one answers a different question, and none of them substitutes another:

| Leg | Question | Tool |
|---|---|---|
| Toolchain | Does the workspace build, lint and pass the whole suite? | `veyra audit . --profile standard` |
| Static | Are there stubs, fake tests, swallowed errors, panic/`unsafe` misuse or invented dependencies? | Rust Audit `scan` |
| Structure | Is the change where it says it is, and what else does it reach? | CodeGraph Rust (`codegraph-rust`) |
| Memory | What must the next session know? | Hindsight note |

The toolchain and static legs are blocking: a rejected verdict or a scan
finding is diagnosed, never silenced. CodeGraph is evidence of structure only
— its graph citations are checked against the source and its prose is
advisory, so it never counts as proof that something works. EvoForge is no
longer part of this process (removed 2026-10-24); the slice eval it ran could
not say anything about the real programme that the suite had not already
said.

## Scope discipline

- [`SPEC.md`](SPEC.md) is the product contract. Behaviour that is not in the
  spec needs a spec change first.
- Design decisions live in [`docs/adr/`](docs/adr/): a change to a module
  interface, the configuration format, the wire behaviour or a dependency
  needs a new or amended ADR.
- All code is safe Rust: `unsafe_code = "forbid"` is set at the workspace
  level and there are no exceptions. `unsafe` and FFI may only come from
  dependencies.
- New dependencies are justified in an ADR, pinned in `Cargo.lock`, audited
  with `cargo deny` and must not pull in a second crypto provider or a C
  toolchain for compression.
- Version numbers are pinned: no unpinned "latest" enters `Cargo.lock`.
- HTTP/3, gRPC and WebSockets over h2 are on `main` but stay labelled
  experimental until their evidence says otherwise; do not present them as
  production-verified beyond what `docs/evidence/` documents.

## What never enters a commit

Credentials, private notes and generated artifacts stay out of the diff.

Before pushing, this check must print nothing:

```bash
# No AI/bot co-authorship trailers: the owner commits as a human author.
git log origin/main..HEAD --format=%b | grep -iE '^co-authored-by:'
```

## Commit style

Subject in the imperative, prefixed with the area it touches, body explaining
why:

```
feat(net): close idle backend h2 sessions and replay refused streams

docs: record the backend HTTP/2 session lifecycle slice
```

Use `feat`, `fix`, `docs`, `ci`, `test` or `refactor` as the prefix and the
crate or area in the scope. Do not add AI co-authorship footers or
"Generated with …" attribution: the commit is signed by its human author. The
owner's human identities (`Doken-Tokuyama`, `ExyonQ`) are both valid; only an
assistant or bot as co-author is refused.

## Documentation and changelog

- Documentation is published in **English only**.
- Public docs live under `docs/` (ADRs, migration guides, differential
  corpus) and the top-level `SPEC.md`, `THREAT_MODEL.md` and
  `BENCHMARK_PLAN.md`.
- Every user-visible change gets a `CHANGELOG.md` entry under `[Unreleased]`,
  in the Keep-a-Changelog style the file already uses, naming what was
  verified and linking its evidence.
- Evidence goes under `docs/evidence/` with the commands, the artifact under
  test (binary or image digest) and the raw data. A conclusion without raw
  data is not evidence.
- A test cited in `docs/evidence/` must exist in the Rust tree of the same
  commit. CI and the release pipeline run
  `.github/scripts/check-evidence-test-citations.py`, which refuses a
  test-shaped name the tree does not define; a name kept on purpose as
  history is declared with its reason in
  `.github/scripts/evidence-test-citations-allow.txt` (run the script locally
  to see the verdict).
- Two blocks of the Linux suite only hold for an **unprivileged** uid: each
  asserts that a `chown(2)` to a foreign group is refused. Run as root they
  print `SKIP (running as root): <reason>` and carry on. CI runs the suite
  both ways: the unprivileged run must print none of those lines, and the root
  run must print exactly the ones declared in
  `.github/scripts/uid-skips.txt`. Run
  `python3 .github/scripts/check-uid-skips.py --self-test`, or give it a
  capture with `--root-log <log>` / `--user-log <log>`; a root capture needs
  `--nocapture`, or the marker never reaches the log.
- `docs/` publishes documentation (`.md`) and the recorded data only, never
  code. The harnesses that produced the measurements live outside the
  repository, in the maintainer's tree, and the evidence names them so a
  reader knows which program produced each number and can ask for it.

## Benchmarks

Scenario IDs and methodology come from [`BENCHMARK_PLAN.md`](BENCHMARK_PLAN.md)
§3–§5: same backends and topology for both products, at least five
repetitions, medians with the full range, and every scenario published —
including the ones EQProxy loses. Never cherry-pick the best run, and never
compare numbers taken on a host whose load you did not record.

## License

EQProxy is dual-licensed under the **MIT** and **Apache-2.0** licenses
(`LICENSE-MIT`, `LICENSE-APACHE`). By submitting a contribution you agree
that it is licensed under both, with no additional terms.

## Security

Do not open a public issue with a working exploit. Describe the affected
surface and the impact, and ask the maintainers for a private channel; the
threat model in [`THREAT_MODEL.md`](THREAT_MODEL.md) is the reference for what
is in scope.
