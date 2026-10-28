# v0.8 — the uid-gated skips of the suite, counted and declared

Language: **English**.

**What this page answers:** whether a skip that only makes sense for an
unprivileged uid can come back silently. Two blocks of the Linux suite print
`SKIP (running as root): <reason>` and carry on when the suite runs as uid 0;
from this increment CI runs the same suite **twice** — unprivileged and as
root — and `.github/scripts/check-uid-skips.py` refuses a skip that is not
declared in `.github/scripts/uid-skips.txt`, a count that moved, and a
declaration that stopped printing.

| Piece | Where |
|---|---|
| The registry, one `<count>  <log line>` per declaration | [.github/scripts/uid-skips.txt](../../.github/scripts/uid-skips.txt) |
| The checker (`--root-log`, `--user-log`, `--self-test`) | [.github/scripts/check-uid-skips.py](../../.github/scripts/check-uid-skips.py) |
| The run as root (job `suite-as-root`, step timeout 20 min) | [.github/workflows/ci.yml](../../.github/workflows/ci.yml) |
| The unprivileged run and its check (job `linux-tier1`) | [.github/workflows/ci.yml](../../.github/workflows/ci.yml) |
| Raw data of this page | [`raw/20261028T004705Z/`](v08-uid-skip-guard/raw/20261028T004705Z/) |

## Why the two declarations exist

The premise is recorded in [v08-linux-e2e-admin.md](v08-linux-e2e-admin.md):
both blocks assert that an unprivileged `chown(2)` to a foreign group is
refused, and root is allowed to perform it. On 2026-10-27 the full suite as
root **hung** instead of failing —
`run_admin_plane_reloads_unix_socket_policy_on_sighup` waited in `read_line`
for a refusal line that, for root, the reload never writes — and only a 90 s
guard ended the run. The blocks then declared their premise (commit
`c93cdb6`); the declaration made the skip visible, but nothing counted the
lines, so a new block would still have passed as a silent skip or a hang.
This increment counts them on both sides of the uid.

## What was run, and what it printed

All of it before the push, on macOS 26.5.1 arm64, Python 3.9.6 (the same
script CI runs with `python3`):

| # | What | Result | Raw |
|---|---|---|---|
| 1 | `--self-test`: synthetic undeclared, missing, duplicated and malformed input | `self-test ok: … all rejected`, exit 0 | [checker-recorded-logs.txt](v08-uid-skip-guard/raw/20261028T004705Z/checker-recorded-logs.txt) |
| 2 | the two SKIP lines recorded on 2026-10-27, together in one log | `2 printed, 2 declared`, exit 0 — the registry matches the recorded reasons byte for byte | same |
| 3 | a root log carrying only one of them (`e2e-admin-as-root.txt`) | exit 1, naming the declaration the log never printed | same |
| 4 | a marker offered as an unprivileged log | exit 1, `printed in an unprivileged run` | same |
| 5 | the recorded root suite captured **without** `--nocapture` (`full-suite-root.txt`) | exit 1: 0 printed, both declarations unobserved — a log that cannot show the marker is rejected as unproven, never accepted | same |
| 6 | the recorded unprivileged run (`cli-e2e-reload-as-eqverify.txt`) | `0 printed`, exit 0 | same |
| 7 | a real unprivileged run here: `cargo test -p eqproxy-cli --test cli_e2e run_admin_plane_reloads_unix_socket_policy_on_sighup -- --nocapture`, uid 501 | `1 passed; 0 failed`, `0 printed`, exit 0 | [local-user-run.txt](v08-uid-skip-guard/raw/20261028T004705Z/local-user-run.txt) |

## The CI gate

Run [40611071975](https://github.com/ExonQ/EQProxy/actions/runs/40611071975)
at `7c5eb92`, workflow `CI`, runners `ubuntu-latest`, toolchain 1.99.1 from
`rust-toolchain.toml`:

| Job | Verdict |
|---|---|
| Linux x86_64 (tier-1) | success |
| Suite as root (uid-gated skips declared) | success |
| Evidence test citations | success |
| Admin socket ACL E2E (native arm64) | success |
| Admin socket ACL E2E (native amd64) | success |

The root job ran the suite as uid 0 through `sudo` and printed the two
declarations; the checker's verdicts, verbatim from the run log:

```console
$ python3 .github/scripts/check-uid-skips.py --root-log /tmp/suite-root.log
uid-gated skips as root: 2 printed, 2 declared in uid-skips.txt
ok: every uid-gated skip of the root run is declared, with its reason
# exit 0
$ python3 .github/scripts/check-uid-skips.py --user-log /tmp/suite-user.log
uid-gated skips in an unprivileged run: 0 printed
ok: the unprivileged run printed no uid-gated skip
# exit 0
```

Both jobs ran the whole suite: `559 passed; 0 failed; 2 ignored` in each,
summed over the `test result:` lines of that run. The raw keeps the two
`WARN … failed to connect` lines of the mirror test that `--nocapture` lets
through, which is why the sum was read from `test result:` and not from a
loose grep. The root step carries `timeout-minutes: 20`, because the original
symptom was a hang and a hang must turn into a red build rather than a
squatting job; its build and cargo registry live under `/tmp` so uid 0 writes
into nothing the other jobs' cache steps save.

## What this does not prove

- The checker reads text logs. A uid-gated block that skips **without**
  printing the marker is invisible to it; that class is covered only bluntly
  by the root run — it fails, or hangs and the step timeout fails it.
- The red path was exercised locally against real recorded logs and synthetic
  ones (checks 3–5 above). CI was never made red on purpose, so no CI run on
  this page shows the gate failing.
- The local real run is macOS, unprivileged (uid 501); the recorded root runs
  are Linux (2026-10-27). The live root-side run is CI's, and it is the one
  cited here.
- Nothing here validates a release artifact or a container image: it counts
  the repository's suite, nothing else.
- The registry is exhaustive on purpose: a block legitimately removed must
  take its entry with it, or the gate stays red.
