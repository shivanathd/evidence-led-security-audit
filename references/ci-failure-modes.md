# CI failure modes

`.github/workflows/test.yml` is the public test workflow. It is a matrix of Ubuntu (Python 3.9 and 3.14), macOS (3.14) and Windows (3.9 and 3.14). `fail-fast` is false so one OS or version does not hide the others. Checkout does not persist credentials. These notes are for this repository's workflow, not a claim that the skill or a target is verified. See also the **CI failure modes** section in [VALIDATION.md](../VALIDATION.md).

## Expected outcomes (not failures)

| Step | Expected | Not a failure |
| --- | --- | --- |
| Unit tests | Every method PASS or SKIP | POSIX-only helpers SKIP on Windows |
| Public package check | Status `NO_RULE_MATCHED` (exit 0) on Ubuntu and macOS | The step is skipped on Windows (`check_public_package.py` exits BLOCKED there). `NEEDS_REVIEW` prints no `ERROR` but exits 3 and fails the matrix cell |
| Example reports | `STRUCTURE_OK` | The after-fix example stays `INCOMPLETE` because a required check is blocked |
| Host-checks smoke | Process exits 0; JSON written to `$RUNNER_TEMP` | Individual checks may be `NOT_APPLICABLE`, `BLOCKED`, or `FAIL`. CI does not pass `--strict`, so `FAIL` or `PARTIAL` coverage still exits 0. The report is never uploaded |

A GitHub App message that **Check publication was denied** is not a workflow failure. It means the app lacks Checks: read and write. An owner must enable that permission. Do not change this repository to work around it.

## Common failures and what to do

**`__pycache__` or `FORBIDDEN_ARTIFACT`.** Bytecode files are not part of the package. Export `PYTHONDONTWRITEBYTECODE=1` and run Python with `-B`, as CI does. Delete any `__pycache__` directories before `check_public_package.py`.

**`SKILL_NAME`.** The folder must be named `evidence-led-security-audit`. A worktree or temp copy with another name fails this rule even when the files are fine.

**`FILE_COUNT` warning.** The compact target is a warning, not an error. Do not delete references or tests to silence it.

**macOS symlink refusals.** `/tmp` and `/var` point at `/private/...`. The file helpers refuse any path with a symlink component. Use a canonical temp directory (`pwd -P` after `mktemp -d`) and the same pattern the tests use.

**Windows `BLOCKED` on inventory, package check, or render `--out`.** Those helpers need POSIX `openat`. CI skips the package-check step on Windows. The unit suite and `validate_report.py` / `host_checks.py` still run.

**`host_checks.py` smoke crash or write error.** The smoke run is read-only against the runner, bounded (`--time-budget 120 --max-entries 200000`), and writes only under `$RUNNER_TEMP`. CI does not pass `--strict`, so a completed run exits 0 even when a check is `FAIL` or coverage is `PARTIAL`; those are findings in the JSON, not a red cell. A traceback, hang, or nonzero exit (usage or `--out` failure) is a real job failure. Reproduce with the local `OUT` path below; do not raise the bounds to hide a hang.

**`validate_report.py` rejects the examples.** The after-fix file is supposed to remain `INCOMPLETE`. A `STRUCTURE` or `SOURCE` error is a real failure. If you changed a validator rule, add a case to `tests/corpus/adversarial_cases.json`.

**One matrix cell red, others green.** Read that cell's log. Ubuntu 3.9 and Windows 3.9 catch syntax the newer interpreters accept.

**After-fix compare drops a required check.** New host-check ids that are added to the example reports must stay in both baseline and after-fix so the compare does not treat them as missing.

**New check id without a fixture.** `tests/test_host_checks.py` must include a simulated-host case for each added id. Coverage does not have to be every OS for every check: Tailscale SSH has macOS, Linux and Windows fixtures; other late-Oct checks use the default simulated host plus any OS-specific cases that exist. Do not treat a missing unused-OS fixture as a red cell if the check is `NOT_APPLICABLE` there.

## Reproduce locally

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/check_public_package.py .
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/validate_report.py \
  assets/examples/after-fix-report.json \
  --baseline assets/examples/baseline-report.json --public
OUT="$(cd "$(mktemp -d)" && pwd -P)"
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/host_checks.py \
  --out "$OUT/host-checks.json" --time-budget 120 --max-entries 200000
```

On Windows, skip the package check. See [VALIDATION.md](../VALIDATION.md) for the release-candidate record.
