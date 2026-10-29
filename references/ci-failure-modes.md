# CI failure modes

`.github/workflows/test.yml` is the public test workflow. It is a matrix of Ubuntu (Python 3.9 and 3.14), macOS (3.14) and Windows (3.9 and 3.14). `fail-fast` is false so one OS or version does not hide the others. Checkout does not persist credentials. These notes are for this repository's workflow, not a claim that the skill or a target is verified.

## Expected outcomes (not failures)

| Step | Expected | Not a failure |
| --- | --- | --- |
| Unit tests | Every method PASS or SKIP | POSIX-only helpers SKIP on Windows |
| Public package check | No ERROR on Ubuntu and macOS | The step is skipped on Windows (`check_public_package.py` exits BLOCKED there) |
| Example reports | `STRUCTURE_OK` | The after-fix example stays `INCOMPLETE` because a required check is blocked |
| Host-checks smoke | Process exits 0; JSON written to `$RUNNER_TEMP` | Individual checks may be `NOT_APPLICABLE` or `BLOCKED` on a clean runner; the report is never uploaded |

A GitHub App message that **Check publication was denied** is not a workflow failure. It means the app lacks Checks: read and write. An owner must enable that permission. Do not change this repository to work around it.

## Common failures and what to do

**`__pycache__` or `FORBIDDEN_ARTIFACT`.** Bytecode files are not part of the package. Export `PYTHONDONTWRITEBYTECODE=1` and run Python with `-B`, as CI does. Delete any `__pycache__` directories before `check_public_package.py`.

**`SKILL_NAME`.** The folder must be named `evidence-led-security-audit`. A worktree or temp copy with another name fails this rule even when the files are fine.

**`FILE_COUNT` warning.** The compact target is a warning, not an error. Do not delete references or tests to silence it.

**macOS symlink refusals.** `/tmp` and `/var` point at `/private/...`. The file helpers refuse any path with a symlink component. Use a canonical temp directory (`pwd -P` after `mktemp -d`) and the same pattern the tests use.

**Windows `BLOCKED` on inventory, package check, or render `--out`.** Those helpers need POSIX `openat`. CI skips the package-check step on Windows. The unit suite and `validate_report.py` / `host_checks.py` still run.

**`host_checks.py` smoke FAIL or crash.** The smoke run is read-only against the runner, bounded (`--time-budget 120 --max-entries 200000`), and writes only under `$RUNNER_TEMP`. A FAIL or traceback is a real job failure. Re-run the same command locally; do not raise the bounds to hide a hang.

**`validate_report.py` rejects the examples.** The after-fix file is supposed to remain `INCOMPLETE`. A `STRUCTURE` or `SOURCE` error is a real failure. If you changed a validator rule, add a case to `tests/corpus/adversarial_cases.json`.

**One matrix cell red, others green.** Read that cell's log. Ubuntu 3.9 and Windows 3.9 catch syntax the newer interpreters accept.

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
