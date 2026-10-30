# Release-candidate validation

Unreleased (expected 0.4.2). Checked on 30 October 2026. This record concerns the skill's helper utilities and synthetic fixtures, not the security of a real system or the comparative detection performance of an agent.

## Executed checks

- **Unit suite:** 293 test methods on Linux with Python 3.12. POSIX-only inventory, package-check and render-output tests skip on Windows. One corpus test iterates 69 adversarial report fixtures; the corpus is included in the suite, not an additional independent benchmark.
- **Skill format:** The candidate passed `agentskills validate` using its absolute directory when that CLI was available. The hub stays under 4,000 characters.
- **Package inspection:** The public-package checker (run from a directory whose name matches `SKILL.md`) reported no rule match and no unreviewed binary content for this text-only candidate. Reviewed public hosts added for this unreleased change: `www.oracle.com`, `oracle.com`, `www.anthropic.com`, `anthropic.com`, `internet.gmo`, `www.teamviewer.com`, `teamviewer.com`, `ubuntu.com`, `www.ubuntu.com`, `lists.openwall.net`, `remedio.io`. Onamae product host strings are assembled at runtime so the leak scanner does not treat detection regexes as live hosts. The compact file-count target was raised from 55 to 60 for the new dated profiles.
- **Secret check:** Pattern checks (`textscan` secret shapes, `check_public_package.py`, a privacy grep of the branch diff) found no leaked values. Pattern checks do not prove that every confidential fact has been detected.
- **Examples:** The baseline and after-fix examples validate structurally; the after-fix example intentionally remains INCOMPLETE because a required check is blocked.
- **Host checks:** Fixture tests cover every check id on simulated macOS, Linux and Windows hosts (positive, negative and edge cases: symlink loops, unreadable directories, missing binaries, prereleases, Windows paths, spaces and unicode). A whole-run test proves no writes, no network, no subprocess beyond the two read-only listings, and no planted secret values in the JSON. CI also runs `host_checks.py` against each runner into `$RUNNER_TEMP`.
- **Endpoint guide commands:** the macOS commands in `references/endpoint-fleet.md` were run read-only on macOS 27.0 in the previous release. The Linux and Windows commands follow each vendor's documented tools and were not executed for this release. The osquery table and column names were checked against the osquery table specs.
- **Manual privacy review:** Audit examples are synthetic. Public-source citations are intentional. The only personal name in the tree is the repository owner's. No company name from the briefing header is present.

## Adversarial development checks

Separate authoring and reviewing model roles were used, followed by deterministic tests. Earlier review found defects in baseline comparison, evidence/target binding, publication policy handling, diagnostic redaction and filesystem containment; those remain covered.

This release's host-check review found and closed: a 1.104.4 install with unread RunSSH prefs being BLOCKED (fixed builds no longer require prefs); exported `ssh` keys only matching at line start (now also match inlined JSON); PeopleSoft `peopletools` trees under `/opt/oracle` missed by the home walk; fragment `retrieved_on` stamped after the report date. Prior-release regressions remain covered. Model agreement was not used as execution evidence.

The tests include rejected missing baselines, wrong-target evidence, non-human technical proof, accepted-risk clearance, missing image/runtime links, unaccepted inventory gaps, root and ancestor symlinks, directory swaps, output overwrite safety, binary-content review, URL userinfo, complete private-key blocks and diagnostic privacy, plus host-check false negatives, false positives, no-write / no-network / no-exec invariants and secret-value withholding.

## Reproduce

Run from the candidate directory in a suitable POSIX environment:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -v
agentskills validate "$PWD"
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/check_public_package.py .
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/validate_report.py \
  assets/examples/after-fix-report.json \
  --baseline assets/examples/baseline-report.json --public
```

On Windows (Python 3.9+), only the unit suite and `validate_report.py` / `host_checks.py` apply. `inventory.py`, `check_public_package.py` and `render_report.py --out` exit BLOCKED by design.

Keep bytecode disabled so the package check does not encounter generated cache files. A package check with a host override must return NEEDS_REVIEW for independent approval, not an automated publication pass.

## Limits

Exercised on Linux (Python 3.12 in this run). CI runs Ubuntu with 3.9 and 3.14, macOS with 3.14, and Windows with 3.9 and 3.14. Filesystem helpers other than `host_checks.py` require POSIX directory-handle/no-follow support and stop when unavailable.

macOS note: `/tmp` and `/var` are symlinks to `/private/...`, and the helpers refuse any path with a symlinked component. The first macOS run failed 15 tests for this reason alone; the tests now use canonical temp paths, and the refusal message names the canonical path to pass instead.

The schema checks submitted structure and consistency, not evidence authenticity, owner authority or actual sandbox controls. The deployed-fix chain is currently image-oriented; do not invent image/provenance fields for bare-metal or managed services. Review the limits in README.md before applying the workflow.

This is a release candidate, not a certification or a published service. A maintainer must review licensing and attribution, enable GitHub private vulnerability reporting, approve publication and rerun these checks after any change.

## CI failure modes

`.github/workflows/test.yml` did not change in this release. The new host checks, inventory hints, examples and tests still run through the same matrix (Ubuntu 3.9/3.14, macOS 3.14, Windows 3.9/3.14, `fail-fast: false`). These notes record how that workflow fails so a script-only change is not shipped without failure-mode evidence.

| Step | Expected | Treat as a failure |
| --- | --- | --- |
| Unit tests | PASS or SKIP | A new check id without a simulated-host fixture |
| Public package check | No ERROR on Ubuntu and macOS | `__pycache__`, a worktree not named `evidence-led-security-audit`, or an unreviewed host |
| Example reports | `STRUCTURE_OK`; after-fix stays `INCOMPLETE` | A new required check dropped from the after-fix compare |
| Host-checks smoke | Exit 0 into `$RUNNER_TEMP` | A traceback, hang, write outside `--out`, or network/subprocess beyond the two read-only listings |

Windows skips the package-check step because those helpers exit BLOCKED. Individual smoke-run checks may be `NOT_APPLICABLE` or `BLOCKED` on a clean runner. A GitHub App "Check publication was denied" message is an app Checks permission gap, not a job failure.

macOS `/tmp` is a symlink; use a canonical temp path. Keep `PYTHONDONTWRITEBYTECODE=1` and `python -B` so bytecode files do not fail the package check. Do not raise `--time-budget` or `--max-entries` to hide a hang.
