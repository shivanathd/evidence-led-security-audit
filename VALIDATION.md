# Release-candidate validation

Version 0.2.0, checked on 25 October 2026. This record concerns the skill's helper utilities and synthetic fixtures, not the security of a real system or the comparative detection performance of an agent.

## Executed checks

- **Unit suite:** 72 test methods passed on Linux with Python 3.12 (the previous 0.2.0 record was 66 on Python 3.14.8 / 3.14.6 / 3.9.6). One corpus test iterates 69 adversarial report fixtures; the corpus is included in the suite, not an additional independent benchmark.
- **Skill format:** The candidate passed `agentskills validate` using its absolute directory.
- **Package inspection:** The public-package checker reported no rule match and no unreviewed binary content for this text-only candidate.
- **Secret check:** Gitleaks 8.30.1 found no leaks in the candidate tree. Pattern checks do not prove that every confidential fact has been detected.
- **Examples:** The baseline and after-fix examples validate structurally; the after-fix example intentionally remains INCOMPLETE because a required check is blocked.
- **Endpoint guide commands:** the macOS commands in `references/endpoint-fleet.md` were run read-only on macOS 27.0. The Linux and Windows commands follow each vendor's documented tools and were not executed for this release. The osquery table and column names were checked against the osquery table specs.
- **Manual privacy review:** Audit examples are synthetic. Public-source citations are intentional; no real audit inventory, credentials or incident evidence is bundled.

## Adversarial development checks

Separate authoring and reviewing model roles were used, followed by deterministic tests. Review found defects in baseline comparison, evidence/target binding, publication policy handling, diagnostic redaction and filesystem containment; regression tests now cover the identified paths.

The tests include rejected missing baselines, wrong-target evidence, non-human technical proof, accepted-risk clearance, missing image/runtime links, unaccepted inventory gaps, root and ancestor symlinks, directory swaps, output overwrite safety, binary-content review, URL userinfo, complete private-key blocks and diagnostic privacy. Model agreement was not used as execution evidence.

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

Keep bytecode disabled so the package check does not encounter generated cache files. A package check with a host override must return NEEDS_REVIEW for independent approval, not an automated publication pass.

## Limits

Exercised on Linux (Python 3.12 in this run). CI runs Ubuntu with 3.9 and 3.14 and macOS with 3.14. Filesystem helpers require POSIX directory-handle/no-follow support and stop when unavailable; Windows is not supported.

macOS note: `/tmp` and `/var` are symlinks to `/private/...`, and the helpers refuse any path with a symlinked component. The first macOS run failed 15 tests for this reason alone; the tests now use canonical temp paths, and the refusal message names the canonical path to pass instead.

The schema checks submitted structure and consistency, not evidence authenticity, owner authority or actual sandbox controls. The deployed-fix chain is currently image-oriented; do not invent image/provenance fields for bare-metal or managed services. Review the limits in README.md before applying the workflow.

This is a release candidate, not a certification or a published service. A maintainer must review licensing and attribution, enable GitHub private vulnerability reporting, approve publication and rerun these checks after any change.
