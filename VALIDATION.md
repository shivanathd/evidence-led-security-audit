# Release-candidate validation

Version 0.3.0, checked on 27 October 2026. This record concerns the skill's helper utilities and synthetic fixtures, not the security of a real system or the comparative detection performance of an agent.

## Executed checks

- **Unit suite:** 188 test methods on Linux with Python 3.12. POSIX-only inventory, package-check and render-output tests skip on Windows. One corpus test iterates 69 adversarial report fixtures; the corpus is included in the suite, not an additional independent benchmark.
- **Skill format:** The candidate passed `agentskills validate` using its absolute directory when that CLI was available. The hub stays under 4,000 characters.
- **Package inspection:** The public-package checker reported no rule match and no unreviewed binary content for this text-only candidate. One coverage-table cell named a product whose last label is a public TLD; it now names the shared-runtime folders instead. Detection rules were not changed and no extra host was added to the reviewed list.
- **Secret check:** Pattern checks (`textscan` secret shapes, `check_public_package.py`, a privacy grep of the branch diff) found no leaked values. Pattern checks do not prove that every confidential fact has been detected.
- **Examples:** The baseline and after-fix examples validate structurally; the after-fix example intentionally remains INCOMPLETE because a required check is blocked.
- **Host checks:** Fixture tests cover every check id on simulated macOS, Linux and Windows hosts (positive, negative and edge cases: symlink loops, unreadable directories, missing binaries, prereleases, Windows paths, spaces and unicode). A whole-run test proves no writes, no network, no subprocess beyond the two read-only listings, and no planted secret values in the JSON. CI also runs `host_checks.py` against each runner into `$RUNNER_TEMP`.
- **Endpoint guide commands:** the macOS commands in `references/endpoint-fleet.md` were run read-only on macOS 27.0 in the previous release. The Linux and Windows commands follow each vendor's documented tools and were not executed for this release. The osquery table and column names were checked against the osquery table specs.
- **Manual privacy review:** Audit examples are synthetic. Public-source citations are intentional. The only personal name in the tree is the repository owner's. No company name from the briefing header is present.

## Adversarial development checks

Separate authoring and reviewing model roles were used, followed by deterministic tests. Earlier review found defects in baseline comparison, evidence/target binding, publication policy handling, diagnostic redaction and filesystem containment; those remain covered.

This release's host-check review found and closed: Plex build hashes parsed as prereleases; UTF-16BE BMPString certificates missed; `py_pins` dropping a package after `RUN pip install`; `py_pins` treating `# litellm==…` comments as pins; .NET shared-framework folder casing; Windows `%TEMP%` not scanned for planted instructions; routine project `npm install`/`curl` lines treated as planted; quoted TOML env keys in Codex config; `~/go/pkg` (module cache) walked while `~/go/src` projects were skipped; Windows path display using case-sensitive compare; `Lib`/`lib` site-packages double-counted on case-folding volumes; simulated PATH entries already under `sysroot` remapped as a guest drive; Claude project keys using POSIX `/home/...` treated as relative on Python 3.13+ Windows and drive-prefixed on 3.9; POSIX `abspath` of a drive-prefixed `/home` locator redacting the runner home; PE version resources in the head of a file larger than the read window. Regression tests cover each of those paths. Model agreement was not used as execution evidence.

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
