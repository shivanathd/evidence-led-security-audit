# Optional profile: Drupal Commerce Core CVE-2026-118539 (2026-10-28)

Last checked: 2026-10-30. This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date.

`host_checks.py` check id: `drupal-commerce-118539`. Inventory key: `drupal_commerce_hints` (a lead, not runtime proof). Read-only metadata only. Never start Drupal, `drush`, `composer`, PHP, or HTTP. Do not write order-audit SQL.

## Primary sources

- Drupal Security Team advisory SA-CONTRIB-2026-254 (28 Oct 2026): [SA-CONTRIB-2026-254](https://www.drupal.org/sa-contrib-2026-254)
- Security release Commerce Core 3.3.13 (requires Drupal `^10.3 || ^11`): [3.3.13](https://www.drupal.org/project/commerce/releases/3.3.13)
- Security release Commerce Core 8.x-2.41 (requires Drupal `^9.3 || ^10`): [8.x-2.41](https://www.drupal.org/project/commerce/releases/8.x-2.41)
- CVE record: [CVE-2026-118539](https://www.cve.org/CVERecord?id=CVE-2026-118539) (CNA: Drupal.org). This run retrieved little besides the CNA field. Do not invent NVD CVSS or CISA KEV membership.

News pointer (not a floor): [The Hacker News](https://thehackernews.com/2026/10/hackers-actively-exploit-highly.html) (30 Oct 2026). The sentence “0.0.0 to 2.41 and 3.0.0 to 3.3.13” includes the patched builds. Discard that wording.

## What was disclosed (as of the date above)

From SA-CONTRIB-2026-254:

- Project: Commerce Core (machine name `commerce`)
- Vulnerability: access bypass. Highly critical 21/25. Actively exploited.
- CVE: **CVE-2026-118539**
- **Affected versions (authoritative):** `<2.41 || >=3.0.0 <3.3.13`
- **Fixed builds:** Commerce Core **3.3.13** (3.x) and **8.x-2.41** (2.x)
- No workaround replaces the upgrade. Sites should also audit orders in the site database; this tool does not.

## Evidence this check reads

- `composer.lock` package `drupal/commerce` (not `composer.json` constraints)
- optional `vendor/composer/installed.json` package `drupal/commerce`
- packaged Commerce info.yml whose YAML `project:` is exactly `commerce`

It does not read companion `commerce_*` modules, Magento / Adobe Commerce, vendored copies of the info.yml, or Drupal 7 commerce INI files.

## Finding to check-result rollup (`run_check`)

Each finding is one evidence row. The check result is the rollup:

| Findings / blockers | Check result |
| --- | --- |
| at least one `affected` or `review` | `FAIL` |
| at least one `unknown` (and no `affected`/`review`) | `BLOCKED` |
| a needed file exists but cannot be read (`r.blocked`) | `BLOCKED` |
| only `info` (every found copy at or above its line floor) | `PASS` |
| nothing found in the listed roots | `NOT_APPLICABLE` |

Classification after an anchored, case-sensitive strip of a leading `8.x-`:

- 2.x below 2.41, or 3.x below 3.3.13 (including a prerelease of the floor) → `affected`
- at or above 2.41 on 2.x, or 3.3.13 on 3.x → `info`
- `*x-dev`, `dev-*`, or a major outside 2.x / 3.x → `review` (“check commit” for dev builds)
- packaged info.yml with `project: commerce` but no version → `unknown`, unless a proven fixed lock or `installed.json` in the same site root is present, in which case it is a note

## How this maps to the skill

- Target: one `other` (endpoint) target per machine, or a repository inventory that listed `drupal_commerce_hints`. Empty inventory hints are not runtime absence.
- Layer: `dependency`. A lock pin is not proof of the running site until the same versions are observed on the host.
- Companion same-day advisories SA-CONTRIB-2026-255 through 259 are out of this check.

## Known limits

- Stale copies under `releases/` or `*.bak` can FAIL. They are not hidden.
- The walk does not cover `/opt`, `/data`, other users' `public_html`, container volumes, or roots that were not passed in.
- Drupal 7 commerce INI files are out of scope. This check cannot see that product line.
- `composer.json` ranges are not evidence. A patched lock plus a loose `^3.3` constraint is still PASS when the lock and info.yml are fixed.

## Closing a finding under this profile

Use `verification_basis: vendor_patch` only with SA-CONTRIB-2026-254 (or the matching release notes) retrieved this run, plus evidence the installed Commerce Core is 3.3.13 (Drupal `^10.3 || ^11`) or 8.x-2.41 (Drupal `^9.3 || ^10`). Order-inconsistency review is a human/database step and stays skipped.

## What needs a human

Confirming a distribution rebuild or a commit-pinned dev build; applying the Drupal core version that the chosen Commerce line requires; auditing orders in the site database; approving `NOT_APPLICABLE`.
