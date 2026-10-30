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

- `composer.lock` package whose `"name"` is `drupal/commerce` (not `composer.json` constraints, and not a `require-dev` / `suggest` / `conflict` mention of that string)
- optional `vendor/composer/installed.json` package `drupal/commerce`
- packaged Commerce info.yml whose YAML `project:` is `commerce` (case-insensitive)

It does not read companion `commerce_*` modules, Magento / Adobe Commerce, copies of the info.yml under a Composer vendor tree (`vendor/autoload.php` or `vendor/composer/installed.json` present), or Drupal 7 commerce INI files. A directory merely named `vendor` is not a Composer vendor tree.

## Finding to check-result rollup (`run_check`)

Each finding is one evidence row. The check result is the rollup:

| Findings / blockers | Check result |
| --- | --- |
| at least one `affected` or `review` | `FAIL` |
| at least one `unknown` (and no `affected`/`review`) | `BLOCKED` |
| a needed file exists but cannot be read (`r.blocked`) | `BLOCKED` |
| only `info` (every found copy at or above its line floor) | `PASS` |
| nothing found in the listed roots | `NOT_APPLICABLE` |

Classification after an anchored, case-sensitive strip of a leading `8.x-`. The version string is lowercased before the development-build match (`-dev` at end, or `-dev` followed by `+`, `.`, a digit, or `-`; also `*x-dev` and `dev-*`). That includes `3.4.0-dev+abc`, `3.4.0-dev1`, and `3.3.13-DEV`.

- 2.x below 2.41, or 3.x below 3.3.13 (including a prerelease of the floor) → `affected`
- at or above 2.41 on 2.x, or 3.3.13 on 3.x → `info`
- development builds (`*x-dev`, `dev-*`, numeric `*-dev` including `+build` / `-dev1` / uppercase `-DEV`) or a major outside 2.x / 3.x → `review` (“check commit”)
- a version whose remainder includes `#` (for example `3.3.13-rc1#local`) → `review` (“unsupported version suffix”); it is not compared to the floor
- several `version:` lines whose values differ → `review`; identical duplicates use that value
- packaged Commerce info.yml whose `project:` names something other than `commerce` (for example `commerce_kickstart`) → `review`
- packaged info.yml with `project: commerce` but no version, or an unpackaged git checkout (no `project:` key; `composer install --prefer-source`) → `unknown`, unless a proven fixed lock or `installed.json` in the same site root is present **and** the relative path is a Drupal module layout (`(web|docroot|html|public)/?modules/(contrib/)?commerce/` plus the packaged info.yml, case-insensitive). That pairing is a note and the check can PASS.
- a nonempty `version:` line that the matcher cannot parse (for example `version: 3.3.12 local`) → `unknown`; it is not treated as missing and is not paired with a fixed lock
- a lock or `installed.json` that names `drupal/commerce` (`"name": "drupal/commerce"`) but has no readable version → `unknown`. A lock that only mentions the string under `require-dev`, `suggest`, `conflict`, or a `drupal/commerce_shipping` package is not evidence.

## How this maps to the skill

- Target: one `other` (endpoint) target per machine, or a repository inventory that listed `drupal_commerce_hints`. Empty inventory hints are not runtime absence.
- Layer: `dependency`. A lock pin is not proof of the running site until the same versions are observed on the host.
- Companion same-day advisories SA-CONTRIB-2026-255 through 259 are out of this check.

## Known limits

- Stale copies under `releases/` or `*.bak` can FAIL. They are not hidden.
- The walk does not cover `/opt`, `/data`, other users' `public_html`, container volumes, or roots that were not passed in.
- Symlinked files and module folders (for example Composer path repos) are not followed.
- Drupal 7 commerce INI files are out of scope. This check cannot see that product line.
- `composer.json` ranges are not evidence. A patched lock plus a loose `^3.3` constraint is still PASS when the lock and info.yml are fixed.
- A folder named `vendor` is treated as Composer’s vendor tree only when `vendor/autoload.php` or `vendor/composer/installed.json` exists. `~/clients/vendor/acme/shop/composer.lock` is therefore still read.

## Closing a finding under this profile

Use `verification_basis: vendor_patch` only with SA-CONTRIB-2026-254 (or the matching release notes) retrieved this run, plus evidence the installed Commerce Core is 3.3.13 (Drupal `^10.3 || ^11`) or 8.x-2.41 (Drupal `^9.3 || ^10`). Order-inconsistency review is a human/database step and stays skipped.

## What needs a human

Confirming a distribution rebuild or a commit-pinned dev build; applying the Drupal core version that the chosen Commerce line requires; auditing orders in the site database; approving `NOT_APPLICABLE`.
