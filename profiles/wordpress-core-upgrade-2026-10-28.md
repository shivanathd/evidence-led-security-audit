# Optional profile: WordPress Core upgrade-window RCE (2026-10-28)

Last checked: 2026-10-30. This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date.

`host_checks.py` check id: `wordpress-core-upgrade-rce`. Read-only metadata only. Never start PHP, never request `setup-config.php`, `install.php`, or any URL under `wp-content/upgrade`.

## Primary sources

- WordPress.org news (28 Oct 2026): [WordPress 7.1.4](https://wordpress.org/news/2026/10/wordpress-7-1-4/)
- HelpHub Version 7.1.4 (28 Oct 2026): [version-7-1-4](https://wordpress.org/documentation/wordpress-version/version-7-1-4/)
- GitHub advisory (29 Oct 2026): [GHSA-4w3m-c66w-69mg](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4w3m-c66w-69mg)

News pointer (not a floor): [The Hacker News](https://thehackernews.com/2026/10/wordpress-rce-flaw-draws-nearly-63000.html). Inclusive “through 7.1.3” wording that would mark 7.1.4 affected is discarded.

No CVE id. GHSA severity is Low; public reporting quotes Wordfence CVSS 8.1. Record both; neither overrides the GHSA/HelpHub patched table.

## What was disclosed (as of the date above)

A race during a full-package core upgrade can expose a staged installer. Patched 28 Oct 2026. Actively probed.

Authoritative patched builds (GHSA + HelpHub), 7.1.4 through 4.7.39. HelpHub: WordPress 4.6 and earlier no longer receive security updates (this check records those as `review`).

7.2: the news post names Beta 3 as containing the applicable fixes; 7.2 final was planned for 8 Dec. Classification: 7.2 with no prerelease, or 7.3 and later → `info`; 7.2 beta 3 or later, or 7.2 RC → `info`; 7.2 beta 1 or 2 → `affected`; 7.2 alpha or any other 7.2 prerelease → `review`.

## Evidence this check reads

A directory is a WordPress core root when it contains `wp-includes/version.php` and (`wp-settings.php` or `wp-load.php`) as regular files. Collection is the index walk over `host.roots` (home plus existing web roots when `--root` is omitted). Composer evidence is out of scope.

`$wp_version` is parsed from `version.php`. Staged copies under `wp-content/upgrade` are `review` even when the number is patched.

## Finding to check-result rollup (`run_check`)

| Findings / blockers | Check result |
| --- | --- |
| at least one `affected` or `review` | `FAIL` |
| at least one `unknown` (and no `affected`/`review`) | `BLOCKED` |
| only `info` | `PASS` |
| nothing found | `NOT_APPLICABLE` |

- 4.7 through 7.1: `classify_lines` with `line_len=2` against the 25 GHSA patched versions. A prerelease of a floor is not fixed.
- 4.6 and earlier → `review`
- Companion 7.1.4 issues (XSS, Customizer, Interactivity API, bundled CA refresh) are out of this check.

## Known limits

- No HTTP to `setup-config.php`, `install.php`, or `wp-content/upgrade`. Reading `version.php` on disk, including staged copies, is in scope.
- Plugin-only trees (no core markers) are not this check.
- The walk does not cover roots that were not passed in.

## Closing a finding under this profile

Use `verification_basis: vendor_patch` only with GHSA-4w3m-c66w-69mg or HelpHub 7.1.4 retrieved this run, plus evidence `$wp_version` is the patched build for that branch.

## What needs a human

Confirming a staged tree is leftover and removable; reviewing logs for upgrade-window probes; approving `NOT_APPLICABLE`.
