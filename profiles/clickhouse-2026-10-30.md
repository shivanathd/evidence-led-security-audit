# Optional profile: ClickHouse CVE-2026-116366 (2026-10-30)

Last checked: 2026-10-30. This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date.

`host_checks.py` check id: `clickhouse-116366`. Read-only metadata only. Never start ClickHouse, `clickhouse-client`, or HTTP.

## Primary sources

- ClickHouse security changelog: [security-changelog](https://clickhouse.com/docs/resources/changelogs/security-changelog) (entry 2026-10-30 / CVE-2026-116366)
- CVE record: [CVE-2026-116366](https://www.cve.org/CVERecord?id=CVE-2026-116366) (CNA: ClickHouse)

Aggregator pages that mix Cloud and OSS “Fixed in” lists are not floors.

## What was disclosed (as of the date above)

Unauthenticated network access could execute code on ClickHouse Server. OSS floors (authoritative, only these four):

- `v26.3.62.3-lts`
- `v26.8.36.3-lts`
- `v26.9.27.3-stable`
- `v26.10.3.7-stable`

Vendor text: a fix was applied to all ClickHouse Cloud and BYOC deployments. Cloud version numbers are not OSS floors. `v26.10.2.84` is a Cloud build; OSS 26.10 is fixed at `v26.10.3.7-stable`.

CNA `defaultStatus=affected` for OSS trains that are not in those four rows. This check records those as `review`, not `affected` without a remediation version.

## Evidence this check reads

- Linux packages `clickhouse-server` and `clickhouse-common-static`. `clickhouse-common-static` is classified with `clickhouse-server`, or when it is present with neither `clickhouse-client` nor `clickhouse-keeper`. It is not server evidence on a client-only or keeper-only install (those packages pull the shared static package).
- Homebrew Cellar formula `clickhouse` (the cask is unread)
- Image tags matching `clickhouse-server` in Dockerfiles / compose / deploy YAML
- A plain `/etc/clickhouse-server` directory with no package is `unknown`

`clickhouse-keeper` alone is not this check. `clickhouse-client` (package or image) is not this check.

## Finding to check-result rollup (`run_check`)

| Findings / blockers | Check result |
| --- | --- |
| at least one `affected` or `review` | `FAIL` |
| at least one `unknown` (and no `affected`/`review`) | `BLOCKED` |
| walk stopped (`max_entries` / time budget) or the check raised (`r.blocked`), including when no findings exist | `BLOCKED` |
| only `info` | `PASS` |
| nothing found | `NOT_APPLICABLE` |

- Named OSS trains use `classify_lines` with `line_len=2` against the four floors. A prerelease of a floor is not fixed.
- Image tags with fewer than four numeric parts, or a non-numeric tag (`latest`, `head`, `lts`) → `info` (“moving tag; pull and rebuild to get the fixed build”)
- Other parseable trains → `review`

## Known limits

- Guessed version files and Windows Program Files are not read. Docker refs cover Windows images.
- Homebrew cask is unread.
- Cloud / BYOC is not a SaaS console this helper can classify. If a Cloud or BYOC image or package name appears in scanned package metadata or Dockerfile / compose / deploy YAML, this check applies the OSS floors and the finding is provisional (no Cloud/BYOC discriminator).

## Closing a finding under this profile

Use `verification_basis: vendor_patch` only with the security changelog (or the CVE record) retrieved this run, plus evidence the OSS package or rebuilt image is at or above the matching train floor.

## What needs a human

Confirming a Cloud vs OSS install; rebuilding images that used a moving tag; approving `NOT_APPLICABLE`.
