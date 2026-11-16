# Optional profile: host advisories 2026-11-16 (PostgreSQL CVE-2026-6460, Quay CVE-2026-123710)

Last checked: 2026-11-16. This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date.

`host_checks.py` check ids: `postgresql-6460`, `quay-123710`. Read-only metadata only. Never start `postgres`, `psql`, `pg_ctl`, `pg_config` or Quay, never HTTP to `/keys`, never search for appliance CGI paths, and never make a network request.

## Terms

- **core server**: the PostgreSQL database server package or image, not `libpq` or `postgresql-client`.
- **PGDATA `PG_VERSION`**: a one-line major-version file in a data directory; this check does not read it.
- **`pg_config.h`**: the compiled `PG_VERSION` string under a Windows PostgreSQL server tree. `/usr/include/postgresql/pg_config.h` is `libpq-dev` and is not this check. Never execute `pg_config`.
- **`/keys`**: Quay's service-key rotation endpoint named in CVE-2026-123710. Restricting it is mitigation, never a vendor patch.
- **RHSA floor**: the Quay 3.x.y named in the matching Red Hat security advisory. Operator and Clair image tags are not that floor.

## Primary sources

- PostgreSQL CVE page (retrieved 2026-11-16): [CVE-2026-6460](https://www.postgresql.org/support/security/CVE-2026-6460/)
- PostgreSQL news 3442 (12 Nov 2026, retrieved 2026-11-16): [18.7 / 17.12 / 16.16 / 15.20 / 14.25 and 19 RC 2](https://www.postgresql.org/about/news/3442/)
- Debian tracker: [CVE-2026-6460](https://security-tracker.debian.org/tracker/CVE-2026-6460)
- Ubuntu CVE page (Needs evaluation as of 13 Nov 2026): [CVE-2026-6460](https://ubuntu.com/security/CVE-2026-6460)
- CVE record: [CVE-2026-6460](https://www.cve.org/CVERecord?id=CVE-2026-6460)
- NVD: [CVE-2026-6460](https://nvd.nist.gov/vuln/detail/CVE-2026-6460)
- Red Hat CVE (retrieved 2026-11-16): [CVE-2026-123710](https://access.redhat.com/security/cve/cve-2026-123710)
- [RHSA-2026:99021](https://access.redhat.com/errata/RHSA-2026:99021) (3.9.28), [RHSA-2026:99025](https://access.redhat.com/errata/RHSA-2026:99025) (3.10.28), [RHSA-2026:99027](https://access.redhat.com/errata/RHSA-2026:99027) (3.12.24), [RHSA-2026:99024](https://access.redhat.com/errata/RHSA-2026:99024) (3.14.10), [RHSA-2026:99023](https://access.redhat.com/errata/RHSA-2026:99023) (3.15.9), [RHSA-2026:99022](https://access.redhat.com/errata/RHSA-2026:99022) (3.16.7), [RHSA-2026:99026](https://access.redhat.com/errata/RHSA-2026:99026) (3.17.7), [RHSA-2026:99019](https://access.redhat.com/errata/RHSA-2026:99019) (3.18.3)
- CVE record: [CVE-2026-123710](https://www.cve.org/CVERecord?id=CVE-2026-123710)
- NVD: [CVE-2026-123710](https://nvd.nist.gov/vuln/detail/CVE-2026-123710)

## What was disclosed (as of the date above)

**PostgreSQL CVE-2026-6460.** Type confusion after `ALTER … SET DATA TYPE` on the core server (CVSS 3.1 8.8). Vendor: versions before **18.7**, **17.12**, **16.16**, **15.20** and **14.25** are affected. Published 2026-11-12. 14.25 is the final PostgreSQL 14 release (EOL). 19 RC 2 shipped with the same security set; 19 RC 1 is still affected. Debian bookworm `postgresql-15` 15.20-0+deb12u1 (DLA-4905-1) and trixie `postgresql-17` 17.12-0+deb13u1 (DSA-6625-1) sit at those minors. The dpkg `postgresql` metapackage (`17+278`) is not a floor. Ubuntu had no USN (Needs evaluation). Do not invent Ubuntu floors.

**Red Hat Quay CVE-2026-123710.** Unauthenticated `/keys` signing-key takeover (CVSS 9.8, CWE-1287, Bugzilla 2568072). RHSA floors above each list CVE-2026-123710. Missing trains 3.11 and 3.13, and Quay 5 / Mirror registry, have no named floor → `review`. Restricting `/keys` is mitigation. Quay.io SaaS is not host-checkable.

## Fixed versions

| Surface | Floor | Source |
| --- | --- | --- |
| PostgreSQL 18 | 18.7 | PostgreSQL CVE-2026-6460 / news 3442 |
| PostgreSQL 17 | 17.12 | PostgreSQL CVE-2026-6460 / news 3442 |
| PostgreSQL 16 | 16.16 | PostgreSQL CVE-2026-6460 / news 3442 |
| PostgreSQL 15 | 15.20 | PostgreSQL CVE-2026-6460 / news 3442 |
| PostgreSQL 14 | 14.25 | PostgreSQL CVE-2026-6460 / news 3442 (final 14) |
| Quay 3.9 | 3.9.28 | RHSA-2026:99021 |
| Quay 3.10 | 3.10.28 | RHSA-2026:99025 |
| Quay 3.12 | 3.12.24 | RHSA-2026:99027 |
| Quay 3.14 | 3.14.10 | RHSA-2026:99024 |
| Quay 3.15 | 3.15.9 | RHSA-2026:99023 |
| Quay 3.16 | 3.16.7 | RHSA-2026:99022 |
| Quay 3.17 | 3.17.7 | RHSA-2026:99026 |
| Quay 3.18 | 3.18.3 | RHSA-2026:99019 |

## Evidence these checks read

- `postgresql-6460`: `linux_packages` names matching the server (`postgresql-N`, `postgresql-server`, `postgresqlN-server`, apk/pacman/rpm `postgresql`). The dpkg `postgresql` metapackage is skipped. Homebrew Cellar `postgresql` / `postgresql@N`; `docker_refs` last path component exactly `postgres` or `postgresql`; Windows `Program Files/PostgreSQL/*/include/pg_config.h`. `/usr/include/postgresql/pg_config.h` is unread. `/etc/postgresql` without a server package is `unknown`. Comparison is `parse_version` / `classify_lines` (`line_len=1`). Major `< 14` is `affected`. 19 RC 1 is `affected`; 19 RC 2 and later are `info`. Moving image tags (`latest`, `16`) are `info`. Never `PGDATA/PG_VERSION`. Never `postgresql.conf`.
- `quay-123710`: `docker_refs` for `quay/quay-rhel8`, `quay/quay-rhel9`, `projectquay/quay`. Operator images (`quay-operator-rhel8`, `quay-rhel9-operator`) are `review`. `classify_lines` (`line_len=2`) against the RHSA table. Tags with fewer than three numeric parts are `info` (moving). `quay.io` as a generic registry prefix for other images is not this check.

## Finding to check-result rollup

Same as every other host check: see [host-checks.md](../references/host-checks.md) (FAIL / BLOCKED / PASS / NOT_APPLICABLE). `review` rolls up to FAIL.

## Limits

- Ubuntu without a USN may later backport under an older upstream minor; until then a package below the vendor minor FAILs.
- Homebrew unversioned formula `postgresql` still uses the Cellar version directory name.
- Image tags `latest` / `16` / `3.18` cannot prove a floor.
- PGDG extension rebuild after a server bump is not a second check.
- Quay 3.11 / 3.13 / 5.x PASS only as `review` (FAIL at check status). Humans must check Red Hat for those trains.
- `/keys` restriction is mitigation, never `vendor_patch`.

## Closing a finding under this profile

Use `verification_basis: vendor_patch` only with the PostgreSQL CVE page / news 3442 or the matching RHSA retrieved this run **and** on-disk metadata at or above the matching floor. `/keys` restriction and `pg_hba` changes are mitigation, never `fixed`.

## What needs a human

Rebuilding PostgreSQL extensions after a PGDG bump; confirming Ubuntu once a USN exists; deciding `/keys` restriction vs RHSA upgrade; approving `NOT_APPLICABLE`.

## Skipped (see `SKIPPED` in `host_checks.py`)

- FBI FLASH-20261113-001 ARTEX — IPs / C2 host / tool names; no host-file hashes; helper has no network.
- Copeland XWEB EVO CVE-2026-124010 / CVE-2026-124014 — EOL refrigeration appliance; no laptop/server artifact.
- 16 Nov 2026 breach-only incidents (Barracuda cloud key, Uber/Fireworks, Expedia, Maileva, Osaka, CSCTelecom, Lithuania customs, ActiveCloud, Arcus, Caribbean Airlines) — org/SaaS; no host artifact.
- CERT-In Crafty Falcon / ARTEX (as a CERT-In campaign) — already skipped; still no local artifact.
- Other PostgreSQL CVEs closed in news 3442 — separate bugs; the same upgrade may cover them; not this check.
- Quay.io SaaS — not an endpoint image tag.
