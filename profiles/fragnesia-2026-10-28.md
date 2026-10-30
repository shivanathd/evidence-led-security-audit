# Optional profile: Linux Fragnesia CVE-2026-46300 (2026-10-28)

Last checked: 2026-10-30. Dated snapshot. Re-read the primary sources on every run. If a source has changed, the source wins.

`host_checks.py` check id: `fragnesia-linux`. Linux only. Classification uses the running `/proc/sys/kernel/osrelease` together with `/etc/os-release` (or `/usr/lib/os-release` when `/etc/os-release` is a symlink). Ubuntu rows are selected by `VERSION_ID` and kernel major.minor. Package versions are notes. This tool never loads or unloads modules, never writes sysctl, and never exercises ESP-in-TCP.

## Primary sources

- CVE Record CVE-2026-46300 (kernel CNA; record updated 2026-10-29): [cve.org](https://www.cve.org/CVERecord?id=CVE-2026-46300). Floors from the CVE record (re-read 2026-10-30). The CNA revised the description and commit list after the 23 May announce; the fixed versions did not change. Quote the record, not the announce, for what the fix does. Title now: "net: skbuff: preserve shared-frag marker during coalescing" (`skb_try_coalesce`).
- CISA KEV (added 2026-10-28, due 2026-10-31): [KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and the [28 Oct 2026 alert](https://www.cisa.gov/news-events/alerts/2026/10/28/cisa-adds-two-known-exploited-vulnerabilities-catalog). Notes describe a chain with CVE-2026-109618 and CVE-2026-109619. KEV names no version floor.
- Ubuntu Security CVE-2026-46300 (last updated 29 Oct 2026): [ubuntu.com](https://ubuntu.com/security/CVE-2026-46300)
- linux-cve-announce 23 May 2026 (upstream history; first announce; description since revised): [lists.openwall.net](https://lists.openwall.net/linux-cve-announce/2026/05/23/1)
- NVD page cited by KEV: [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2026-46300)

Do not use press "kernels released before 13 May 2026" as a version rule. Do not encode third-party Debian/RHEL tables.

## Floors (retrieved 2026-10-30)

CVE record: introduced in 3.9; fixed in 5.10.257, 5.15.208, 6.1.174, 6.6.141, 6.12.91, 6.18.33, 7.0.10; 7.1 and later unaffected.

Ubuntu official `x.y.0-N-generic` osrelease only (`N` is 1–9999, no leading zero), keyed on `(VERSION_ID, major.minor)` (HWE kernels report a plain `-generic` string). When `/proc/version` has `#NNN-Ubuntu`, the check also compares the upload number. Mainline-PPA and other strings are `review`.

| Release | Series | Fixed ABI | Page row |
| --- | --- | --- | --- |
| 26.04 | 7.0 | 22 | linux 7.0.0-22.22 |
| 25.10 | 6.17 | 35 | linux 6.17.0-35.35 |
| 24.04 | 6.8 | 124 | linux 6.8.0-124.124 |
| 24.04 | 6.17 | 35 | linux-hwe-6.17 6.17.0-35.35~24.04.1 |
| 22.04 | 5.15 | 181 | linux 5.15.0-181.191 |
| 22.04 | 6.8 | 124 | linux-hwe-6.8 6.8.0-124.124~22.04.1 |
| 20.04 | 5.15 | 181 | linux-hwe-5.15 5.15.0-181.191~20.04.1 (Ubuntu Pro) |

Any other `(release, series)` pair, including 26.10 and 20.04 on 5.4, is `review`. Never emit info "Not affected" from `VERSION_ID` alone. Cloud/FIPS/aws strings and mainline-PPA kernels that are not official `x.y.0-N-generic` are `review`. Missing `VERSION_ID` is `review`. An unreadable running osrelease when other kernel metadata is present is `unknown`. Non-Ubuntu: upstream floors only when osrelease matches `^\d+\.\d+\.\d+$`.

## PHP2Shell chain

CISA KEV describes a chain with CVE-2026-109618 and CVE-2026-109619. Also run `php2shell` on the same host. The two checks stay separate: a Fragnesia PASS does not clear PHP, and the reverse is also false.

## What this skill will not invent

No "before 13 May 2026" cutoff. No whole Ubuntu flavor matrix. No claim that a newer installed `linux-image` package has fixed the host (that is a reboot note). No kernel-tree commit URLs.

## How a finding closes

Closing needs the CVE record or the Ubuntu page retrieved this run, plus evidence the **running** kernel is a listed fixed build.

## What needs a human

Matching a non-generic Ubuntu flavor to the Ubuntu page; confirming a vendor backport on Debian/RHEL/Arch; running `php2shell` for the KEV chain.
