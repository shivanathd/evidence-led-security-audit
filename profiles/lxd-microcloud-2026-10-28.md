# Optional profile: Canonical LXD / MicroCloud CVE-2026-112816 (2026-10-28)

Last checked: 2026-11-02. This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date.

`host_checks.py` check id: `lxd-112816`. Read-only metadata only. Never start `lxc`, `lxd`, `microcloud`, `incus` or `snap`, never open the HTTPS API, and never parse the LXD database.

## Primary sources

- Canonical Discourse 90557 (markylaing, 2026-10-28): [security advisory](https://discourse.ubuntu.com/t/security-advisory-critical-vulnerability-found-in-canonical-lxd-and-microcloud/90557)
- GitHub Advisory Database GHSA-pq55-m3w3-jh54 (published 2026-10-30, unreviewed): [GHSA-pq55-m3w3-jh54](https://github.com/advisories/GHSA-pq55-m3w3-jh54)
- Ubuntu Security: [CVE-2026-112816](https://ubuntu.com/security/CVE-2026-112816) (page last updated 30 Oct 2026)
- Related Incus advisory GHSA-xg75-xf37-cph9 (published 2026-10-29): [GHSA-xg75](https://github.com/lxc/incus/security/advisories/GHSA-xg75-xf37-cph9)

Pointer (not a floor): [The Hacker News, 1 Nov 2026](https://thehackernews.com/2026/11/critical-lxd-and-microcloud-flaw-cvss.html).

The Canonical LXD repo advisory GHSA-99jp-jwmc-65p4 did not load this run. Floors do not depend on it.

## What was disclosed (as of the date above)

Mutual-TLS authentication compared every peer certificate to the trust store; only the leaf proves the key. An attacker who can reach the HTTPS API and who has a trusted client's public certificate can authenticate as that client. In MicroCloud, intercepting a joining member's public certificate can authenticate as that member. Privilege of the impersonated identity can mean host root.

CVSS 4.0 10.0 from the CNA (Canonical) via GHSA-pq55-m3w3-jh54, which GitHub lists as unreviewed.

Third-party lab proof-of-concept code was public by 1 Nov 2026 (not vendor-confirmed; this skill does not link exploit repositories). Not on CISA KEV as of 2 Nov 2026.

## Fixed snap versions (Discourse 90557, released 2026-10-29)

| Product | Channel | Floor |
| --- | --- | --- |
| LXD | 6/stable | 6.10.1 |
| LXD | 5.21/stable | 5.21.9 |
| LXD | 5.0/stable | 5.0.11 |
| LXD | 4.0/stable | 4.0.15 |
| MicroCloud | 3/stable | 3.4.1 |
| MicroCloud | 2/stable | 2.1.5 |

Incus GHSA-xg75 names only the Go module `github.com/lxc/incus/v7/cmd/incusd`, affected `< v7.6.0`. Incus findings cite that GHSA, not CVE-2026-112816. Incus 6.0 LTS and other lines are review.

Point releases were in progressive rollout from `candidate` to `stable` at advisory time; confirm the installed version after refresh.

## Evidence this check reads

- Linux snaps `lxd` and `microcloud`: the active revision is the basename of `/snap/<name>/current` when that path is a symlink whose target has a readable `meta/snap.yaml`. The link text is read; the link is never opened as a file. Other `x?digit` revisions on disk are recorded as inactive retained copies. `/snap/incus` is not read.
- When `current` is missing, is not a symlink, or points at a revision with no readable yaml, every matching revision is classified and the detail says the active revision was not read.
- Linux packages `lxd` and `microcloud` from dpkg/apk/pacman/rpm: always `review` (Canonical ships the fix in the snap). Ubuntu archive `lxd` is not treated as "Not affected" from `VERSION_ID`.
- Linux package `incus`, or `incus-base` only when `incus` is absent. `incus-client` alone is not this check.
- Presence without version, only when no snap revision and no package was found: `/var/snap/lxd/common/lxd`, `/var/snap/microcloud/common`, `/var/lib/incus` as a plain directory (`unknown`). `/var/lib/lxd` is ignored (deb-era leftover).

Homebrew and Chocolatey `incus`/`lxc` are clients and are not classified. Container image references are not classified for this check. `core.https_address` in text files is not a finding.

## Finding to check-result rollup (`run_check`)

| Findings / blockers | Check result |
| --- | --- |
| at least one `affected` or `review` | `FAIL` |
| at least one `unknown` (and no `affected`/`review`) | `BLOCKED` |
| only `info` | `PASS` |
| nothing found | `NOT_APPLICABLE` |

- Named LXD trains: major 6 vs 6.10.1; 5.21.* vs 5.21.9; 5.0.* vs 5.0.11; 4.0.* vs 4.0.15. A prerelease of a floor is not fixed. A git-hash suffix (`5.21.9-1a2b3c4`) is build metadata, not a prerelease.
- Other LXD or MicroCloud lines, and an unparsable `version:` line, are `review`.
- Missing or unreadable `snap.yaml`, or one with no `version:` line, is `unknown`.

## HTTPS / default socket

Standalone LXD listens on a local socket by default. MicroCloud clustering uses the network API. Restricting the listener is mitigation, not a vendor fix. This check never claims "not exposed" from silence.

## Closing a finding under this profile

Use `verification_basis: vendor_patch` only with the Discourse advisory or the CVE/GHSA record retrieved this run **and** on-disk metadata at or above the matching floor. Socket-only exposure is mitigation, not a fix.

## What needs a human

Confirming a distro backport against the distro tracker; confirming Incus 6.0 LTS notes; approving `NOT_APPLICABLE`; deciding whether a retained inactive snap revision should be removed.
