# Optional profile: Oracle PeopleSoft PeopleTools of 2026-10-28

Last checked: 2026-10-28. This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date.

The durable check class is **known-bad or hijacked package versions** / a vendor-alert footprint in [references/scoped-checks.md](../references/scoped-checks.md). This file is a dated starting point for Oracle Security Alert CVE-2026-35273. `scripts/host_checks.py` check id: `peoplesoft-presence`. Inventory key: `peoplesoft_hints`.

## Primary sources

- Oracle Security Alert: [CVE-2026-35273](https://www.oracle.com/security-alerts/alert-cve-2026-35273.html) (PeopleSoft Enterprise PeopleTools 8.61 and 8.62)
- CVE record: [CVE-2026-35273](https://www.cve.org/CVERecord?id=CVE-2026-35273) when it is populated; this run treated the Oracle alert as the primary
- For a specific PeopleTools patch: that customer's Oracle Patch Availability Document for PeopleSoft. This run did not retrieve a public patch-number table beyond the alert.

News coverage of ShinyHunters can point you to the Oracle alert. It is not a primary source for CVE count, CVSS or affected versions.

## What was disclosed (as of the date above)

From the Oracle alert:

- One CVE: **CVE-2026-35273**. Product: PeopleSoft Enterprise PeopleTools. Component: Updates Environment Management. Protocol: HTTP. Remotely exploitable without authentication. CVSS 3.1 base score **9.8**. Supported versions affected: **8.61, 8.62**.
- Impact if exploited: remote code execution.
- The alert's first revision is dated **2026-06-10**. The October 2026 public reporting is about later use of this issue, not a new Oracle CVE.
- Oracle does **not** describe a "three-flaw chain" and does not publish three CVE identifiers. Public reporting that names PSIGW SSRF, loopback `allowedhosts` and PSEMHUB RCE is a secondary write-up of the same alert. Record that wording as **unverified** unless Oracle later says it.

## How this maps to the skill

This is a **runtime** (and, when code is on disk, **image**) presence check. A PeopleTools version string is not proof of a patch: Oracle security alerts for PeopleSoft are often applied as patches that keep the same PeopleTools number.

- `review` when a PeopleSoft / PeopleTools path, package, image, `psadmin` binary or config file (`psconfig.sh`, `psappsrv.cfg`, `allowedhosts.properties` under a PeopleSoft path) is present
- `NOT_APPLICABLE` when inventory and the host walk found none of those, with that empty result as evidence
- Never probe a PIA URL, never authenticate, never send a request to PSIGW or PSEMHUB

Targets to list in scope, linked with `related_targets`:

- each host or image that may run PeopleTools (`runtime` / `image`)
- the repository or config export that holds `allowedhosts.properties` or `psconfig.sh` (`repository`)

## Closing a finding under this profile

Use `verification_basis: vendor_patch` only with the Oracle Patch Availability Document for the installed PeopleTools line, plus evidence that the patch is present on the running PIA / app server. A directory named `pt8.62` is not that evidence.

`mitigated` only for owner-applied network restrictions recorded on the target (not applied by this skill).

## Report wording

- Check title: `Oracle PeopleSoft / PeopleTools footprint (CVE-2026-35273)`.
- Finding summary: name the path class (tools tree, config file, image tag) without dumping file contents. Use placeholders such as `/opt/oracle/psft` and `example-host`.
- Absence: `NOT_APPLICABLE` with the inventory / walk evidence, never "clean".
- Verdict: unchanged.

## What needs a human

Deciding whether a found tree is a live PIA, applying the Oracle alert patches, and approving `NOT_APPLICABLE`.
