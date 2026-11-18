# Optional profile: host advisories 2026-11-18 (catch-up)

Last checked: 2026-11-18. This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date.

`host_checks.py` check ids: `artex-gateway-keys`, `vcenter-log4shell`, `axis-90436`, `ncentral-hf3`, `blank-canvas-vsx`, `apple-65339`, `agent-framework-1-26`, `java4shell-114938`, `puppet-115731`, `roller-129448`, `mysql-114952`. Read-only metadata only. Never start `java`, `mysql`, `mysqld`, `vpxd`, `puppet`, N-central, Axis, Confluence, LiteLLM, Dify or One API, never HTTP, and never copy secret values.

Already on main (do not re-implement): `claude-code-vsx-21313` (2.1.312 and 2.1.313), `unrealircd-114713`, `postgresql-6460`, `quay-123710` (CVE-2026-110697 shares those RHSA floors).

## Terms

- **indicator check**: PASS when nothing matching is found; FAIL when a named IOC or credential-field name is present.
- **HF3**: N-central 2026.4 Hotfix 3, build `2026.4.1.39`. HF2 `2026.4.1.26` is not that floor.
- **web.xml mitigation**: Roller CSRF/filter edits. Not a vendor patch for 6.1.6.
- **Remote API off**: Confluence "Remote API (XML-RPC & SOAP)" cleared. Mitigation, not 9.2.28.

## Primary sources

- AWS Security Blog (ARTEX / AI gateways): [aws.amazon.com/blogs/security](https://aws.amazon.com/blogs/security/)
- The Hacker News (ARTEX / ConnectWise): cited as `thn-connectwise`
- Microsoft RemovedPackages (11/03/2026 Malware rows): [RemovedPackages.md](https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md)
- Aikido (retrieved 2026-11-18): [two malicious agent-framework releases](https://www.aikido.dev/blog/two-malicious-agent-framework-releases-hit-pypi-in-33-minutes)
- GHSA-764m-3ppc-5m73: [advisory](https://github.com/advisories/GHSA-764m-3ppc-5m73)
- SafeDep: [agent-framework PyPI compromise](https://safedep.io/blog/microsoft-agent-framework-pypi-compromise)
- Apple HT148281 (Tahoe 26.6.2): [148281](https://support.apple.com/en-us/148281)
- Apple HT149043 (Sequoia 15.8): [149043](https://support.apple.com/en-us/149043)
- CVE-2026-65339: [cve.org](https://www.cve.org/CVERecord?id=CVE-2026-65339)
- OpenJDK 17 Nov 2026: [advisory](https://openjdk.org/groups/vulnerability/advisories/2026-11-17)
- CVE-2026-114938: [cve.org](https://www.cve.org/CVERecord?id=CVE-2026-114938)
- Oracle CSPU November 2026: [cspunov2026](https://www.oracle.com/security-alerts/cspunov2026.html)
- CVE-2026-114952: [cve.org](https://www.cve.org/CVERecord?id=CVE-2026-114952)
- oss-security Axis (6 Nov 2026): [2026/11/06/12](https://www.openwall.com/lists/oss-security/2026/11/06/12)
- Atlassian Confluence DC: [CVE-2026-90436](https://confluence.atlassian.com/security/cve-2026-90436-remote-code-execution-in-confluence-data-center-1874560038.html)
- N-able HF3 (16 Nov 2026): [2026.4.1.39](https://status.n-able.com/2026/11/16/n-central-2026-4-hf3-release-notes/)
- Broadcom KB 87081: [vCenter Log4j](https://knowledge.broadcom.com/external/article/87081)
- CISA KEV 17 Nov 2026: [CVE-2026-115731](https://www.cisa.gov/news-events/alerts/2026/11/17/cisa-adds-one-known-exploited-vulnerability-catalog)
- Puppet what's new: [PE 2026.0.1 / 2025.12.1 / 2023.8.13](https://www.puppet.com/products/puppet-enterprise/whats-new)
- Apache Roller security: [6.1.6 / CVE-2026-82384](https://roller.apache.org/security.html)
- Google Cloud (COLD RELIC, SaaS only): [threat-intelligence](https://cloud.google.com/blog/topics/threat-intelligence/)

## What was disclosed (as of the date above)

**ARTEX gateway keys.** Activity stole provider keys from LiteLLM, Dify and One API deployments. No host-file hashes. This helper reads named local config files and records credential **field names** only.

**vCenter Log4Shell.** Broadcom KB 87081 floors: 7.0 U3c build 19234570, 6.7 U3q 19300125, 6.5 U3s 19261680. 8.x is outside those trains. Workaround files are not a vendor patch.

**Apache Axis CVE-2026-90436.** Axis 1.x through 1.4 is EOL; Apache will not ship a 1.x fix. Confluence Data Center 1.x–9.x floor **9.2.28** when Remote API is in play; 10.x removed the feature. Axis 2 jars are not Axis 1.x.

**N-central HF3.** On-prem floor **2026.4.1.39**. HF2 **2026.4.1.26** is still below that floor. Hosted NCOD is upgraded by N-able.

**Blank Canvas VSX.** Microsoft RemovedPackages **11/03/2026** Malware rows (131 ids, including TiroAppTeam and JonnyClyde). Later dates and docsflowy are not this check.

**Apple CVE-2026-65339 (audiomxd).** HT148281 Tahoe **26.6.2**; HT149043 Sequoia **15.8**. macOS 14 is review. iOS / iPadOS need MDM.

**agent-framework 1.26.1 / 1.26.2.** Malicious PyPI releases (removed). Last clean 1.26.0. IOC filenames and SHA-256 from Aikido/GHSA. Sibling unpinned pins are a lead. The exfil URL is not stored here.

**Java4Shell CVE-2026-114938.** OpenJDK 17.0.6 through before **v17.0.21.1**, and matching 21/25/27 trains below **v21.0.13.1** / **v25.0.5.1** / **v27.0.1.1**. 8/11 are not this CVE except **8u511-perf** until **8u513-perf**. Four-part floors are assembled at runtime.

**Puppet CVE-2026-115731 (CISA KEV 17 Nov 2026).** PE **2023.8.13** / **2025.12.1** / **2026.0.1**. Core **9.1.3** and **8.22.2**. Marketing 8.22.1 is review.

**Apache Roller CVE-2026-82384** (also listed as CVE-2026-129448). Floor **6.1.6**; 6.1.5 is still affected. 6.1.7 is a later set of other CVEs, not this check. web.xml edits are mitigation.

**MySQL CVE-2026-114952.** Oracle November 2026 CSPU: Server **8.4.0–8.4.13**, **9.7.0–9.7.4**, **26.10**; Cluster also **8.0.0–8.0.50**. MariaDB is not this check. Generic 8.0 server is review.

**Cold Relic.** Google Workspace Super Admin takeover is a tenant/admin-console event. See [saas-identity.md](../references/saas-identity.md).

## Fixed versions

| Surface | Floor | Source |
| --- | --- | --- |
| vCenter 7.0 | U3c build 19234570 | Broadcom KB 87081 |
| vCenter 6.7 | U3q build 19300125 | Broadcom KB 87081 |
| vCenter 6.5 | U3s build 19261680 | Broadcom KB 87081 |
| Confluence DC 9.x | 9.2.28 | Atlassian CVE-2026-90436 |
| N-central 2026.4 | 2026.4.1.39 (HF3) | N-able HF3 notes |
| macOS Tahoe 26 | 26.6.2 | HT148281 |
| macOS Sequoia 15 | 15.8 | HT149043 |
| OpenJDK 17 | v17.0.21.1 | OpenJDK 17 Nov 2026 / CERT-EU |
| OpenJDK 21 | v21.0.13.1 | OpenJDK 17 Nov 2026 / CERT-EU |
| OpenJDK 25 | v25.0.5.1 | OpenJDK 17 Nov 2026 / CERT-EU |
| OpenJDK 27 | v27.0.1.1 | OpenJDK 17 Nov 2026 / CERT-EU |
| Java 8 perf | 8u513-perf | CERT-EU (8u511-perf only) |
| Puppet Enterprise | 2023.8.13 / 2025.12.1 / 2026.0.1 | Puppet what's new / CISA KEV |
| Puppet Core | 9.1.3 / 8.22.2 | SecurityWeek / NVD (8.22.1 is review) |
| Apache Roller | 6.1.6 | roller.apache.org/security.html |
| MySQL Server 8.4 | outside 8.4.0–8.4.13 | Oracle CSPU Nov 2026 |
| MySQL Server 9.7 | outside 9.7.0–9.7.4 | Oracle CSPU Nov 2026 |
| agent-framework | not 1.26.1 or 1.26.2 (pin 1.26.0) | Aikido / GHSA |

## Evidence these checks read

- `artex-gateway-keys`: `~/.litellm`, `~/litellm_config.yaml`, `/etc/litellm`, `~/.dify`, `/opt/dify`, `/opt/one-api`, `/opt/new-api` and sibling `.env` / `config.yaml`. Field names matching key/secret/token/password. Docker last-path `litellm` / `dify` / `dify-api` / `one-api` / `new-api` is `review`. Values are never copied.
- `vcenter-log4shell`: packages `vmware-vpx` / `vmware-vcenter` / `vcenter-server`; `/etc/vmware-vpx/buildNumber`; `/usr/lib/vmware-vpx`; Windows `Program Files/VMware/vCenter Server`. Never `vpxd`.
- `axis-90436`: home-walk `axis*.jar` excluding `axis2*`; Confluence `confluence-N.N.N.jar` under `/opt/atlassian/confluence`; image `confluence` / `confluence-server`.
- `ncentral-hf3`: packages `n-central` / `ncentral` / `nable-ncentral`; `/opt/n-able/n-central` version files; Windows `Program Files/N-able/N-central`.
- `blank-canvas-vsx`: the same editor extension directories as `claude-code-vsx-21313`. Folder `publisher.name` vs the 131 Malware ids.
- `apple-65339`: darwin `ProductVersion` only.
- `agent-framework-1-26`: `py_installs` / `py_pin_hits` for `agent_framework` and five siblings; SHA-256 of named `.pth` / `.py` files in site-packages.
- `java4shell-114938`: `JAVA_VERSION` in JVM `release` files, linux `openjdk-*` / `java-N-openjdk*` packages, Homebrew `openjdk`, images `openjdk` / `eclipse-temurin` / `amazoncorretto`. Never `java`.
- `puppet-115731`: packages `puppet-agent` / `puppet` / `puppetserver` / `pe-puppetserver`; `/opt/puppetlabs/puppet/VERSION`; `/opt/puppetlabs/server/pe_version`.
- `roller-129448`: `*.properties` under a `roller` path (`ro.version=`); image `roller`.
- `mysql-114952`: linux `mysql-server*` (not client, not MariaDB); Homebrew `mysql`; Windows `mysql_version.h`; image last-path `mysql`.

## Finding to check-result rollup

Same as every other host check: see [host-checks.md](../references/host-checks.md) (FAIL / BLOCKED / PASS / NOT_APPLICABLE). `review` rolls up to FAIL. Indicator checks PASS when nothing matching is found.

## Limits

- ARTEX C2 hosts and IPs are not evaluated (no network).
- Axis 1.x has no 1.x vendor release; presence is `review`.
- Remote API off, web.xml edits, `/keys` restriction and HF2 are mitigation, never `vendor_patch`.
- Puppet Core 8.22.1 is review (what's-new vs 8.22.2 in NVD/press).
- MySQL 26.10.1+ has no named CSPU floor (`review`). Generic 8.0 server is not the Cluster 8.0.0–8.0.50 row.
- Java 17 before 17.0.6 is outside the named Java4Shell range (`info`). AVX-512 VBMI and `-XX:UseAVX=2` are not read (would need to start `java`).
- iOS / iPadOS / tvOS / watchOS / visionOS for CVE-2026-65339 need MDM.

## Closing a finding under this profile

Use `verification_basis: vendor_patch` only with the matching primary page retrieved this run **and** on-disk metadata at or above the matching floor for the active install. A patched checkout or Dockerfile tag is not enough for an image-based target: record the deployed image digest. Do not invent image fields for non-image installs. Remote API off, web.xml, HF2 and JVM flags are mitigation, never `fixed`.

## What needs a human

Rotating provider keys after ARTEX; confirming vCenter train vs build; deciding Remote API off vs 9.2.28; upgrading on-prem N-central and Agents/Probes; uninstalling Blank Canvas extensions; pinning `agent-framework==1.26.0` and rotating reachable secrets; restarting JVMs and `puppetserver` after a package bump; approving `NOT_APPLICABLE`.

## Skipped (see `SKIPPED` in `host_checks.py`)

- Google Workspace Super Admin takeover (Cold Relic) — SaaS tenant.
- Claude Code VSX 2.1.312 as a separate floor — already `claude-code-vsx-21313`.
- Red Hat Quay CVE-2026-110697 as a second check — same RHSA set as `quay-123710`.
- Axis / Confluence HTTP probe; N-central hosted NCOD; iOS for CVE-2026-65339; agent-framework C2 URL.
- 16–18 Nov 2026 breach-only incidents (Coles, Optimizely CDN, Infoblox, Fandango, South Portland, Deutsche Bank, StubHub, Fugaku, Irish credit unions, IIHF, Telegram Android, CISA ICS advisories, TPM lockout reset, bunny net CDN).
- Apache Roller 6.1.7 CVEs — separate bugs; not this check.
