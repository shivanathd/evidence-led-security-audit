# Optional profile: host advisories 2026-11-20 (OpenSSL, GPUStack, VMware Tools, ASUS ACCE)

Last checked: 2026-11-20. This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date.

`host_checks.py` check ids: `openssl-121481`, `gpustack-102895`, `vmware-tools-123894`, `asus-acce-114202`. Read-only metadata only. Never start `openssl`, GPUStack, VMware Tools or ASUS Control Center Express, never HTTP, and never copy PoC, proxy-header values or hard-coded keys.

Already on main (do not re-implement): `php-129289` (GHSA-qc49 / CVE-2026-129289 floors, same train as GHSA-gr4f-wgx5-jpfv), `vcenter-log4shell` (KB 87081; not VMSA-2026-0009 vCenter).

## Terms

- **OpenSSL CNA floors**: **4.0.4** and **4.1.1** from the CVE-2026-121481 CNA version ranges (4.0.0 to before 4.0.4; 4.1.0 to before 4.1.1). OpenSSL 3.x and older are not this CVE. LibreSSL and BoringSSL are not this CVE. Distro packages may backport a fix under an older version string.
- **GPUStack floor**: **2.2.0** from GHSA-gj9m-f8ph-pmhr `first_patched_version`. `force_auth_localhost` is mitigation, not 2.2.0.
- **VMware Tools floors**: Windows only, **13.1.5** and **12.5.5** from VMSA-2026-0009 / CVE-2026-123894. **12.4.10** is the named 32-bit floor published with 12.5.5 and applies only when the install is confirmed 32-bit. 64-bit and unknown-arch 12.4.x need 12.5.5. 11.x has no 11-line fix (upgrade to 12.5.5). Linux `open-vm-tools` is not this CVE.
- **ASUS Control Center Express floor**: **1.7.29** from the vendor bulletin quoted 20 Nov 2026. CNA CVE-2026-114202 lists through v1.7.27; 1.7.28 is treated as below 1.7.29. ASUS Control Center without Express is a different product.

## Primary sources

- GHSA-83xj-7xh4-4p7x: [advisory](https://github.com/advisories/GHSA-83xj-7xh4-4p7x)
- CVE-2026-121481: [cve.org](https://www.cve.org/CVERecord?id=CVE-2026-121481)
- OpenSSL PR 33652: [pull request](https://github.com/openssl/openssl/pull/33652)
- GHSA-gj9m-f8ph-pmhr: [advisory](https://github.com/advisories/GHSA-gj9m-f8ph-pmhr)
- CVE-2026-102895: [cve.org](https://www.cve.org/CVERecord?id=CVE-2026-102895)
- SANS ISC GPUStack diary: [exploit attempts](https://isc.sans.edu/diary/Exploit+Attempts+for+GPUStack+Authentication+Bypass+CVE2026102895/33514/)
- GHSA-gr4f-wgx5-jpfv: [advisory](https://github.com/php/php-src/security/advisories/GHSA-gr4f-wgx5-jpfv)
- Broadcom VMSA-2026-0009: [advisory](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/39495)
- CVE-2026-123894: [cve.org](https://www.cve.org/CVERecord?id=CVE-2026-123894)
- CVE-2026-114202: [cve.org](https://www.cve.org/CVERecord?id=CVE-2026-114202)
- ASUS security advisory: [ASUS](https://www.asus.com/security-advisory/)
- BleepingComputer: [ASUS Control Center Express](https://www.bleepingcomputer.com/news/security/asus-warns-of-critical-hard-coded-key-flaw-in-control-center-express/)
- CISA ICS advisories: [index](https://www.cisa.gov/news-events/ics-advisories)

## What was disclosed (as of the date above)

**OpenSSL CVE-2026-121481.** `EVP_EncodeBlock()` output-size overflow (heap write past buffer). CNA affected 4.0.0 to before 4.0.4 and 4.1.0 to before 4.1.1. 3.x is not in the CNA range. Never run `openssl version`.

**GPUStack CVE-2026-102895.** Spoofed proxy-header authentication bypass before **2.2.0**. SANS ISC reported exploit attempts. Do not treat a localhost-auth setting as the vendor patch. Never HTTP-probe the API.

**PHP GHSA-gr4f-wgx5-jpfv.** Timezone cache use-after-free on the same 19 Nov 2026 PHP release train as `php-129289` (8.5.13 / 8.4.28 / 8.3.37 / 8.2.36). Not a second check.

**VMSA-2026-0009.** vCenter authentication-bypass (CVE-2026-123890) and SDDC Manager issues are appliances. Windows VMware Tools is CVE-2026-123894 with the floors above. Linux `open-vm-tools` is not that Windows CVE.

**ASUS Control Center Express CVE-2026-114202.** Critical flaws including a hard-coded key. Fixed in **v1.7.29**. Windows-only. This helper does not store key material.

**CISA ICSA-26-323-01..03.** OpenPLC Runtime, Elecbrakes firmware, libumqtt. OT / embedded; not host-checkable here.

**Breach-only.** JPMorgan/Visa/Mastercard third-party vendor, Rakuten Securities test-environment leak, Prime Intellect DeepSeek v4.1 Flash model swap (8-10 Nov), SBC Medical, BundID, Equinor, KPMG Canada. No host package or version floor.

## Fixed versions

| Surface | Floor | Source |
| --- | --- | --- |
| OpenSSL 4.0 | 4.0.4 | CVE-2026-121481 CNA `lessThan` |
| OpenSSL 4.1 | 4.1.1 | CVE-2026-121481 CNA `lessThan` |
| GPUStack | 2.2.0 | GHSA-gj9m-f8ph-pmhr `first_patched_version` |
| VMware Tools 13.x (Windows) | 13.1.5 | VMSA-2026-0009 / CVE-2026-123894 |
| VMware Tools 12.5.x (Windows) | 12.5.5 | VMSA-2026-0009 / CVE-2026-123894 |
| VMware Tools 12.4.x 32-bit (Windows) | 12.4.10 | VMSA-2026-0009 FAQ |
| ASUS Control Center Express | 1.7.29 | ASUS bulletin (quoted 20 Nov 2026) |
| PHP 8.5 / 8.4 / 8.3 / 8.2 (GHSA-gr4f) | 8.5.13 / 8.4.28 / 8.3.37 / 8.2.36 | already `php-129289` |

## What this helper checks

- `openssl-121481`: linux packages `openssl` / `libssl*` / `libcrypto*` / `openssl-libs` (skip `*-dev` / `*-doc`); Homebrew `openssl` / `openssl@N`; `opensslv.h`; ASCII `OpenSSL X.Y.Z` in binary bytes (including `-dev`); Windows PE / uninstall registry; FROM/`image:` tags whose last path component is `openssl`. 3.x and LibreSSL/BoringSSL are `info`. Digest-pinned and moving tags are `unknown`.
- `gpustack-102895`: `py_installs` / `py_pin_hits` / `docker_decl_refs`. Exact `==` / `===` pins classify. Unpinned specs are `review`, including Dockerfile `RUN pip install` lines. FROM / `image:` operands are not pip pins. Digest-pinned and moving tags are `unknown`.
- `vmware-tools-123894`: Windows uninstall registry `VMware Tools` and Program Files `vmtoolsd.exe` PE version. 12.4.10 is `info` only for confirmed 32-bit installs. Linux `open-vm-tools` is not this check.
- `asus-acce-114202`: Windows uninstall registry and Program Files tree matching Control Center Express. DisplayNames without Express are not this check. PE versions come from ACCE-named executables only.

## Out of scope (not a host check)

- vCenter CVE-2026-123890 and SDDC Manager CVE-2026-123891 / 123892 / 123893 (appliances).
- CISA ICSA-26-323-01 OpenPLC Runtime, ICSA-26-323-02 Elecbrakes, ICSA-26-323-03 libumqtt.
- Named 20 Nov 2026 breach-only incidents.
- Starting openssl, GPUStack, VMware Tools or ACCE; HTTP to GPUStack; storing a hard-coded key or proxy-header value.
