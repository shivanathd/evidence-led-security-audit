# Optional profile: host advisories 2026-11-24

Last checked: 2026-11-24 (evening watch). This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date.

`host_checks.py` check ids: `binary-parser-134814`, `leadstack-crm-connect`, `monailabel-133968`, `gpgme-129975`, `ghostscript-125396`, `idunno-anticsrf-131914`, `whmcs-82981`. Read-only metadata and leftover-file names/hashes only. Never start node, monailabel, gpgme-tool, gpg, gs, IIS, PHP or ionCube, and never load `Idunno.AntiCsrf.dll`. Never open WHMCS `configuration.php` (secrets). Never contact npm, PyPI or a C2 host. Never store leadstack network IOCs.

Already on main (do not re-implement): dated 22 Nov `bitwarden-cli-42994`; Mail Assure / SpamExperts hosted skip; ICSA-26-323-02 Elecbrakes skip; VMSA-2026-0009 vCenter CVE-2026-123890 appliance skip.

## Primary sources

- binary-parser: [GHSA-xmxc-6c22-m377](https://github.com/keichi/binary-parser/security/advisories/GHSA-xmxc-6c22-m377), [NVD CVE-2026-134814](https://nvd.nist.gov/vuln/detail/CVE-2026-134814)
- @leadstack/crm-connect: [SafeDep](https://safedep.io/blog/malicious-npm-leadstack-crm-connect-hermes-agent-backdoor), [GHSA-hqfp-fhqg-4xc5](https://github.com/advisories/GHSA-hqfp-fhqg-4xc5)
- MONAI Label: [GHSA-qc22-rmgc-vg94](https://github.com/Project-MONAI/MONAILabel/security/advisories/GHSA-qc22-rmgc-vg94), [0.8.6 release](https://github.com/Project-MONAI/MONAILabel/releases/tag/0.8.6), [NVD CVE-2026-133968](https://nvd.nist.gov/vuln/detail/CVE-2026-133968)
- GPGME: [gnupg-announce 000517](https://lists.gnupg.org/pipermail/gnupg-announce/2026q4/000517.html), [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-129975), [NVD CVE-2026-129975](https://nvd.nist.gov/vuln/detail/CVE-2026-129975)
- Ghostscript: [oss-security 2026/11/21/2](https://www.openwall.com/lists/oss-security/2026/11/21/2), [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-125396), [NVD CVE-2026-125396](https://nvd.nist.gov/vuln/detail/CVE-2026-125396)
- Idunno.AntiCsrf: [MNDT-2026-0048](https://github.com/mandiant/Vulnerability-Disclosures/blob/master/2026/MNDT-2026-0048.md), [NVD CVE-2026-131914](https://nvd.nist.gov/vuln/detail/CVE-2026-131914)
- WHMCS CVE-2026-82981: [vendor advisory](https://help.whmcs.com/m/125386/l/2151347-cve-2026-82981-whmcs-security-update-2026-11-23), [Security Update 2026-11-23](https://blog.whmcs.com/133803/security-update-2026-11-23), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-82981)
- VMSA-2026-0011 (skip): [Broadcom advisory 39626](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/39626)

## Fixed versions / floors

| Surface | Floor / rule | Source |
| --- | --- | --- |
| npm `binary-parser` | 2.3.1 | GHSA-xmxc |
| npm `@leadstack/crm-connect` | exact malicious: 1.0.15, 1.0.18–1.0.21, 1.0.29–1.0.30, 1.1.0, 1.1.1 | SafeDep / GHSA |
| pip `monailabel` | 0.8.6 | GHSA-qc22 / release |
| GPGME upstream | 2.3.1 | gnupg-announce |
| Debian libgpgme bookworm / trixie | 1.18.0-3+deb12u1 / 1.24.2-3+deb13u1 | Debian tracker |
| Gpg4win | 5.1.2 (ships GPGME 2.3.1) | announce |
| Ghostscript upstream | 10.08.0 | oss-security |
| Debian ghostscript bookworm / trixie | 10.0.0~dfsg-11+deb12u9 / 10.05.1~dfsg-1+deb13u3 | Debian tracker |
| Idunno.AntiCsrf | no patch; published DLL SHA-256s are affected | MNDT-2026-0048 |
| WHMCS 9.0.x | 9.0.10 | CVE-2026-82981 |
| WHMCS 9.1.x | 9.1.2 | CVE-2026-82981 |

## What this helper checks

- `binary-parser-134814`: lockfiles, `package.json` ranges, `node_modules/binary-parser`. Below 2.3.1 affected; ≥2.3.1 info; unsafe ranges review.
- `leadstack-crm-connect`: exact malicious versions; leftover `~/.leadstack`, `~/.config/leadstack`, `~/.local/share/leadstack`; systemd `leadstack-routing.service` / `leadstack-ingest-worker.service`. Indicator check. No C2 host/IP stored.
- `monailabel-133968`: dist-info, pins, Dockerfile requirements, image tags. Floor 0.8.6.
- `gpgme-129975`: linux packages `gpgme`/`libgpgme*`, Homebrew Cellar, Gpg4win uninstall registry. Debian series floors via Policy 5.6.12. Vendor suffix below upstream is review.
- `ghostscript-125396`: packages `ghostscript`/`libgs*`, Homebrew, Windows uninstall. Debian series floors. Never starts `gs`.
- `idunno-anticsrf-131914`: walked `Idunno.AntiCsrf.dll` (published SHA-256 → affected; name-only → review) and `Web.config` mentioning the module. Indicator check. No vendor patch.
- `whmcs-82981`: `configuration.php` + `includes/version.php` (WHMCS marker). Floors 9.0.10 / 9.1.2. Below 9.0 is info (out of CVE range). Never opens `configuration.php`.

## Out of scope (not a host check)

- Azure API Management Classic credential theft (cloud; rotate Named Values / IdP secrets in Azure).
- CVE-2026-134624 Mail Assure / SpamExperts SSRF (already skipped as hosted).
- SonicWall Gen6 / SonicOS 6 EOL (appliance).
- React2STEAL GitHub Actions campaign (remote / WAF IOCs).
- MoldyRoost iOS malvertising (mobile / MDM).
- SAP NetWeaver CVE-2025-42884, Cisco Expressway RCE (appliances).
- CERT-In AI-assisted attacks advisory (campaign text only).
- VMware vCenter CVE-2026-123903..123907 (VMSA-2026-0011) — appliance; distinct from CVE-2026-123890.
- CISA ICSA-26-323-02 Elecbrakes (already skipped).
- PlayStation Network ATO (hosted service; patched by Sony).
- 24 Nov and evening breach-only incidents (EU Academy, KEPCO, GoFundMe Pro, LaLiga, GlobeTopper, 1984 Hosting, FBI NCIC/USDA, Algonquin Dam, Rackspace Spot including 8 Dec 2026 wind-down, Cleverbridge, Bell/Virgin Plus, Nissan repair, Pentagon CAC PIN, gov breaches, DonorPerfect/Unibet/Tigerfish, McDonald's Japan app, Hugendubel / Tolino Cloud / eBook de).
