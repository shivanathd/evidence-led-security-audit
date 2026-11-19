# Optional profile: host advisories 2026-11-19 (LiteLLM CVE-2026-40217, nginx CVE-2026-123007)

Last checked: 2026-11-19. This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date.

`host_checks.py` check ids: `litellm-40217`, `nginx-123007`. Read-only metadata only. Never start `nginx`, LiteLLM or Python, never HTTP, and never copy PoC or credential values.

Already on main (do not re-implement): `litellm-1-107-0` (malicious 1.107.0), `artex-gateway-keys` (credential field names), `nginx-present` (presence-only), `axis-90436` (CVE-2026-90436).

## Terms

- **GHSA first_patched_version**: structured GitHub advisory field. For CVE-2026-40217 it is **1.83.10**. The advisory **body** also names 1.83.11; this helper classifies against 1.83.10.
- **nginx OSS floors**: stable **1.30.7** and mainline **1.31.9** from nginx.org CHANGES (18 Nov 2026). Distro packages may backport a fix under an older version string.
- **nginx-present**: older presence-only check. It does not classify these floors.

## Primary sources

- GHSA-wxxx-gvqv-xp7p: [advisory](https://github.com/advisories/GHSA-wxxx-gvqv-xp7p)
- CVE-2026-40217: [cve.org](https://www.cve.org/CVERecord?id=CVE-2026-40217)
- NVD: [CVE-2026-40217](https://nvd.nist.gov/vuln/detail/CVE-2026-40217)
- CISA KEV 18 Nov 2026: [four KEVs](https://www.cisa.gov/news-events/alerts/2026/11/18/cisa-adds-four-known-exploited-vulnerabilities-catalog)
- X41-2026-001: [LiteLLM advisory](https://www.x41-dsec.de/lab/advisories/x41-2026-001-litellm)
- nginx.org security advisories: [CVE-2026-123007](https://nginx.org/en/security_advisories.html)
- nginx.org CHANGES (mainline 1.31.9): [CHANGES](https://nginx.org/en/CHANGES)
- nginx.org CHANGES-1.30 (stable 1.30.7): [CHANGES-1.30](https://nginx.org/en/CHANGES-1.30)
- CVE-2026-123007: [cve.org](https://www.cve.org/CVERecord?id=CVE-2026-123007)
- NVD: [CVE-2026-123007](https://nvd.nist.gov/vuln/detail/CVE-2026-123007)
- Cloudflare Radar: [nginx2root](https://radar.cloudflare.com/zero-wire/nginx2root)
- Wiz: [nginx HTTP/2 RCE](https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities)
- Xint: [nginx2root](https://xint.io/blog/nginx2root-remote-code-execution)

## What was disclosed (as of the date above)

**LiteLLM CVE-2026-40217 (CISA KEV).** Sandbox escape in a custom-code guardrail. GHSA range **1.81.8** through before **1.83.10**. The advisory body also names 1.83.11. Distinct from the malicious 1.107.0 release. Workaround named by vendors is to disable the custom-code guardrail test endpoint; that is mitigation, not 1.83.10.

**nginx OSS CVE-2026-123007.** HTTP/2 issue present since 1.9.5, fixed in **1.30.7** / **1.31.9** (18 Nov 2026). The same releases close the rest of that nginx.org security set. OpenResty and NGINX Plus use other version lines. Distro builds may backport. Never run `nginx -v` or reload nginx for this check.

## Fixed versions

| Surface | Floor | Source |
| --- | --- | --- |
| LiteLLM (PyPI / GHSA) | 1.83.10 | GHSA-wxxx-gvqv-xp7p `first_patched_version` |
| nginx OSS stable | 1.30.7 | nginx.org CHANGES-1.30 / security_advisories |
| nginx OSS mainline | 1.31.9 | nginx.org CHANGES / security_advisories |

## What this helper checks

- `litellm-40217`: `py_installs` / `py_pin_hits` / `docker_decl_refs`. Exact `==` / `===` pins classify. Unpinned specs are `review`. Digest-pinned and moving tags are `unknown`.
- `nginx-123007`: linux packages `nginx` / `nginx-core` / `nginx-full` / `nginx-light` / `nginx-extras` / `nginx-mainline`; Homebrew `nginx`; Windows PE / uninstall registry (`nginx Plus` / OpenResty DisplayNames are `review`); ASCII `nginx/X.Y.Z` in binary bytes; FROM/`image:` tags whose last path component is `nginx` or `nginx-unprivileged`. OpenResty and NGINX Plus are `review`. `nginx-prometheus-exporter` is not this check.

## What this helper does not check

- Synology DSM / BeeStation CVE-2024-10441 (CISA KEV) — appliance firmware.
- REDCap CVE-2026-90817 (CISA KEV) — survey appliance / PHP app; no vendor version-file primary fetched this run.
- Apache Axis CVE-2026-90436 — already `axis-90436`.
- F5 BIG-IP TMM flaws (CVE-2026-123637 / 121805 / 120292 / 120285 / 116953 / 120722) — network appliance.
- TfL Oyster photocard breach — org/SaaS incident; no host package or version floor.
- Exploit details, PoC, LiteLLM master keys, HTTP to nginx or LiteLLM.
