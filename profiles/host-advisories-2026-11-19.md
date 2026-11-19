# Optional profile: host advisories 2026-11-19 (LiteLLM, nginx, Ruby2shell, PHP-FPM, Drupal core)

Last checked: 2026-11-19. This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date.

`host_checks.py` check ids: `litellm-40217`, `nginx-123007`, `ruby2shell`, `php-129289`, `drupal-132165`. Read-only metadata only. Never start `nginx`, LiteLLM, Python, `ruby`, `php`, `php-fpm`, Drupal or `drush`, never HTTP, and never copy PoC or credential values.

Already on main (do not re-implement): `litellm-1-107-0` (malicious 1.107.0), `artex-gateway-keys` (credential field names), `nginx-present` (presence-only), `axis-90436` (CVE-2026-90436), `ruby-regex` (older Ruby floors), `php2shell` (older PHP floors + `session.upload_progress.enabled`), `postgresql-6460` (CVE-2026-6460 / same floors as CVE-2026-116331), `drupal-commerce-118539` (Commerce contrib, not core).

## Terms

- **GHSA first_patched_version**: structured GitHub advisory field. For CVE-2026-40217 it is **1.83.10**. The advisory **body** also names 1.83.11; this helper classifies against 1.83.10.
- **nginx OSS floors**: stable **1.30.7** and mainline **1.31.9** from nginx.org CHANGES (18 Nov 2026). Distro packages may backport a fix under an older version string.
- **nginx-present**: older presence-only check. It does not classify these floors.
- **Ruby2shell floors**: **4.0.10 / 3.4.13 / 3.3.14** from ruby-lang.org 18 Nov 2026 / GHSA-34m4-m9fh-gqp5. Distinct from `ruby-regex` (4.0.9 / 3.4.12 / 3.3.13). Ruby 3.2 and older are EOL (no fix).
- **PHP-FPM smuggling floors**: **8.5.13 / 8.4.28 / 8.3.37 / 8.2.36** from GHSA-qc49-hpvq-g2w6 / php.net ChangeLog-8 (CVE-2026-129289). Distinct from `php2shell`. Distro builds may backport.
- **Drupal core floors**: **10.6.22 / 11.3.22 / 11.4.13** from SA-CORE-2026-017. 11.2.x and below, 10.5.x and below, and Drupal 8/9 are EOL. Blocking `/core/install.php` is mitigation, not a patch.

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
- GHSA-34m4-m9fh-gqp5: [advisory](https://github.com/advisories/GHSA-34m4-m9fh-gqp5)
- Ruby 18 Nov 2026: [regexp and string](https://www.ruby-lang.org/en/news/2026/11/18/multiple-vulnerabilities-in-regexp-and-string/)
- Cloudflare Radar: [Ruby2shell](https://radar.cloudflare.com/zero-wire/ruby2shell)
- Veria Labs: [Ruby2shell](https://verialabs.com/ruby2shell/)
- The Hacker News: [Ruby regex/string fixes](https://thehackernews.com/2026/11/ruby-releases-fixes-for-7-regex-and.html)
- GHSA-qc49-hpvq-g2w6: [advisory](https://github.com/php/php-src/security/advisories/GHSA-qc49-hpvq-g2w6)
- PHP ChangeLog 8: [ChangeLog-8.php](https://www.php.net/ChangeLog-8.php)
- CVE-2026-129289: [cve.org](https://www.cve.org/CVERecord?id=CVE-2026-129289)
- Drupal SA-CORE-2026-017: [advisory](https://www.drupal.org/sa-core-2026-017)
- CVE-2026-132165: [cve.org](https://www.cve.org/CVERecord?id=CVE-2026-132165)
- BleepingComputer: [Drupal RCE](https://www.bleepingcomputer.com/news/security/drupal-patches-critical-rce-flaw-warns-exploits-may-surface-quickly/)

## What was disclosed (as of the date above)

**LiteLLM CVE-2026-40217 (CISA KEV).** Sandbox escape in a custom-code guardrail. GHSA range **1.81.8** through before **1.83.10**. The advisory body also names 1.83.11. Distinct from the malicious 1.107.0 release. Workaround named by vendors is to disable the custom-code guardrail test endpoint; that is mitigation, not 1.83.10.

**nginx OSS CVE-2026-123007.** HTTP/2 issue present since 1.9.5, fixed in **1.30.7** / **1.31.9** (18 Nov 2026). The same releases close the rest of that nginx.org security set. OpenResty and NGINX Plus use other version lines. Distro builds may backport. Never run `nginx -v` or reload nginx for this check.

**Ruby2shell (GHSA-34m4-m9fh-gqp5).** Heap overflow in string case conversion; same 18 Nov 2026 releases also fix six regexp/string memory-safety flaws. Fixed in **3.3.14 / 3.4.13 / 4.0.10**. 3.2 and older are EOL. Distinct from `ruby-regex`. GitLab `/opt/gitlab/version-manifest.txt` `ruby` is a vendor-bundled hint only.

**PHP-FPM GHSA-qc49 / CVE-2026-129289.** Unread-body request smuggling, unauthenticated RCE on sapi-fpm/LSAPI. Fixed in **8.2.36 / 8.3.37 / 8.4.28 / 8.5.13**. Distinct from `php2shell`. The same releases also patch CVE-2026-115560; `php2shell` still records `session.upload_progress.enabled`. Never start or reload php-fpm.

**Drupal core CVE-2026-132165 / SA-CORE-2026-017.** `install.php` reinstall can take over the site. Floors **10.6.22 / 11.3.22 / 11.4.13**. Blocking `/core/install.php` is mitigation. No HTTP.

## Fixed versions

| Surface | Floor | Source |
| --- | --- | --- |
| LiteLLM (PyPI / GHSA) | 1.83.10 | GHSA-wxxx-gvqv-xp7p `first_patched_version` |
| nginx OSS stable | 1.30.7 | nginx.org CHANGES-1.30 / security_advisories |
| nginx OSS mainline | 1.31.9 | nginx.org CHANGES / security_advisories |
| Ruby 4.0 | 4.0.10 | ruby-lang.org / GHSA-34m4-m9fh-gqp5 |
| Ruby 3.4 | 3.4.13 | ruby-lang.org / GHSA-34m4-m9fh-gqp5 |
| Ruby 3.3 | 3.3.14 | ruby-lang.org / GHSA-34m4-m9fh-gqp5 |
| PHP 8.5 | 8.5.13 | GHSA-qc49-hpvq-g2w6 / php.net ChangeLog-8 |
| PHP 8.4 | 8.4.28 | GHSA-qc49-hpvq-g2w6 / php.net ChangeLog-8 |
| PHP 8.3 | 8.3.37 | GHSA-qc49-hpvq-g2w6 / php.net ChangeLog-8 |
| PHP 8.2 | 8.2.36 | GHSA-qc49-hpvq-g2w6 / php.net ChangeLog-8 |
| Drupal 10.6 | 10.6.22 | SA-CORE-2026-017 |
| Drupal 11.3 | 11.3.22 | SA-CORE-2026-017 |
| Drupal 11.4 | 11.4.13 | SA-CORE-2026-017 |

## What this helper checks

- `litellm-40217`: `py_installs` / `py_pin_hits` / `docker_decl_refs`. Exact `==` / `===` pins classify. Unpinned specs are `review`. Digest-pinned and moving tags are `unknown`.
- `nginx-123007`: linux packages `nginx` / `nginx-core` / `nginx-full` / `nginx-light` / `nginx-extras` / `nginx-mainline`; Homebrew `nginx`; Windows PE / uninstall registry (`nginx Plus` / OpenResty DisplayNames are `review`); ASCII `nginx/X.Y.Z` in binary bytes; FROM/`image:` tags whose last path component is `nginx` or `nginx-unprivileged`. OpenResty and NGINX Plus are `review`. `nginx-prometheus-exporter` is not this check.
- `ruby2shell`: `ruby_installs` (rbenv / asdf / mise / chruby / rvm / Homebrew / distro packages / rbconfig.rb); FROM/`image:` tags whose last path component is `ruby`. GitLab `version-manifest.txt` `ruby` is `info` only. Digest-pinned and moving tags are `unknown`.
- `php-129289`: `php_installs` (distro `php` / `php-fpm`, Homebrew, `php_version.h`, MAMP, Windows DLL PE); FROM/`image:` tags whose last path component is `php` or `php-fpm`. php.ini is not this check. Digest-pinned and moving tags are `unknown`.
- `drupal-132165`: walk `composer.lock` / `vendor/composer/installed.json` for `drupal/core` (or `drupal/core-recommended` when core is absent); `core/lib/Drupal.php` `const VERSION` next to `index.php` or `autoload.php`; FROM/`image:` tags whose last path component is `drupal`. `composer.json` is not evidence.

## What this helper does not check

- Synology DSM / BeeStation CVE-2024-10441 (CISA KEV) — appliance firmware.
- REDCap CVE-2026-90817 (CISA KEV) — survey appliance / PHP app; no vendor version-file primary fetched this run.
- Apache Axis CVE-2026-90436 — already `axis-90436`.
- F5 BIG-IP TMM flaws (CVE-2026-123637 / 121805 / 120292 / 120285 / 116953 / 120722) — network appliance.
- TfL Oyster photocard breach — org/SaaS incident; no host package or version floor.
- CVE-2026-115560 as a second check — already `php2shell`; 19 Nov PHP floors also patch it (`php-129289`).
- PostgreSQL CVE-2026-116331 — already `postgresql-6460` (same floors).
- MySQL CVE-2026-101786 — press names 26.7.0–26.7.1; no Oracle primary floor this run; `mysql-114952` is a different CVE.
- ClickHouse Depthfirst RCE PoC — no confirmed patched OSS floor; `clickhouse-116366` is a different CVE.
- Oracle Text CVE-2026-114819 / ORDS CVE-2026-91609 — appliance/product; no cheap local version-file pattern.
- European Commission cyberattack (ARTEX) — org/SaaS incident; `artex-gateway-keys` is credential field names.
- N-able Mail Assure / SpamExperts hosted cloud — vendor-hosted; `ncentral-hf3` is on-prem N-central.
- Exploit details, PoC, LiteLLM master keys, HTTP to nginx, LiteLLM, php-fpm, Drupal `install.php`, or Ruby.
