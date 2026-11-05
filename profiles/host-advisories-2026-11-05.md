# Optional profile: host advisories 2026-11-05 (OpenSSH musl / Alpine, LiteSpeed Cache)

Last checked: 2026-11-05. This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date.

`host_checks.py` check ids: `openssh-musl-pwauth`, `litespeed-cache-93389`. Read-only metadata only. Never start `sshd`, `apk`, `php` or WordPress, never read `/etc/shadow` or `/etc/passwd`, never request the WooCommerce Store API, and never make an HTTP request.

## Terms

- **musl**: the C library Alpine Linux uses (and some other Linux distributions); the portable OpenSSH bypass applies when sshd is linked to musl and is not using PAM.
- **PAM**: Pluggable Authentication Modules; Alpine `openssh-server-pam` with `UsePAM yes` is not this bug.
- **apk**: Alpine's package manager; this check reads `/lib/apk/db/installed` `P:` / `V:` stanzas only.
- **Alpine edge**: the rolling Alpine branch; `VERSION_ID` with `_alpha` or a missing/empty `VERSION_ID` uses the edge floor `10.6_p2-r0`.
- **Cache REST**: LiteSpeed Cache's public REST-cache feature; turning it off is mitigation, never a vendor patch.
- **WooCommerce Store API**: the cart/checkout HTTP API this CVE can leak through; this check never requests it.
- **Cart-Token**: a WooCommerce Store API token named in CVE-2026-93389; this check never reads or prints one.

## Primary sources

- Alpine Linux (5 Nov 2026): [OpenSSH password authentication bypass](https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/)
- Portable OpenSSH 10.6p2 (5 Nov 2026): [release-10.6p2](https://www.openssh.org/txt/release-10.6p2)
- Wordfence: [LiteSpeed Cache 7.9.1 Store API PII via public REST caching](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/litespeed-cache/litespeed-cache-791-unauthenticated-sensitive-information-disclosure-woocommerce-store-api-cartcheckout-pii-cart-token-via-public-rest-caching)
- LiteSpeed (4 Nov 2026): [security update for LSCWP CVE-2026-93389](https://blog.litespeedtech.com/2026/11/04/security-update-for-lscwp-cve-2026-93389/)
- CVE record: [CVE-2026-93389](https://www.cve.org/CVERecord?id=CVE-2026-93389)

## What was disclosed (as of the date above)

**OpenSSH musl password-auth bypass (no CVE).** On Linux systems that use musl and do not use PAM for password authentication, portable OpenSSH can accept a password login for an account whose stored password field is `*`. Alpine's `openssh-server` is built without PAM. OpenSSH 10.6p2 is an upstream workaround; Alpine published per-branch backports the same day. No CVE identifier was assigned at Alpine's time of writing. `PasswordAuthentication no` is mitigation, not a vendor patch. An authorized host audit can see apk metadata, musl-loader presence, and `sshd_config` keywords. It must not attempt a login or read shadow.

**LiteSpeed Cache CVE-2026-93389.** Unauthenticated WooCommerce Store API cart/checkout PII and Cart-Token via public REST caching. Wordfence and the vendor name LiteSpeed Cache 7.9.1 and older as affected and 7.9.2 as patched. Cache REST off is mitigation, never a fix. This check reads the plugin `Version:` header only.

## Fixed versions

| Surface | Floor | Source |
| --- | --- | --- |
| Alpine edge `openssh` | `10.6_p2-r0` | Alpine advisory 5 Nov 2026 |
| Alpine 3.24 `openssh` | `10.3_p1-r2` | Alpine advisory 5 Nov 2026 |
| Alpine 3.23 `openssh` | `10.2_p1-r1` | Alpine advisory 5 Nov 2026 |
| Alpine 3.22 `openssh` | `10.0_p1-r11` | Alpine advisory 5 Nov 2026 |
| Alpine 3.21 `openssh` | `9.9_p2-r1` | Alpine advisory 5 Nov 2026 |
| Alpine 3.20 `openssh` | `9.7_p1-r6` | Alpine advisory 5 Nov 2026 |
| Alpine 3.19 `openssh` | `9.6_p1-r3` | Alpine advisory 5 Nov 2026 |
| Alpine 3.18 `openssh` | `9.3_p2-r4` | Alpine advisory 5 Nov 2026 |
| Alpine 3.17 `openssh` | `9.1_p1-r7` | Alpine advisory 5 Nov 2026 |
| Alpine 3.16 `openssh` | `9.0_p1-r6` | Alpine advisory 5 Nov 2026 |
| Non-Alpine musl portable OpenSSH | `10.6p2` | OpenSSH 10.6p2 release text |
| LiteSpeed Cache | `7.9.2` | Wordfence / vendor / CVE-2026-93389 |

## Evidence these checks read

- `openssh-musl-pwauth`: `os_release_fields` (`ID` / `VERSION_ID`), `linux_packages` (`openssh-server`, `openssh-server-pam`, `openssh-server-common`), listdir of musl/glibc loader names, and `/etc/ssh/sshd_config` plus `/etc/ssh/sshd_config.d/*.conf` (keywords `UsePAM` / `PasswordAuthentication` / `Include` / `Match` only). Alpine `ID` is enough musl evidence. Non-Alpine needs a regular `ld-musl-*.so*` and no glibc loader. Comparison is `hostscan.apk_version_cmp` or `hostscan.openssh_portable_cmp`, never `at_least` / `classify_lines`.
- `litespeed-cache-93389`: walk `wp-content/plugins/litespeed-cache` (`Index.litespeed_cache`) and open only `litespeed-cache.php`. `parse_version` + `at_least` against `7.9.2`. A directory with a missing main file is `unknown` (rolls up to BLOCKED).

## Finding to check-result rollup

Same as every other host check: see [host-checks.md](../references/host-checks.md) (FAIL / BLOCKED / PASS / NOT_APPLICABLE).

## Limits

- No shadow read (may over-FAIL when no `*` account or no `$5$` / `$6$` hash is present).
- An sshd restart after a package upgrade is not visible.
- `Match` blocks in `sshd_config` are not evaluated.
- `PasswordAuthentication no` and Cache REST off are mitigation, never a fix.

## Closing a finding under this profile

Use `verification_basis: vendor_patch` only with the Alpine advisory or OpenSSH 10.6p2 text (or CVE-2026-93389 / 7.9.2) retrieved this run **and** on-disk metadata at or above the matching floor. `PasswordAuthentication no` or Cache REST off is mitigation, never `fixed`.

## What needs a human

Restarting sshd after an Alpine upgrade; deciding mitigation vs upgrade; confirming WooCommerce / Cache REST; approving `NOT_APPLICABLE`.

## Skipped (see `SKIPPED` in `host_checks.py`)

- OpenSSH musl bypass on Dropbear — vendor/Copa: not affected; not this check.
- OpenSSH musl bypass login / shadow / log review — would read secrets or usernames; human only.
- LiteSpeed Cache REST / WooCommerce runtime probe — production HTTP; this check reads `Version:` only.
- Other LSCWP CVEs closed in 7.9.2 (109215, 116763, 113501, 113499, 113500, …) — separate bugs; same upgrade may cover them; not this check.
- French blood bank / fridge claims — press/org; no local developer-endpoint artifact.
- Zyxel GS1900 patch-failure claims — appliance; no prior host profile fits this helper.
- Tata Motors IRA — org/vehicle; no local artifact.
- CERT-In Crafty Falcon / ARTEX (as a CERT-In campaign) — no local developer-endpoint artifact; ARTEX remains a ConnectWise news pointer only.
- eMudhra Python ecosystem write-up — already `emudhra-certifi` / `emudhra-trust-store`; not a new check.

## Alternatives considered

- Reuse `classify_lines` / `at_least` for OpenSSH: rejected. `10.6p1` and Alpine `10.3_p1-r1` would false PASS.
- Widen `parse_debian_version` for apk `_`: rejected. Apt tests depend on rejecting `_`.
- Two dated profiles: rejected. One dated profile keeps the tracked-file budget to one new file.
- Inventory hint or PHP profile edit: rejected. Runtime apk / plugin Version only.

## Risks

- apk and portable OpenSSH compares are reimplemented in Python; a future format change needs a test update.
- Skipping shadow means a host without a `*` account can still FAIL.
- LiteSpeed metadata can lie; the tool never starts PHP or requests the Store API.
