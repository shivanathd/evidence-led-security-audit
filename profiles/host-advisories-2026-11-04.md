# Optional profile: host advisories 2026-11-04 (apt, Apple KEV, Active Storage, Better Auth)

Last checked: 2026-11-05. This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date.

`host_checks.py` check ids: `apt-109518`, `apple-27834`, `activestorage-122006`, `better-auth-2026-11-03`. Read-only metadata only. Never start `apt`, `dpkg`, Safari, `bundle`, `rails` or `npm`, never write package config, and never make an HTTP request.

## Terms

- **USN**: Ubuntu Security Notice; Canonical's per-series package advisory (here USN-8996-1).
- **DSA / DLA**: Debian Security Advisory (stable) / Debian LTS Advisory (here DSA-6607-1 and DLA-4880-1).
- **ESM**: Ubuntu Expanded Security Maintenance; Pro/ESM version strings are not archive `-security` builds.
- **KEV**: CISA Known Exploited Vulnerabilities catalog; a KEV listing is evidence of exploitation, not a version floor.
- **PAC**: Pointer Authentication Codes (arm64e); CVE-2024-27834 is a WebKit PAC bypass.
- **MDM**: mobile-device management inventory; required for Apple phones and tablets, which this helper does not scan.

## Primary sources

- Ubuntu USN-8996-1 (4 Nov 2026): [USN-8996-1](https://ubuntu.com/security/notices/USN-8996-1)
- Ubuntu Security: [CVE-2026-109518](https://ubuntu.com/security/CVE-2026-109518)
- Debian DSA-6607-1: [debian-security-announce](https://lists.debian.org/debian-security-announce/2026/msg00526.html)
- Debian Security Tracker: [CVE-2026-109518](https://security-tracker.debian.org/tracker/CVE-2026-109518) and [DLA-4880-1](https://security-tracker.debian.org/tracker/DLA-4880-1)
- oss-security quote of DSA-6607-1 (4 Nov 2026): [oss-security](https://www.openwall.com/lists/oss-security/2026/11/04/12)
- Apple HT214103 (Safari 17.5): [HT214103](https://support.apple.com/en-us/HT214103)
- Apple HT214106 (macOS Sonoma 14.5): [HT214106](https://support.apple.com/en-us/HT214106)
- CISA KEV (4 Nov 2026): [CVE-2024-27834 added](https://www.cisa.gov/news-events/alerts/2026/11/04/cisa-adds-one-known-exploited-vulnerability-catalog)
- Ruby on Rails (4 Nov 2026): [v8.0.5.2 and v8.1.4.1](https://rubyonrails.org/2026/11/4/Rails-8.0.5%2E2-and-8.1.4%2E1-have-been-released)
- GitHub advisory GHSA-f3w6-w445-fwh9: [Active Storage](https://github.com/rails/rails/security/advisories/GHSA-f3w6-w445-fwh9)
- Better Auth (3 Nov 2026): [security release](https://better-auth.com/blog/security-release-2026-11-03)

Skipped (see below): Xen [XSA-523](https://xenbits.xen.org/xsa/advisory-523.html) (3 Nov 2026). No LWN reprint is cited.

## What was disclosed (as of the date above)

**apt / CVE-2026-109518.** An on-path attacker who can manipulate HTTP between an apt client and an archive (including a malicious mirror or proxy) can cause the client to install an unverified package as root. The USN and DSA name the package floors below. A non-zero retry count is required for the bug; that setting is mitigation, never a vendor fix, and this check does not read it.

**Apple CVE-2024-27834.** CISA added this CVE to KEV on 4 Nov 2026. Desktop floors remain the May 2024 Apple bulletins: macOS Sonoma 14.5 and Safari 17.5. iOS / iPadOS / tvOS / watchOS need MDM and are out of scope.

**Active Storage / GHSA-f3w6-w445-fwh9.** Possible arbitrary file write and read in image analysis. Fixed in Rails v8.0.5.2 and v8.1.4.1. Processor choice (vips vs ImageMagick) is not detected; version-only matches the repo pattern.

**Better Auth, 3 Nov 2026.** v1.7.16 and v1.8.0-beta.5 fix the listed issues. Other release lines and package.json ranges stay review.

## Fixed versions

| Surface | Floor | Source |
| --- | --- | --- |
| Ubuntu 26.10 `apt` | 3.3.3ubuntu0.1 | USN-8996-1 |
| Ubuntu 26.04 `apt` | 3.2.1ubuntu0.1 | USN-8996-1 |
| Ubuntu 24.04 `apt` | 2.8.4ubuntu0.1 | USN-8996-1 |
| Ubuntu 22.04 `apt` | 2.4.15ubuntu0.1 | USN-8996-1 |
| Ubuntu 20.04 ESM `apt` | 2.0.12+esm1 | USN-8996-1 |
| Ubuntu 18.04 ESM `apt` | 1.6.19+esm1 | USN-8996-1 |
| Ubuntu 16.04 ESM `apt` | 1.2.36+esm1 | USN-8996-1 |
| Ubuntu 14.04 ESM `apt` | 1.0.1ubuntu2.24+esm4 | USN-8996-1 |
| Debian 13 `apt` | 3.0.4 | tracker / DSA-6607-1 |
| Debian 12 `apt` | 2.6.2 | tracker / DLA-4880-1 |
| macOS Sonoma | 14.5 | HT214106 |
| Safari | 17.5 | HT214103 |
| `activestorage` 8.0.x | v8.0.5.2 | GHSA-f3w6-w445-fwh9 |
| `activestorage` 8.1.x | v8.1.4.1 | GHSA-f3w6-w445-fwh9 |
| `better-auth` 1.7.x | 1.7.16 | Better Auth 2026-11-03 |
| `better-auth` 1.8.0-beta.N | N >= 5 | Better Auth 2026-11-03 |

A Ubuntu/Debian series with no string on the USN or DSA/DLA is `review`. ESM rows below the ESM string are `review` (not archive `-security`). Debian 11 and older, sid/testing without `VERSION_ID`, and any `ID` other than `ubuntu`/`debian` (including `ID_LIKE`-only derivatives) are `review`.

## Evidence these checks read

- `apt-109518`: `linux_packages` (`apt` stanza) plus `os_release_fields`. No `apt.conf`. Comparison is Debian Policy 5.6.12 in `hostscan.debian_version_cmp` (epoch, upstream, last-hyphen revision; `~` before empty). Linux with no installed `apt` package is `NOT_APPLICABLE`. An unreadable `/var/lib/dpkg/status` is `BLOCKED`. Missing os-release when `apt` is present is `unknown`.
- `apple-27834`: `ProductVersion` from `/System/Library/CoreServices/SystemVersion.plist` and Safari via `browsers()` (Info.plist, including the Preboot Cryptex path already listed there). One finding per surface. macOS 15+ is `info` on the OS line; Safari is still classified. macOS 11 and older are `review`. macOS 12/13 classify Safari, or `review` if Safari is unreadable.
- `activestorage-122006`: `Index.gem_lock` (`Gemfile.lock` only; not `vendor/bundle/`, `.bundle/`, or `gems/<name>-<version>/`). GEM `specs:` at 4-space indent. GIT/PATH-only is `review` ("built from source"). A `-` platform suffix is `review`. `mini_magick` below 5.1 next to activestorage is extra `review`. `Gemfile` ranges are not evidence. An unreadable needed lock is `BLOCKED`.
- `better-auth-2026-11-03`: npm lockfiles / `package.json` for `better-auth` and `@better-auth/{expo,electron,passkey,stripe,kysely-adapter}` only. Beta helper: `^1\.8\.0-beta\.(\d+)$` then integer compare against 5. Other `@better-auth/*` names are ignored.

## Finding to check-result rollup

Same as every other host check: see [host-checks.md](../references/host-checks.md) (FAIL / BLOCKED / PASS / NOT_APPLICABLE). `apple-27834` emits one line per surface; the check status is the worst of the two (`affected` > `review` > `unknown` > `info`).

## Closing a finding under this profile

Use `verification_basis: vendor_patch` only with the USN, DSA/DLA, Apple bulletin, GHSA or Better Auth post retrieved this run **and** on-disk metadata at or above the matching floor. A retry-count setting or a loopback bind is mitigation, not a fix.

## What needs a human

Confirming an ESM or distro backport against the tracker; approving `NOT_APPLICABLE`; MDM inventory for Apple mobile OS; deciding whether a GIT/PATH gem or a 1.8.0 final pin is actually patched.

## Alternatives considered

- `dpkg --compare-versions`: rejected. It runs a program, and the repo allows only `rpm -qa` and `security find-certificate`.
- Reuse `classify_lines` / `at_least` for apt: rejected. A nums-only compare gives a false PASS on `2.8.4` vs `2.8.4ubuntu0.1`.
- A Xen check from `/sys/hypervisor`: rejected. XSA-523 has no released guest-visible floor, so presence would FAIL forever.
- `Gemfile` constraints instead of `Gemfile.lock`: rejected. Ranges are not installed versions.
- One profile per item: rejected. The compact file budget is 65 (63 files on main + this one profile = 64).

## Risks

- Debian Policy compare is reimplemented in Python; a future policy change needs a test update.
- ESM strings are Pro-only; a host below the ESM floor is `review`, not `affected`.
- Safari and macOS metadata can lie; the tool never starts the programs.
- Active Storage processor (vips vs ImageMagick) is not detected.
- Better Auth 1.8.0 final is `review` until the vendor names it as a floor.
