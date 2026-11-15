# Optional profile: UnrealIRCd CVE-2026-114713 (2026-11-08)

Last checked: 2026-11-14. This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date.

`host_checks.py` check id: `unrealircd-114713`. Read-only metadata only. Never start UnrealIRCd, never run `./unrealircd module-status`, never apply a hot-patch installer, and never open an IRC socket.

## Primary sources

- Vendor forum: [UnrealIRCd CVE-2026-114713](https://forums.unrealircd.org/viewtopic.php?t=9487) (7 Nov 2026)
- oss-security: [CVE-2026-114713](https://www.openwall.com/lists/oss-security/2026/11/08/1) (8 Nov 2026)
- CVE record: [CVE-2026-114713](https://www.cve.org/CVERecord?id=CVE-2026-114713)
- NVD: [CVE-2026-114713](https://nvd.nist.gov/vuln/detail/CVE-2026-114713)
- CISA KEV: [13 Nov 2026 catalog addition](https://www.cisa.gov/news-events/alerts/2026/11/13/cisa-adds-one-known-exploited-vulnerability-catalog)

Press write-ups and public proof-of-concept repositories are not floors. This check never runs them.

## What was disclosed (as of the date above)

CWE-140 delimiter injection in the IRCv3 **labeled-response** tag. Remote, no authentication. Linked-server / services context is a vendor precondition; this check does not evaluate it.

Floors:

- Vendor / NVD: UnrealIRCd **v6.2.7.1**. **6.2.7 is not the fix** (`parse_version` zero-pads, so 6.2.7 compares below v6.2.7.1).
- Hot-patch **bundle-20261107**. Official verify is `./unrealircd module-status` showing labeled-response `5.0-hot-patch-bundle-20261107`. This tool never runs that command. The read-only substitute is the ASCII token `hot-patch-bundle-20261107` in the **installed** `labeled-response` module bytes. Uncompiled source is not that evidence.
- UnrealIRCd **5** (EOL) is affected. A 5.x hot-patch exists; without the token, 5.x is `affected`.
- UnrealIRCd **3.x / 4.x** were not checked by the vendor → `review`.
- Windows: **no vendor hot-patch**; upgrade only.
- `blacklist-module labeled-response` is mitigation, not a vendor patch.

CISA added CVE-2026-114713 to KEV on 13 Nov 2026 (FCEB due 16 Nov 2026). The due date is not a host-check floor.

No distro-named backport floor was retrieved for this profile. An NVR that keeps `6.2.7` is `affected` unless the hot-patch token is on disk.

## Evidence this check reads

- Linux packages `unrealircd` / `unrealircd-src`
- Homebrew Cellar formula `unrealircd`
- Targeted prefixes: `~/unrealircd`, `/opt/unrealircd`, `/usr/local/unrealircd`, `/etc/unrealircd`, `/usr/lib/unrealircd`, `/usr/lib64/unrealircd`, `/usr/share/unrealircd`
- `src/version.c` `VERSIONONLY`, `configure.ac` `AC_INIT`, Windows PE `UnrealIRCd.exe`
- Image tags matching `unrealircd` in Dockerfiles / compose / deploy YAML
- ASCII `hot-patch-bundle-20261107` in installed `modules/labeled-response.so` / `.dll` (bytes, including ELF nulls). Not `src/modules` and not `modules/*.c`.

## Finding to check-result rollup (`run_check`)

| Findings / blockers | Check result |
| --- | --- |
| at least one `affected` or `review` | `FAIL` |
| at least one `unknown` (and no `affected`/`review`) | `BLOCKED` |
| walk stopped (`max_entries` / time budget) or the check raised (`r.blocked`), including when no findings exist | `BLOCKED` |
| only `info` | `PASS` |
| nothing found | `NOT_APPLICABLE` |

- A prerelease of v6.2.7.1 is not fixed. A newer minor prerelease such as 6.2.8-rc1 is `info`.
- An unreadable labeled-response module, or a `modules/third` path that cannot be listed or is not a directory, next to 5.x / 6.x below the floor is `unknown`, even if another candidate carries the token. Never a silent PASS.
- Moving image tags (`latest`) are `info`.

## Known limits

- Version spoofing and a hot-patch `.so` that lacks the ASCII token over-FAIL as affected (safe direction).
- A retained `labeled-response.so.bak` (or `.old` / similar) is not hot-patch evidence.
- Uncompiled `labeled-response.c` (`src/modules` or `modules/`) and extensionless `modules/labeled-response` are not hot-patch evidence.
- A live unpatched module is not cleared by a token under another prefix (`/usr/lib64` vs `/usr/lib`).
- Windows: a token in `labeled-response.dll` is not a vendor patch.
- Linked-server preconditions are not evaluated.
- Distro backports that keep the 6.2.7 number without the token are not treated as fixed.

## Closing a finding under this profile

Use `verification_basis: vendor_patch` only with the vendor forum or oss-security retrieved this run, plus evidence the install is **at or above** v6.2.7.1 (including Windows), or that the **installed** labeled-response module contains the hot-patch token. Record `package` and `fixed_build` for the installed copy; `scripts/validate_report.py` rejects `vendor_patch` without them. A token only in uncompiled source is not enough to close. Windows has no vendor hot-patch: close a Windows finding on a version at or above v6.2.7.1, not on a module token.

## What needs a human

Confirming a linked-server exposure; applying the vendor hot-patch or upgrade; deciding whether a `blacklist-module` workaround is accepted risk; approving `NOT_APPLICABLE`.
