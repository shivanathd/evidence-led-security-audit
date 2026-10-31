# Optional profile: JetBrains JBR / eMudhra IDE floors (2026-10-30)

Last checked: 2026-10-30. This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date.

`host_checks.py` check id: `jetbrains-jbr-emudhra`. Read-only metadata only. Never start an IDE, Toolbox, `jetbrainsd`, or Java.

The OS-store check remains [emudhra-2026-10-17.md](emudhra-2026-10-17.md). Do not fold JBR floors into `emudhra-trust-store`.

## Primary sources

- JetBrains Security Blog (30 Oct 2026): [compromised eMudhra certificates in IDEs](https://blog.jetbrains.com/security/2026/10/compromised-emudhra-certificates-ides/)
- Pointer (not a floor): [Cloudflare eMudhra patching](https://blog.cloudflare.com/emudhra-patching/)

## What was disclosed (as of the date above)

Bundled JBR still trusted the compromised eMudhra intermediates. OS updates do not cover IDEs, Toolbox, Gateway, or ReSharper. JCEF on 2025.2 is JBR-only until a pending hotfix; 2025.3+ JCEF updates come from Google after start. `jetbrainsd` is a separate store, fixed in 0.9.9728. IDE 2025.1 and earlier, and Toolbox 3.7 and earlier, get no fix.

Product floors are per product on the blog. Do not share one table across products. CLion 2026.2.4 is below 2026.2.4.1; IntelliJ 2026.2.4 is the IntelliJ floor.

## Evidence this check reads

- IDE / Gateway: `product-info.json` only (`productCode`, `version`, `versionSuffix`). Other `productCode` values are skipped.
- Toolbox: macOS JetBrains Toolbox application bundle `CFBundleShortVersionString`; Windows uninstall `DisplayName` `JetBrains Toolbox`; Linux `~/.local/share/JetBrains/Toolbox/bin` is unknown
- ReSharper: Windows uninstall `DisplayName` starting `JetBrains ReSharper`
- `jetbrainsd`: highest non-symlink sibling under `Daemon/bundles` with three or more numbers (`current` is not followed)
- Standalone JBR: macOS `JavaVirtualMachines/*/Contents/Home/release` when `IMPLEMENTOR` contains JetBrains

## Finding to check-result rollup (`run_check`)

| Findings / blockers | Check result |
| --- | --- |
| at least one `affected` or `review` | `FAIL` |
| at least one `unknown` (and no `affected`/`review`) | `BLOCKED` |
| only `info` | `PASS` |
| nothing found | `NOT_APPLICABLE` |

- Any RC or EAP (`versionSuffix` or `version`) → `review`
- A final 2026.3 on a product whose listed 2026.3 floor is RC/EAP → `info`
- IDE on line 2025.2 at or above its floor → `review` (JCEF pending). Gateway is not this rule
- Unlisted line older than that product's oldest listed line → `affected` (“no fixed build on this line”)
- Other unlisted line → `review`
- Toolbox 3.7 and older, and 2.x → `affected`; 3.8 / 3.9 against 3.8.2 / 3.9.1; other 3.x → `review`

## Known limits

- Flatpak, Linux/Windows standalone JBR, and `XDG_DATA_HOME` are unread.
- Snap never follows `current`.
- PE FileVersion, Info.plist, and package names are not IDE version sources.
- 2025.3+ JCEF depends on reaching Google's update servers.

## Closing a finding under this profile

Use `verification_basis: vendor_patch` only with the JetBrains 30 Oct blog retrieved this run, plus evidence the product is at or above its listed floor and (for 2025.3+ IDEs) JCEF could reach Google.

## What needs a human

Confirming an RC/EAP is the fixed build; applying the JCEF workaround on 2025.2; approving `NOT_APPLICABLE`.
