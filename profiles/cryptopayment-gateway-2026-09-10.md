# Optional profile: WordPress CryptoPayment Gateway CVE-2026-81648 (2026-09-10)

Last checked: 2026-11-03. This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date.

`host_checks.py` check id: `cryptopayment-gateway-81648`. Read-only metadata only. Never call the plugin AJAX router, never start PHP, and never open any file in the plugin directory other than `cryptopayment-gateway.php`.

## Primary sources

- CVE Record: [CVE-2026-81648](https://www.cve.org/CVERecord?id=CVE-2026-81648)
- WPScan: [CryptoPayment Gateway missing authorization](https://wpscan.com/vulnerability/9b1490a0-1381-4d22-8086-f75aade4e898/)

Pointer (not a floor): [The Hacker News](https://thehackernews.com/2026/11/attackers-target-unpatched.html).

## What was disclosed (as of the date above)

Missing authorization in the WordPress plugin CryptoPayment Gateway. WPScan lists **1.2.1–1.2.2**. No fixed release exists. The plugin is closed on wordpress.org.

## Evidence this check reads

The home walk plus existing web roots already visit `wp-content/plugins`. A directory named `cryptopayment-gateway` there is recorded. Only `cryptopayment-gateway.php` is opened (256 KiB, same `Version:` regex as UpdraftPlus). Other `*.php` files, including under `vendor/`, are never listed or opened.

- Version `1.2.1` or `1.2.2` → `affected`.
- Any other parsed version → `review` (outside WPScan's listed range; no fixed release exists).
- Main file missing, unreadable, or no `Version:` header → `unknown`.

## Finding to check-result rollup (`run_check`)

| Findings / blockers | Check result |
| --- | --- |
| at least one `affected` or `review` | `FAIL` |
| at least one `unknown` (and no `affected`/`review`) | `BLOCKED` |
| walk stopped (`max_entries` / time budget) or the check raised (`r.blocked`), including when no findings exist | `BLOCKED` |
| only `info` | `PASS` |
| nothing found | `NOT_APPLICABLE` |

## Closing a finding under this profile

There is no vendor-patched release to close against. Removal or replacement of the plugin is an owner decision. Do not treat "outside the listed range" as fixed.

## What needs a human

Deciding whether to remove the plugin; approving `NOT_APPLICABLE`.
