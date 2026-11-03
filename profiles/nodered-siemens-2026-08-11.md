# Optional profile: Node-RED editor auth / Siemens SIMATIC IoT2050 CVE-2026-58115 (2026-08-11)

Last checked: 2026-11-03. This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date.

`host_checks.py` check id: `nodered-admin-http`. Read-only metadata only. Never HTTP GET/POST the editor, never deploy flows, never write `settings.js`, and never execute it.

## Primary sources

- Siemens ProductCERT SSA-834709 (published / last update 2026-08-11, V1.0): [ssa-834709](https://cert-portal.siemens.com/productcert/html/ssa-834709.html)
- CISA ICSA-26-237-03: [SIMATIC IoT2050 Advanced](https://www.cisa.gov/news-events/ics-advisories/icsa-26-237-03)
- Node-RED user guide: [Securing Node-RED](https://nodered.org/docs/user-guide/runtime/securing-node-red)

Pointer (not a floor): [The Hacker News, 3 Nov 2026](https://thehackernews.com/2026/11/attackers-exploit-critical-siemens.html).

**CVE-2026-58115** is a Siemens product CVE for SIMATIC IoT2050 Advanced (`6ES7647-0BA00-1YA2`) running Industrial OS with Node-RED. Generic Node-RED without `adminAuth` is the same exploited missing-auth class (Node-RED's own default). This check must not label a non-Siemens host as "affected by CVE-2026-58115". CISA KEV did not list CVE-2026-58115 as of 3 Nov 2026.

## What was disclosed (as of the date above)

SSA-834709: all versions of SIMATIC IoT2050 Advanced below firmware **V4.3.4.1** that run Industrial OS with Node-RED installed expose an unauthenticated HTTP editor. CWE-306. Vendor fix: V4.3.4.1 or later. Mitigations: uninstall Node-RED, or harden per the Node-RED user guide. `adminAuth` is a mitigation, not the firmware fix.

The Node-RED securing guide: by default the editor is not secured; anyone who can reach the IP can deploy changes. Current editor auth is the `adminAuth` object. Deprecated `httpAdminAuth` is not current auth. Absent `uiHost` means listen on all interfaces.

## Evidence this check reads

Presence is any of: dpkg/rpm/apk/pacman `node-red` / `nodered`; `node-red/package.json` under `global_node_modules`; `~/.node-red/settings.js` and, on Linux, `/root/.node-red/settings.js`; a unit file named `nodered.service` or `node-red.service` in `/etc/systemd/system`, `/lib/systemd/system`, `/usr/lib/systemd/system` or their `*.wants` dirs (file name only); `/proc/<pid>/comm` equal to `node-red`.

`settings.js` is read as at most 256 KiB of text. Block comments and `//` line comments outside quotes are stripped, then `adminAuth`, `httpAdminAuth` and a quoted `uiHost` literal are matched. Nothing from the file (hashes, user names, secrets, URLs) is copied into the report.

Siemens markers: os-release `ID` / `NAME` / `PRETTY_NAME` containing Industrial OS, SIMATIC or IoT2050, or the model string `6ES7647-0BA00-1YA2`. Firmware version is not compared.

## Finding to check-result rollup (`run_check`)

| Findings / blockers | Check result |
| --- | --- |
| at least one `affected` or `review` | `FAIL` |
| at least one `unknown` (and no `affected`/`review`) | `BLOCKED` |
| only `info` | `PASS` |
| nothing found | `NOT_APPLICABLE` |

- `adminAuth` present → `info`.
- `adminAuth` set to false, null or undefined counts as no adminAuth.
- No `adminAuth` and `uiHost` is a quoted `127.0.0.1` / `localhost` / `::1` → `info`.
- No `adminAuth` and `uiHost` absent, another literal, or not a quoted literal → `review`.
- Only deprecated `httpAdminAuth` → `review`.
- Unreadable `settings.js` → `unknown`.
- Node-RED present but no `settings.js` at the known paths → `review`.
- Siemens markers plus Node-RED → extra `review` even when `adminAuth` is set. Siemens markers without Node-RED → note only.

## Closing a finding under this profile

Use `verification_basis: vendor_patch` only for Siemens firmware V4.3.4.1 retrieved this run. `adminAuth` or a loopback bind is mitigation, not that firmware fix. On a generic host, `adminAuth` set is enough for this check to PASS.

## What needs a human

Confirming firmware on a SIMATIC device; a custom `--userDir` or another network namespace (not seen); approving `NOT_APPLICABLE`.
