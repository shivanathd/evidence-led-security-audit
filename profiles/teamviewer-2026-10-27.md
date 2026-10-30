# Optional profile: TeamViewer CVE-2026-111585 / TV-2026-1011 (2026-10-27)

Last checked: 2026-10-30. Dated snapshot. Re-read [TV-2026-1011](https://www.teamviewer.com/en/resources/trust-center/security-bulletins/tv-2026-1011/) and [CVE-2026-111585](https://www.cve.org/CVERecord?id=CVE-2026-111585) on every run. If a source has changed, the source wins.

`host_checks.py` check id: `teamviewer-111585`. Read-only metadata only. Never start TeamViewer, never open a session, never decode a `.tvs` file, and never read or run anything under `/opt/teamviewer`.

## Primary sources

- Vendor bulletin TV-2026-1011 (issue date 27 Oct 2026, last update 28 Oct 2026): [teamviewer.com](https://www.teamviewer.com/en/resources/trust-center/security-bulletins/tv-2026-1011/)
- CVE Record CVE-2026-111585 (CNA: TeamViewer): [cve.org](https://www.cve.org/CVERecord?id=CVE-2026-111585)
- Researcher write-up (lead; not a version floor): [remedio.io](https://remedio.io/research/vulnerability-disclosures/remote-code-execution-in-teamviewer/) (published 29 Oct 2026). Cite the URL and dates only.

The bulletin also lists CVE-2026-92372 and CVE-2026-92374 on the same 15.83 / legacy floors. This check is titled and sourced for 111585. Updating to 15.83 covers the bulletin.

## Fixed builds (retrieved 2026-10-30)

| Line | Fixed version | Platforms |
| --- | --- | --- |
| Current Full Client / Host / Portable | 15.83 | Windows, Linux, macOS (Portable: Windows) |
| Legacy 15.64 | 15.64.10 | Windows 7 and 8 only |
| Legacy 14.7 | 14.7.48868 | Windows, Linux, macOS |
| Legacy 13.2 | 13.2.36231 (Windows), 13.2.154008 (Linux), 13.2.154007 (macOS) | as named |

CVE-2026-111585 range: below 15.83 affected. 16.x and later are info. Other lines below 15.83 with no listed legacy fix are affected. 15.64.x on Linux or macOS is affected (the 15.64 legacy fix is Windows 7 and 8 only). Android Remote Control is out of scope.

## What this skill will not invent

No screen-buffer dimensions, no WinExec path, no extra findings for 92372/92374, and no Homebrew cask lookup (a cask installs into `/Applications`, which is already read). Linux packages are `teamviewer` and `teamviewer-host` only. A `/opt/teamviewer` directory without a package is `unknown`, not a guessed version file.

## How a finding closes

Closing needs the vendor bulletin (or CVE record) retrieved this run, plus evidence the installed Full Client / Host / Portable build is 15.83 or a listed legacy floor for that platform.

## What needs a human

Confirming a distribution rebuild against the vendor changelog; deciding whether a Host-only install is in scope; Android clients (not checked here).
