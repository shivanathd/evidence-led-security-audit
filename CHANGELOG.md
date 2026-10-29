# Changelog

## 0.3.1 - 2026-10-29

### Added

- `references/ci-failure-modes.md`: troubleshooting notes for the public test workflow (bytecode cache, macOS temp symlinks, Windows BLOCKED helpers, expected INCOMPLETE after-fix example).

### Changed

- Phase 2, SaaS/identity, scoped-checks, reporting and contributing notes: treat single-source and press-only reports as unconfirmed leads. They can set identity and messaging-tenant checks to `BLOCKED` and open related findings as `unknown`; they cannot confirm a breach or clear one. Example: the TechRadar report published 28 Oct 2026 (retrieved 29 Oct 2026).
- `validate_report.py` rejects `vulnerable_component` findings that cite only a non-primary or stale source.

## 0.3.0 - 2026-10-27

### Added

- `scripts/host_checks.py`: read-only checks of the machine it runs on (macOS, Linux, Windows) for the 2026-10-27 developer-endpoint briefing: 33 checks covering testmetest hooks, payload blobs and package, planted `AGENTS.md`/`CLAUDE.md`, MCP servers and base URLs in coding-agent configs, `function-color`, LiteLLM 1.107.0, Brotli CVE-2026-111497 (Node, Python, .NET), eMudhra (certifi and trust stores), Chrome 156 and browser versions, PHP2Shell, and the briefing's "check if we use it" items. It never runs the programs it checks, makes no network calls, writes only `--out`, redacts config values, and is bounded by depth, entries and time. It can emit `report_fragments` to merge into a report.
- `scripts/hostscan.py`: the bounded, no-follow walker and metadata parsers behind it (Python dist-info, conda, lockfiles, PE and Go build info, plists, DER/PEM, git index and pack headers, LFS patterns).
- `references/host-checks.md` (how to run it, per-OS coverage, limits) and `profiles/dev-endpoint-2026-10-27.md` (dated briefing facts, sources and skipped items).
- Fixture tests for every check on simulated macOS, Linux and Windows hosts, and a whole-run test proving no writes, no network, no subprocess beyond two read-only listings, and no secret values in output.
- CI runs on Windows (Python 3.9 and 3.14) alongside Ubuntu and macOS, and adds a host_checks smoke run on each runner.

### Changed

- Tests for the POSIX-only helpers (`inventory.py`, `check_public_package.py`, `render_report.py --out`) are skipped where those helpers exit BLOCKED, so the suite runs on Windows.
- Briefing source hosts added to the reviewed public-host list used by the leak scanner.
- Host path helpers treat POSIX `/home/...` locators the same on every OS, keep simulated PATH entries that already sit under `sysroot`, and de-duplicate `Lib`/`lib` site-packages on case-folding volumes. `display()` redacts the original locator before POSIX `abspath` of a drive-prefixed `/home` path.
- `py_pins` ignores `#`-comments so a commented pin is not treated as installed.
- `pe_file_version` still scans the head of a file larger than the read window (the tail-only pass used to abort).

## 0.2.x - 2026-10-25 to 2026-10-26

- Added bundled-library and hijacked-package checks (Brotli, LiteLLM, eMudhra) with dated profiles.
- Added mesh VPN SSH, PHP runtime and hosted AI/ML credential checks and profiles.

## 0.2.0 - 2026-10-22

- First public release: phases and gates, report schema, validator, renderer, inventory, public-package checker, endpoint and fleet guide.
