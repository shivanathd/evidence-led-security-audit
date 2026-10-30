# Changelog

## Unreleased

### Added

- `scripts/host_checks.py`: three read-only checks (44 checks total). `teamviewer-111585` classifies TeamViewer metadata against TV-2026-1011 / CVE-2026-111585 (15.83; 15.64.10 on Windows only; 14.7.48868; platform 13.2 floors). Host findings cite TV-2026-1011. Portable folders under Downloads/Desktop and present-but-unversioned installs are covered. It never starts TeamViewer and does not read under `/opt/teamviewer`. `fragnesia-linux` classifies the running Linux kernel for CVE-2026-46300 from the CVE record floors and the Ubuntu official `x.y.0-N-generic` release + kernel-series table (including HWE and `#NNN-Ubuntu` upload). Mainline-PPA kernels are review. An unreadable running osrelease when other kernel metadata is present is unknown. It never emits info "Not affected" from `VERSION_ID` alone. `linux-tcp-uaf-98432` records the running kernel and distro as review: Ubuntu last updated 29 Oct 2026 had no released fixed build; cve.org floors published 30 Oct 2026 are not Ubuntu floors.
- Dated profiles: `teamviewer-2026-10-27.md`, `fragnesia-2026-10-28.md`. Skipped-list rows for the DHS staff identity leak and Synology NAS ransomware reports.

### Changed

- `profiles/golang-mptcp-2026-10-29.md` cites Ubuntu CVE-2026-98432 (last updated 29 Oct 2026) and the cve.org record published 30 Oct 2026: no released Ubuntu fixed package; upstream floors are not Ubuntu floors; WIP targets are not floors; the running-kernel record is `linux-tcp-uaf-98432`.
- Reviewed public hosts: `www.teamviewer.com`, `teamviewer.com`, `ubuntu.com`, `www.ubuntu.com`, `lists.openwall.net`, `remedio.io`.
- `check_public_package.py` compact file-count target raised from 55 to 60.

## 0.4.1 - 2026-10-30

### Added

- `scripts/host_checks.py`: four read-only checks from the 29–30 Oct 2026 briefing (41 checks total). `claude-code-vsx-21313` looks for Anthropic.claude-code 2.1.313 and the vendor-named persistence indicators (key comment only; no key material). `yoba-fake-ai-apps` looks for the Check Point Yoba sideload layout. `huggingface-qwen2-tiny` lists named cache paths as `unknown` (unconfirmed lead). `go-mptcp-linux` records Go 1.24+ on Linux and `godebug multipathtcp=0`; it does not invent a kernel version for CVE-2026-98432.
- `scripts/inventory.py`: `untrusted_run_interpolations` on GitHub workflow files when untrusted `github.event` / `github.head_ref` text is interpolated into a `run:` step. Numeric fields and `env:` assignments are not listed.
- Dated profiles: `dev-endpoint-2026-10-30.md`, `claude-code-vsx-2026-10-29.md`, `golang-mptcp-2026-10-29.md`, `freebsd-wireguard-2026-07-29.md`.

### Changed

- `gitlab-self-hosted` now classifies CE/EE 19.2 / 19.3 / 19.4 against the NVD floors for CVE-2026-97229 (CISA KEV, 29 Oct 2026). Versions outside that range stay `review`.
- Briefing date stamped on host-check fragments is 2026-10-30. A human must still re-read primary sources before closing findings.
- Host-check review fixes: crontab `.smt` uses a word-boundary match; `HF_HOME` is resolved to its `hub` subdirectory; Go `VERSION` is the first line only; standalone `go.mod` files are indexed. Inventory `untrusted_run_interpolations` flags untrusted github refs anywhere in an expression and ends a `- run:` block at the `run` key so a same-level `env:` is not treated as script.

## 0.4.0 - 2026-10-30

### Added

- Four host checks for the 2026-10-28 briefing items, taking the bundled set from 33 to 37:
  - `tailscale-ssh-1104`: Tailscale SSH forwarding (TS-2026-014 to TS-2026-017). Fixed in 1.104.4. Reads package/app metadata, prefs `RunSSH`, the `TS_SSH_DISABLE_FORWARDING` name in service files or tailscaled environ, and exported `ssh` policy keys. Never runs `tailscale` or restarts `tailscaled`.
  - `peoplesoft-presence`: Oracle PeopleSoft / PeopleTools footprint for CVE-2026-35273. Presence is `review` (a patched host may keep the same PeopleTools version). No PIA probe.
  - `anthropic-ai-chain` (unconfirmed): browser and OS patch level against a dated Chrome 156 floor. Safari, Windows and Linux exact builds are recorded as unverified. The Anthropic research post is real; mapping a given host to those chains is not.
  - `gmo-onamae-presence`: local zone/config hints for Onamae Desktop Cloud / DNS. No live DNS. Generic "GMO" text is not a hit.
- `inventory.py` emits `peoplesoft_hints` and `gmo_onamae_hints`, and records `actions/setup-node` `node-version` pins as runtime hints.
- Dated profiles: `peoplesoft-2026-10-28.md`, `anthropic-ai-chain-2026-10-27.md`, `gmo-onamae-2026-10-21.md`.

### Changed

- `brotli-nodejs` also classifies `.nvmrc`, `.node-version`, `.tool-versions`, `package.json` `engines.node` and CI `setup-node` pins. In-the-wild use against Node 24.22.0 is labelled unverified (not a Node.js or NVD claim).
- Mesh-VPN profile last-checked 2026-10-28: Tailscale published bulletins TS-2026-014..017 and named 1.104.4. No CVE id. `TS_SSH_DISABLE_FORWARDING=1` is the vendor-documented mitigation when a host cannot update.
- Example baseline / after-fix reports include the four checks as `BLOCKED`: empty inventory hints are not runtime or Onamae-non-use evidence. Tailscale, Anthropic and GMO sources published after the baseline date are omitted from the baseline and kept on the after-fix report.
- Reviewed public hosts: `www.oracle.com`, `oracle.com`, `www.anthropic.com`, `anthropic.com`, `internet.gmo`.
- `check_public_package.py` compact file-count target raised from 40 to 50 for the new dated profiles.
- Host-check report fragments stamp `retrieved_on` with `--collected-on` (this run does not fetch advisories).
- VALIDATION.md and `references/ci-failure-modes.md` record CI failure modes for the unchanged test workflow (bytecode cache, macOS temp symlinks, Windows BLOCKED helpers, expected INCOMPLETE after-fix example, host-check smoke bounds).

## 0.3.1 - 2026-10-29

### Added

- `references/ci-failure-modes.md`: troubleshooting notes for the public test workflow (bytecode cache, macOS temp symlinks, Windows BLOCKED helpers, expected INCOMPLETE after-fix example).

### Changed

- Phase 2, SaaS/identity, scoped-checks, reporting and contributing notes: treat single-source and press-only reports as unconfirmed leads. They can set identity and messaging-tenant checks to `BLOCKED` and open related findings as `unknown`; they cannot confirm a breach or clear one. Example: the TechRadar report published 28 Oct 2026 (retrieved 29 Oct 2026).
- `validate_report.py` rejects `vulnerable_component` findings that cite only a non-primary or stale source. After-fix reports also reject a primary advisory retrieved before the baseline (`retrieved_on` must be on or after the baseline `generated_on`). Same-day retrievals count as this run. The refresh rule applies only to primary advisory kinds. Nested baseline checks skip the new primary-source rule so a historical baseline that only cited non-primary sources is not made invalid; empty `source_ids` on a component finding is still `SOURCE_MISSING`.

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
