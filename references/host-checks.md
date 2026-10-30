# Host checks: one machine, read-only

`scripts/host_checks.py` runs 44 read-only checks of the machine it runs on (macOS, Linux or Windows) for the locally visible items in the 16-30 Oct 2026 developer-endpoint briefings. The dated briefing facts and source links are in [profiles/dev-endpoint-2026-10-27.md](../profiles/dev-endpoint-2026-10-27.md) and [profiles/dev-endpoint-2026-10-30.md](../profiles/dev-endpoint-2026-10-30.md). Use it in phase 3 for an `other` (endpoint) target. For a fleet, run it through the collection channels in [endpoint-fleet.md](endpoint-fleet.md) and treat devices that did not report as gaps.

It is a metadata reader, not a scanner. It reads files and the Windows registry, and it never runs the programs it checks.

## Run it

```bash
OUT="$(cd "$(mktemp -d)" && pwd -P)"
python3 scripts/host_checks.py --list-checks
python3 scripts/host_checks.py --out "$OUT/host-checks.json"
python3 scripts/host_checks.py --only litellm-1-107-0 --target dev-laptop-1 --collected-on 2026-10-27
```

On Windows: `py -3 scripts\host_checks.py --out "%TEMP%\host-checks.json"`. Without `--out` the JSON goes to stdout and a one-line summary goes to stderr.

| Flag | Meaning |
| --- | --- |
| `--root DIR` | Folder to walk (repeatable). Default: the home folder plus web roots that exist (`/var/www`, `/srv`, `C:/inetpub`, and similar). |
| `--only CHECK_ID` | Run only these checks (repeatable). |
| `--target ID --collected-on DATE` | Also emit `report_fragments` (sources, evidence and required checks) to merge into a report. |
| `--allowlist FILE` | Owner-confirmed hooks, large files, instruction files, MCP servers and base URLs. Matches become `info`, with the reason shown. |
| `--strict` | Exit 3 when any check FAILs or coverage is PARTIAL. |
| `--max-depth`, `--max-entries`, `--time-budget`, `--repo-seconds` | Walk bounds. Defaults: 10 levels, 400,000 entries, 240 s for the whole run, 15 s per repository. |
| `--blob-review-mib LO-HI` | Size band for "about 13 MB" payload blobs. Default 11-16 MiB. |

Allowlist format. Every entry needs a `reason` and at least one of `path_glob`, `sha256`, `object_id`, `name` or `host`:

```json
{"hooks": [{"path_glob": "~/code/app/.cursor/hooks/*", "reason": "formatter hook the owner wrote"}],
 "large_files": [{"object_id": "<git blob sha1>", "reason": "test fixture"}],
 "instruction_files": [{"sha256": "<file sha256>", "reason": "my notes"}],
 "mcp_servers": [{"name": "docs", "reason": "team server"}],
 "base_urls": [{"host": "llm.example.com", "reason": "company proxy"}]}
```

## Results

Each check ends as `PASS`, `FAIL`, `BLOCKED` or `NOT_APPLICABLE`. Each finding is `affected`, `review`, `unknown` or `info`.

- **FAIL**: at least one `affected` or `review` finding.
- **BLOCKED**: the check recorded a blocked reason, a present component's version or state could not be read without executing it, the walk ran out of time or entries, or (for trust stores) no store could be read. The reason says which. An unreadable file is a gap; it only BLOCKS if that check needed the file.
- **PASS**: for the indicator checks (planted hooks, large blobs, planted instruction files, `testmetest`, `function-color`, LiteLLM 1.107.0), PASS means "searched the listed roots and found none". For version checks, PASS means the component was found and every copy is fixed.
- **NOT_APPLICABLE**: the component was not found. A missing tool is "not present", not an error. In a report, NOT_APPLICABLE still needs a human `approved_by_role`.

The output has `coverage` (`COMPLETE_FOR_LISTED_ROOTS` or `PARTIAL`) and `scan` (roots, bounds, folders listed, and gaps by reason). If folders were deeper than `--max-depth`, the check's reason says how many. A walk that is complete for the listed roots says nothing about folders outside them.

## Read-only guarantees and bounds

- Writes nothing except the `--out` file. It refuses to overwrite without `--force`. On POSIX the write goes through `safeio` (no symlinks, mode 0600).
- No network calls, no installs, no token revocation and no deletion. The tests replace `socket.connect`, `subprocess.Popen` and `os.system` and fail if any of them is used during a run.
- It runs only two commands, both read-only listings: `rpm -qa` (only when an RPM database exists) and macOS `security find-certificate -a -p <keychain>`. Everything else is parsed from files: dpkg/apk/pacman databases, `dist-info`/`conda-meta`, lockfiles, `node_version.h`, PE version resources, Go build info, `Info.plist`, git index and object headers. Git itself is never run, so repository hooks cannot fire.
- On Windows it uses `winreg` (uninstall keys) and `ssl.enum_certificates` (ROOT and CA stores), both read-only.
- It never follows symlinks, does not read FIFOs or devices, and caps every read. It skips `node_modules` while walking, except where a check looks inside a specific `node_modules/<package>` folder. It also skips caches, `.git` content and tool folders such as `~/Library` and `~/.cargo`.
- Config files are reduced to server names, env var **names**, command basenames, package names, and scheme plus host of URLs. URL credentials, query strings and argument values are dropped. The whole output then passes through the same redaction used by `render_report.py`.
- A file that cannot be read becomes a gap with a reason, never a crash.

## testmetest clean-up order (reported, never performed)

Per the briefing, the worm wipes the home folder if its stolen GitHub token is revoked first. The output carries `cleanup_order_testmetest`:

1. Clean or rebuild the affected machine first, and any machine that ran the repository's hooks.
2. Then revoke and replace the GitHub token, from a clean device.
3. Then remove the planted hook files and payload blobs from the repositories, and review who pushed them.

## Coverage by OS

The walk (default: home) indexes project files under `--root`: lockfiles, manifests, Dockerfiles, compose files and deploy YAML. The table lists extra places each check reads per OS. Browser, package, trust-store and binary lookups use those fixed locations; they are not limited to `--root`.

| Check | macOS | Linux | Windows |
| --- | --- | --- | --- |
| `testmetest-ai-hooks` | Walk: `.cursor`, `.vscode`, `.claude`, `.gemini`, `.windsurf`, `.codex` folders in repos; user-level `~/.cursor/hooks`, `~/.claude/settings.json` | same | same |
| `testmetest-large-blobs` | Git index, loose-object and pack headers in each repo (no git binary); untracked files in the size band | same | same |
| `testmetest-npm-package` | Walk lockfiles and `node_modules`; Homebrew and `/usr/local` global modules; `~/.npm/_cacache` index | same, plus `/usr/lib/node_modules` | same, plus `%APPDATA%\npm\node_modules` |
| `planted-agent-instructions` | `AGENTS.md`, `CLAUDE.md`, `GEMINI.md` and similar in Downloads, home, `/tmp` and outside projects; risky lines anywhere | same | same, plus `%TEMP%` |
| `agent-config-endpoints` | `~/.codex/config.toml`, `~/.claude/settings*.json`, `~/.claude.json`, `~/.cursor/mcp.json`, `.mcp.json`, project `.claude`/`.cursor` configs, Claude Desktop and VS Code/Cursor `mcp.json` under `~/Library/Application Support` | same, desktop configs under `~/.config` | same, desktop configs under `%APPDATA%` |
| `function-color-npm-package` | As `testmetest-npm-package` | same | same |
| `litellm-1-107-0` | venvs, conda, pipx, uv, pyenv, Poetry/Hatch envs; requirements and lockfiles; Dockerfile `pip install`; image tags | same, plus `/usr/lib/python3*` | same, plus `%LOCALAPPDATA%\Programs\Python` and Program Files |
| `brotli-nodejs` | nvm, fnm, volta, asdf, mise, nodenv, n, Homebrew `node@*`; `node_version.h`; `node` on PATH; image tags | same, plus dpkg/apk/pacman/rpm `nodejs*` | nvm-windows, fnm, Volta; `node.exe` PE version; uninstall registry |
| `brotli-python` | `Brotli` and `brotlicffi` in every Python environment and lockfile | same | same |
| `brotli-dotnet` | `shared/Microsoft.NETCore.App` and `shared/Microsoft.AspNetCore.App` under `/usr/local/share/dotnet`, Homebrew, `~/.dotnet`, `DOTNET_ROOT` | `/usr/share/dotnet`, `/usr/lib/dotnet`, `/opt/dotnet`, `~/.dotnet` | `Program Files\dotnet`, `~/.dotnet` |
| `emudhra-certifi` | `certifi` in every environment, plus pip's vendored copy | same | same |
| `emudhra-trust-store` | `/etc/ssl/cert.pem`, Homebrew bundles, System and SystemRoots keychains (read with `security`), certifi bundles | distro CA bundles under `/etc/ssl` and `/etc/pki`, certifi bundles | ROOT and CA stores via `ssl.enum_certificates`, certifi bundles |
| `chrome-156`, `browser-versions` | `Info.plist` of Chrome, Chromium, Edge, Brave, Firefox, Safari, Opera, Vivaldi, Arc | dpkg/rpm/apk/pacman packages, snap metadata, flatpak (version not read), `application.ini` | Version folders under Program Files and `%LOCALAPPDATA%`, Firefox `application.ini`, uninstall registry |
| `php2shell` | Homebrew `php@*`, `php_version.h`, MAMP; `php.ini` for `session.upload_progress.enabled`; image tags | distro packages, `php_version.h`, `/etc/php/*/*/php.ini` | `php8ts.dll`/`php8.dll` PE version under XAMPP, Laragon, `C:\php`, `C:\tools`, Program Files, PATH |
| `railway-client`, `opencode-client`, `warp-terminal`, `lightning-ai-client`, `connectwise-presence` | App bundles, CLI binaries, config folders | packages, binaries, config folders | Program Files, uninstall registry, `%APPDATA%` folders |
| `vitest-5-dev-server`, `pillow-13`, `wasmtime-embedded` | Walk lockfiles (npm, Cargo, Go, NuGet, Python) and environments; Homebrew `wasmtime` | same | same |
| `ovhcloud-cli`, `ruby-regex`, `nginx-present`, `qdrant-cluster`, `plex-media-server` | Homebrew Cellar, version managers (rbenv, rvm, asdf), binaries, app bundles, image tags | distro packages, version managers, binaries, image tags | Program Files, uninstall registry, PE versions, image tags |
| `gitlab-self-hosted`, `collabora-nextcloud` | Image tags and code on disk | distro packages, image tags and code on disk | image tags and code on disk |
| `ksmbd-linux` | not applicable | `/sys/module/ksmbd`, `/etc/ksmbd/ksmbd.conf`, `ksmbd-tools` package | not applicable |
| `wordpress-updraftplus`, `magento-store` | Walk plus web roots: `wp-content/plugins/updraftplus`, Magento `app/etc/env.php` | same | same, plus `C:\inetpub` |
| `tailscale-ssh-1104` | App bundle `Info.plist`; Homebrew Cellar; prefs JSON/plist `RunSSH`; LaunchDaemon env; exported `ssh` policy filenames. Never runs `tailscale` | dpkg/apk/pacman/rpm `tailscale`; `/var/lib/tailscale/prefs.json`; `/etc/default/tailscaled` and systemd drop-ins; tailscaled `/proc/<pid>/environ` (boolean only, path reported as `/proc/<pid>/environ`); exported policy files | Program Files, uninstall registry, PE version; prefs if present |
| `peoplesoft-presence` | Walk: `psconfig.sh`, `psappsrv.cfg`, `allowedhosts.properties` under a PeopleSoft/PeopleTools path; `/opt/PT8.*` | same, plus `/opt/oracle/psft`, distro packages, image tags | Program Files `PeopleSoft*` / `PeopleTools*`, uninstall registry |
| `anthropic-ai-chain` | Chrome/Safari/other browser plists vs dated Chrome 156 floor; macOS `ProductVersion` recorded as unverified | Chrome packages; `/proc/sys/kernel/osrelease` recorded as unverified | Chrome version folders; Windows registry build recorded as unverified |
| `gmo-onamae-presence` | Local zone files, `named.conf`, DNS-ish tf/conf under a `dns` path. No live DNS. Only Onamae host strings | same, plus `/etc/bind`, `/etc/named`, `/var/named` | same walk of `--root` |
| `claude-code-vsx-21313` | `~/.cursor/extensions` and editor extension folders (targeted, not a full extensions walk); `~/.ssh/authorized_keys` comment only; `~/Library/LaunchAgents/com.apple.sysmond.plist`; `~/.config/.smt` / `.smtk`; `$TMPDIR/.stk_*` | same, plus user crontab files if readable | same, plus `%USERPROFILE%\.ssh`, `administrators_authorized_keys`, Startup `sysmon.cmd`, `Tasks\SysMon` |
| `yoba-fake-ai-apps` | Downloads/Desktop folder names and `Setup.exe`+`winmm.dll` pairs | same | same, plus `C:\ProgramData\WMProcess` |
| `huggingface-qwen2-tiny` | `~/.cache/huggingface` names and `/tmp/.cch` (unconfirmed; findings are `unknown`) | same | same |
| `go-mptcp-linux` | indexed `go.mod` (with or without `go.sum` / `.git`), toolchain VERSION, Homebrew `go` (recorded only) | same plus distro `golang*`, `/usr/local/go/VERSION`, `/proc/version` note | toolchain if present (MPTCP default is Linux-only) |
| `teamviewer-111585` | Info.plist of the TeamViewer and TeamViewer Host application bundles under `/Applications` and `~/Applications` (including `TeamViewerHost`). A present bundle without a readable plist is `unknown`. Downloads/Desktop portable names (compact `teamviewerportable`, including space and underscore forms). Never starts TeamViewer | dpkg/apk/pacman/rpm `teamviewer` / `teamviewer-host`; `/opt/teamviewer` directory without a package is `unknown` (nothing under it is read) | Program Files `TeamViewer*` PE of `TeamViewer.exe` / `TeamViewer_Desktop.exe`; uninstall registry `^TeamViewer(?: \d+)?(?: Host)?$`; Downloads/Desktop/Public Downloads portable names (space and underscore forms); a present folder without a versioned PE is `unknown`; an empty Host dir is `unknown` even when another install is versioned |
| `fragnesia-linux` | not applicable | running `/proc/sys/kernel/osrelease` plus `/etc/os-release` or `/usr/lib/os-release` `ID`/`VERSION_ID`; Ubuntu official `x.y.0-N-generic` `(release, major.minor)` ABI table including HWE and `#NNN[.N][~suffix]-Ubuntu` upload when present; a `~YY.MM` suffix that does not match `VERSION_ID` is `review`; equal ABI with an unreadable upload is `review` when the floor needs the upload; plain `x.y.z` upstream floors otherwise. Unreadable osrelease when other kernel metadata is present is `unknown` | not applicable |
| `linux-tcp-uaf-98432` | not applicable | running osrelease / `/proc/version` / os-release / `linux-image*` recorded as `review` only. cve.org published 15 Oct 2026, updated 30 Oct 2026 upstream floors are cited, not applied as Ubuntu floors | not applicable |

## Known limits

- **Version spoofing.** Versions come from metadata (folder names, `dist-info`, plists, headers, PE resources). A binary whose metadata lies is not detected, because the tool never runs programs.
- **Hook scripts.** In a repository's AI tool folder, files in `hooks/` folders, hook keys in settings JSON, scripts with a script extension and executable files are all reported. An extensionless, non-executable file outside `hooks/` is not reported on its own, but the hook config that runs it is.
- **Plugin caches** under `~/.cursor/plugins`, `~/.claude/plugins` and editor `extensions/` folders are not walked. They are vendor-managed and large; review them through the editor.
- **Windows PHP rebuild suffix.** A `-1` rebuild suffix is not visible in the DLL version resource, so a Windows build exactly at a fixed version is a `review` rather than a PASS.
- **Depth and roots.** The walk does not see anything deeper than `--max-depth` or outside `--root`. Depth misses are counted and named in the reason; they do not make the check FAIL. Browser, package, trust-store and binary lookups still use the fixed locations in the table.
- **Large blobs.** LFS-tracked files in the size band are `info`, not `review`. A payload committed under an LFS pattern is therefore not flagged as `review`; check LFS objects nobody expected by hand.
- **CVE-2026-40369** is unconfirmed in the briefing. `browser-versions` lists versions only and never says "affected".
- **Anthropic AI-discovered chains** are a published vendor research post, but mapping a given host to those chains is unconfirmed. `anthropic-ai-chain` uses Chrome 156 as a dated floor (Chrome below 156 is `review` / FAIL) and records Safari / Windows / Linux builds as unverified. Android is out of scope (no collection path). It never says "affected" for those OS/browser pairs.
- **Tailscale SSH** versions come from package/app metadata. Distro-patched builds that keep an older number, and prereleases of 1.104.4, are not treated as fixed. `TS_SSH_DISABLE_FORWARDING` is a mitigation, not a vendor patch. The check never sets the variable or restarts `tailscaled`.
- **Fragnesia Ubuntu ABI.** `parse_version` nums ignore the Ubuntu ABI, so `6.8.0-90-generic` and `6.8.0-124-generic` both parse as `(6, 8, 0)`. `fragnesia-linux` applies the Ubuntu table only to official `x.y.0-N-generic` strings (`N` = 1–999, no leading zero) and compares `(VERSION_ID, major.minor, abi[, upload])` against the Ubuntu page rows, including HWE. `N >= 1000` and Mainline-PPA kernels are `review`. Dotted `#NNN.N-Ubuntu` uploads are parsed; a `~YY.MM` suffix that does not match `VERSION_ID` is `review`. It never emits info "Not affected" from `VERSION_ID` alone.
- **CVE-2026-98432** has no released Ubuntu fixed build (page last updated 29 Oct 2026). The cve.org record published 15 Oct 2026, updated 30 Oct 2026 lists upstream floors that are not Ubuntu package floors. `linux-tcp-uaf-98432` is review only and never claims the host is fixed. WIP targets are not floors.
- **TeamViewer** versions come from package, plist, PE or uninstall-registry metadata. Host findings cite TV-2026-1011. Windows 15.64.10+ is `review` (legacy fix is Windows 7/8 only; no Windows-build reader). Portable names match compact `teamviewerportable` (space and underscore forms) under Downloads/Desktop/Public Downloads. Registry names include `TeamViewer 14 Host`. An empty Host dir is not reported when a versioned Host install exists. The check never starts TeamViewer and never reads under `/opt/teamviewer`.
- **Not covered here:** anything needing network scanning or admin consoles. See the skipped list in the profile.
