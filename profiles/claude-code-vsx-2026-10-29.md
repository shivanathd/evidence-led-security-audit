# Optional profile: tampered Claude Code extension 2.1.313 (2026-10-29)

Last checked: 2026-10-30. Dated snapshot. Re-read the vendor notice on every run.

## What is confirmed

[Cursor's security notice](https://cursor.com/blog/claude-code-extension-security-notice) (29 Oct 2026) states:

- The Cursor VS Code extension Marketplace served a malicious **Anthropic.claude-code 2.1.313** that Anthropic did not build.
- Window: about **2:27am PT to 1:35pm PT** on 29 Oct 2026 (**09:27–20:35 UTC**).
- The payload tries to install a persistent SSH backdoor: host/user reconnaissance, an attacker SSH key in `authorized_keys`, a reverse tunnel, and persistence.
- Cursor's own impact check is the key comment `svc-telemetry` in `~/.ssh/authorized_keys` (Windows also `C:\ProgramData\ssh\administrators_authorized_keys`).
- Uninstalling the extension is not enough: standalone persistence scripts keep running.
- Enabling the local SSH service needs admin rights and often failed; the key, persistence and host-detail POST can still succeed.
- Cursor removed the package, took the marketplace down, rotated keys, and worked with the hosting provider to take the attacker server offline.

[Phorion](https://phorion.io/blog/offical-claude-code-vsx-compromise/) (30 Oct 2026) independently describes the same implant on macOS, Linux and Windows, including a macOS `systemsetup -getremotelogin` logic bug and a Linux `@reboot` crontab entry for `~/.config/.smt`.

## Indicators this skill will read (paths and names only)

- Extension folder or VSIX name containing `anthropic.claude-code-2.1.313`.
- `svc-telemetry` as a **comment** in `authorized_keys`. The public key body is not stored in this repository and is not copied into findings.
- `~/Library/LaunchAgents/com.apple.sysmond.plist` (label `com.apple.sysmond`).
- `~/.config/.smt`, `~/.config/.smtk` (macOS/Linux); `~/.config/smt.cmd`, `~/.config/smtk` (Windows).
- Temp files named `.stk_` plus ten hex characters.
- Windows Startup `sysmon.cmd`; scheduled task file named `SysMon` (review if the file does not mention the persistence script — Sysinternals Sysmon is a different name).
- Linux user crontab text that mentions `.smt`.

Network indicators from the vendor notice (defanged here): `134[.]209[.]82[.]225` on TCP 22 and HTTP POST `/beacon` on port 8099. This tool makes no network calls and does not search for that address.

## What is unknown

- Whether a given host actually completed the reverse tunnel or received an inbound login. SSH logs showing `localhost` authenticating with the planted key would need a human review; this tool does not read auth logs by default.
- Whether copies of 2.1.313 outside the Cursor Marketplace (npm / VS Code Marketplace) existed. Phorion says Cursor pulled those too; the vendor notice is about the Cursor Marketplace package.

## How a finding closes

`affected` stays open until a human confirms the persistence files and planted key are gone **and** credentials reachable from that account have been rotated from a clean device. A missing extension folder after a rebuild is not enough if `.smt` or the key comment remains. This tool never remediates.

## What needs a human

Isolation, rebuild vs clean-in-place, vendor remediation scripts (only from the vendor notice), credential rotation, and deciding whether a `SysMon` task is this implant.
