# Optional profile: developer-endpoint briefing of 2026-10-30

Last checked: 2026-10-30. This profile is a dated snapshot, not a standing rule. On every run, re-read the primary sources below and record their `retrieved_on` dates. If a source has changed, the source wins and this file is out of date. `host_checks.py` does not fetch sources; fragments stamp `retrieved_on` with this briefing date until a human corrects it.

This file is the dated fact base for the 29–30 Oct 2026 additions to `scripts/host_checks.py` and the GitHub Actions workflow lint in `scripts/inventory.py`. How those checks run is in [references/host-checks.md](../references/host-checks.md). The 27 Oct briefing remains [dev-endpoint-2026-10-27.md](dev-endpoint-2026-10-27.md).

## Check now

| Check id | Briefing fact | Source |
| --- | --- | --- |
| `claude-code-vsx-21313` | Cursor's VS Code extension Marketplace served a tampered `Anthropic.claude-code` **2.1.313** from about 09:27 UTC to 20:35 UTC on 29 Oct 2026 (2:27am–1:35pm PT). The package was not built by Anthropic. It appends an SSH public key whose comment is `svc-telemetry`, writes `~/.config/.smt` / `.smtk` (Windows: `smt.cmd` / `smtk`), a fake LaunchAgent `com.apple.sysmond`, temp files `.stk_<10 hex>`, and tries a reverse SSH tunnel. Cursor's own impact check is the key comment, not the key body. Uninstalling the extension does not remove persistence. | [Cursor notice](https://cursor.com/blog/claude-code-extension-security-notice), [Phorion write-up](https://phorion.io/blog/offical-claude-code-vsx-compromise/) |

## Check if we use it

| Check id | Briefing fact | Source |
| --- | --- | --- |
| `gitlab-self-hosted` (extended) | **CVE-2026-97229** (CWE-190): GitLab CE/EE from 19.2 before **19.2.8**, 19.3 before **19.3.5**, 19.4 before **19.4.2**. Unauthenticated code execution via a crafted CI/CD regular expression. CISA added it to KEV on 29 Oct 2026. Self-hosted only. | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-97229) (CNA: GitLab Inc.), [CISA KEV notice](https://www.cisa.gov/news-events/alerts/2026/10/29/cisa-adds-two-known-exploited-vulnerabilities-catalog) |
| `yoba-fake-ai-apps` | Check Point Research campaign **Yoba**: fake GitHub desktop apps (GPT-5.6 Sol, GPT-6 Astra, Claude Opus) pair a legitimate signed `Setup.exe` with `winmm.dll`, then `ProgramData\WMProcess`. OpenAI and Anthropic were not breached. | [Check Point Research](https://research.checkpoint.com/2026/tricks-from-the-past-deployed-via-signed-chatgpt-and-claude-binaries/), [The Hacker News](https://thehackernews.com/2026/10/fake-chatgpt-and-claude-apps-abuse.html) |
| `go-mptcp-linux` | As of Go 1.24, Go enables Multipath TCP on Linux listen sockets by default. [golang-announce](https://groups.google.com/g/golang-announce/c/PCoQcdxoScw) (29 Oct 2026) describes **CVE-2026-98432** as a Linux kernel IPv4 TCP use-after-free; a demonstrated exploit used an MPTCP listener. No patched kernel version was named. `GODEBUG=multipathtcp=0` / `godebug multipathtcp=0` is a fragile mitigation. | [golang-announce](https://groups.google.com/g/golang-announce/c/PCoQcdxoScw) |
| `teamviewer-111585` | TeamViewer Full Client / Host / Portable below **15.83** (CVE-2026-111585). Legacy floors: 15.64.10 (Windows 7/8 only), 14.7.48868, 13.2.36231 / 13.2.154008 / 13.2.154007. Other lines below 15.83 are affected. Never start TeamViewer. | [TV-2026-1011](https://www.teamviewer.com/en/resources/trust-center/security-bulletins/tv-2026-1011/), [CVE-2026-111585](https://www.cve.org/CVERecord?id=CVE-2026-111585) |
| `fragnesia-linux` | Linux kernel **CVE-2026-46300** (Fragnesia). CISA KEV added 28 Oct 2026 (due 31 Oct 2026); chain with CVE-2026-109618 / 109619 — also run `php2shell`. Floors from the CVE record; Ubuntu generic/HWE rows from the 29 Oct 2026 page. Classification uses the running osrelease only. | [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-46300), [CISA KEV alert](https://www.cisa.gov/news-events/alerts/2026/10/28/cisa-adds-two-known-exploited-vulnerabilities-catalog), [Ubuntu](https://ubuntu.com/security/CVE-2026-46300) |
| `linux-tcp-uaf-98432` | Running-kernel record for **CVE-2026-98432**. Ubuntu last updated 29 Oct 2026: current releases vulnerable, work in progress; no released fixed build. cve.org published 15 Oct 2026, updated 30 Oct 2026 lists upstream floors that are not Ubuntu floors. Review only. WIP targets are not floors. | [Ubuntu CVE-2026-98432](https://ubuntu.com/security/CVE-2026-98432), [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-98432) |
| `drupal-commerce-118539` | **CVE-2026-118539** / SA-CONTRIB-2026-254: Drupal Commerce Core access bypass, actively exploited. Affected `<2.41` or `>=3.0.0 <3.3.13`. Fixed builds **8.x-2.41** (needs Drupal `^9.3 \|\| ^10`) and **3.3.13** (needs Drupal `^10.3 \|\| ^11`). News ranges that include those builds are not floors. Reads `composer.lock`, optional `vendor/composer/installed.json`, and packaged Commerce info.yml (`project: commerce` only). Drupal 7 commerce INI files are unseen. | [SA-CONTRIB-2026-254](https://www.drupal.org/sa-contrib-2026-254), [3.3.13](https://www.drupal.org/project/commerce/releases/3.3.13), [8.x-2.41](https://www.drupal.org/project/commerce/releases/8.x-2.41), [CVE-2026-118539](https://www.cve.org/CVERecord?id=CVE-2026-118539) |
| `jetbrains-jbr-emudhra` | JetBrains 30 Oct 2026 blog: bundled JBR still trusted the compromised eMudhra intermediates. Product-specific floors. IDE version from `product-info.json` only. RC/EAP is review. 2025.2 at or above its floor is JCEF-pending. OS updates do not cover this. | [JetBrains blog](https://blog.jetbrains.com/security/2026/10/compromised-emudhra-certificates-ides/) |
| `clickhouse-116366` | **CVE-2026-116366**: unauthenticated network RCE on ClickHouse Server. OSS floors only (`v26.3.62.3-lts`, `v26.8.36.3-lts`, `v26.9.27.3-stable`, `v26.10.3.7-stable`). Cloud / BYOC numbers are not OSS floors. `clickhouse-client` and `clickhouse-keeper` (with or without `clickhouse-common-static`) are not this check. | [ClickHouse changelog](https://clickhouse.com/docs/resources/changelogs/security-changelog), [CVE-2026-116366](https://www.cve.org/CVERecord?id=CVE-2026-116366) |
| `wordpress-core-upgrade-rce` | GHSA-4w3m-c66w-69mg: race during a full-package core upgrade. Patched 28 Oct 2026 in **7.1.4** and HelpHub/GHSA branch backports through **4.7.39**. 4.6 and earlier are review. Reads `$wp_version` only. No HTTP to `setup-config.php`. | [WordPress 7.1.4](https://wordpress.org/news/2026/10/wordpress-7-1-4/), [HelpHub](https://wordpress.org/documentation/wordpress-version/version-7-1-4/), [GHSA-4w3m-c66w-69mg](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4w3m-c66w-69mg) |
| inventory `untrusted_run_interpolations` | Generic lint: `github.event` issue/comment/PR string fields (and `github.head_ref`) flowing into a `run:` step. The 61-repo campaign itself is press-only (below). | GitHub's documented script-injection pattern; campaign lead: [The Register](https://www.theregister.com/security/2026/10/29/attackers-turn-github-issues-into-supply-chain-campaign-against-61-public-repos-in-less-than-an-hour/5306153) |

## Unconfirmed leads (no FAIL, no clearance)

| Item | Why it is a lead | Source |
| --- | --- | --- |
| EMBRACE embedded browsers (Cursor, Copilot, Codex, VS Code, Claude Desktop) | Single-source research blog. No CVE and no vendor advisory retrieved. Cursor is described as silently patched on 1 Oct 2026; Codex and VS Code described as still open. Cannot confirm or clear. | [Forever Security](https://forever.security/blog/embrace-hacking-5-ai-assistants-embedded-browsers/) |
| Hugging Face `qwen2-tiny` mining campaign | Press plus a third-party research shop. No Hugging Face vendor advisory retrieved. `huggingface-qwen2-tiny` only lists named cache paths as `unknown`. | [BleepingComputer](https://www.bleepingcomputer.com/news/security/hugging-face-malware-campaign-returns-to-hijack-gpus-for-crypto-mining/) |
| Fake Solana starter kit (Air Security) | Mentioned in the same press piece. README one-liner, no local metadata indicator that is safe to automate. | same BleepingComputer article |
| GitHub Actions campaign against 61 public repos (LangExtract, Trivy, MLflow, …) | The Register exclusive citing Radware. No primary vendor advisory. The inventory lint is generic, not attribution. | [The Register](https://www.theregister.com/security/2026/10/29/attackers-turn-github-issues-into-supply-chain-campaign-against-61-public-repos-in-less-than-an-hour/5306153) |

`huggingface-qwen2-tiny` is the only host check that may open `unknown` findings for a lead. It never reports `affected`.

## Skipped (not visible on the machine, or needs another OS)

| Item | Why it is skipped |
| --- | --- |
| FreeBSD WireGuard CVE-2026-58085 | Confirmed by [FreeBSD-SA-26:52.if_wg](https://security.freebsd.org/advisories/FreeBSD-SA-26:52.if_wg.asc) (29 Jul 2026). `host_checks.py` does not cover FreeBSD. See [freebsd-wireguard-2026-07-29.md](freebsd-wireguard-2026-07-29.md). |
| Binance / Polymarket organisation incidents | No local client or artifact named; organisation accounts. |
| Cisco Secure Firewall CVE-2026-76418 (same CISA KEV notice) | Network appliance; needs the admin console. |
| DHS staff identity leak | Government data leak; nothing on the endpoint shows it. |
| Synology NAS ransomware reports | Appliance; single forum source; no vendor confirmation. |
| Drupal Commerce order-inconsistency audit | Needs the site database; `drupal-commerce-118539` only reads the packaged Commerce info.yml, `composer.lock` and `vendor/composer/installed.json`. |

## How this maps to the skill

- Target: one `other` target per machine. Run with `--target ID` and merge `report_fragments`.
- A `claude-code-vsx-21313` hit is also a credential-exposure event (phase 4): list every credential the account could read. Follow the vendor notice from a clean device. This tool never deletes keys or persistence.
- A GitLab version PASS on this machine says nothing about GitLab SaaS or a GitLab image built elsewhere.

## What needs a human

Deciding whether a `SysMon` scheduled task is this implant or something else; rebuilding machines that ran 2.1.313; rotating credentials after a backdoor finding; confirming a Linux kernel build against a distro advisory for CVE-2026-98432; and approving NOT_APPLICABLE checks.
